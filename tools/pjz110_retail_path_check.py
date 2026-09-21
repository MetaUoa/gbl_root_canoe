#!/usr/bin/env python3
"""Fail-closed offline verifier for PJZ110 P0-P4 deployment-path analysis.

The tool never modifies an input. For the exact profiled PJZ110 16.0.10.501
artifacts it verifies:

P0  frozen image/XBL_CONFIG baseline;
P1  USB Host auto-start is gated off in the shipping UsbConfigDxe;
P2  the normal DFP -> XHCI chain is therefore blocked before HostHandle setup;
P3  the late Vol-/removable BDS path is reached only after DefaultBDSBootApp,
    while the current LA config launches LinuxLoader first;
P4  the exact LinuxLoader is a normal AArch64 EFI application with no observed
    self-FV / LoadedImage-device-path dependency.

P1-P4 require --modules-dir and --linuxloader. Without them the tool still
performs the P0 exact-profile check and reports the deeper stages as UNCHECKED.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9


class CheckError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def align4(v: int) -> int:
    return (v + 3) & ~3


def parse_dtb_properties(blob: bytes, base: int) -> dict[str, dict[str, bytes]]:
    if base < 0 or base + 40 > len(blob):
        raise CheckError("DTB base is outside image")
    hdr = struct.unpack_from(">10I", blob, base)
    magic, total, off_struct, off_strings, _off_mem, version, _last, _boot, size_strings, _size_struct = hdr
    if magic != FDT_MAGIC:
        raise CheckError(f"bad FDT magic at 0x{base:X}")
    if total < 40 or base + total > len(blob):
        raise CheckError("invalid FDT total size")
    if version < 16:
        raise CheckError(f"unsupported FDT version {version}")

    struct_base = base + off_struct
    strings_base = base + off_strings
    strings_end = strings_base + size_strings
    end = base + total
    if not (base <= struct_base < end and base <= strings_base < end and strings_end <= end):
        raise CheckError("invalid FDT offsets")

    p = struct_base
    stack: list[str] = []
    out: dict[str, dict[str, bytes]] = {}
    while p + 4 <= end:
        token = struct.unpack_from(">I", blob, p)[0]
        p += 4
        if token == FDT_BEGIN_NODE:
            nul = blob.find(b"\0", p, end)
            if nul < 0:
                raise CheckError("unterminated FDT node name")
            stack.append(blob[p:nul].decode("ascii", errors="replace"))
            p = base + align4((nul + 1) - base)
        elif token == FDT_END_NODE:
            if not stack:
                raise CheckError("unbalanced FDT END_NODE")
            stack.pop()
        elif token == FDT_PROP:
            if p + 8 > end:
                raise CheckError("truncated FDT property")
            length, name_off = struct.unpack_from(">II", blob, p)
            p += 8
            if p + length > end or name_off >= size_strings:
                raise CheckError("invalid FDT property bounds")
            value = blob[p:p + length]
            p = base + align4((p + length) - base)
            name_start = strings_base + name_off
            name_end = blob.find(b"\0", name_start, strings_end)
            if name_end < 0:
                raise CheckError("unterminated FDT property name")
            name = blob[name_start:name_end].decode("ascii", errors="replace")
            path = "/" + "/".join(x for x in stack if x)
            out.setdefault(path, {})[name] = value
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            return out
        else:
            raise CheckError(f"unknown FDT token {token} at 0x{p - 4:X}")
    raise CheckError("FDT_END not found")


def decode_fdt_value(raw: bytes) -> int | str:
    if len(raw) in (4, 8):
        return int.from_bytes(raw, "big")
    if raw.endswith(b"\0") and all((32 <= x < 127) or x == 0 for x in raw):
        return raw.rstrip(b"\0").decode("ascii", errors="replace")
    return raw.hex()


def find_profile_dtb(blob: bytes, expected_offset: int) -> tuple[int, dict[str, dict[str, bytes]]]:
    if expected_offset >= 0:
        try:
            props = parse_dtb_properties(blob, expected_offset)
            if any(path.startswith("/sw/uefi") for path in props):
                return expected_offset, props
        except CheckError:
            pass
    magic = struct.pack(">I", FDT_MAGIC)
    start = 0
    while True:
        pos = blob.find(magic, start)
        if pos < 0:
            break
        start = pos + 4
        try:
            props = parse_dtb_properties(blob, pos)
        except CheckError:
            continue
        if any(path.startswith("/sw/uefi") for path in props):
            return pos, props
    raise CheckError("no /sw/uefi DTB found")


def parse_pe_bytes(b: bytes) -> dict[str, Any]:
    if len(b) < 0x100 or b[:2] != b"MZ":
        raise CheckError("not a PE image")
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    if pe + 0x108 > len(b) or b[pe:pe + 4] != b"PE\0\0":
        raise CheckError("invalid PE signature")
    machine = struct.unpack_from("<H", b, pe + 4)[0]
    sections_count = struct.unpack_from("<H", b, pe + 6)[0]
    opt_size = struct.unpack_from("<H", b, pe + 20)[0]
    opt = pe + 24
    if struct.unpack_from("<H", b, opt)[0] != 0x20B:
        raise CheckError("image is not PE32+")
    entry = struct.unpack_from("<I", b, opt + 0x10)[0]
    subsystem = struct.unpack_from("<H", b, opt + 0x44)[0]
    number_rva = struct.unpack_from("<I", b, opt + 0x6C)[0]
    imports_rva = imports_size = reloc_rva = reloc_size = 0
    if number_rva > 1:
        imports_rva, imports_size = struct.unpack_from("<II", b, opt + 0x70 + 1 * 8)
    if number_rva > 5:
        reloc_rva, reloc_size = struct.unpack_from("<II", b, opt + 0x70 + 5 * 8)
    sec_base = opt + opt_size
    sections = []
    for i in range(sections_count):
        o = sec_base + i * 40
        if o + 40 > len(b):
            raise CheckError("truncated PE section table")
        name = b[o:o + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", b, o + 8)
        sections.append({
            "name": name,
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_ptr": raw_ptr,
        })
    return {
        "machine": machine,
        "entry_rva": entry,
        "subsystem": subsystem,
        "imports_rva": imports_rva,
        "imports_size": imports_size,
        "reloc_rva": reloc_rva,
        "reloc_size": reloc_size,
        "size": len(b),
        "sections": sections,
    }


def parse_pe(path: Path) -> dict[str, Any]:
    return parse_pe_bytes(path.read_bytes())


def pe_rva_to_offset(pe: dict[str, Any], rva: int) -> int:
    for s in pe["sections"]:
        start = int(s["virtual_address"])
        span = max(int(s["virtual_size"]), int(s["raw_size"]))
        if start <= rva < start + span:
            delta = rva - start
            if delta >= int(s["raw_size"]):
                raise CheckError(f"RVA 0x{rva:X} is not backed by file data")
            return int(s["raw_ptr"]) + delta
    raise CheckError(f"RVA 0x{rva:X} not found in PE sections")


def u32_at_rva(data: bytes, pe: dict[str, Any], rva: int) -> int:
    off = pe_rva_to_offset(pe, rva)
    if off + 4 > len(data):
        raise CheckError(f"RVA 0x{rva:X} truncated")
    return struct.unpack_from("<I", data, off)[0]


def u8_at_rva(data: bytes, pe: dict[str, Any], rva: int) -> int:
    off = pe_rva_to_offset(pe, rva)
    return data[off]


def decode_bl_target(rva: int, insn: int) -> int | None:
    if (insn & 0xFC000000) != 0x94000000:
        return None
    imm26 = insn & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    return rva + (imm26 << 2)


def bl_callsites_to(data: bytes, pe: dict[str, Any], target_rva: int) -> list[int]:
    out: list[int] = []
    for s in pe["sections"]:
        if s["name"] != ".text":
            continue
        va = int(s["virtual_address"])
        rp = int(s["raw_ptr"])
        size = int(s["raw_size"])
        for delta in range(0, size - 3, 4):
            insn = struct.unpack_from("<I", data, rp + delta)[0]
            rva = va + delta
            if decode_bl_target(rva, insn) == target_rva:
                out.append(rva)
    return out


def verify_artifact(label: str, path: Path, spec: dict[str, Any]) -> dict[str, Any]:
    actual_size = path.stat().st_size
    actual_hash = sha256_file(path)
    ok = actual_size == int(spec["size"]) and actual_hash == spec["sha256"]
    return {
        "label": label,
        "path": str(path),
        "size": actual_size,
        "expected_size": int(spec["size"]),
        "sha256": actual_hash,
        "expected_sha256": spec["sha256"],
        "pass": ok,
    }


def verify_xbl_config(path: Path, profile: dict[str, Any]) -> dict[str, Any]:
    xb = path.read_bytes()
    spec = profile["xbl_config"]
    expected_dtb = int(spec["dtb_offset"], 16)
    dtb_off, props = find_profile_dtb(xb, expected_dtb)
    checks: list[dict[str, Any]] = []
    for node, required in spec["required_by_path"].items():
        node_props = props.get(node, {})
        for name, expected in required.items():
            raw = node_props.get(name)
            actual = None if raw is None else decode_fdt_value(raw)
            checks.append({
                "path": node,
                "name": name,
                "expected": expected,
                "actual": actual,
                "pass": actual == expected,
            })
    for prefix, names in spec.get("forbidden_anywhere_under", {}).items():
        for name in names:
            hits = [path_name for path_name, node_props in props.items()
                    if path_name.startswith(prefix) and name in node_props]
            checks.append({
                "path": prefix,
                "name": name,
                "expected": "absent",
                "actual": hits or "absent",
                "pass": not hits,
            })
    return {
        "dtb_offset": hex(dtb_off),
        "expected_dtb_offset": hex(expected_dtb),
        "properties": checks,
        "pass": dtb_off == expected_dtb and all(c["pass"] for c in checks),
    }


def find_exact_module(modules_dir: Path, label: str, spec: dict[str, Any]) -> Path:
    candidates = [p for p in modules_dir.rglob("*") if p.is_file() and label.lower() in p.name.lower()]
    for p in candidates:
        if p.stat().st_size == int(spec["size"]) and sha256_file(p) == spec["sha256"]:
            return p
    detail = ", ".join(p.name for p in candidates[:8]) or "none"
    raise CheckError(f"exact module {label} not found in {modules_dir}; candidates: {detail}")


def verify_module(modules_dir: Path, label: str, profile: dict[str, Any]) -> tuple[Path, bytes, dict[str, Any]]:
    spec = profile["exact_modules"][label]
    path = find_exact_module(modules_dir, label, spec)
    data = path.read_bytes()
    pe = parse_pe_bytes(data)
    return path, data, pe


def verify_p1(modules_dir: Path, xbl_result: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    spec = profile["p1_usb_host_gate"]
    usb_path, usb, usb_pe = verify_module(modules_dir, spec["usb_config_module"], profile)
    qcom_path, qcom, _ = verify_module(modules_dir, "QcomBds", profile)

    pcd_rva = int(spec["init_usb_controller_on_boot_rva"], 16)
    pcd_actual = u8_at_rva(usb, usb_pe, pcd_rva)
    instruction_checks = []
    for rva_text, expected_text in spec["dfp_gate_instructions"].items():
        rva = int(rva_text, 16)
        expected = int(expected_text, 16)
        actual = u32_at_rva(usb, usb_pe, rva)
        instruction_checks.append({
            "rva": rva_text,
            "expected": expected_text,
            "actual": hex(actual),
            "pass": actual == expected,
        })

    target = int(spec["usb_start_controller_rva"], 16)
    actual_calls = bl_callsites_to(usb, usb_pe, target)
    expected_calls = [int(x, 16) for x in spec["expected_bl_callsites_to_usb_start_controller"]]

    guid_checks = []
    for name, hex_bytes in spec["qcombds_forbidden_guids"].items():
        raw = bytes.fromhex(hex_bytes)
        count = qcom.count(raw)
        guid_checks.append({"name": name, "count": count, "pass": count == 0})

    usb_cfg_checks = [c for c in xbl_result["properties"] if c["path"] == "/soc/usb0/usb_overwrite_cfg"]
    ok = (
        pcd_actual == int(spec["init_usb_controller_on_boot_expected"])
        and all(x["pass"] for x in instruction_checks)
        and actual_calls == expected_calls
        and all(x["pass"] for x in guid_checks)
        and usb_cfg_checks and all(x["pass"] for x in usb_cfg_checks)
    )
    return {
        "status": spec["expected_status"] if ok else "MISMATCH",
        "pass": ok,
        "usb_config_module": str(usb_path),
        "qcombds_module": str(qcom_path),
        "init_usb_controller_on_boot": {
            "rva": spec["init_usb_controller_on_boot_rva"],
            "expected": spec["init_usb_controller_on_boot_expected"],
            "actual": pcd_actual,
            "pass": pcd_actual == int(spec["init_usb_controller_on_boot_expected"]),
        },
        "dfp_gate_instructions": instruction_checks,
        "usb_start_controller_callsites": {
            "target_rva": spec["usb_start_controller_rva"],
            "expected": [hex(x) for x in expected_calls],
            "actual": [hex(x) for x in actual_calls],
            "pass": actual_calls == expected_calls,
        },
        "qcombds_usb_start_guid_absence": guid_checks,
        "xbl_usb_override": usb_cfg_checks,
        "interpretation": "shipping DFP callback records host mode but skips UsbStartController because InitUsbControllerOnBoot is zero" if ok else "exact USB-host gate invariants changed",
    }


def verify_p2(modules_dir: Path, p1: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    spec = profile["p2_dfp_xhci"]
    xhci_path, xhci, _ = verify_module(modules_dir, spec["xhci_pci_module"], profile)
    guid = bytes.fromhex(spec["qcom_usb_config_guid"])
    guid_count = xhci.count(guid)
    ok = p1["pass"] and guid_count > 0
    return {
        "status": spec["expected_status"] if ok else "MISMATCH",
        "pass": ok,
        "xhci_pci_module": str(xhci_path),
        "qcom_usb_config_guid_count": guid_count,
        "intended_chain": spec["intended_chain"],
        "blocked_at": "InitUsbControllerOnBoot before HostHandle / QcomUsbConfig host controller creation",
        "interpretation": "XHCI binding code exists, but the normal Retail DFP path never creates the host-mode controller handle it requires" if ok else "DFP/XHCI invariants changed",
    }


def verify_p3(modules_dir: Path, xbl_result: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    spec = profile["p3_bds_order"]
    qcom_path, _qcom, _ = verify_module(modules_dir, spec["qcombds_module"], profile)
    app_checks = [c for c in xbl_result["properties"] if c["name"] == "DefaultBDSBootApp"]
    app_ok = len(app_checks) == 1 and app_checks[0]["actual"] == spec["default_bds_boot_app"]
    # Ordering itself is an exact-binary RE invariant gated by the exact QcomBds hash.
    ok = app_ok and bool(spec["default_app_launch_precedes_late_hotkey"]) and bool(spec["normal_linuxloader_expected_to_not_return"])
    return {
        "status": spec["expected_status"] if ok else "MISMATCH",
        "pass": ok,
        "qcombds_module": str(qcom_path),
        "default_bds_boot_app": app_checks[0] if app_checks else None,
        "late_hotkey_rva": spec["late_hotkey_rva"],
        "late_hotkey_call_site_rva": spec["late_hotkey_call_site_rva"],
        "ordering": "PlatBdsLaunchDefaultApps(DefaultBDSBootApp=LinuxLoader) precedes QcomBdsDetectBootHotKey",
        "interpretation": "normal LA boot transfers into LinuxLoader before the late SCAN_DOWN removable-media detector; R3 is not a stock cold-boot chainload route" if ok else "BDS ordering/profile invariant changed",
    }


def verify_p4(linuxloader: Path, profile: dict[str, Any]) -> dict[str, Any]:
    spec = profile["p4_linuxloader"]
    data = linuxloader.read_bytes()
    pe = parse_pe_bytes(data)
    exact = len(data) == int(spec["size"]) and sha256_bytes(data) == spec["sha256"]
    pe_ok = (
        pe["machine"] == int(spec["machine"])
        and pe["subsystem"] == int(spec["subsystem"])
        and pe["entry_rva"] == int(spec["entry_rva"])
        and pe["imports_rva"] == int(spec["imports_rva"])
        and pe["imports_size"] == int(spec["imports_size"])
    )
    guid_checks = []
    for name, hex_bytes in spec["forbidden_guids"].items():
        count = data.count(bytes.fromhex(hex_bytes))
        guid_checks.append({"name": name, "count": count, "pass": count == 0})
    string_checks = []
    for s in spec["forbidden_strings"]:
        ac = data.count(s.encode("ascii"))
        uc = data.count(s.encode("utf-16le"))
        string_checks.append({"string": s, "ascii_count": ac, "utf16_count": uc, "pass": ac == 0 and uc == 0})
    ok = exact and pe_ok and all(x["pass"] for x in guid_checks) and all(x["pass"] for x in string_checks)
    return {
        "status": spec["expected_status"] if ok else "MISMATCH",
        "pass": ok,
        "path": str(linuxloader),
        "sha256": sha256_bytes(data),
        "size": len(data),
        "pe": {k: pe[k] for k in ("machine", "subsystem", "entry_rva", "imports_rva", "imports_size")},
        "forbidden_guid_absence": guid_checks,
        "self_path_string_absence": string_checks,
        "interpretation": "standard UEFI LoadImage/StartImage origin is not the identified compatibility blocker; no viable stock temporary carrier is proven" if ok else "LinuxLoader execution-context invariants changed",
    }


def verify_probe(path: Path, profile: dict[str, Any]) -> dict[str, Any]:
    pe = parse_pe(path)
    ps = profile["probe"]
    actual_hash = sha256_file(path)
    ok = (
        pe["size"] == int(ps["size"])
        and actual_hash == ps["sha256"]
        and pe["machine"] == int(ps["machine"])
        and pe["subsystem"] == int(ps["subsystem"])
        and pe["entry_rva"] == int(ps["entry_rva"])
        and (not ps.get("requires_reloc") or (pe["reloc_rva"] != 0 and pe["reloc_size"] != 0))
    )
    return {**{k: v for k, v in pe.items() if k != "sections"}, "sha256": actual_hash, "pass": ok}


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", type=Path, default=root / "profiles" / "PJZ110_16.0.10.501_retail_path.json")
    ap.add_argument("--abl", type=Path, required=True)
    ap.add_argument("--uefi", type=Path, required=True)
    ap.add_argument("--toolsfv", type=Path, required=True)
    ap.add_argument("--xbl-config", type=Path, required=True)
    ap.add_argument("--modules-dir", type=Path, help="directory containing exact extracted UEFI PE modules")
    ap.add_argument("--linuxloader", type=Path, help="exact extracted current LinuxLoader.efi")
    ap.add_argument("--probe", type=Path)
    ap.add_argument("--full-p0-p4", action="store_true", help="require and verify P1-P4 evidence")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        profile = json.loads(args.profile.read_text(encoding="utf-8"))
        paths = {"abl": args.abl, "uefi": args.uefi, "toolsfv": args.toolsfv, "xbl_config": args.xbl_config}
        artifacts = [verify_artifact(name, path, profile["artifacts"][name]) for name, path in paths.items()]
        xbl_result = verify_xbl_config(args.xbl_config, profile)
        p0_ok = all(x["pass"] for x in artifacts) and xbl_result["pass"]
        p0 = {
            "status": "PASS" if p0_ok else "MISMATCH",
            "pass": p0_ok,
            "artifacts": artifacts,
            "xbl_config": xbl_result,
            "interpretation": "exact PJZ110 16.0.10.501 baseline frozen" if p0_ok else "fail-closed: baseline drift detected",
        }

        p1 = p2 = p3 = p4 = None
        deep_requested = args.full_p0_p4 or args.modules_dir is not None or args.linuxloader is not None
        if deep_requested:
            if args.modules_dir is None or args.linuxloader is None:
                raise CheckError("P1-P4 verification requires both --modules-dir and --linuxloader")
            if not p0_ok:
                raise CheckError("P1-P4 refused because P0 exact-profile baseline failed")
            p1 = verify_p1(args.modules_dir, xbl_result, profile)
            p2 = verify_p2(args.modules_dir, p1, profile)
            p3 = verify_p3(args.modules_dir, xbl_result, profile)
            p4 = verify_p4(args.linuxloader, profile)

        probe_result = verify_probe(args.probe, profile) if args.probe is not None else None
        deep_ok = all(x is not None and x["pass"] for x in (p1, p2, p3, p4)) if deep_requested else True
        overall = p0_ok and deep_ok and (probe_result is None or probe_result["pass"])

        route_decision = {
            "removable_r3": "CLOSED" if p3 and p3["pass"] else "UNVERIFIED",
            "usb_host_autostart": "CLOSED" if p1 and p1["pass"] else "UNVERIFIED",
            "linuxloader_external_compatibility": "PASS-IN-PRINCIPLE" if p4 and p4["pass"] else "UNVERIFIED",
            "next_research_route": "R4 staged/memory EFI execution before normal LinuxLoader",
            "live_vol_down_otg_test": "DO-NOT-RUN for this exact current build",
        }
        report = {
            "profile": profile["id"],
            "build": profile["build"],
            "analysis_revision": profile["analysis_revision"],
            "P0": p0,
            "P1": p1 or {"status": "UNCHECKED", "pass": None},
            "P2": p2 or {"status": "UNCHECKED", "pass": None},
            "P3": p3 or {"status": "UNCHECKED", "pass": None},
            "P4": p4 or {"status": "UNCHECKED", "pass": None},
            "probe": probe_result,
            "route_decision": route_decision,
            "pass": overall,
            "interpretation": (
                "P0-P4 exact offline conclusions reproduced; removable Retail route is closed and research must move to R4 staged/memory EFI"
                if overall and deep_requested
                else "P0 exact baseline verified; run with --full-p0-p4 for binary-level closure"
                if overall
                else "fail-closed: one or more exact-profile invariants do not match"
            ),
        }

        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(f"P0 baseline            : {p0['status']}")
            if deep_requested:
                print(f"P1 USB host auto-start : {p1['status']}")
                print(f"P2 DFP -> XHCI         : {p2['status']}")
                print(f"P3 late removable BDS  : {p3['status']}")
                print(f"P4 LinuxLoader context : {p4['status']}")
                print("NEXT                   : R4 staged/memory EFI before normal LinuxLoader")
            else:
                print("P1-P4                  : UNCHECKED (use --full-p0-p4 --modules-dir ... --linuxloader ...)")
            if probe_result is not None:
                print(f"probe                  : {'PASS' if probe_result['pass'] else 'FAIL'} {probe_result['sha256']}")
            print(f"RESULT                 : {'PASS' if overall else 'FAIL'}")
        return 0 if overall else 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError, struct.error, CheckError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
