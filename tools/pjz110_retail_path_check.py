#!/usr/bin/env python3
"""Fail-closed offline verifier for the exact PJZ110 Retail removable-EFI path.

This tool does not patch or write any input.  It verifies that the supplied
PJZ110 boot-chain images are byte-for-byte the profiled 16.0.10.501 artifacts,
parses the active XBL_CONFIG FDT, and optionally validates the read-only
BOOTAA64.EFI probe.

Deep QcomBds/SecurityStub/DxeCore reverse-engineering conclusions are recorded
in the profile and are only emitted when the exact UEFI image hash matches.
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
            name = blob[p:nul].decode("ascii", errors="replace")
            stack.append(name)
            p = align4(nul + 1)
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
            p = align4(p + length)
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
            return expected_offset, parse_dtb_properties(blob, expected_offset)
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
        if "/sw/uefi" in props:
            return pos, props
    raise CheckError("no /sw/uefi DTB found")


def parse_pe(path: Path) -> dict[str, int]:
    b = path.read_bytes()
    if len(b) < 0x100 or b[:2] != b"MZ":
        raise CheckError("probe is not a PE image")
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    if pe + 0x108 > len(b) or b[pe:pe + 4] != b"PE\0\0":
        raise CheckError("invalid PE signature")
    machine = struct.unpack_from("<H", b, pe + 4)[0]
    opt = pe + 24
    if struct.unpack_from("<H", b, opt)[0] != 0x20B:
        raise CheckError("probe is not PE32+")
    entry = struct.unpack_from("<I", b, opt + 0x10)[0]
    subsystem = struct.unpack_from("<H", b, opt + 0x44)[0]
    number_rva = struct.unpack_from("<I", b, opt + 0x6C)[0]
    reloc_rva = reloc_size = 0
    if number_rva > 5:
        reloc_rva, reloc_size = struct.unpack_from("<II", b, opt + 0x70 + 5 * 8)
    return {
        "machine": machine,
        "entry_rva": entry,
        "subsystem": subsystem,
        "reloc_rva": reloc_rva,
        "reloc_size": reloc_size,
        "size": len(b),
    }


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


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", type=Path, default=root / "profiles" / "PJZ110_16.0.10.501_retail_path.json")
    ap.add_argument("--abl", type=Path, required=True)
    ap.add_argument("--uefi", type=Path, required=True)
    ap.add_argument("--toolsfv", type=Path, required=True)
    ap.add_argument("--xbl-config", type=Path, required=True)
    ap.add_argument("--probe", type=Path)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        profile = json.loads(args.profile.read_text(encoding="utf-8"))
        paths = {
            "abl": args.abl,
            "uefi": args.uefi,
            "toolsfv": args.toolsfv,
            "xbl_config": args.xbl_config,
        }

        artifacts = [
            verify_artifact(name, path, profile["artifacts"][name])
            for name, path in paths.items()
        ]
        exact_images = all(x["pass"] for x in artifacts)

        xb = args.xbl_config.read_bytes()
        expected_dtb = int(profile["xbl_config"]["dtb_offset"], 16)
        dtb_off, props = find_profile_dtb(xb, expected_dtb)
        uefi_props = props.get(profile["xbl_config"]["path"], {})

        property_results: list[dict[str, Any]] = []
        for name, expected in profile["xbl_config"]["required"].items():
            raw = uefi_props.get(name)
            actual = None if raw is None else decode_fdt_value(raw)
            property_results.append({
                "name": name,
                "expected": expected,
                "actual": actual,
                "pass": actual == expected,
            })
        for name in profile["xbl_config"].get("forbidden_present", []):
            property_results.append({
                "name": name,
                "expected": "absent",
                "actual": "present" if name in uefi_props else "absent",
                "pass": name not in uefi_props,
            })

        probe_result = None
        if args.probe is not None:
            pe = parse_pe(args.probe)
            ps = profile["probe"]
            probe_result = {
                **pe,
                "sha256": sha256_file(args.probe),
                "pass": (
                    pe["size"] == int(ps["size"])
                    and sha256_file(args.probe) == ps["sha256"]
                    and pe["machine"] == int(ps["machine"])
                    and pe["subsystem"] == int(ps["subsystem"])
                    and pe["entry_rva"] == int(ps["entry_rva"])
                    and (not ps.get("requires_reloc") or (pe["reloc_rva"] != 0 and pe["reloc_size"] != 0))
                ),
            }

        overall = (
            exact_images
            and dtb_off == expected_dtb
            and all(x["pass"] for x in property_results)
            and (probe_result is None or probe_result["pass"])
        )

        report = {
            "profile": profile["id"],
            "build": profile["build"],
            "artifacts": artifacts,
            "xbl_config": {
                "dtb_offset": hex(dtb_off),
                "expected_dtb_offset": hex(expected_dtb),
                "properties": property_results,
            },
            "exact_module_invariants": profile["exact_modules"] if exact_images else None,
            "retail_path_invariants": profile["retail_path"] if exact_images else None,
            "probe": probe_result,
            "pass": overall,
            "interpretation": (
                "exact profiled Retail removable-EFI path invariants verified"
                if overall
                else "fail-closed: one or more exact-profile invariants do not match"
            ),
        }

        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            for a in artifacts:
                print(f"{a['label']:10s}: {'PASS' if a['pass'] else 'FAIL'} {a['sha256']}")
            print(f"xbl DTB   : {'PASS' if dtb_off == expected_dtb else 'FAIL'} {dtb_off:#x}")
            for p in property_results:
                print(f"  {p['name']}: {'PASS' if p['pass'] else 'FAIL'} actual={p['actual']!r}")
            if probe_result is not None:
                print(f"probe     : {'PASS' if probe_result['pass'] else 'FAIL'} {probe_result['sha256']}")
            print(f"RESULT    : {'PASS' if overall else 'FAIL'}")
        return 0 if overall else 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError, struct.error, CheckError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
