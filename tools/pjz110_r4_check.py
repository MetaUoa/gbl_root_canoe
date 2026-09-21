#!/usr/bin/env python3
"""Exact-profile PJZ110 R4-A -> R4-D offline verifier.

This tool is read-only and fail-closed. It verifies the exact current boot-chain
baseline plus the binary/config invariants used to conclude that no stock
non-flashing pre-LinuxLoader EFI carrier was identified for
PJZ110_16.0.10.501(CN01).

RESULT=PASS means the R4 conclusions reproduced. R4-D is expected to be CLOSED.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

BASE_TOOL = Path(__file__).with_name("pjz110_retail_path_check.py")
spec = importlib.util.spec_from_file_location("pjz110_retail_path_check_for_r4", BASE_TOOL)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load pjz110_retail_path_check.py")
base = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = base
spec.loader.exec_module(base)


class R4Error(RuntimeError):
    pass


def ascii_prop(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", errors="replace")


def verify_xbl(path: Path, profile: dict[str, Any]) -> dict[str, Any]:
    cfg = profile["xbl_config"]
    blob = path.read_bytes()
    expected_off = int(cfg["dtb_offset"], 16)
    dtb_off, props = base.find_profile_dtb(blob, expected_off)
    checks: list[dict[str, Any]] = []

    for node, required in cfg["uefi_required"].items():
        node_props = props.get(node, {})
        for name, expected in required.items():
            raw = node_props.get(name)
            actual = None if raw is None else base.decode_fdt_value(raw)
            checks.append({"path": node, "name": name, "expected": expected,
                           "actual": actual, "pass": actual == expected})

    for node, names in cfg.get("uefi_absent", {}).items():
        for name in names:
            hits = [p for p, node_props in props.items()
                    if p.startswith(node) and name in node_props]
            checks.append({"path": node, "name": name, "expected": "absent",
                           "actual": hits or "absent", "pass": not hits})

    pil = props.get(cfg["pil_path"], {})
    retail = [x.decode("ascii", errors="replace")
              for x in pil.get("RetailImages", b"").split(b"\0") if x]
    want_retail = cfg["pil_required"]["RetailImages_contains"]
    checks.append({"path": cfg["pil_path"], "name": "RetailImages",
                   "expected": f"contains {want_retail}", "actual": retail,
                   "pass": want_retail in retail})
    auto = pil.get("AutoStartImages")
    want_auto = cfg["pil_required"]["AutoStartImages_raw_hex"]
    checks.append({"path": cfg["pil_path"], "name": "AutoStartImages",
                   "expected": want_auto,
                   "actual": None if auto is None else auto.hex(),
                   "pass": auto is not None and auto.hex() == want_auto})

    abl_path = cfg["abl_cfg_path"]
    abl = props.get(abl_path, {})
    for key, expected in cfg["abl_cfg_required"].items():
        if key.endswith("_ascii"):
            name = key[:-6]
            raw = abl.get(name)
            actual = None if raw is None else ascii_prop(raw)
        elif key.endswith("_hex"):
            name = key[:-4]
            raw = abl.get(name)
            actual = None if raw is None else raw.hex()
        else:
            name = key
            raw = abl.get(name)
            actual = None if raw is None else int.from_bytes(raw, "big")
        checks.append({"path": abl_path, "name": name, "expected": expected,
                       "actual": actual, "pass": actual == expected})

    mem = cfg["memory_regions"]
    for node, required in mem["required"].items():
        node_props = props.get(node, {})
        for key, expected in required.items():
            if key.endswith("_ascii"):
                name = key[:-6]
                raw = node_props.get(name)
                actual = None if raw is None else ascii_prop(raw)
            else:
                name = key[:-4]
                raw = node_props.get(name)
                actual = None if raw is None else raw.hex()
            checks.append({"path": node, "name": name, "expected": expected,
                           "actual": actual, "pass": actual == expected})

    forbidden = set(mem.get("forbidden_mem_labels", []))
    found = []
    for node, node_props in props.items():
        raw = node_props.get("mem-label")
        if raw is not None and ascii_prop(raw) in forbidden:
            found.append((node, ascii_prop(raw)))
    checks.append({"path": "/soc/memorymap", "name": "forbidden_mem_labels",
                   "expected": "absent", "actual": found or "absent",
                   "pass": not found})

    ok = dtb_off == expected_off and all(x["pass"] for x in checks)
    return {"dtb_offset": hex(dtb_off), "checks": checks, "pass": ok}


def verify_strings(data: bytes, required: list[str], forbidden: list[str] | None = None) -> dict[str, Any]:
    checks = []
    for text in required:
        count = data.count(text.encode("ascii"))
        checks.append({"text": text, "count": count, "pass": count > 0})
    for text in forbidden or []:
        count = data.count(text.encode("ascii"))
        checks.append({"text": text, "count": count, "pass": count == 0})
    return {"checks": checks, "pass": all(x["pass"] for x in checks)}


def c_string_at_rva(data: bytes, pe: dict[str, Any], rva: int) -> str:
    off = base.pe_rva_to_offset(pe, rva)
    end = data.find(b"\0", off)
    if end < 0:
        end = min(len(data), off + 512)
    return data[off:end].decode("ascii", errors="replace")


def verify_linuxloader(path: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    data = path.read_bytes()
    exact = len(data) == int(cfg["size"]) and base.sha256_file(path) == cfg["sha256"]
    pe = base.parse_pe_bytes(data)
    pe_ok = (pe["machine"] == int(cfg["machine"])
             and pe["subsystem"] == int(cfg["subsystem"])
             and pe["entry_rva"] == int(cfg["entry_rva"]))
    strings = verify_strings(data, cfg["required_ascii"], cfg["forbidden_ascii"])

    insns = []
    for rva_s, expected_s in cfg["exact_u32_rva"].items():
        rva = int(rva_s, 16)
        actual = base.u32_at_rva(data, pe, rva)
        expected = int(expected_s, 16)
        insns.append({"rva": rva_s, "expected": expected_s,
                      "actual": hex(actual), "pass": actual == expected})

    rva_strings = []
    for expected, rva_s in cfg["string_rva"].items():
        actual = c_string_at_rva(data, pe, int(rva_s, 16))
        rva_strings.append({"rva": rva_s, "expected": expected,
                            "actual": actual, "pass": actual == expected})

    ok = exact and pe_ok and strings["pass"] \
        and all(x["pass"] for x in insns) \
        and all(x["pass"] for x in rva_strings)
    return {"sha256": base.sha256_file(path), "size": len(data), "exact": exact,
            "pe_pass": pe_ok, "strings": strings, "instruction_checks": insns,
            "string_rva_checks": rva_strings, "pass": ok}


def verify_module(modules_dir: Path, label: str, profile: dict[str, Any]) -> dict[str, Any]:
    cfg = profile["modules"][label]
    path = base.find_exact_module(modules_dir, label, cfg)
    data = path.read_bytes()
    string_cfg = profile.get("module_strings", {}).get(label, {})
    strings = verify_strings(data, string_cfg.get("required_ascii", []),
                             string_cfg.get("forbidden_ascii", []))
    return {"path": str(path), "sha256": base.sha256_file(path),
            "size": len(data), "strings": strings, "pass": strings["pass"]}


def verify_log(path: Path, required: list[str]) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace").replace("\r", "")
    checks = [{"text": item, "pass": item in text} for item in required]
    return {"checks": checks, "pass": all(x["pass"] for x in checks)}


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", type=Path,
                    default=root / "profiles" / "PJZ110_16.0.10.501_r4.json")
    ap.add_argument("--abl", type=Path, required=True)
    ap.add_argument("--uefi", type=Path, required=True)
    ap.add_argument("--xbl-config", type=Path, required=True)
    ap.add_argument("--modules-dir", type=Path, required=True)
    ap.add_argument("--linuxloader", type=Path, required=True)
    ap.add_argument("--bootloader-log", type=Path, required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        profile = json.loads(args.profile.read_text(encoding="utf-8"))
        artifacts = [
            base.verify_artifact("abl", args.abl, profile["artifacts"]["abl"]),
            base.verify_artifact("uefi", args.uefi, profile["artifacts"]["uefi"]),
            base.verify_artifact("xbl_config", args.xbl_config, profile["artifacts"]["xbl_config"]),
        ]
        if not all(x["pass"] for x in artifacts):
            raise R4Error("exact artifact baseline mismatch")

        xbl = verify_xbl(args.xbl_config, profile)
        if not xbl["pass"]:
            raise R4Error("XBL_CONFIG R4 invariant mismatch")

        modules = {label: verify_module(args.modules_dir, label, profile)
                   for label in profile["modules"]}
        if not all(x["pass"] for x in modules.values()):
            raise R4Error("UEFI module R4 invariant mismatch")

        linuxloader = verify_linuxloader(args.linuxloader, profile["linuxloader"])
        if not linuxloader["pass"]:
            raise R4Error("LinuxLoader R4 invariant mismatch")

        runtime = verify_log(args.bootloader_log, profile["runtime_log"]["required_ascii"])
        if not runtime["pass"]:
            raise R4Error("runtime UFS/Retail baseline mismatch")

        expected = profile["expected"]
        stages = {
            "R4-A": expected["R4-A"],
            "R4-B": expected["R4-B"],
            "R4-C": expected["R4-C"],
            "R4-D": expected["R4-D"],
        }
        report = {
            "profile": profile["id"], "build": profile["build"],
            "artifacts": artifacts, "xbl_config": xbl, "modules": modules,
            "linuxloader": linuxloader, "runtime_log": runtime,
            "semantic_invariants": profile["semantic_invariants"],
            "stages": stages,
            "stock_nonflashing_carrier": expected["stock_nonflashing_carrier"],
            "next": expected["next"], "pass": True,
        }
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print("R4 exact profile        : PASS")
            for name in ("R4-A", "R4-B", "R4-C", "R4-D"):
                print(f"{name:4s}                    : {stages[name]}")
            print("stock non-flash carrier : NOT FOUND / CLOSED")
            print("live EFI test           : DO NOT RUN")
            print("RESULT                  : PASS")
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError,
            base.CheckError, R4Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
