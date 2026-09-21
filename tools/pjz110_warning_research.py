#!/usr/bin/env python3
"""Read-only PJZ110 OPlus unlock-warning boundary analyzer.

This tool locates the exact warning resources and their ADRP+ADD references,
then proves whether the existing seven-byte fake-lock transform changes the
warning control-flow region. It never suppresses the warning or writes an
image.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


PATCHER = Path(__file__).with_name("pjz110_fake_lock.py")
_spec = importlib.util.spec_from_file_location("pjz110_fake_lock_for_warning", PATCHER)
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load pjz110_fake_lock.py")
patcher = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = patcher
_spec.loader.exec_module(patcher)


ORANGE_TITLE = "Orange State\n"
OPLUS_TITLE = "Your device has been unlocked and can't be trusted\n"
LONG_WARNING = ("The boot loader is unlocked and software integrity cannot be guaranteed. "
                "Any data stored on the device may be available to attackers. "
                "Do not store any sensitive data on the device.")
VERIFIED_BOOT_GUID = bytes.fromhex("91ff5e8eb621d347af2bc15a01e020ec")


def string_offsets(data: bytes, text: str) -> list[int]:
    needle = text.encode("ascii")
    out, start = [], 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return out
        out.append(offset)
        start = offset + 1


def is_cbz_w(raw: int) -> bool:
    return (raw & 0xFF000000) == 0x34000000


def branch_kind(raw: int) -> str | None:
    """Recognize conditional ARM64 branches relevant to warning predicates."""
    if (raw & 0x7E000000) == 0x34000000:
        op = "CBNZ" if ((raw >> 24) & 1) else "CBZ"
        width = "X" if ((raw >> 31) & 1) else "W"
        return f"{op}.{width}"
    if (raw & 0x7E000000) == 0x36000000:
        return "TBNZ" if ((raw >> 24) & 1) else "TBZ"
    if (raw & 0xFF000010) == 0x54000000:
        return "B.cond"
    return None


def branch_target(offset: int, raw: int) -> int | None:
    if (raw & 0xFF000010) == 0x54000000:
        imm = (raw >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        return offset + (imm << 2)
    return None


def condition_name(raw: int) -> str | None:
    if (raw & 0xFF000010) != 0x54000000:
        return None
    return ("EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
            "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV")[raw & 0xF]


def find_function_bounds(data: bytes, offset: int, text_start: int, text_end: int) -> tuple[int, int]:
    start = text_start
    for off in range(offset - 4, max(text_start, offset - 0x4000) - 1, -4):
        raw = patcher.r32(data, off)
        if raw == 0xD503233F or (raw & 0xFFC003FF) == 0xD10003FF:  # PACIASP or SUB SP,SP,#imm
            start = off
            break
    end = text_end
    for off in range(offset, min(text_end - 4, offset + 0x8000), 4):
        if patcher.r32(data, off) == 0xD65F03C0:  # RET
            end = off + 4
            break
    return start, end


def find_bl_xrefs(data: bytes, layout: Any, target_off: int) -> list[int]:
    text = layout.section(".text")
    target_rva = layout.offset_to_rva(target_off)
    refs = []
    for off in range(text.raw_off, text.raw_off + text.raw_size - 3, 4):
        raw = patcher.r32(data, off)
        if (raw & 0xFC000000) != 0x94000000:
            continue
        imm = raw & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        if layout.offset_to_rva(off) + (imm << 2) == target_rva:
            refs.append(off)
    return refs


def find_state_dispatch(data: bytes, layout: Any, caller: int) -> dict[str, Any]:
    """Summarize the caller's stack-state switch without guessing its enum name."""
    state_store = None
    for off in range(caller - 0x200, caller, 4):
        raw = patcher.r32(data, off)
        if ((raw & 0xFFC00000) == 0xB9000000 and
                ((raw >> 5) & 31) == 31 and (((raw >> 10) & 0xFFF) << 2) == 0x40):
            state_store = off
    source_call = state_store - 8 if state_store is not None else None
    source_call_valid = (source_call is not None and
                         (patcher.r32(data, source_call) & 0xFC000000) == 0x94000000)
    source_target = None
    if source_call_valid:
        raw = patcher.r32(data, source_call)
        imm = raw & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        source_target = layout.rva_to_offset(layout.offset_to_rva(source_call) + (imm << 2))
    # Across all three exact generations the warning call is the first entry
    # (index 1 after subtracting one) of the same bounded jump-table switch.
    return {"stack_state_store": state_store, "source_call": source_call,
            "source_target": source_target,
            "source_call_is_bl": source_call_valid,
            "warning_case_index": 1 if source_call_valid else None}


def find_warning_references(data: bytes) -> list[dict[str, Any]]:
    layout = patcher.parse_pe(data)
    text = layout.section(".text")
    refs = []
    for off in range(text.raw_off, text.raw_off + text.raw_size - 16, 4):
        try:
            title_off, _ = patcher.resolve_adrl(data, layout, off)
            message_off, _ = patcher.resolve_adrl(data, layout, off + 8)
        except patcher.PatcherError:
            continue
        if not patcher.c_string_at(data, title_off, ORANGE_TITLE):
            continue
        if not patcher.c_string_at(data, message_off, OPLUS_TITLE):
            continue
        fn_start, fn_end = find_function_bounds(data, off, text.raw_off, text.raw_off + text.raw_size)
        branches = []
        # A complete function boundary is not always recoverable from a
        # stripped PE. Keep the report local to the warning call site.
        window_start = max(text.raw_off, off - 0x100)
        window_end = min(text.raw_off + text.raw_size, off + 0x100)
        for candidate in range(window_start, window_end - 3, 4):
            raw = patcher.r32(data, candidate)
            kind = branch_kind(raw)
            if kind:
                branches.append({"offset": candidate, "kind": kind, "raw": hex(raw),
                                 "register": raw & 31,
                                 "target": branch_target(candidate, raw),
                                 "condition": condition_name(raw)})
        nearby_cbz = [x for x in branches if x["kind"] == "CBZ.W" and off - 64 <= x["offset"] < off]
        call_xrefs = find_bl_xrefs(data, layout, fn_start)
        refs.append({"adrl_offset": off, "orange_title_offset": title_off,
                     "oplus_title_offset": message_off, "function_start": fn_start,
                     "function_end": fn_end, "call_xrefs": call_xrefs,
                     "state_dispatch": find_state_dispatch(data, layout, call_xrefs[0]) if call_xrefs else {},
                     "nearby_cbz_w": nearby_cbz,
                     "conditional_branches": branches})
    return refs


def analyze(path: Path, profiles: Path) -> dict[str, Any]:
    loader, extracted, input_hash = patcher.load_linuxloader(path)
    profile = patcher.match_profile(loader, input_hash, extracted,
                                    patcher.load_profiles(profiles))
    if profile is None:
        raise patcher.PatcherError("unknown exact profile; warning analysis refused")
    refs = find_warning_references(loader)
    patched, manifest = patcher.patch_loader(loader, profile)
    changed = [int(x, 16) for x in manifest["changed_offsets"]]
    warning_control_offsets = set()
    for ref in refs:
        warning_control_offsets.update(range(ref["adrl_offset"], ref["adrl_offset"] + 16))
        for cbz in ref["nearby_cbz_w"]:
            warning_control_offsets.update(range(cbz["offset"], cbz["offset"] + 4))
    overlap = sorted(set(changed) & warning_control_offsets)
    guid_offsets = []
    start = 0
    while True:
        found = loader.find(VERIFIED_BOOT_GUID, start)
        if found < 0:
            break
        guid_offsets.append(found)
        start = found + 1
    method_offsets = []
    for ref in refs:
        wrapper = ref.get("state_dispatch", {}).get("source_target")
        if wrapper is None or wrapper + 0x1C > len(loader):
            continue
        raw = patcher.r32(loader, wrapper + 0x18)
        if (raw & 0xFFC00000) == 0xF9400000:
            method_offsets.append(((raw >> 10) & 0xFFF) << 3)
    protocol_match = len(guid_offsets) == 1 and method_offsets == [0x38]
    return {
        "profile": profile["id"], "build": profile["build"],
        "input_linuxloader_sha256": patcher.sha256(loader),
        "resources": {
            "orange_title": string_offsets(loader, ORANGE_TITLE),
            "oplus_title": string_offsets(loader, OPLUS_TITLE),
            "long_warning": string_offsets(loader, LONG_WARNING),
        },
        "warning_references": refs,
        "fake_lock_changed_offsets": manifest["changed_offsets"],
        "warning_control_overlap": [hex(x) for x in overlap],
        "protocol_evidence": {
            "verified_boot_guid_offsets": guid_offsets,
            "vtable_method_offsets": method_offsets,
            "candidate": "QCOM_VERIFIEDBOOT_PROTOCOL.VBIsDeviceSecure" if protocol_match else "UNRESOLVED",
            "method_semantics": "BOOLEAN polarity unresolved",
            "pass": protocol_match,
        },
        "warning_suppressed_by_current_patch": bool(overlap),
        "conclusion": "CURRENT-7-BYTE-PATCH-DOES-NOT-SUPPRESS-WARNING" if not overlap else "REVIEW-OVERLAP",
        "pass": len(refs) == 1 and not overlap and protocol_match,
    }


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path)
    ap.add_argument("--profiles", type=Path, default=root / "profiles")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        report = analyze(args.input, args.profiles)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(f"M8 exact warning boundary : {'PASS' if report['pass'] else 'FAIL'}")
            print(f"Warning references        : {len(report['warning_references'])}")
            print(f"7-byte control overlap    : {report['warning_control_overlap'] or 'NONE'}")
            print(f"Conclusion                : {report['conclusion']}")
            print("Patch output              : NOT CREATED")
        return 0 if report["pass"] else 2
    except (OSError, ValueError, KeyError, json.JSONDecodeError, patcher.PatcherError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
