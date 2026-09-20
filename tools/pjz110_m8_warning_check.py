#!/usr/bin/env python3
"""Fail-closed exact-profile checker for the PJZ110 M8 warning boundary."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


RESEARCH = Path(__file__).with_name("pjz110_warning_research.py")
_spec = importlib.util.spec_from_file_location("pjz110_warning_for_m8", RESEARCH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load pjz110_warning_research.py")
research = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = research
_spec.loader.exec_module(research)


class M8Error(RuntimeError):
    pass


def compare_report(report: dict[str, Any], profile: dict[str, Any]) -> list[str]:
    errors = []
    ll = profile["linuxloader"]
    if report["input_linuxloader_sha256"] != ll["sha256"]:
        errors.append("LinuxLoader SHA-256 mismatch")
    if report["resources"] != profile["resources"]:
        errors.append("warning resource offsets changed")
    refs = report["warning_references"]
    if len(refs) != 1:
        errors.append(f"expected one warning reference, got {len(refs)}")
        return errors
    ref = refs[0]
    expected = profile["reference"]
    for field in ("adrl_offset", "function_start", "function_end", "call_xrefs"):
        if ref[field] != expected[field]:
            errors.append(f"warning reference field changed: {field}")
    dispatch = expected.get("state_dispatch", {})
    for field in ("source_call", "source_target", "stack_state_store", "warning_case_index"):
        if field in dispatch and ref["state_dispatch"].get(field) != dispatch[field]:
            errors.append(f"warning state dispatch changed: {field}")
    if ref["nearby_cbz_w"] != expected["legacy_nearby_cbz_w"]:
        errors.append("legacy nearby CBZ.W boundary changed")
    gates = [x for x in ref["conditional_branches"]
             if x["offset"] == expected["local_gate"]["offset"]]
    if len(gates) != 1:
        errors.append("local warning gate is missing or ambiguous")
    else:
        gate = gates[0]
        for field in ("offset", "kind", "condition", "target", "raw"):
            if gate[field] != expected["local_gate"][field]:
                errors.append(f"local warning gate changed: {field}")
    if report["fake_lock_changed_offsets"] != profile["fake_lock_changed_offsets"]:
        errors.append("fake-lock changed offsets changed")
    if report["warning_control_overlap"] != profile["expected"]["warning_control_overlap"]:
        errors.append("fake-lock/warning control overlap changed")
    for field, expected_value in profile.get("protocol_evidence", {}).items():
        if report["protocol_evidence"].get(field) != expected_value:
            errors.append(f"warning protocol evidence changed: {field}")
    return errors


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path)
    ap.add_argument("--profile", type=Path,
                    default=root / "profiles" / "PJZ110_16.0.10.501_m8.json")
    ap.add_argument("--profiles", type=Path, default=root / "profiles")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        profile = json.loads(args.profile.read_text(encoding="utf-8"))
        report = research.analyze(args.input, args.profiles)
        if args.input.stat().st_size != profile["linuxloader"]["size"]:
            raise M8Error("LinuxLoader size mismatch")
        errors = compare_report(report, profile)
        result = {"profile": profile["id"], "errors": errors,
                  "state_predicate": profile["expected"]["state_predicate"],
                  "warning_patch_authorized": False, "pass": not errors}
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"M8 exact profile          : {'PASS' if result['pass'] else 'FAIL'}")
            print(f"warning state predicate   : {result['state_predicate']}")
            print("legacy warning patch      : NOT APPLICABLE")
            print("warning patch authorized  : NO")
            print("M8 status                 : CLOSED-NO-SAFE-UI-ONLY-PATCH")
            print(f"RESULT                    : {'PASS' if result['pass'] else 'FAIL'}")
            for error in errors:
                print(f"Error                     : {error}")
        return 0 if result["pass"] else 2
    except (OSError, ValueError, KeyError, json.JSONDecodeError,
            research.patcher.PatcherError, M8Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
