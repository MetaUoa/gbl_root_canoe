#!/usr/bin/env python3
"""Validate and report the complete PJZ110 exact-profile regression matrix."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


OTA_TOOL = Path(__file__).with_name("pjz110_ota_profile_check.py")
_spec = importlib.util.spec_from_file_location("pjz110_ota_profile_for_matrix", OTA_TOOL)
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load pjz110_ota_profile_check.py")
ota = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ota
_spec.loader.exec_module(ota)


class MatrixError(RuntimeError):
    pass


def build_matrix(profiles_dir: Path) -> dict[str, Any]:
    profiles = ota.load_profiles(profiles_dir)
    if not profiles:
        raise MatrixError("no base PJZ110 profiles found")
    errors: list[str] = []
    rows = []
    unique_fields = ("id", "build", "abl_sha256", "linuxloader_sha256",
                     "patched_linuxloader_sha256")
    for profile in profiles:
        errors.extend(f"{profile.get('id', '?')}: {x}"
                      for x in ota.validate_profile_schema(profile))
        if profile.get("changed_byte_count") != 7:
            errors.append(f"{profile.get('id', '?')}: changed_byte_count is not 7")
        patches = profile.get("patches", {})
        for key in ("androidboot.vbmeta.device_state", "androidboot.verifiedbootstate"):
            if key not in patches:
                errors.append(f"{profile.get('id', '?')}: missing patch descriptor {key}")
        rows.append({
            "id": profile["id"], "build": profile["build"],
            "abl_sha256": profile["abl_sha256"],
            "linuxloader_sha256": profile["linuxloader_sha256"],
            "linuxloader_size": profile["linuxloader_size"],
            "patched_linuxloader_sha256": profile["patched_linuxloader_sha256"],
            "changed_byte_count": profile["changed_byte_count"],
            "device_state_site": patches.get("androidboot.vbmeta.device_state", {}).get("unlocked_adrp"),
            "verified_state_site": patches.get("androidboot.verifiedbootstate", {}).get("orange_pointer"),
        })
    for field in unique_fields:
        values = [row[field] for row in rows]
        if len(values) != len(set(values)):
            errors.append(f"duplicate matrix field: {field}")
    rows.sort(key=lambda row: row["build"])
    return {"profile_count": len(rows), "profiles": rows, "errors": errors,
            "pass": not errors}


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profiles", type=Path, default=root / "profiles")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        report = build_matrix(args.profiles)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(f"PJZ110 profile matrix : {'PASS' if report['pass'] else 'FAIL'}")
            for row in report["profiles"]:
                print(f"{row['build']}: size={row['linuxloader_size']} delta={row['changed_byte_count']}")
            for error in report["errors"]:
                print(f"Error                 : {error}")
            print(f"RESULT                : {'PASS' if report['pass'] else 'FAIL'}")
        return 0 if report["pass"] else 2
    except (OSError, ValueError, KeyError, json.JSONDecodeError, MatrixError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
