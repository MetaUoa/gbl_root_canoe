#!/usr/bin/env python3
"""Fail-closed OTA/profile lifecycle checker for exact PJZ110 firmware.

The checker is read-only. It accepts a firmware directory containing an
``abl.img`` and optionally sibling ``xbl.img``/``xbl_config.img`` files,
selects one exact known profile, re-runs the semantic patcher, and refuses
unknown or internally inconsistent images.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


PATCHER = Path(__file__).with_name("pjz110_fake_lock.py")
_spec = importlib.util.spec_from_file_location("pjz110_fake_lock_for_ota", PATCHER)
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load pjz110_fake_lock.py")
patcher = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = patcher
_spec.loader.exec_module(patcher)


class OtaProfileError(RuntimeError):
    pass


CORE_FIELDS = ("id", "model", "platform", "build", "abl_sha256",
               "linuxloader_sha256", "linuxloader_size",
               "patched_linuxloader_sha256", "changed_byte_count")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_profiles(directory: Path) -> list[dict[str, Any]]:
    profiles = []
    for path in sorted(directory.glob("PJZ110_*.json")):
        obj = json.loads(path.read_text(encoding="utf-8"))
        if obj.get("model") == "PJZ110" and obj.get("linuxloader_sha256"):
            obj["_path"] = str(path)
            profiles.append(obj)
    return profiles


def validate_profile_schema(profile: dict[str, Any]) -> list[str]:
    errors = []
    for field in CORE_FIELDS:
        if field not in profile:
            errors.append(f"missing core field: {field}")
    for field in ("abl_sha256", "linuxloader_sha256", "patched_linuxloader_sha256"):
        value = profile.get(field)
        if not isinstance(value, str) or len(value) != 64:
            errors.append(f"invalid SHA-256 field: {field}")
    for field in ("linuxloader_size", "changed_byte_count"):
        if not isinstance(profile.get(field), int) or profile[field] <= 0:
            errors.append(f"invalid positive integer field: {field}")
    if profile.get("model") != "PJZ110" or profile.get("platform") != "SM8750":
        errors.append("profile is not PJZ110/SM8750")
    return errors


def select_profile(abl_hash: str, profiles: list[dict[str, Any]]) -> dict[str, Any] | None:
    matches = [p for p in profiles if p.get("abl_sha256") == abl_hash]
    return matches[0] if len(matches) == 1 else None


def verify_profile(profile: dict[str, Any], firmware_dir: Path) -> dict[str, Any]:
    errors = validate_profile_schema(profile)
    abl = firmware_dir / "abl.img"
    if not abl.is_file():
        errors.append("abl.img is missing")
        return {"profile": profile.get("id"), "errors": errors, "pass": False}

    abl_hash = sha256_file(abl)
    if abl_hash != profile["abl_sha256"]:
        errors.append(f"abl hash mismatch: {abl_hash}")

    optional = {}
    for name, field in (("xbl.img", "xbl_sha256"), ("xbl_config.img", "xbl_config_sha256")):
        path = firmware_dir / name
        if field in profile:
            if not path.is_file():
                errors.append(f"{name} is required by profile")
            else:
                actual = sha256_file(path)
                optional[name] = actual
                if actual != profile[field]:
                    errors.append(f"{name} hash mismatch: {actual}")

    try:
        loader, extracted, input_hash = patcher.load_linuxloader(abl)
        if not extracted or input_hash != profile["abl_sha256"]:
            errors.append("ABL did not yield the exact profiled LinuxLoader")
        if patcher.sha256(loader) != profile["linuxloader_sha256"]:
            errors.append("LinuxLoader hash mismatch")
        if len(loader) != profile["linuxloader_size"]:
            errors.append("LinuxLoader size mismatch")
        patched, manifest = patcher.patch_loader(loader, profile)
        if manifest["output_linuxloader_sha256"] != profile["patched_linuxloader_sha256"]:
            errors.append("patched LinuxLoader hash mismatch")
        if manifest["changed_byte_count"] != profile["changed_byte_count"]:
            errors.append("patched byte count mismatch")
    except Exception as exc:  # patcher errors are a fail-closed profile failure
        errors.append(f"semantic patch invariant failed: {exc}")

    return {"profile": profile.get("id"), "build": profile.get("build"),
            "abl_sha256": abl_hash, "optional_artifacts": optional,
            "errors": errors, "pass": not errors}


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--firmware-dir", type=Path, required=True)
    ap.add_argument("--profiles", type=Path, default=root / "profiles")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        abl = args.firmware_dir / "abl.img"
        if not abl.is_file():
            raise OtaProfileError("abl.img is required")
        abl_hash = sha256_file(abl)
        profiles = load_profiles(args.profiles)
        invalid = {p["id"]: validate_profile_schema(p) for p in profiles
                   if validate_profile_schema(p)}
        profile = select_profile(abl_hash, profiles)
        if profile is None:
            raise OtaProfileError(f"unknown or ambiguous ABL profile: {abl_hash}")
        result = verify_profile(profile, args.firmware_dir)
        result["schema_errors"] = invalid
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"OTA/profile exact match : {'PASS' if result['pass'] else 'FAIL'}")
            print(f"Profile                  : {result['profile']}")
            print(f"Build                    : {result['build']}")
            print("Unknown firmware         : REFUSED")
            print(f"RESULT                   : {'PASS' if result['pass'] else 'FAIL'}")
            for error in result["errors"]:
                print(f"Error                    : {error}")
        return 0 if result["pass"] else 2
    except (OSError, ValueError, KeyError, json.JSONDecodeError, OtaProfileError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
