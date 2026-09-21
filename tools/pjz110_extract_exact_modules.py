#!/usr/bin/env python3
"""Extract exact profiled UEFI modules from decoded PJZ110 FV containers."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


class ExtractError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_modules(profile: dict, decoded_dir: Path) -> dict[str, bytes]:
    result = {}
    for name, cfg in profile["modules"].items():
        source = decoded_dir / cfg["source"]
        data = source.read_bytes()
        offset = int(cfg["offset"], 0)
        size = int(cfg["size"])
        module = data[offset:offset + size]
        if len(module) != size:
            raise ExtractError(f"{name}: source range exceeds {source.name}")
        actual = sha256(module)
        if actual != cfg["sha256"]:
            raise ExtractError(f"{name}: exact hash mismatch: {actual}")
        result[cfg["file"]] = module
    return result


def write_modules(modules: dict[str, bytes], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, data in modules.items():
        path = output_dir / filename
        if path.exists() and path.read_bytes() != data:
            raise ExtractError(f"refusing to replace mismatched output: {path}")
        path.write_bytes(data)


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", type=Path,
                    default=root / "profiles" / "PJZ110_16.0.10.501_m25b.json")
    ap.add_argument("--decoded-dir", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        profile = json.loads(args.profile.read_text(encoding="utf-8"))
        modules = extract_modules(profile, args.decoded_dir)
        write_modules(modules, args.output_dir)
        for filename, data in sorted(modules.items()):
            print(f"{filename}: size={len(data)} sha256={sha256(data)}")
        print("RESULT: PASS")
        return 0
    except (OSError, KeyError, ValueError, json.JSONDecodeError, ExtractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
