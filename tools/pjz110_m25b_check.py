#!/usr/bin/env python3
"""Read-only M25-B baseline and candidate-boundary verifier.

This checker does not claim an execution carrier.  It proves that the exact
device capture matches the profiled firmware payloads, that the runtime lock
state is split between bootconfig and Android properties, and that the known
UEFI/PIL modules are the expected exact binaries.  The resulting boundary is
fail-closed: no post-authentication external producer is treated as proven.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


class M25BError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_file(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    data = path.read_bytes()
    actual = {"size": len(data), "sha256": sha256(data)}
    wanted = {"size": expected["size"], "sha256": expected["sha256"]}
    return {"path": str(path), "expected": wanted, "actual": actual,
            "pass": actual == wanted}


def check_partition(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    data = path.read_bytes()
    n = int(expected["payload_size"])
    payload = data[:n]
    padding = data[n:]
    actual = {"size": len(data), "sha256": sha256(data),
              "payload_size": n, "payload_sha256": sha256(payload),
              "padding_zero": not any(padding)}
    wanted = {"size": expected["size"], "sha256": expected["sha256"],
              "payload_size": n, "payload_sha256": expected["payload_sha256"],
              "padding_zero": True}
    return {"path": str(path), "expected": wanted, "actual": actual,
            "pass": actual == wanted}


def contains(text: str, value: str) -> bool:
    return value in text


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", type=Path,
                    default=root / "profiles" / "PJZ110_16.0.10.501_m25b.json")
    ap.add_argument("--capture-dir", type=Path, required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        profile = json.loads(args.profile.read_text(encoding="utf-8"))
        cap = args.capture_dir
        checks: dict[str, Any] = {}
        for name, cfg in profile["partitions"].items():
            checks[name] = check_partition(cap / cfg["file"], cfg)
        for name, cfg in profile["files"].items():
            checks[name] = check_file(cap / cfg["file"], cfg)

        modules = {}
        for name, cfg in profile["modules"].items():
            modules[name] = check_file(cap / "extracted-uefi-modules" / cfg["file"], cfg)
        checks["modules"] = modules

        bootlog = (cap / "bootloader_log.txt").read_text(encoding="utf-8", errors="replace")
        bootconfig = (cap / "bootconfig.txt").read_text(encoding="utf-8", errors="replace")
        getprop = (cap / "getprop.txt").read_text(encoding="utf-8", errors="replace")
        log_checks = [{"text": x, "pass": contains(bootlog, x)}
                      for x in profile["runtime"]["bootlog_required"]]
        bc_checks = [{"text": x, "pass": contains(bootconfig, x)}
                     for x in profile["runtime"]["bootconfig_required"]]
        prop_checks = [{"text": x, "pass": contains(getprop, x)}
                       for x in profile["runtime"]["getprop_required"]]
        checks["runtime"] = {"bootlog": log_checks, "bootconfig": bc_checks,
                              "getprop": prop_checks,
                              "pass": all(x["pass"] for x in log_checks + bc_checks + prop_checks)}

        all_binary = all(x["pass"] for x in checks.values() if isinstance(x, dict) and "pass" in x)
        all_modules = all(x["pass"] for x in modules.values())
        passed = all_binary and all_modules and checks["runtime"]["pass"]
        report = {"profile": profile["id"], "checks": checks,
                  "candidate_boundaries": profile["candidate_boundaries"],
                  "pass": passed}
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print("M25-B exact capture baseline : {}".format("PASS" if passed else "FAIL"))
            print("post-auth external producer   : CLOSED / NONE IN STOCK PATH")
            print("temporary carrier             : CLOSED / NONE IN STOCK PATH")
            print("live execution                : DO NOT RUN")
            print("RESULT                        : {}".format("PASS" if passed else "FAIL"))
        return 0 if passed else 2
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, M25BError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
