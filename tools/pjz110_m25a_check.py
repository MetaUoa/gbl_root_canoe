#!/usr/bin/env python3
"""Exact-current PJZ110 M25-A ABL/PIL authentication-boundary verifier.

Read-only and fail-closed. It proves that the current fake-lock LinuxLoader is
embedded inside the SHA-384 covered primary ABL LOAD segment and verifies the
signed Qualcomm ELF-v7 hash-table region. It never creates or writes a device
partition image.

RESULT=PASS means the M25-A conclusion reproduced:
  direct patched ABL under the stock authentication path = CLOSED-BY-PIL-AUTH.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import lzma
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

BASE_TOOL = Path(__file__).with_name("pjz110_retail_path_check.py")
spec = importlib.util.spec_from_file_location("pjz110_retail_path_check_for_m25a", BASE_TOOL)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load pjz110_retail_path_check.py")
base = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = base
spec.loader.exec_module(base)


class M25AError(RuntimeError):
    pass


def der_total_len(data: bytes, offset: int) -> int:
    if offset + 2 > len(data) or data[offset] != 0x30:
        raise M25AError(f"expected DER SEQUENCE at 0x{offset:X}")
    first = data[offset + 1]
    if first < 0x80:
        return 2 + first
    n = first & 0x7F
    if n == 0 or n > 4 or offset + 2 + n > len(data):
        raise M25AError("invalid DER length")
    return 2 + n + int.from_bytes(data[offset + 2:offset + 2 + n], "big")


def parse_elf32(data: bytes) -> dict[str, Any]:
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise M25AError("ABL is not little-endian ELF32")
    vals = struct.unpack_from("<16sHHIIIIIHHHHHH", data, 0)
    out = {
        "type": vals[1],
        "machine": vals[2],
        "entry": vals[4],
        "phoff": vals[5],
        "phentsize": vals[9],
        "phnum": vals[10],
        "phdrs": [],
    }
    for i in range(out["phnum"]):
        off = out["phoff"] + i * out["phentsize"]
        if off + 32 > len(data):
            raise M25AError("truncated ELF program header")
        p = struct.unpack_from("<IIIIIIII", data, off)
        out["phdrs"].append({
            "type": p[0], "offset": p[1], "vaddr": p[2], "paddr": p[3],
            "filesz": p[4], "memsz": p[5], "flags": p[6], "align": p[7],
        })
    return out


def as_int(value: int | str) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def decode_fdt_value(raw: bytes, expected: Any) -> Any:
    if isinstance(expected, str):
        return raw.split(b"\0", 1)[0].decode("ascii", errors="replace")
    return int.from_bytes(raw, "big")


def verify_openssl(
    abl: bytes,
    signed_region: bytes,
    sig_off: int,
    sig_len: int,
    cert_off: int,
    cert_len: int,
) -> str:
    openssl = shutil.which("openssl")
    if not openssl:
        return "UNAVAILABLE"
    try:
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            (td / "sig.der").write_bytes(abl[sig_off:sig_off + sig_len])
            (td / "leaf.der").write_bytes(abl[cert_off:cert_off + cert_len])
            (td / "signed.bin").write_bytes(signed_region)
            pub = subprocess.run(
                [openssl, "x509", "-inform", "DER", "-in", str(td / "leaf.der"), "-pubkey", "-noout"],
                capture_output=True,
                check=False,
            )
            if pub.returncode != 0:
                return "FAIL"
            (td / "pub.pem").write_bytes(pub.stdout)
            verify = subprocess.run(
                [
                    openssl, "dgst", "-sha384", "-verify", str(td / "pub.pem"),
                    "-signature", str(td / "sig.der"), str(td / "signed.bin"),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            return "PASS" if verify.returncode == 0 and "Verified OK" in verify.stdout else "FAIL"
    except OSError:
        return "UNAVAILABLE"


def check(args: argparse.Namespace) -> dict[str, Any]:
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    abl = args.abl.read_bytes()
    xbl = args.xbl_config.read_bytes()
    original = args.original_linuxloader.read_bytes()
    fake = args.fake_linuxloader.read_bytes()

    result: dict[str, Any] = {"profile": profile["id"], "checks": {}}
    ok = True

    def expect(name: str, actual: Any, expected: Any) -> bool:
        nonlocal ok
        passed = actual == expected
        result["checks"][name] = {"actual": actual, "expected": expected, "pass": passed}
        ok = ok and passed
        return passed

    abl_cfg = profile["abl"]
    expect("abl.size", len(abl), int(abl_cfg["size"]))
    expect("abl.sha256", base.sha256_file(args.abl), abl_cfg["sha256"])

    elf = parse_elf32(abl)
    elf_cfg = abl_cfg["elf"]
    for name in ("type", "machine", "entry", "phoff", "phentsize", "phnum"):
        expect(f"elf.{name}", elf[name], as_int(elf_cfg[name]))
    for index, wanted in enumerate(elf_cfg["phdrs"]):
        for name, value in wanted.items():
            expect(f"elf.phdr{index}.{name}", elf["phdrs"][index][name], as_int(value))

    hs = abl_cfg["hash_segment"]
    hs_off = as_int(hs["offset"])
    hs_size = as_int(hs["size"])
    hash_seg = abl[hs_off:hs_off + hs_size]
    fields = [
        "reserved", "version", "common_metadata_size", "qti_metadata_size",
        "oem_metadata_size", "hash_table_size", "qti_signature_size",
        "qti_certificate_chain_size", "oem_signature_size", "oem_certificate_chain_size",
    ]
    header = struct.unpack_from("<10I", hash_seg, 0)
    for i, name in enumerate(fields):
        expect(f"hash_header.{name}", header[i], int(hs["header"][name]))

    load = elf["phdrs"][1]
    header_digest = hashlib.sha384(abl[:as_int(hs["header_hash_end"])]).digest()
    load_digest = hashlib.sha384(
        abl[load["offset"]:load["offset"] + load["filesz"]]
    ).digest()
    table_off = as_int(hs["hash_table_offset"])
    stored = [
        hash_seg[table_off + i * 48:table_off + (i + 1) * 48]
        for i in range(3)
    ]
    expect("hash_table.header_sha384", stored[0].hex(), header_digest.hex())
    expect("hash_table.load_sha384", stored[1].hex(), load_digest.hex())
    expect("hash_table.self_zero", stored[2].hex(), "00" * 48)
    expect("hash_table.expected_header_digest", header_digest.hex(), hs["header_sha384"])
    expect("hash_table.expected_load_digest", load_digest.hex(), hs["load_sha384"])

    mutated = bytearray(abl[load["offset"]:load["offset"] + load["filesz"]])
    mutated[as_int(hs["mutation_probe_offset_in_load"])] ^= 1
    mutated_digest = hashlib.sha384(mutated).digest()
    mutation_pass = mutated_digest != stored[1]
    result["checks"]["covered_load_mutation"] = {
        "actual_sha384": mutated_digest.hex(),
        "stored_sha384": stored[1].hex(),
        "pass": mutation_pass,
    }
    ok = ok and mutation_pass

    signed_off = as_int(hs["signed_region_offset"])
    signed_size = as_int(hs["signed_region_size"])
    signed_region = abl[signed_off:signed_off + signed_size]
    expect(
        "hash_segment.signed_region_sha384",
        hashlib.sha384(signed_region).hexdigest(),
        hs["signed_region_sha384"],
    )

    sig_off = as_int(hs["oem_signature_offset"])
    sig_len = der_total_len(abl, sig_off)
    expect("signature.der_size", sig_len, int(hs["oem_signature_der_size"]))
    expect("signature.slot_size", int(hs["oem_signature_slot_size"]), int(hs["header"]["oem_signature_size"]))
    expect(
        "signature.padding",
        abl[sig_off + sig_len:sig_off + int(hs["oem_signature_slot_size"])].hex(),
        "00",
    )

    cert_results = []
    for cert in hs["certificates"]:
        off = as_int(cert["offset"])
        size = der_total_len(abl, off)
        raw = abl[off:off + size]
        item = {
            "offset": hex(off),
            "size": size,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "expected_size": int(cert["size"]),
            "expected_sha256": cert["sha256"],
        }
        item["pass"] = item["size"] == item["expected_size"] and item["sha256"] == item["expected_sha256"]
        cert_results.append(item)
        ok = ok and item["pass"]
    result["certificates"] = cert_results

    openssl_status = verify_openssl(
        abl, signed_region, sig_off, sig_len,
        as_int(hs["certificates"][0]["offset"]), int(hs["certificates"][0]["size"]),
    )
    openssl_pass = openssl_status == "PASS" if args.require_openssl else openssl_status != "FAIL"
    result["openssl_ecdsa_sha384_verify"] = {"status": openssl_status, "pass": openssl_pass}
    ok = ok and openssl_pass

    lz = abl_cfg["lzma"]
    lz_off = as_int(lz["offset"])
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    decompressed = decoder.decompress(abl[lz_off:])
    consumed = len(abl) - lz_off - len(decoder.unused_data)
    expect("lzma.consumed", consumed, as_int(lz["compressed_size"]))
    expect("lzma.decompressed_size", len(decompressed), as_int(lz["decompressed_size"]))
    expect("lzma.pe_offset", decompressed.find(b"MZ"), as_int(lz["pe_offset"]))

    ll = profile["linuxloader"]
    pe_off = as_int(lz["pe_offset"])
    extracted = decompressed[pe_off:pe_off + int(ll["size"])]
    expect("linuxloader.extracted_sha256", hashlib.sha256(extracted).hexdigest(), ll["original_sha256"])
    expect("linuxloader.original_sha256", hashlib.sha256(original).hexdigest(), ll["original_sha256"])
    expect("linuxloader.fake_sha256", hashlib.sha256(fake).hexdigest(), ll["fake_sha256"])
    expect("linuxloader.original_size", len(original), int(ll["size"]))
    expect("linuxloader.fake_size", len(fake), int(ll["size"]))
    diffs = [i for i, (a, b) in enumerate(zip(original, fake)) if a != b]
    expect("linuxloader.diff_offsets", [hex(x) for x in diffs], ll["diff_offsets"])

    xc = profile["xbl_config"]
    expect("xbl_config.size", len(xbl), int(xc["size"]))
    expect("xbl_config.sha256", base.sha256_file(args.xbl_config), xc["sha256"])
    _, props = base.find_profile_dtb(xbl, as_int(xc["dtb_offset"]))
    node = props.get(xc["abl_cfg_path"], {})
    for name, wanted in xc["abl_cfg_required"].items():
        raw = node.get(name)
        actual = None if raw is None else decode_fdt_value(raw, wanted)
        expect(f"abl_cfg.{name}", actual, wanted)

    if args.bootloader_log is not None:
        log = args.bootloader_log.read_text(encoding="utf-8", errors="replace")
        for text in profile["runtime"]["required_strings"]:
            present = text in log
            result["checks"][f"runtime:{text}"] = {"actual": present, "expected": True, "pass": present}
            ok = ok and present

    result["conclusion"] = {
        "M25-A": profile["expected"]["M25-A"],
        "outer_primary_load_is_sha384_covered": True,
        "hash_table_region_has_valid_current_oplus_signature": openssl_status,
        "fake_linuxloader_changes": len(diffs),
        "stock_direct_patched_abl_status": profile["expected"]["direct_patched_abl_stock_auth"],
        "interpretation": profile["expected"]["interpretation"],
    }
    result["pass"] = bool(ok)
    return result


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", type=Path, default=root / "profiles" / "PJZ110_16.0.10.501_m25a.json")
    ap.add_argument("--abl", type=Path, required=True)
    ap.add_argument("--xbl-config", type=Path, required=True)
    ap.add_argument("--original-linuxloader", type=Path, required=True)
    ap.add_argument("--fake-linuxloader", type=Path, required=True)
    ap.add_argument("--bootloader-log", type=Path)
    ap.add_argument("--require-openssl", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        report = check(args)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(f"M25-A exact profile       : {'PASS' if report['pass'] else 'FAIL'}")
            print(f"ABL LOAD SHA384 coverage : {'PASS' if report['checks']['hash_table.load_sha384']['pass'] else 'FAIL'}")
            print(f"LinuxLoader 7-byte delta : {'PASS' if report['checks']['linuxloader.diff_offsets']['pass'] else 'FAIL'}")
            print(f"signed hash-table ECDSA  : {report['openssl_ecdsa_sha384_verify']['status']}")
            print(f"direct patched ABL       : {report['conclusion']['stock_direct_patched_abl_status']}")
            print(f"RESULT                   : {'PASS' if report['pass'] else 'FAIL'}")
        return 0 if report["pass"] else 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError, struct.error, lzma.LZMAError, M25AError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
