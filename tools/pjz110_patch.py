#!/usr/bin/env python3
"""OnePlus 13 (PJZ110 / SM8750) LinuxLoader analyzer and fail-closed patcher.

This tool is intentionally version-scoped.  The only writable profile shipped in
this first revision is PJZ110_16.0.10.501(CN01).  Unknown images are analyzed but
never patched.

The patch keeps the persisted Qualcomm DeviceInfo unlock bit untouched.  It only
rewrites software-visible strings selected by LinuxLoader:
  * androidboot.vbmeta.device_state => locked
  * verified boot state table: orange => green

It does not modify KeyMaster/TEE RootOfTrust state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import struct
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

PROFILE_ID = "pjz110-16.0.10.501-cn01"
PROFILE_BUILD = "PJZ110_16.0.10.501(CN01)"
ABL_SHA256 = "c6aa137b7e2b8c6f86040438022488eee6b2a69a1fad95f109a86c8a77d64bed"
LINUXLOADER_SHA256 = "4d4aaa42e86917e65c2b2c3fdd477851282a31d5c64f9ca9d20710a650da8b4b"
LINUXLOADER_SIZE = 0xC3000

# Exact offsets for the profiled LinuxLoader. Each write is guarded by expected
# bytes/values and the whole image SHA256, so an OTA cannot silently reuse them.
DEVICE_STATE_UNL_ADRP = 0x4AF3C
DEVICE_STATE_UNL_ADD = 0x4AF40
DEVICE_STATE_LOCK_ADRP = 0x4AF44
DEVICE_STATE_LOCK_ADD = 0x4AF48
DEVICE_STATE_KEY_ADRP = 0x4AF4C
DEVICE_STATE_KEY_ADD = 0x4AF50
DEVICE_STATE_CMP = 0x4AF58
DEVICE_STATE_CSEL = 0x4AF5C

VERIFIED_TABLE_BASE = 0xA2C90
VERIFIED_GREEN_PTR = 0xA2C98  # state 0
VERIFIED_ORANGE_PTR = 0xA2CA8  # state 1
GREEN_STRING = 0x86015
ORANGE_STRING = 0x82F87

EXPECTED_DEVICE_WORDS = {
    DEVICE_STATE_UNL_ADRP: 0xB0000229,
    DEVICE_STATE_UNL_ADD: 0x91042929,
    DEVICE_STATE_LOCK_ADRP: 0xD00001AA,
    DEVICE_STATE_LOCK_ADD: 0x91328D4A,
    DEVICE_STATE_KEY_ADRP: 0xB0000181,
    DEVICE_STATE_KEY_ADD: 0x91364021,
    DEVICE_STATE_CMP: 0x7100011F,
    DEVICE_STATE_CSEL: 0x9A890142,
}

MARKERS = {
    "device_state_key": b"androidboot.vbmeta.device_state",
    "verified_state_key": b"androidboot.verifiedbootstate=",
    "unlocked": b"unlocked",
    "locked": b"locked",
    "orange": b"orange",
    "green": b"green",
    "oplus_unlock_warning": b"Your device has been unlocked and can't be trusted",
    "orange_state_warning": b"Orange State\n",
    "keymaster_rot": b"KeyMasterSetRotAndBootState",
}


@dataclass
class Analysis:
    input_path: str
    input_sha256: str
    extracted_from_abl: bool
    linuxloader_sha256: str
    linuxloader_size: int
    profile: str | None
    exact_profile_match: bool
    marker_counts: dict[str, int]
    device_state_signature_ok: bool
    verified_table_ok: bool
    legacy_efisp_ascii_count: int
    legacy_efisp_utf16_count: int
    gbl_status: str
    patchable: bool
    notes: list[str]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def r16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def r32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def r64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def w32(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", buf, off, value & 0xFFFFFFFF)


def w64(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<Q", buf, off, value & 0xFFFFFFFFFFFFFFFF)


def count_all(data: bytes, needle: bytes) -> int:
    n = 0
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return n
        n += 1
        pos += 1


def pe_real_size(data: bytes, off: int) -> int | None:
    if off + 0x40 > len(data):
        return None
    pe = r32(data, off + 0x3C)
    if off + pe + 0x58 > len(data) or data[off + pe: off + pe + 4] != b"PE\0\0":
        return None
    num_sec = r16(data, off + pe + 0x06)
    opt_size = r16(data, off + pe + 0x14)
    sec_table = off + pe + 0x18 + opt_size
    real_len = r32(data, off + pe + 0x54)
    for i in range(num_sec):
        sec = sec_table + i * 0x28
        if sec + 0x28 > len(data):
            break
        size_raw = r32(data, sec + 0x10)
        ptr_raw = r32(data, sec + 0x14)
        real_len = max(real_len, ptr_raw + size_raw)
    if real_len <= 0 or off + real_len > len(data):
        return None
    return real_len


def _scan_pe(data: bytes) -> list[bytes]:
    out: list[bytes] = []
    pos = 0
    while True:
        pos = data.find(b"MZ", pos)
        if pos < 0:
            break
        size = pe_real_size(data, pos)
        if size:
            out.append(data[pos:pos + size])
        pos += 2
    return out


def extract_linuxloader(data: bytes) -> bytes:
    """Replicate the upstream investigator strategy with stdlib-only LZMA."""
    candidates: list[bytes] = []
    seen: set[tuple[int, bytes]] = set()

    def walk(blob: bytes, depth: int) -> None:
        if depth > 5 or len(blob) < 0x40:
            return
        key = (len(blob), hashlib.sha256(blob[: min(len(blob), 4096)]).digest())
        if key in seen:
            return
        seen.add(key)
        candidates.extend(_scan_pe(blob))

        pos = 0
        while True:
            pos = blob.find(b"\x5D\x00\x00", pos)
            if pos < 0:
                break
            chunk = blob[pos: pos + 0x200000]
            for skip in range(min(32, len(chunk))):
                d = chunk[skip:]
                if len(d) < 13 or d[0] != 0x5D:
                    continue
                try:
                    decoded = lzma.decompress(d, format=lzma.FORMAT_ALONE)
                except (lzma.LZMAError, EOFError):
                    continue
                if len(decoded) > 64:
                    walk(decoded, depth + 1)
                    break
            pos += 1

    walk(data, 0)
    if not candidates:
        raise ValueError("no embedded PE/COFF image found")
    return max(candidates, key=len)


def looks_like_pe(data: bytes) -> bool:
    return len(data) >= 0x40 and data[:2] == b"MZ" and pe_real_size(data, 0) is not None


def load_linuxloader(path: Path) -> tuple[bytes, bool, str]:
    raw = path.read_bytes()
    raw_hash = sha256(raw)
    if looks_like_pe(raw):
        return raw, False, raw_hash
    return extract_linuxloader(raw), True, raw_hash


def device_signature_ok(data: bytes) -> bool:
    if len(data) < DEVICE_STATE_CSEL + 4:
        return False
    return all(r32(data, off) == word for off, word in EXPECTED_DEVICE_WORDS.items())


def verified_table_ok(data: bytes) -> bool:
    if len(data) < VERIFIED_ORANGE_PTR + 8:
        return False
    return (
        r64(data, VERIFIED_GREEN_PTR) == GREEN_STRING
        and r64(data, VERIFIED_ORANGE_PTR) == ORANGE_STRING
    )


def analyze(path: Path) -> tuple[Analysis, bytes]:
    loader, extracted, input_hash = load_linuxloader(path)
    loader_hash = sha256(loader)
    marker_counts = {name: count_all(loader, marker) for name, marker in MARKERS.items()}
    exact = loader_hash == LINUXLOADER_SHA256 and len(loader) == LINUXLOADER_SIZE
    notes: list[str] = []
    if extracted and input_hash == ABL_SHA256:
        notes.append("input matches the profiled PJZ110 16.0.10.501 ABL")
    elif extracted:
        notes.append("input is an ABL-like container but its SHA256 is not the profiled ABL")
    if marker_counts["keymaster_rot"]:
        notes.append("KeyMaster/TEE boot-state path is present and is intentionally not patched")

    legacy_ascii = count_all(loader, b"efisp")
    legacy_utf16 = count_all(loader, "efisp".encode("utf-16le"))
    gbl = (
        "legacy-efisp-not-present"
        if legacy_ascii == 0 and legacy_utf16 == 0
        else "legacy-efisp-present"
    )
    sig_ok = device_signature_ok(loader)
    table_ok = verified_table_ok(loader)
    patchable = exact and sig_ok and table_ok
    if not exact:
        notes.append("image is not the exact writable profile; patch command will refuse")
    if not sig_ok:
        notes.append("PJZ110 device-state instruction signature did not match")
    if not table_ok:
        notes.append("PJZ110 verified-state table did not match")
    return Analysis(
        input_path=str(path),
        input_sha256=input_hash,
        extracted_from_abl=extracted,
        linuxloader_sha256=loader_hash,
        linuxloader_size=len(loader),
        profile=PROFILE_ID if exact else None,
        exact_profile_match=exact,
        marker_counts=marker_counts,
        device_state_signature_ok=sig_ok,
        verified_table_ok=table_ok,
        legacy_efisp_ascii_count=legacy_ascii,
        legacy_efisp_utf16_count=legacy_utf16,
        gbl_status=gbl,
        patchable=patchable,
        notes=notes,
    ), loader


def rewrite_reg(raw: int, rd: int, rn: int | None = None) -> int:
    raw = (raw & ~0x1F) | (rd & 0x1F)
    if rn is not None:
        raw = (raw & ~(0x1F << 5)) | ((rn & 0x1F) << 5)
    return raw


def apply_device_state_patch(out: bytearray) -> None:
    if not device_signature_ok(out):
        raise ValueError("device-state signature mismatch")
    locked_adrp = r32(out, DEVICE_STATE_LOCK_ADRP)
    locked_add = r32(out, DEVICE_STATE_LOCK_ADD)
    w32(out, DEVICE_STATE_UNL_ADRP, rewrite_reg(locked_adrp, 9))
    w32(out, DEVICE_STATE_UNL_ADD, rewrite_reg(locked_add, 9, 9))


def apply_verified_state_patch(out: bytearray) -> None:
    if not verified_table_ok(out):
        raise ValueError("verified-state table mismatch")
    w64(out, VERIFIED_ORANGE_PTR, GREEN_STRING)


def patch_loader(loader: bytes) -> tuple[bytes, dict]:
    if sha256(loader) != LINUXLOADER_SHA256 or len(loader) != LINUXLOADER_SIZE:
        raise ValueError(
            "refusing to patch: LinuxLoader SHA256/size is not the exact PJZ110 profile"
        )
    if not device_signature_ok(loader):
        raise ValueError("refusing to patch: device-state signature mismatch")
    if not verified_table_ok(loader):
        raise ValueError("refusing to patch: verified-state table mismatch")

    out = bytearray(loader)
    before = bytes(out)
    locked_adrp = r32(loader, DEVICE_STATE_LOCK_ADRP)
    locked_add = r32(loader, DEVICE_STATE_LOCK_ADD)
    apply_device_state_patch(out)
    apply_verified_state_patch(out)

    changed = [i for i, (a, b) in enumerate(zip(before, out)) if a != b]
    allowed = set(range(DEVICE_STATE_UNL_ADRP, DEVICE_STATE_UNL_ADD + 4)) | set(
        range(VERIFIED_ORANGE_PTR, VERIFIED_ORANGE_PTR + 8)
    )
    unexpected = [i for i in changed if i not in allowed]
    if unexpected:
        raise AssertionError(f"unexpected modified offsets: {unexpected[:16]}")

    if r32(out, DEVICE_STATE_UNL_ADRP) != rewrite_reg(locked_adrp, 9):
        raise AssertionError("device-state ADRP postcondition failed")
    if r32(out, DEVICE_STATE_UNL_ADD) != rewrite_reg(locked_add, 9, 9):
        raise AssertionError("device-state ADD postcondition failed")
    if r64(out, VERIFIED_ORANGE_PTR) != GREEN_STRING:
        raise AssertionError("verified-state table postcondition failed")

    manifest = {
        "profile": PROFILE_ID,
        "build": PROFILE_BUILD,
        "input_sha256": sha256(loader),
        "output_sha256": sha256(out),
        "image_size": len(out),
        "device_state_patch": {
            "offsets": [hex(DEVICE_STATE_UNL_ADRP), hex(DEVICE_STATE_UNL_ADD)],
            "before": [
                hex(r32(loader, DEVICE_STATE_UNL_ADRP)),
                hex(r32(loader, DEVICE_STATE_UNL_ADD)),
            ],
            "after": [
                hex(r32(out, DEVICE_STATE_UNL_ADRP)),
                hex(r32(out, DEVICE_STATE_UNL_ADD)),
            ],
        },
        "verified_state_patch": {
            "offset": hex(VERIFIED_ORANGE_PTR),
            "before": hex(r64(loader, VERIFIED_ORANGE_PTR)),
            "after": hex(r64(out, VERIFIED_ORANGE_PTR)),
        },
        "changed_byte_count": len(changed),
        "changed_offsets": [hex(i) for i in changed],
        "tee_keymaster_modified": False,
        "gbl_modified": False,
    }
    return bytes(out), manifest


def print_human(a: Analysis) -> None:
    print(f"Profile candidate : {PROFILE_ID}")
    print(f"Input SHA256      : {a.input_sha256}")
    print(f"Embedded loader   : {'yes' if a.extracted_from_abl else 'input is PE'}")
    print(f"LinuxLoader SHA256: {a.linuxloader_sha256}")
    print(f"LinuxLoader size  : 0x{a.linuxloader_size:X}")
    print(f"Exact profile     : {'PASS' if a.exact_profile_match else 'FAIL'}")
    print(f"Device-state sig  : {'PASS' if a.device_state_signature_ok else 'FAIL'}")
    print(f"Verified table    : {'PASS' if a.verified_table_ok else 'FAIL'}")
    print(
        f"Legacy efisp      : ascii={a.legacy_efisp_ascii_count}, "
        f"utf16={a.legacy_efisp_utf16_count}"
    )
    print(f"GBL status        : {a.gbl_status}")
    print(f"Patchable         : {'YES' if a.patchable else 'NO'}")
    print("Markers:")
    for k, v in a.marker_counts.items():
        print(f"  {k:24s} {v}")
    if a.notes:
        print("Notes:")
        for n in a.notes:
            print(f"  - {n}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sp = p.add_subparsers(dest="cmd", required=True)

    pa = sp.add_parser(
        "analyze", help="read-only analysis; accepts abl.img or LinuxLoader.efi"
    )
    pa.add_argument("input", type=Path)
    pa.add_argument("--json", action="store_true")
    pa.add_argument(
        "--extract", type=Path, help="write extracted LinuxLoader.efi (read-only operation)"
    )

    pp = sp.add_parser(
        "patch", help="patch exact PJZ110 profile; accepts abl.img or LinuxLoader.efi"
    )
    pp.add_argument("input", type=Path)
    pp.add_argument("output", type=Path)
    pp.add_argument("--manifest", type=Path)

    args = p.parse_args(argv)
    try:
        analysis, loader = analyze(args.input)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.cmd == "analyze":
        if args.extract:
            args.extract.write_bytes(loader)
        if args.json:
            print(json.dumps(asdict(analysis), indent=2, sort_keys=True))
        else:
            print_human(analysis)
        return 0 if analysis.patchable else 1

    if not analysis.patchable:
        print_human(analysis)
        print(
            "error: fail-closed: image is not an exact writable PJZ110 profile",
            file=sys.stderr,
        )
        return 3
    try:
        patched, manifest = patch_loader(loader)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 4
    args.output.write_bytes(patched)
    manifest_path = args.manifest or Path(str(args.output) + ".manifest.json")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"patched: {args.output}")
    print(f"manifest: {manifest_path}")
    print(f"output SHA256: {manifest['output_sha256']}")
    print("note: GBL/EFISP chain and KeyMaster/TEE state were not modified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
