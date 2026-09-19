#!/usr/bin/env python3
"""Read-only Qualcomm/UEFI firmware-volume analyzer for PJZ110 partitions.

Designed for imagefv_<slot>, toolsfv and uefi_<slot> dumps.  It never writes
the input image.  The report is intended to answer one deployment question:
is there a stock firmware-volume / EFI path that can execute the already
validated PJZ110 fake-locked LinuxLoader without flashing a modified ABL?
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


def r16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def r24(b: bytes, o: int) -> int:
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)


def r32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def r64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def guid_text(raw: bytes) -> str:
    if len(raw) != 16:
        return raw.hex()
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    tail = raw[8:]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{tail[0]:02x}{tail[1]:02x}-{tail[2:].hex()}"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for x in data:
        counts[x] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


SECTION_NAMES = {
    0x01: "compression",
    0x02: "guid_defined",
    0x10: "pe32",
    0x11: "pic",
    0x12: "te",
    0x13: "dxe_depex",
    0x14: "version",
    0x15: "user_interface",
    0x16: "compatibility16",
    0x17: "fv_image",
    0x18: "freeform_subtype_guid",
    0x19: "raw",
    0x1B: "pei_depex",
    0x1C: "smm_depex",
}

FILE_TYPES = {
    0x01: "raw",
    0x02: "freeform",
    0x03: "security_core",
    0x04: "pei_core",
    0x05: "dxe_core",
    0x06: "peim",
    0x07: "driver",
    0x08: "combined_peim_driver",
    0x09: "application",
    0x0A: "smm",
    0x0B: "firmware_volume_image",
    0x0C: "combined_smm_dxe",
    0x0D: "smm_core",
    0xF0: "pad",
}


@dataclass
class Section:
    offset: int
    size: int
    section_type: int
    section_name: str
    sha256: str | None = None
    ui_name: str | None = None
    pe_machine: str | None = None
    pe_subsystem: int | None = None


@dataclass
class FfsFile:
    offset: int
    size: int
    guid: str
    file_type: int
    file_type_name: str
    attributes: int
    state: int
    sections: list[Section]


@dataclass
class FirmwareVolume:
    offset: int
    length: int
    filesystem_guid: str
    attributes: int
    header_length: int
    revision: int
    files: list[FfsFile]


def align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def pe_info(blob: bytes) -> tuple[str | None, int | None]:
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        return None, None
    try:
        pe = r32(blob, 0x3C)
        if pe + 0x5C > len(blob) or blob[pe:pe + 4] != b"PE\0\0":
            return None, None
        machine = r16(blob, pe + 4)
        opt = pe + 24
        subsystem = r16(blob, opt + 0x44) if r16(blob, opt) == 0x20B else None
        m = {0xAA64: "AARCH64", 0x8664: "X86_64", 0x14C: "X86"}.get(machine, hex(machine))
        return m, subsystem
    except (IndexError, struct.error):
        return None, None


def utf16_ui(payload: bytes) -> str | None:
    try:
        s = payload.decode("utf-16le", errors="strict").split("\x00", 1)[0]
        return s if s and all(ch.isprintable() for ch in s) else None
    except UnicodeDecodeError:
        return None


def parse_sections(data: bytes, start: int, end: int) -> list[Section]:
    out: list[Section] = []
    p = align(start, 4)
    while p + 4 <= end:
        size = r24(data, p)
        stype = data[p + 3]
        header = 4
        if size == 0xFFFFFF:
            if p + 8 > end:
                break
            size = r32(data, p + 4)
            header = 8
        if size < header or p + size > end:
            break
        payload = data[p + header:p + size]
        sec = Section(p, size, stype, SECTION_NAMES.get(stype, f"0x{stype:02x}"))
        if stype in (0x10, 0x12):
            sec.sha256 = sha256(payload)
            machine, subsystem = pe_info(payload)
            sec.pe_machine = machine
            sec.pe_subsystem = subsystem
        elif stype == 0x15:
            sec.ui_name = utf16_ui(payload)
        out.append(sec)
        p = align(p + size, 4)
    return out


def parse_fv(data: bytes, base: int) -> FirmwareVolume | None:
    if base < 0 or base + 0x38 > len(data):
        return None
    try:
        length = r64(data, base + 0x20)
        if data[base + 0x28:base + 0x2C] != b"_FVH":
            return None
        header_len = r16(data, base + 0x30)
        attrs = r32(data, base + 0x2C)
        rev = data[base + 0x37]
        if length < header_len or length > len(data) - base:
            return None
        files: list[FfsFile] = []
        p = align(base + header_len, 8)
        end = base + length
        while p + 24 <= end:
            hdr = data[p:p + 24]
            if hdr == b"\xff" * 24 or hdr == b"\x00" * 24:
                p += 8
                continue
            size = r24(data, p + 20)
            ftype = data[p + 18]
            attrs_f = data[p + 19]
            state = data[p + 23]
            header_size = 24
            if size == 0xFFFFFF and p + 32 <= end:
                size = r64(data, p + 24)
                header_size = 32
            if size < header_size or p + size > end:
                p += 8
                continue
            files.append(FfsFile(
                p, size, guid_text(data[p:p + 16]), ftype,
                FILE_TYPES.get(ftype, f"0x{ftype:02x}"),
                attrs_f, state,
                parse_sections(data, p + header_size, p + size)
            ))
            p = align(p + size, 8)
        return FirmwareVolume(
            base, length, guid_text(data[base + 16:base + 32]),
            attrs, header_len, rev, files
        )
    except (IndexError, struct.error):
        return None


def find_fvs(data: bytes) -> list[FirmwareVolume]:
    out: list[FirmwareVolume] = []
    seen: set[int] = set()
    p = 0
    while True:
        sig = data.find(b"_FVH", p)
        if sig < 0:
            break
        base = sig - 0x28
        if base not in seen:
            fv = parse_fv(data, base)
            if fv:
                out.append(fv)
                seen.add(base)
        p = sig + 4
    return out


def ascii_count(data: bytes, text: str) -> int:
    return data.count(text.encode("ascii"))


def utf16_count(data: bytes, text: str) -> int:
    return data.count(text.encode("utf-16le"))


def global_pe_offsets(data: bytes) -> list[int]:
    out: list[int] = []
    p = 0
    while True:
        p = data.find(b"MZ", p)
        if p < 0:
            break
        machine, _ = pe_info(data[p:])
        if machine:
            out.append(p)
        p += 2
    return out


def analyze(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    fvs = find_fvs(data)
    ui_names = sorted({
        s.ui_name
        for fv in fvs for f in fv.files for s in f.sections
        if s.ui_name
    })
    pe_sections = [
        {
            "ffs_guid": f.guid,
            "file_type": f.file_type_name,
            **asdict(s)
        }
        for fv in fvs for f in fv.files for s in f.sections
        if s.section_type in (0x10, 0x12)
    ]
    markers = {}
    for x in [
        "LinuxLoader", "QcomChargerApp", "Shell", "UEFI Shell",
        "imagefv", "toolsfv", "uefi", "uefisecapp",
        "LoadImage", "StartImage", "Authenticate", "Security Violation",
        "Secure Boot", "VerifiedBoot"
    ]:
        markers[x] = {"ascii": ascii_count(data, x), "utf16": utf16_count(data, x)}
    return {
        "path": str(path),
        "size": len(data),
        "sha256": sha256(data),
        "entropy": round(entropy(data), 4),
        "firmware_volume_count": len(fvs),
        "firmware_volumes": [asdict(x) for x in fvs],
        "ui_names": ui_names,
        "pe_sections": pe_sections,
        "global_pe_offsets": [hex(x) for x in global_pe_offsets(data)],
        "markers": markers,
        "interpretation": {
            "contains_firmware_volume": bool(fvs),
            "contains_efi_pe_payloads": bool(pe_sections or global_pe_offsets(data)),
            "unsigned_chainload_proven": False,
            "note": "FV/PE presence alone does not prove an unauthenticated execution path."
        }
    }


def print_human(r: dict[str, Any]) -> None:
    print(f"Path      : {r['path']}")
    print(f"Size      : {r['size']}")
    print(f"SHA256    : {r['sha256']}")
    print(f"Entropy   : {r['entropy']}")
    print(f"FVs       : {r['firmware_volume_count']}")
    print(f"Global PEs: {len(r['global_pe_offsets'])}")
    if r["ui_names"]:
        print("UI names:")
        for x in r["ui_names"]:
            print(f"  - {x}")
    print("Markers:")
    for k, v in r["markers"].items():
        if v["ascii"] or v["utf16"]:
            print(f"  {k:20s} ascii={v['ascii']} utf16={v['utf16']}")
    for i, fv in enumerate(r["firmware_volumes"]):
        print(f"FV[{i}] @0x{fv['offset']:X} len=0x{fv['length']:X} files={len(fv['files'])}")
        for f in fv["files"]:
            names = [s["ui_name"] for s in f["sections"] if s.get("ui_name")]
            pes = [s for s in f["sections"] if s["section_type"] in (0x10, 0x12)]
            if names or pes or f["file_type_name"] == "application":
                print(f"  {f['guid']} {f['file_type_name']} size=0x{f['size']:X} ui={names}")
                for s in pes:
                    print(f"    {s['section_name']} @0x{s['offset']:X} size=0x{s['size']:X} machine={s.get('pe_machine')} sha256={s.get('sha256')}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("images", nargs="+", type=Path)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    reports = []
    try:
        for p in args.images:
            reports.append(analyze(p))
    except (OSError, struct.error, ValueError) as e:
        print(f"error: {e}")
        return 2
    if args.output:
        args.output.write_text(json.dumps(reports, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(reports, indent=2, sort_keys=True))
    else:
        for i, r in enumerate(reports):
            if i:
                print()
            print_human(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
