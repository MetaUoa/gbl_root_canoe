#!/usr/bin/env python3
"""PJZ110 / SM8750 ABL-level fake-lock offline patcher.

Fail-closed tool for exact known PJZ110 ABL/LinuxLoader profiles.

Patches only the ABL-visible software state:
  * androidboot.vbmeta.device_state -> locked
  * verified-boot enum state 1 (orange) -> stock green string

It intentionally does NOT modify Qualcomm DeviceInfo.is_unlocked,
VBRwDeviceState, KeyMaster/TEE RootOfTrust, XBL/XBL_CONFIG, or device
partitions. Output is a patched LinuxLoader EFI payload for later true-device
chainload validation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


class PatcherError(RuntimeError):
    pass


@dataclass(frozen=True)
class Section:
    name: str
    vaddr: int
    vsize: int
    raw_off: int
    raw_size: int


@dataclass(frozen=True)
class PeLayout:
    image_base: int
    entry_rva: int
    size_of_image: int
    size_of_headers: int
    sections: tuple[Section, ...]

    def offset_to_rva(self, off: int) -> int:
        if 0 <= off < self.size_of_headers:
            return off
        for s in self.sections:
            if s.raw_off <= off < s.raw_off + s.raw_size:
                return s.vaddr + (off - s.raw_off)
        raise PatcherError(f"file offset 0x{off:X} is outside mapped PE sections")

    def rva_to_offset(self, rva: int) -> int:
        if 0 <= rva < self.size_of_headers:
            return rva
        for s in self.sections:
            span = max(s.vsize, s.raw_size)
            if s.vaddr <= rva < s.vaddr + span:
                off = s.raw_off + (rva - s.vaddr)
                if off >= s.raw_off + s.raw_size:
                    raise PatcherError(f"RVA 0x{rva:X} points into non-file-backed PE data")
                return off
        raise PatcherError(f"RVA 0x{rva:X} is outside mapped PE sections")

    def section(self, name: str) -> Section:
        for s in self.sections:
            if s.name == name:
                return s
        raise PatcherError(f"PE section {name!r} not found")


@dataclass(frozen=True)
class DeviceStateCandidate:
    unlocked_adrp: int
    unlocked_add: int
    locked_adrp: int
    locked_add: int
    key_adrp: int
    key_add: int
    cmp_off: int
    csel_off: int
    unlocked_reg: int
    locked_reg: int
    state_reg: int
    value_reg: int
    unlocked_string: int
    locked_string: int
    key_string: int


@dataclass(frozen=True)
class VerifiedStateTable:
    base: int
    green_pointer_off: int
    orange_pointer_off: int
    yellow_pointer_off: int
    red_pointer_off: int
    green_rva: int
    orange_rva: int
    yellow_rva: int
    red_rva: int


@dataclass
class Analysis:
    input_path: str
    input_sha256: str
    extracted_from_abl: bool
    linuxloader_sha256: str
    linuxloader_size: int
    profile_id: str | None
    build: str | None
    exact_profile_match: bool
    device_state_candidates: list[dict[str, Any]]
    verified_state_tables: list[dict[str, Any]]
    legacy_efisp_ascii_count: int
    legacy_efisp_utf16_count: int
    keymaster_marker_count: int
    patchable: bool
    notes: list[str]


def r16(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def r32(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def r64(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def w32(data: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", data, off, value & 0xFFFFFFFF)


def w64(data: bytearray, off: int, value: int) -> None:
    struct.pack_into("<Q", data, off, value & 0xFFFFFFFFFFFFFFFF)


def sha256(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def count_all(data: bytes, needle: bytes) -> int:
    count = 0
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return count
        count += 1
        pos += 1


def parse_pe(data: bytes) -> PeLayout:
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise PatcherError("input is not a PE/COFF image")
    pe = r32(data, 0x3C)
    if pe + 0x18 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise PatcherError("invalid PE signature")
    num_sections = r16(data, pe + 6)
    optional_size = r16(data, pe + 20)
    opt = pe + 24
    if r16(data, opt) != 0x20B:
        raise PatcherError("expected PE32+ EFI image")
    entry_rva = r32(data, opt + 0x10)
    image_base = r64(data, opt + 0x18)
    size_of_image = r32(data, opt + 0x38)
    size_of_headers = r32(data, opt + 0x3C)
    sec_base = opt + optional_size
    sections: list[Section] = []
    for i in range(num_sections):
        p = sec_base + i * 40
        if p + 40 > len(data):
            raise PatcherError("truncated PE section table")
        name = data[p:p + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
        vsize = r32(data, p + 8)
        vaddr = r32(data, p + 12)
        raw_size = r32(data, p + 16)
        raw_off = r32(data, p + 20)
        if raw_off + raw_size > len(data):
            raise PatcherError(f"section {name} exceeds file size")
        sections.append(Section(name, vaddr, vsize, raw_off, raw_size))
    return PeLayout(image_base, entry_rva, size_of_image, size_of_headers, tuple(sections))


def pe_real_size(data: bytes, off: int) -> int | None:
    try:
        if off + 0x40 > len(data) or data[off:off + 2] != b"MZ":
            return None
        pe = r32(data, off + 0x3C)
        if off + pe + 0x58 > len(data) or data[off + pe:off + pe + 4] != b"PE\0\0":
            return None
        nsec = r16(data, off + pe + 6)
        opt_size = r16(data, off + pe + 20)
        opt = off + pe + 24
        size_of_headers = r32(data, opt + 0x3C)
        max_end = size_of_headers
        sec = opt + opt_size
        for i in range(nsec):
            s = sec + 40 * i
            max_end = max(max_end, r32(data, s + 20) + r32(data, s + 16))
        if max_end <= 0 or off + max_end > len(data):
            return None
        return max_end
    except (IndexError, struct.error):
        return None


def scan_pe_images(data: bytes) -> list[bytes]:
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
    candidates: list[bytes] = []
    seen: set[tuple[int, bytes]] = set()

    def walk(blob: bytes, depth: int) -> None:
        if depth > 5 or len(blob) < 0x40:
            return
        key = (len(blob), hashlib.sha256(blob[: min(len(blob), 4096)]).digest())
        if key in seen:
            return
        seen.add(key)
        candidates.extend(scan_pe_images(blob))
        pos = 0
        while True:
            pos = blob.find(b"\x5d\x00\x00", pos)
            if pos < 0:
                break
            chunk = blob[pos:pos + 0x200000]
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
        raise PatcherError("no embedded PE/COFF image found in ABL")
    return max(candidates, key=len)


def looks_like_pe(data: bytes) -> bool:
    return pe_real_size(data, 0) is not None


def load_linuxloader(path: Path) -> tuple[bytes, bool, str]:
    raw = path.read_bytes()
    input_hash = sha256(raw)
    if looks_like_pe(raw):
        parse_pe(raw)
        return raw, False, input_hash
    loader = extract_linuxloader(raw)
    parse_pe(loader)
    return loader, True, input_hash


def _sign_extend(v: int, bits: int) -> int:
    top = 1 << (bits - 1)
    return v - (1 << bits) if v & top else v


def is_adrp(raw: int) -> bool:
    return (raw & 0x9F000000) == 0x90000000


def is_add_x_imm(raw: int) -> bool:
    return (raw & 0xFF000000) == 0x91000000


def decode_adrp_target_rva(pc_rva: int, raw: int) -> int:
    if not is_adrp(raw):
        raise PatcherError("instruction is not ADRP")
    immlo = (raw >> 29) & 0x3
    immhi = (raw >> 5) & 0x7FFFF
    imm = _sign_extend((immhi << 2) | immlo, 21) << 12
    return (pc_rva & ~0xFFF) + imm


def decode_add_imm(raw: int) -> tuple[int, int, int]:
    if not is_add_x_imm(raw):
        raise PatcherError("instruction is not ADD X,#imm")
    rd = raw & 31
    rn = (raw >> 5) & 31
    imm = (raw >> 10) & 0xFFF
    if (raw >> 22) & 1:
        imm <<= 12
    return rd, rn, imm


def resolve_adrl(data: bytes, layout: PeLayout, off: int) -> tuple[int, int]:
    adrp = r32(data, off)
    add = r32(data, off + 4)
    if not is_adrp(adrp) or not is_add_x_imm(add):
        raise PatcherError("not an ADRP+ADD pair")
    rd = adrp & 31
    add_rd, add_rn, imm = decode_add_imm(add)
    if add_rd != rd or add_rn != rd:
        raise PatcherError("ADRP+ADD register chain mismatch")
    target_rva = decode_adrp_target_rva(layout.offset_to_rva(off), adrp) + imm
    return layout.rva_to_offset(target_rva), rd


def c_string_at(data: bytes, off: int, expected: str) -> bool:
    b = expected.encode("ascii") + b"\0"
    return 0 <= off <= len(data) - len(b) and data[off:off + len(b)] == b


def _is_cmp_w_imm_zero(raw: int) -> tuple[bool, int]:
    ok = (raw & 0x7F00001F) == 0x7100001F and ((raw >> 10) & 0xFFF) == 0
    return ok, (raw >> 5) & 31


def _decode_csel_x(raw: int) -> tuple[bool, int, int, int, int]:
    ok = (raw & 0xFFE00C00) == 0x9A800000
    return ok, raw & 31, (raw >> 5) & 31, (raw >> 16) & 31, (raw >> 12) & 0xF


def find_device_state_candidates(data: bytes) -> list[DeviceStateCandidate]:
    layout = parse_pe(data)
    text = layout.section(".text")
    candidates: list[DeviceStateCandidate] = []
    for off in range(text.raw_off, text.raw_off + text.raw_size - 0x24 + 1, 4):
        try:
            unlocked_off, unlocked_reg = resolve_adrl(data, layout, off)
            locked_off, locked_reg = resolve_adrl(data, layout, off + 8)
            key_off, _ = resolve_adrl(data, layout, off + 16)
        except PatcherError:
            continue
        if not c_string_at(data, unlocked_off, "unlocked"):
            continue
        if not c_string_at(data, locked_off, "locked"):
            continue
        if not c_string_at(data, key_off, "androidboot.vbmeta.device_state"):
            continue
        cmp_off, csel_off = off + 0x1C, off + 0x20
        cmp_ok, state_reg = _is_cmp_w_imm_zero(r32(data, cmp_off))
        csel_ok, value_reg, csel_rn, csel_rm, cond = _decode_csel_x(r32(data, csel_off))
        if not cmp_ok or not csel_ok or cond != 0:
            continue
        if csel_rn != locked_reg or csel_rm != unlocked_reg:
            continue
        candidates.append(DeviceStateCandidate(
            off, off + 4, off + 8, off + 12, off + 16, off + 20,
            cmp_off, csel_off, unlocked_reg, locked_reg, state_reg, value_reg,
            unlocked_off, locked_off, key_off
        ))
    return candidates


def find_verified_state_tables(data: bytes) -> list[VerifiedStateTable]:
    layout = parse_pe(data)
    out: list[VerifiedStateTable] = []
    for sec in layout.sections:
        off = (sec.raw_off + 7) & ~7
        end = sec.raw_off + sec.raw_size
        while off + 64 <= end:
            if r64(data, off) != 0 or r64(data, off + 16) != 1 or r64(data, off + 32) != 2 or r64(data, off + 48) != 3:
                off += 8
                continue
            gp, op, yp, rp = (r64(data, off + x) for x in (8, 24, 40, 56))
            try:
                go, oo, yo, ro = (layout.rva_to_offset(x) for x in (gp, op, yp, rp))
            except PatcherError:
                off += 8
                continue
            if not (c_string_at(data, go, "green") and c_string_at(data, oo, "orange") and
                    c_string_at(data, yo, "yellow") and c_string_at(data, ro, "red")):
                off += 8
                continue
            out.append(VerifiedStateTable(
                off, off + 8, off + 24, off + 40, off + 56,
                gp, op, yp, rp
            ))
            off += 64
    return out


def rewrite_adrl_register(raw: int, rd: int, rn: int | None = None) -> int:
    raw = (raw & ~0x1F) | (rd & 0x1F)
    if rn is not None:
        raw = (raw & ~(0x1F << 5)) | ((rn & 0x1F) << 5)
    return raw


def apply_device_state_patch(buf: bytearray, c: DeviceStateCandidate) -> None:
    locked_adrp = r32(buf, c.locked_adrp)
    locked_add = r32(buf, c.locked_add)
    w32(buf, c.unlocked_adrp, rewrite_adrl_register(locked_adrp, c.unlocked_reg))
    w32(buf, c.unlocked_add, rewrite_adrl_register(locked_add, c.unlocked_reg, c.unlocked_reg))


def apply_verified_state_patch(buf: bytearray, table: VerifiedStateTable) -> None:
    w64(buf, table.orange_pointer_off, table.green_rva)


def load_profiles(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not root.exists():
        return out
    for p in sorted(root.glob("PJZ110_*.json")):
        obj = json.loads(p.read_text(encoding="utf-8"))
        if obj.get("model") == "PJZ110" and obj.get("linuxloader_sha256"):
            out.append(obj)
    return out


def match_profile(loader: bytes, input_hash: str, extracted: bool, profiles: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    lh = sha256(loader)
    for p in profiles:
        if p.get("linuxloader_sha256") != lh:
            continue
        if int(p.get("linuxloader_size", -1)) != len(loader):
            continue
        if extracted and p.get("abl_sha256") and p["abl_sha256"] != input_hash:
            continue
        return p
    return None


def analyze(path: Path, profiles_dir: Path) -> tuple[Analysis, bytes, dict[str, Any] | None]:
    loader, extracted, input_hash = load_linuxloader(path)
    profile = match_profile(loader, input_hash, extracted, load_profiles(profiles_dir))
    dsc = find_device_state_candidates(loader)
    vst = find_verified_state_tables(loader)
    notes: list[str] = []
    if count_all(loader, b"KeyMasterSetRotAndBootState"):
        notes.append("KeyMaster/TEE boot-state code is present and intentionally untouched")
    if profile is None:
        notes.append("unknown image: analysis allowed, patching refused")
    if len(dsc) != 1:
        notes.append(f"device-state semantic candidate count is {len(dsc)}; exactly 1 is required")
    if len(vst) != 1:
        notes.append(f"verified-state table count is {len(vst)}; exactly 1 is required")
    patchable = profile is not None and len(dsc) == 1 and len(vst) == 1
    return Analysis(
        str(path), input_hash, extracted, sha256(loader), len(loader),
        profile.get("id") if profile else None,
        profile.get("build") if profile else None,
        profile is not None,
        [asdict(x) for x in dsc], [asdict(x) for x in vst],
        count_all(loader, b"efisp"), count_all(loader, "efisp".encode("utf-16le")),
        count_all(loader, b"KeyMasterSetRotAndBootState"),
        patchable, notes
    ), loader, profile


def patch_loader(loader: bytes, profile: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    if sha256(loader) != profile["linuxloader_sha256"] or len(loader) != int(profile["linuxloader_size"]):
        raise PatcherError("exact-profile LinuxLoader hash/size check failed")
    dsc = find_device_state_candidates(loader)
    vst = find_verified_state_tables(loader)
    if len(dsc) != 1:
        raise PatcherError(f"refusing to patch: expected 1 device-state candidate, got {len(dsc)}")
    if len(vst) != 1:
        raise PatcherError(f"refusing to patch: expected 1 verified-state table, got {len(vst)}")

    d, t = dsc[0], vst[0]
    out = bytearray(loader)
    before = bytes(out)
    apply_device_state_patch(out, d)
    apply_verified_state_patch(out, t)

    changed = [i for i, (a, b) in enumerate(zip(before, out)) if a != b]
    allowed = set(range(d.unlocked_adrp, d.unlocked_add + 4)) | set(range(t.orange_pointer_off, t.orange_pointer_off + 8))
    unexpected = [x for x in changed if x not in allowed]
    if unexpected:
        raise PatcherError(f"unexpected modified offsets: {[hex(x) for x in unexpected[:16]]}")

    layout = parse_pe(bytes(out))
    a, _ = resolve_adrl(bytes(out), layout, d.unlocked_adrp)
    b, _ = resolve_adrl(bytes(out), layout, d.locked_adrp)
    if not c_string_at(bytes(out), a, "locked") or not c_string_at(bytes(out), b, "locked"):
        raise PatcherError("device-state postcondition failed")
    if r64(out, t.orange_pointer_off) != t.green_rva:
        raise PatcherError("verified-state postcondition failed")
    if r32(out, d.cmp_off) != r32(before, d.cmp_off) or r32(out, d.csel_off) != r32(before, d.csel_off):
        raise PatcherError("CMP/CSEL unexpectedly changed")

    manifest: dict[str, Any] = {
        "schema": 2,
        "profile": profile.get("id"),
        "build": profile.get("build"),
        "input_linuxloader_sha256": sha256(before),
        "output_linuxloader_sha256": sha256(out),
        "image_size": len(out),
        "changed_byte_count": len(changed),
        "changed_offsets": [hex(x) for x in changed],
        "device_state": {**asdict(d), "postcondition": "both CSEL string operands resolve to locked"},
        "verified_state": {**asdict(t), "postcondition": "state 1 (orange) aliases state 0 (green)"},
        "real_deviceinfo_unlock_bit_modified": False,
        "keymaster_tee_root_of_trust_modified": False,
        "gbl_or_chainload_modified": False,
        "device_flashing_performed": False,
        "validation_stage": "offline-complete; requires true-device chainload validation"
    }
    expected_output = profile.get("patched_linuxloader_sha256")
    if expected_output and manifest["output_linuxloader_sha256"] != expected_output:
        raise PatcherError(
            f"patched output hash mismatch: {manifest['output_linuxloader_sha256']} != {expected_output}"
        )
    expected_count = profile.get("changed_byte_count")
    if expected_count is not None and len(changed) != int(expected_count):
        raise PatcherError(f"changed-byte count mismatch: {len(changed)} != {expected_count}")
    return bytes(out), manifest


def print_analysis(a: Analysis) -> None:
    print(f"Input SHA256       : {a.input_sha256}")
    print(f"Extracted from ABL : {'yes' if a.extracted_from_abl else 'no'}")
    print(f"LinuxLoader SHA256 : {a.linuxloader_sha256}")
    print(f"LinuxLoader size   : 0x{a.linuxloader_size:X}")
    print(f"Profile            : {a.profile_id or 'UNKNOWN'}")
    print(f"Build              : {a.build or 'UNKNOWN'}")
    print(f"Device-state paths : {len(a.device_state_candidates)}")
    print(f"Verified tables    : {len(a.verified_state_tables)}")
    print(f"Legacy efisp       : ascii={a.legacy_efisp_ascii_count} utf16={a.legacy_efisp_utf16_count}")
    print(f"KeyMaster marker   : {a.keymaster_marker_count}")
    print(f"Patchable          : {'YES' if a.patchable else 'NO'}")
    for n in a.notes:
        print(f"Note               : {n}")


def prepare_payload(path: Path, out_dir: Path, profiles_dir: Path) -> dict[str, Any]:
    analysis, loader, profile = analyze(path, profiles_dir)
    if not analysis.patchable or profile is None:
        raise PatcherError("fail-closed: input is not an exact patchable PJZ110 profile")
    patched, manifest = patch_loader(loader, profile)
    out_dir.mkdir(parents=True, exist_ok=True)
    original_path = out_dir / "LinuxLoader.original.efi"
    patched_path = out_dir / "LinuxLoader.fake_locked.efi"
    boot_path = out_dir / "boot.efi"
    original_path.write_bytes(loader)
    patched_path.write_bytes(patched)
    boot_path.write_bytes(patched)
    manifest["source_input"] = str(path)
    manifest["artifacts"] = {
        "original": original_path.name,
        "patched": patched_path.name,
        "boot_efi": boot_path.name
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def runtime_check(getprop_text: str, bootconfig_text: str) -> dict[str, Any]:
    props: dict[str, str] = {}
    for line in getprop_text.splitlines():
        if line.startswith("[") and "]: [" in line and line.endswith("]"):
            k, v = line.split("]: [", 1)
            props[k[1:]] = v[:-1]
    bc: dict[str, str] = {}
    for line in bootconfig_text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            bc[k.strip()] = v.strip().strip('"')
    result = {
        "bootconfig_device_state": bc.get("androidboot.vbmeta.device_state"),
        "bootconfig_verified_state": bc.get("androidboot.verifiedbootstate"),
        "getprop_device_state": props.get("ro.boot.vbmeta.device_state"),
        "getprop_verified_state": props.get("ro.boot.verifiedbootstate")
    }
    result["abl_fake_lock_pass"] = (
        result["bootconfig_device_state"] == "locked" and
        result["bootconfig_verified_state"] == "green"
    )
    return result


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profiles", type=Path, default=repo_root / "profiles")
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("analyze")
    p.add_argument("input", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument("--extract", type=Path)

    p = sp.add_parser("patch")
    p.add_argument("input", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--manifest", type=Path)

    p = sp.add_parser("prepare")
    p.add_argument("input", type=Path)
    p.add_argument("output_dir", type=Path)

    p = sp.add_parser("runtime-check")
    p.add_argument("getprop", type=Path)
    p.add_argument("bootconfig", type=Path)
    p.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "analyze":
            analysis, loader, _ = analyze(args.input, args.profiles)
            if args.extract:
                args.extract.write_bytes(loader)
            print(json.dumps(asdict(analysis), indent=2, sort_keys=True) if args.json else "")
            if not args.json:
                print_analysis(analysis)
            return 0 if analysis.patchable else 1

        if args.cmd == "patch":
            analysis, loader, profile = analyze(args.input, args.profiles)
            if not analysis.patchable or profile is None:
                print_analysis(analysis)
                raise PatcherError("fail-closed: image is not an exact patchable PJZ110 profile")
            patched, manifest = patch_loader(loader, profile)
            args.output.write_bytes(patched)
            manifest_path = args.manifest or Path(str(args.output) + ".manifest.json")
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"patched: {args.output}")
            print(f"manifest: {manifest_path}")
            print(f"output SHA256: {manifest['output_linuxloader_sha256']}")
            return 0

        if args.cmd == "prepare":
            manifest = prepare_payload(args.input, args.output_dir, args.profiles)
            print(f"prepared: {args.output_dir}")
            print(f"profile: {manifest['profile']}")
            print(f"output SHA256: {manifest['output_linuxloader_sha256']}")
            print("next stage: true-device chainload validation only")
            return 0

        if args.cmd == "runtime-check":
            result = runtime_check(
                args.getprop.read_text(encoding="utf-8", errors="replace"),
                args.bootconfig.read_text(encoding="utf-8", errors="replace")
            )
            print(json.dumps(result, indent=2, sort_keys=True) if args.json else "\n".join(f"{k}: {v}" for k,v in result.items()))
            return 0 if result["abl_fake_lock_pass"] else 1
    except (OSError, PatcherError, ValueError, struct.error, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
