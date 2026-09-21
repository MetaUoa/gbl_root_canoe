import hashlib
import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "pjz110_fake_lock.py"
spec = importlib.util.spec_from_file_location("pjz110_fake_lock", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def u16(b, o, v): struct.pack_into("<H", b, o, v)
def u32(b, o, v): struct.pack_into("<I", b, o, v)
def u64(b, o, v): struct.pack_into("<Q", b, o, v)


def enc_adrp(pc, target, rd):
    delta = (target & ~0xFFF) - (pc & ~0xFFF)
    pages = delta >> 12
    imm = pages & ((1 << 21) - 1)
    return 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | rd


def enc_add(target, rd):
    return 0x91000000 | ((target & 0xFFF) << 10) | (rd << 5) | rd


def make_pe():
    b = bytearray(0x5000)
    b[0:2] = b"MZ"
    u32(b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\0\0"
    fh = 0x84
    u16(b, fh + 0, 0xAA64)
    u16(b, fh + 2, 2)
    u16(b, fh + 16, 0xF0)
    u16(b, fh + 18, 0x22)
    opt = fh + 20
    u16(b, opt + 0x00, 0x20B)
    u32(b, opt + 0x10, 0x1000)
    u64(b, opt + 0x18, 0)
    u32(b, opt + 0x20, 0x1000)
    u32(b, opt + 0x24, 0x1000)
    u32(b, opt + 0x38, 0x5000)
    u32(b, opt + 0x3C, 0x1000)
    u16(b, opt + 0x44, 10)
    u32(b, opt + 0x6C, 16)
    sec = opt + 0xF0

    b[sec:sec+8] = b".text\0\0\0"
    u32(b, sec + 8, 0x1000); u32(b, sec + 12, 0x1000)
    u32(b, sec + 16, 0x1000); u32(b, sec + 20, 0x1000)
    u32(b, sec + 36, 0x60000020)

    sec2 = sec + 40
    b[sec2:sec2+8] = b".data\0\0\0"
    u32(b, sec2 + 8, 0x2000); u32(b, sec2 + 12, 0x2000)
    u32(b, sec2 + 16, 0x2000); u32(b, sec2 + 20, 0x2000)
    u32(b, sec2 + 36, 0xC0000040)

    unlocked, locked, key = 0x2800, 0x2820, 0x2860
    green, orange, yellow, red = 0x2900, 0x2910, 0x2920, 0x2930
    for off, s in [
        (unlocked, b"unlocked\0"), (locked, b"locked\0"),
        (key, b"androidboot.vbmeta.device_state\0"),
        (green, b"green\0"), (orange, b"orange\0"),
        (yellow, b"yellow\0"), (red, b"red\0")
    ]:
        b[off:off+len(s)] = s

    code = 0x1100
    u32(b, code + 0x00, enc_adrp(code + 0x00, unlocked, 9)); u32(b, code + 0x04, enc_add(unlocked, 9))
    u32(b, code + 0x08, enc_adrp(code + 0x08, locked, 10)); u32(b, code + 0x0C, enc_add(locked, 10))
    u32(b, code + 0x10, enc_adrp(code + 0x10, key, 1)); u32(b, code + 0x14, enc_add(key, 1))
    u32(b, code + 0x18, 0xAA1303E0)
    u32(b, code + 0x1C, 0x7100011F)
    u32(b, code + 0x20, 0x9A890142)

    table = 0x3000
    u64(b, table + 0x00, 0); u64(b, table + 0x08, green)
    u64(b, table + 0x10, 1); u64(b, table + 0x18, orange)
    u64(b, table + 0x20, 2); u64(b, table + 0x28, yellow)
    u64(b, table + 0x30, 3); u64(b, table + 0x38, red)
    marker = b"KeyMasterSetRotAndBootState\0"
    b[0x2A00:0x2A00+len(marker)] = marker
    return bytes(b)


class SemanticTests(unittest.TestCase):
    def test_semantic_locators(self):
        pe = make_pe()
        d = mod.find_device_state_candidates(pe)
        v = mod.find_verified_state_tables(pe)
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0].unlocked_adrp, 0x1100)
        self.assertEqual(d[0].locked_string, 0x2820)
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].base, 0x3000)

    def test_patch_postconditions(self):
        pe = make_pe()
        profile = {
            "id": "synthetic",
            "build": "synthetic",
            "linuxloader_sha256": hashlib.sha256(pe).hexdigest(),
            "linuxloader_size": len(pe)
        }
        out, manifest = mod.patch_loader(pe, profile)
        layout = mod.parse_pe(out)
        d = mod.find_device_state_candidates(pe)[0]
        t = mod.find_verified_state_tables(pe)[0]
        a, _ = mod.resolve_adrl(out, layout, d.unlocked_adrp)
        b, _ = mod.resolve_adrl(out, layout, d.locked_adrp)
        self.assertTrue(mod.c_string_at(out, a, "locked"))
        self.assertTrue(mod.c_string_at(out, b, "locked"))
        self.assertEqual(mod.r64(out, t.orange_pointer_off), t.green_rva)
        self.assertFalse(manifest["real_deviceinfo_unlock_bit_modified"])
        self.assertFalse(manifest["keymaster_tee_root_of_trust_modified"])

    def test_multiple_device_state_candidates_detected(self):
        pe = bytearray(make_pe())
        pe[0x1200:0x1224] = pe[0x1100:0x1124]
        for rel, target, reg in [(0, 0x2800, 9), (8, 0x2820, 10), (16, 0x2860, 1)]:
            u32(pe, 0x1200 + rel, enc_adrp(0x1200 + rel, target, reg))
        self.assertEqual(len(mod.find_device_state_candidates(bytes(pe))), 2)

    def test_runtime_check_requires_bootconfig(self):
        getprop = (
            "[ro.boot.vbmeta.device_state]: [locked]\n"
            "[ro.boot.verifiedbootstate]: [green]\n"
        )
        stock = (
            'androidboot.vbmeta.device_state = "unlocked"\n'
            'androidboot.verifiedbootstate = "orange"\n'
        )
        patched = (
            'androidboot.vbmeta.device_state = "locked"\n'
            'androidboot.verifiedbootstate = "green"\n'
        )
        self.assertFalse(mod.runtime_check(getprop, stock)["abl_fake_lock_pass"])
        self.assertTrue(mod.runtime_check(getprop, patched)["abl_fake_lock_pass"])

    def test_unknown_profile_refuses_patch(self):
        pe = make_pe()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.efi"
            p.write_bytes(pe)
            analysis, _, profile = mod.analyze(p, Path(td) / "missing")
            self.assertFalse(analysis.patchable)
            self.assertIsNone(profile)


if __name__ == "__main__":
    unittest.main()
