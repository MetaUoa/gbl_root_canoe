import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "pjz110_fv_analyze.py"
spec = importlib.util.spec_from_file_location("pjz110_fv_analyze", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def u16(b, o, v):
    struct.pack_into("<H", b, o, v)


def u24(b, o, v):
    b[o:o+3] = bytes((v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff))


def u32(b, o, v):
    struct.pack_into("<I", b, o, v)


def u64(b, o, v):
    struct.pack_into("<Q", b, o, v)


def make_pe():
    b = bytearray(0x100)
    b[:2] = b"MZ"
    u32(b, 0x3C, 0x40)
    b[0x40:0x44] = b"PE\0\0"
    u16(b, 0x44, 0xAA64)
    u16(b, 0x46, 0)
    u16(b, 0x54, 0xF0)
    u16(b, 0x58, 0x20B)
    u16(b, 0x58 + 0x44, 10)
    return bytes(b)


def section(stype, payload):
    size = 4 + len(payload)
    out = bytearray(mod.align(size, 4))
    u24(out, 0, size)
    out[3] = stype
    out[4:4+len(payload)] = payload
    return bytes(out)


def make_fv():
    ui = section(0x15, "TestApp\0".encode("utf-16le"))
    pe = section(0x10, make_pe())
    payload = ui + pe
    fsize = 24 + len(payload)
    ffile = bytearray(mod.align(fsize, 8))
    ffile[:16] = bytes.fromhex("00112233445566778899aabbccddeeff")
    ffile[18] = 0x09
    ffile[19] = 0
    u24(ffile, 20, fsize)
    ffile[23] = 0x07
    ffile[24:24+len(payload)] = payload

    b = bytearray(0x1000)
    b[16:32] = bytes.fromhex("78563412bc9af0de1122334455667788")
    u64(b, 0x20, len(b))
    b[0x28:0x2C] = b"_FVH"
    u32(b, 0x2C, 0)
    u16(b, 0x30, 0x48)
    u16(b, 0x32, 0)
    u16(b, 0x34, 0)
    b[0x37] = 2
    u32(b, 0x38, 1)
    u32(b, 0x3C, len(b))
    u32(b, 0x40, 0)
    u32(b, 0x44, 0)
    b[0x48:0x48+len(ffile)] = ffile
    return bytes(b)


class FvAnalyzerTests(unittest.TestCase):
    def test_fv_and_efi_application(self):
        image = make_fv()
        fvs = mod.find_fvs(image)
        self.assertEqual(len(fvs), 1)
        self.assertEqual(len(fvs[0].files), 1)
        f = fvs[0].files[0]
        self.assertEqual(f.file_type_name, "application")
        names = [x.ui_name for x in f.sections if x.ui_name]
        self.assertEqual(names, ["TestApp"])
        pes = [x for x in f.sections if x.section_type == 0x10]
        self.assertEqual(len(pes), 1)
        self.assertEqual(pes[0].pe_machine, "AARCH64")
        self.assertEqual(pes[0].pe_subsystem, 10)

    def test_report_does_not_claim_unsigned_chainload(self):
        image = make_fv()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "imagefv.img"
            p.write_bytes(image)
            report = mod.analyze(p)
            self.assertTrue(report["interpretation"]["contains_firmware_volume"])
            self.assertTrue(report["interpretation"]["contains_efi_pe_payloads"])
            self.assertFalse(report["interpretation"]["unsigned_chainload_proven"])


if __name__ == "__main__":
    unittest.main()
