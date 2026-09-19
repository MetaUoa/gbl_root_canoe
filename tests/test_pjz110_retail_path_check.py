import hashlib
import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "pjz110_retail_path_check.py"
spec = importlib.util.spec_from_file_location("pjz110_retail_path_check", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def be32(v):
    return struct.pack(">I", v)


def pad4(b):
    return b + b"\0" * ((-len(b)) & 3)


def build_dtb():
    names = [
        "EnableShell",
        "AllowNonPersistentVarsInRetail",
        "DefaultBDSBootApp",
    ]
    strings = b""
    offsets = {}
    for n in names:
        offsets[n] = len(strings)
        strings += n.encode() + b"\0"

    st = bytearray()
    st += be32(mod.FDT_BEGIN_NODE) + pad4(b"\0")
    st += be32(mod.FDT_BEGIN_NODE) + pad4(b"sw\0")
    st += be32(mod.FDT_BEGIN_NODE) + pad4(b"uefi\0")

    def prop(name, value):
        nonlocal st
        st += be32(mod.FDT_PROP)
        st += be32(len(value))
        st += be32(offsets[name])
        st += pad4(value)

    prop("EnableShell", (1).to_bytes(8, "big"))
    prop("AllowNonPersistentVarsInRetail", (1).to_bytes(8, "big"))
    prop("DefaultBDSBootApp", b"LinuxLoader\0")
    st += be32(mod.FDT_END_NODE)
    st += be32(mod.FDT_END_NODE)
    st += be32(mod.FDT_END_NODE)
    st += be32(mod.FDT_END)

    off_mem = 40
    mem = b"\0" * 16
    off_struct = off_mem + len(mem)
    off_strings = off_struct + len(st)
    total = off_strings + len(strings)
    header = struct.pack(
        ">10I",
        mod.FDT_MAGIC,
        total,
        off_struct,
        off_strings,
        off_mem,
        17,
        16,
        0,
        len(strings),
        len(st),
    )
    return header + mem + bytes(st) + strings


def build_pe():
    b = bytearray(0x200)
    b[:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", b, 0x84, 0xAA64)
    struct.pack_into("<H", b, 0x94, 0xF0)
    opt = 0x98
    struct.pack_into("<H", b, opt, 0x20B)
    struct.pack_into("<I", b, opt + 0x10, 0x1000)
    struct.pack_into("<H", b, opt + 0x44, 10)
    struct.pack_into("<I", b, opt + 0x6C, 16)
    struct.pack_into("<II", b, opt + 0x70 + 5 * 8, 0x3000, 12)
    return bytes(b)


class RetailPathCheckTests(unittest.TestCase):
    def test_parse_profile_fdt(self):
        blob = b"prefix" + build_dtb() + b"suffix"
        off, props = mod.find_profile_dtb(blob, -1)
        self.assertEqual(off, len(b"prefix"))
        uefi = props["/sw/uefi"]
        self.assertEqual(mod.decode_fdt_value(uefi["EnableShell"]), 1)
        self.assertEqual(mod.decode_fdt_value(uefi["AllowNonPersistentVarsInRetail"]), 1)
        self.assertEqual(mod.decode_fdt_value(uefi["DefaultBDSBootApp"]), "LinuxLoader")

    def test_parse_probe_pe(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "BOOTAA64.EFI"
            p.write_bytes(build_pe())
            info = mod.parse_pe(p)
            self.assertEqual(info["machine"], 0xAA64)
            self.assertEqual(info["subsystem"], 10)
            self.assertEqual(info["entry_rva"], 0x1000)
            self.assertEqual(info["reloc_rva"], 0x3000)
            self.assertEqual(info["reloc_size"], 12)

    def test_exact_artifact_check(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.bin"
            p.write_bytes(b"PJZ110")
            spec = {
                "size": 6,
                "sha256": hashlib.sha256(b"PJZ110").hexdigest(),
            }
            self.assertTrue(mod.verify_artifact("x", p, spec)["pass"])
            spec["size"] = 7
            self.assertFalse(mod.verify_artifact("x", p, spec)["pass"])


if __name__ == "__main__":
    unittest.main()
