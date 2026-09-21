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
        "status",
        "usb_mode",
    ]
    strings = b""
    offsets = {}
    for n in names:
        offsets[n] = len(strings)
        strings += n.encode() + b"\0"

    st = bytearray()

    def begin(name):
        nonlocal st
        st += be32(mod.FDT_BEGIN_NODE) + pad4(name.encode() + b"\0")

    def end():
        nonlocal st
        st += be32(mod.FDT_END_NODE)

    def prop(name, value):
        nonlocal st
        st += be32(mod.FDT_PROP)
        st += be32(len(value))
        st += be32(offsets[name])
        st += pad4(value)

    begin("")
    begin("sw")
    begin("uefi")
    begin("int_param")
    prop("EnableShell", (1).to_bytes(8, "big"))
    prop("AllowNonPersistentVarsInRetail", (1).to_bytes(8, "big"))
    end()
    begin("str_param")
    prop("DefaultBDSBootApp", b"LinuxLoader\0")
    end()
    end()
    end()

    begin("soc")
    begin("usb0")
    begin("usb_overwrite_cfg")
    prop("status", b"disabled\0")
    prop("usb_mode", (3).to_bytes(4, "big"))
    end()
    end()
    end()
    end()
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


def build_pe(size=0x5000):
    b = bytearray(size)
    b[:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", b, 0x84, 0xAA64)
    struct.pack_into("<H", b, 0x86, 2)
    struct.pack_into("<H", b, 0x94, 0xF0)
    opt = 0x98
    struct.pack_into("<H", b, opt, 0x20B)
    struct.pack_into("<I", b, opt + 0x10, 0x1000)
    struct.pack_into("<H", b, opt + 0x44, 10)
    struct.pack_into("<I", b, opt + 0x6C, 16)
    struct.pack_into("<II", b, opt + 0x70 + 5 * 8, 0x3000, 12)

    sec = opt + 0xF0
    b[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", b, sec + 8, 0x2000, 0x1000, 0x2000, 0x1000)
    sec += 40
    b[sec:sec + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", b, sec + 8, 0x1000, 0x3000, 0x1000, 0x3000)
    return b


def enc_bl(pc, target):
    delta = target - pc
    assert delta % 4 == 0
    imm = (delta // 4) & 0x03FFFFFF
    return 0x94000000 | imm


class RetailPathCheckTests(unittest.TestCase):
    def test_parse_profile_fdt_nested_paths(self):
        blob = b"prefix" + build_dtb() + b"suffix"
        off, props = mod.find_profile_dtb(blob, -1)
        self.assertEqual(off, len(b"prefix"))
        self.assertEqual(mod.decode_fdt_value(props["/sw/uefi/int_param"]["EnableShell"]), 1)
        self.assertEqual(
            mod.decode_fdt_value(props["/sw/uefi/str_param"]["DefaultBDSBootApp"]),
            "LinuxLoader",
        )
        self.assertEqual(
            mod.decode_fdt_value(props["/soc/usb0/usb_overwrite_cfg"]["status"]),
            "disabled",
        )
        self.assertEqual(
            mod.decode_fdt_value(props["/soc/usb0/usb_overwrite_cfg"]["usb_mode"]),
            3,
        )

    def test_parse_pe_and_rva_mapping(self):
        b = build_pe()
        pe = mod.parse_pe_bytes(bytes(b))
        self.assertEqual(pe["machine"], 0xAA64)
        self.assertEqual(pe["subsystem"], 10)
        self.assertEqual(pe["entry_rva"], 0x1000)
        self.assertEqual(pe["imports_rva"], 0)
        self.assertEqual(mod.pe_rva_to_offset(pe, 0x1234), 0x1234)

    def test_bl_target_scan(self):
        b = build_pe()
        pe = mod.parse_pe_bytes(bytes(b))
        for site in (0x1100, 0x1200, 0x1300):
            struct.pack_into("<I", b, mod.pe_rva_to_offset(pe, site), enc_bl(site, 0x1800))
        pe = mod.parse_pe_bytes(bytes(b))
        self.assertEqual(
            mod.bl_callsites_to(bytes(b), pe, 0x1800),
            [0x1100, 0x1200, 0x1300],
        )

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

    def test_linuxloader_dependency_absence(self):
        b = bytes(build_pe())
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "LinuxLoader.efi"
            p.write_bytes(b)
            profile = {
                "p4_linuxloader": {
                    "sha256": hashlib.sha256(b).hexdigest(),
                    "size": len(b),
                    "machine": 0xAA64,
                    "subsystem": 10,
                    "entry_rva": 0x1000,
                    "imports_rva": 0,
                    "imports_size": 0,
                    "forbidden_guids": {
                        "synthetic": "00112233445566778899aabbccddeeff"
                    },
                    "forbidden_strings": ["LoadedImage", "LoadOptions"],
                    "expected_status": "PASS-IN-PRINCIPLE",
                }
            }
            result = mod.verify_p4(p, profile)
            self.assertTrue(result["pass"])
            self.assertEqual(result["status"], "PASS-IN-PRINCIPLE")


if __name__ == "__main__":
    unittest.main()
