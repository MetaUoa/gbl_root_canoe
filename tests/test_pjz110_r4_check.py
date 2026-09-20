import hashlib
import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "pjz110_r4_check.py"
spec = importlib.util.spec_from_file_location("pjz110_r4_check", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def be32(v):
    return struct.pack(">I", v)


def pad4(b):
    return b + b"\0" * ((-len(b)) & 3)


def build_dtb():
    names = [
        "compatible", "DefaultBDSBootApp", "RetailImages", "AutoStartImages",
        "Version", "Type", "FwName", "PartiGuid", "ImagePath", "SubsysID",
        "Unlock", "MediaType", "mem-label", "reg",
    ]
    strings = b""
    offsets = {}
    for name in names:
        offsets[name] = len(strings)
        strings += name.encode() + b"\0"

    st = bytearray()

    def begin(name):
        nonlocal st
        st += be32(mod.base.FDT_BEGIN_NODE) + pad4(name.encode() + b"\0")

    def end():
        nonlocal st
        st += be32(mod.base.FDT_END_NODE)

    def prop(name, value):
        nonlocal st
        st += be32(mod.base.FDT_PROP)
        st += be32(len(value))
        st += be32(offsets[name])
        st += pad4(value)

    begin("")
    begin("sw")
    begin("uefi")
    prop("compatible", b"qcom,uefi\0")
    begin("int_param")
    end()
    begin("str_param")
    prop("DefaultBDSBootApp", b"LinuxLoader\0")
    end()
    end()
    end()

    begin("soc")
    begin("pil")
    prop("RetailImages", b"ABL\0ImageFv\0")
    prop("AutoStartImages", b"\0")
    begin("pil_images")
    begin("ABL_CFG")
    prop("Version", (5).to_bytes(8, "big"))
    prop("Type", (1).to_bytes(4, "big"))
    prop("FwName", b"ABL\0")
    prop("PartiGuid", bytes.fromhex("bd6928a14ce0a0384f3a1495e3eddffb"))
    prop("ImagePath", b"\0")
    prop("SubsysID", (21).to_bytes(4, "big"))
    prop("Unlock", (1).to_bytes(4, "big"))
    prop("MediaType", b"\0")
    end()
    end()
    end()

    begin("memorymap")
    begin("memory@A7AD9000")
    prop("mem-label", b"FV_Region\0")
    prop("reg", bytes.fromhex("00000000a7ad90000000000000400000"))
    end()
    end()
    end()
    end()
    st += be32(mod.base.FDT_END)

    mem = b"\0" * 16
    off_mem = 40
    off_struct = off_mem + len(mem)
    off_strings = off_struct + len(st)
    total = off_strings + len(strings)
    header = struct.pack(
        ">10I", mod.base.FDT_MAGIC, total, off_struct, off_strings,
        off_mem, 17, 16, 0, len(strings), len(st),
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

    sec = opt + 0xF0
    b[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", b, sec + 8, 0x2000, 0x1000, 0x2000, 0x1000)
    sec += 40
    b[sec:sec + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", b, sec + 8, 0x1000, 0x3000, 0x1000, 0x3000)
    return b


class R4CheckTests(unittest.TestCase):
    def test_verify_strings_fail_closed(self):
        self.assertTrue(mod.verify_strings(
            b"kernel\0uefi\0", ["kernel", "uefi"], ["boot-efi"]
        )["pass"])
        self.assertFalse(mod.verify_strings(
            b"kernel\0boot-efi\0", ["kernel"], ["boot-efi"]
        )["pass"])

    def test_verify_xbl_nested_pil_and_memory(self):
        cfg = {
            "dtb_offset": "0x0",
            "uefi_required": {
                "/sw/uefi/str_param": {"DefaultBDSBootApp": "LinuxLoader"},
            },
            "uefi_absent": {
                "/sw/uefi/int_param": ["LoadAutoImageInPILFlag"],
                "/sw/uefi": ["OEMSetupApp"],
            },
            "pil_path": "/soc/pil",
            "pil_required": {
                "RetailImages_contains": "ABL",
                "AutoStartImages_raw_hex": "00",
            },
            "abl_cfg_path": "/soc/pil/pil_images/ABL_CFG",
            "abl_cfg_required": {
                "Version": 5,
                "Type": 1,
                "FwName_ascii": "ABL",
                "PartiGuid_hex": "bd6928a14ce0a0384f3a1495e3eddffb",
                "ImagePath_ascii": "",
                "SubsysID": 21,
                "Unlock": 1,
                "MediaType_ascii": "",
            },
            "memory_regions": {
                "required": {
                    "/soc/memorymap/memory@A7AD9000": {
                        "mem-label_ascii": "FV_Region",
                        "reg_hex": "00000000a7ad90000000000000400000",
                    }
                },
                "forbidden_mem_labels": ["ABOOT FV", "TestFV_Region"],
            },
        }
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "xbl_config.img"
            p.write_bytes(build_dtb())
            self.assertTrue(mod.verify_xbl(p, {"xbl_config": cfg})["pass"])

    def test_verify_linuxloader_exact_rva_invariants(self):
        b = build_pe()
        struct.pack_into("<I", b, 0x1200, 0x94000000)
        b[0x3300:0x3307] = b"kernel\0"
        b[0x3400:0x3405] = b"uefi\0"
        data = bytes(b)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "LinuxLoader.efi"
            p.write_bytes(data)
            cfg = {
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "machine": 0xAA64,
                "subsystem": 10,
                "entry_rva": 0x1000,
                "required_ascii": ["kernel", "uefi"],
                "forbidden_ascii": ["boot-efi"],
                "exact_u32_rva": {"0x1200": "0x94000000"},
                "string_rva": {"kernel": "0x3300", "uefi": "0x3400"},
            }
            self.assertTrue(mod.verify_linuxloader(p, cfg)["pass"])

    def test_verify_exact_module_by_name_and_hash(self):
        data = b"Overriding PIL cfg by caller\0RetailImages\0"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root / "PILDxe__test.efi"
            p.write_bytes(data)
            profile = {
                "modules": {
                    "PILDxe": {
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                },
                "module_strings": {
                    "PILDxe": {
                        "required_ascii": [
                            "Overriding PIL cfg by caller", "RetailImages"
                        ]
                    }
                },
            }
            self.assertTrue(mod.verify_module(root, "PILDxe", profile)["pass"])


if __name__ == "__main__":
    unittest.main()
