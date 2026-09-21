import importlib.util
import struct
import sys
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "pjz110_m25a_check.py"
spec = importlib.util.spec_from_file_location("pjz110_m25a_check", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class M25ACheckTests(unittest.TestCase):
    def test_der_total_len_short_and_long(self):
        self.assertEqual(mod.der_total_len(bytes.fromhex("3003010203"), 0), 5)
        self.assertEqual(mod.der_total_len(bytes.fromhex("308103010203"), 0), 6)

    def test_parse_elf32(self):
        blob = bytearray(0x100)
        blob[:4] = b"\x7fELF"
        blob[4] = 1
        blob[5] = 1
        blob[6] = 1
        struct.pack_into(
            "<HHIIIIIHHHHHH",
            blob,
            16,
            2,
            40,
            1,
            0x9FA00000,
            0x34,
            0,
            0,
            52,
            32,
            1,
            0,
            0,
            0,
        )
        struct.pack_into(
            "<IIIIIIII",
            blob,
            0x34,
            1,
            0x1000,
            0x9FA00000,
            0x9FA00000,
            0x42000,
            0x42000,
            7,
            0x1000,
        )
        elf = mod.parse_elf32(bytes(blob))
        self.assertEqual(elf["machine"], 40)
        self.assertEqual(elf["entry"], 0x9FA00000)
        self.assertEqual(elf["phdrs"][0]["filesz"], 0x42000)

    def test_decode_fdt_value(self):
        self.assertEqual(mod.decode_fdt_value(b"ABL\0", "ABL"), "ABL")
        self.assertEqual(mod.decode_fdt_value((21).to_bytes(4, "big"), 21), 21)

    def test_as_int(self):
        self.assertEqual(mod.as_int("0x43000"), 0x43000)
        self.assertEqual(mod.as_int(21), 21)


if __name__ == "__main__":
    unittest.main()
