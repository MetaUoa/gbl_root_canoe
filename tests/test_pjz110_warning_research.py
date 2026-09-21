import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pjz110_warning_research", ROOT / "tools" / "pjz110_warning_research.py")
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)


class WarningResearchTests(unittest.TestCase):
    def test_string_offsets(self):
        self.assertEqual(MOD.string_offsets(b"xxabcxxabc", "abc"), [2, 7])

    def test_cbz_w_decoder(self):
        self.assertTrue(MOD.is_cbz_w(0x34000000))
        self.assertTrue(MOD.is_cbz_w(0x34000125))
        self.assertFalse(MOD.is_cbz_w(0x35000000))
        self.assertFalse(MOD.is_cbz_w(0xB4000000))
        self.assertEqual(MOD.branch_kind(0x34000000), "CBZ.W")
        self.assertEqual(MOD.branch_kind(0x35000000), "CBNZ.W")
        self.assertEqual(MOD.branch_kind(0xB4000000), "CBZ.X")
        self.assertEqual(MOD.branch_kind(0xB5000000), "CBNZ.X")


if __name__ == "__main__":
    unittest.main()
