import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pjz110_profile_matrix", ROOT / "tools" / "pjz110_profile_matrix.py")
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)


class ProfileMatrixTests(unittest.TestCase):
    def test_three_generation_matrix(self):
        report = MOD.build_matrix(ROOT / "profiles")
        self.assertTrue(report["pass"], report["errors"])
        self.assertEqual(report["profile_count"], 3)
        self.assertEqual({row["build"] for row in report["profiles"]}, {
            "PJZ110_15.0.0.702(CN01)",
            "PJZ110_16.0.3.501(CN01)",
            "PJZ110_16.0.10.501(CN01)",
        })

    def test_all_profiles_preserve_seven_byte_contract(self):
        report = MOD.build_matrix(ROOT / "profiles")
        self.assertTrue(all(row["changed_byte_count"] == 7 for row in report["profiles"]))


if __name__ == "__main__":
    unittest.main()
