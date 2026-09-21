import importlib.util
import hashlib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pjz110_ota_profile_check", ROOT / "tools" / "pjz110_ota_profile_check.py")
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)


class OtaProfileCheckTests(unittest.TestCase):
    def test_schema_accepts_known_profile(self):
        profile = MOD.load_profiles(ROOT / "profiles")[0]
        self.assertEqual(MOD.validate_profile_schema(profile), [])

    def test_unknown_hash_is_rejected(self):
        profiles = MOD.load_profiles(ROOT / "profiles")
        self.assertIsNone(MOD.select_profile("0" * 64, profiles))

    def test_ambiguous_hash_is_rejected(self):
        profiles = MOD.load_profiles(ROOT / "profiles")
        duplicate = dict(profiles[0])
        profiles.append(duplicate)
        self.assertIsNone(MOD.select_profile(profiles[0]["abl_sha256"], profiles))

    def test_invalid_schema_is_fail_closed(self):
        errors = MOD.validate_profile_schema({"model": "PJZ110", "platform": "SM8750"})
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
