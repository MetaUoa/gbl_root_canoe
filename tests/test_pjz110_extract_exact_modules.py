import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pjz110_extract_exact_modules", ROOT / "tools" / "pjz110_extract_exact_modules.py")
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)


class ExtractExactModulesTests(unittest.TestCase):
    def test_exact_slice(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "fv.dec").write_bytes(b"prefix" + b"module" + b"tail")
            profile = {"modules": {"Test": {
                "source": "fv.dec", "offset": "0x6", "size": 6,
                "file": "Test.efi", "sha256": MOD.sha256(b"module")}}}
            result = MOD.extract_modules(profile, root)
            self.assertEqual(result["Test.efi"], b"module")

    def test_hash_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "fv.dec").write_bytes(b"module")
            profile = {"modules": {"Test": {
                "source": "fv.dec", "offset": "0", "size": 6,
                "file": "Test.efi", "sha256": "0" * 64}}}
            with self.assertRaises(MOD.ExtractError):
                MOD.extract_modules(profile, root)


if __name__ == "__main__":
    unittest.main()
