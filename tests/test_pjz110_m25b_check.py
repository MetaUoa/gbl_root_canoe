import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pjz110_m25b_check", ROOT / "tools" / "pjz110_m25b_check.py")
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)


class M25BCheckTests(unittest.TestCase):
    def test_partition_payload_and_zero_padding(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "part.img"
            path.write_bytes(b"payload" + b"\0" * 4)
            expected = {"size": 11, "sha256": MOD.sha256(path.read_bytes()),
                        "payload_size": 7, "payload_sha256": MOD.sha256(b"payload")}
            self.assertTrue(MOD.check_partition(path, expected)["pass"])

    def test_nonzero_padding_fails(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "part.img"
            path.write_bytes(b"payload" + b"\0\x01")
            expected = {"size": 9, "sha256": MOD.sha256(path.read_bytes()),
                        "payload_size": 7, "payload_sha256": MOD.sha256(b"payload")}
            self.assertFalse(MOD.check_partition(path, expected)["pass"])

    def test_candidate_boundaries_are_fail_closed(self):
        profile = json.loads((ROOT / "profiles" / "PJZ110_16.0.10.501_m25b.json").read_text())
        self.assertEqual(profile["candidate_boundaries"]["direct_patched_abl"], "CLOSED-BY-PIL-AUTH")
        self.assertEqual(profile["candidate_boundaries"]["post_auth_pre_linuxloader_substitution"], "CLOSED-NO-STOCK-EXTERNAL-PRODUCER")
        self.assertFalse(profile["expected"]["live_execution"])


if __name__ == "__main__":
    unittest.main()
