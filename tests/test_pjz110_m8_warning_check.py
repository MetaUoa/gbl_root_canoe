import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pjz110_m8_warning_check", ROOT / "tools" / "pjz110_m8_warning_check.py")
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)


class M8WarningCheckTests(unittest.TestCase):
    def test_exact_report_shape(self):
        profile = {
            "linuxloader": {"sha256": "a"},
            "resources": {"orange_title": [1]},
            "reference": {
                "adrl_offset": 2, "function_start": 3, "function_end": 4,
                "call_xrefs": [5], "legacy_nearby_cbz_w": [],
                "state_dispatch": {},
                "local_gate": {"offset": 6, "kind": "B.cond", "condition": "LS",
                               "target": 4, "raw": "0x1"}},
            "fake_lock_changed_offsets": ["0x7"],
            "expected": {"warning_control_overlap": []}}
        report = {
            "input_linuxloader_sha256": "a", "resources": {"orange_title": [1]},
            "warning_references": [{
                "adrl_offset": 2, "function_start": 3, "function_end": 4,
                "call_xrefs": [5], "nearby_cbz_w": [],
                "state_dispatch": {},
                "conditional_branches": [{"offset": 6, "kind": "B.cond",
                                           "condition": "LS", "target": 4,
                                           "raw": "0x1"}]}],
            "fake_lock_changed_offsets": ["0x7"], "warning_control_overlap": []}
        self.assertEqual(MOD.compare_report(report, profile), [])

    def test_ambiguous_reference_fails(self):
        profile = {"linuxloader": {"sha256": "a"}, "resources": {},
                   "reference": {}, "fake_lock_changed_offsets": [],
                   "expected": {"warning_control_overlap": []}}
        report = {"input_linuxloader_sha256": "a", "resources": {},
                  "warning_references": [], "fake_lock_changed_offsets": [],
                  "warning_control_overlap": []}
        self.assertTrue(MOD.compare_report(report, profile))


if __name__ == "__main__":
    unittest.main()
