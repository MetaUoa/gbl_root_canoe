import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class M8WarningMatrixTests(unittest.TestCase):
    def test_three_exact_generations_have_same_boundary_shape(self):
        matrix = json.loads((ROOT / "profiles" / "PJZ110_M8_WARNING_MATRIX.json").read_text())
        self.assertEqual(len(matrix["profiles"]), 3)
        self.assertTrue(all(p["local_gate"]["raw"] == "0x54000509" for p in matrix["profiles"]))
        self.assertTrue(all(p["local_gate"]["condition"] == "LS" for p in matrix["profiles"]))
        self.assertTrue(all(len(p["fake_lock_changed_offsets"]) == 7 for p in matrix["profiles"]))
        self.assertTrue(all(p["state_dispatch"]["warning_case_index"] == 1 for p in matrix["profiles"]))
        self.assertTrue(all(p["state_dispatch"]["source_target"] > 0 for p in matrix["profiles"]))
        self.assertEqual(matrix["expected"]["state_predicate"], "QCOM_VERIFIEDBOOT_PROTOCOL.VBIsDeviceSecure-POLARITY-UNRESOLVED")
        self.assertFalse(matrix["expected"]["warning_patch_authorized"])
        self.assertEqual(matrix["expected"]["M8"], "CLOSED-NO-SAFE-UI-ONLY-PATCH")
        self.assertTrue(all(p["protocol_evidence"]["vtable_method_offsets"] == [56]
                            for p in matrix["profiles"]))


if __name__ == "__main__":
    unittest.main()
