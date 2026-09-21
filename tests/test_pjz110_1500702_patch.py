import importlib.util
import struct
import sys
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "pjz110_1500702_patch.py"
spec = importlib.util.spec_from_file_location("pjz110_1500702_patch", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def fixture():
    b = bytearray(mod.LINUXLOADER_SIZE)
    for off, word in mod.EXPECTED_DEVICE_WORDS.items():
        struct.pack_into("<I", b, off, word)
    struct.pack_into("<Q", b, mod.VERIFIED_GREEN_PTR, mod.GREEN_STRING)
    struct.pack_into("<Q", b, mod.VERIFIED_ORANGE_PTR, mod.ORANGE_STRING)
    return b


class Pjz110PatchTests(unittest.TestCase):
    def test_device_state_transform(self):
        b = fixture()
        mod.apply_device_state_patch(b)
        locked_adrp = mod.EXPECTED_DEVICE_WORDS[mod.DEVICE_STATE_LOCK_ADRP]
        locked_add = mod.EXPECTED_DEVICE_WORDS[mod.DEVICE_STATE_LOCK_ADD]
        self.assertEqual(
            mod.r32(b, mod.DEVICE_STATE_UNL_ADRP), mod.rewrite_reg(locked_adrp, 9)
        )
        self.assertEqual(
            mod.r32(b, mod.DEVICE_STATE_UNL_ADD), mod.rewrite_reg(locked_add, 9, 9)
        )

    def test_verified_state_transform(self):
        b = fixture()
        mod.apply_verified_state_patch(b)
        self.assertEqual(mod.r64(b, mod.VERIFIED_ORANGE_PTR), mod.GREEN_STRING)

    def test_signature_fail_closed(self):
        b = fixture()
        b[mod.DEVICE_STATE_CSEL] ^= 1
        with self.assertRaises(ValueError):
            mod.apply_device_state_patch(b)

    def test_full_patch_rejects_synthetic_fixture(self):
        with self.assertRaisesRegex(ValueError, "SHA256/size"):
            mod.patch_loader(bytes(fixture()))


if __name__ == "__main__":
    unittest.main()
