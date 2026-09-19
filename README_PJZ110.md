# PJZ110 / SM8750 development branch

This branch contains the OnePlus 13 China (`PJZ110`) / Snapdragon 8 Elite (`SM8750`, Pakala) adaptation work.

The current milestone provides a tested **offline, fail-closed ABL fake-lock implementation** for three exact PJZ110 firmware profiles, including the current `PJZ110_16.0.10.501(CN01)`. The canonical semantic patcher is `tools/pjz110_fake_lock.py`; the C patcher also contains the PJZ110 semantic path. Device flashing remains disabled while a temporary/non-flashing stock EFI execution path is being validated.

See [`docs/PJZ110_SM8750.md`](docs/PJZ110_SM8750.md) for exact hashes, patch semantics, current limitations, and next research steps.

Development status is tracked in [`docs/PJZ110_ROADMAP.md`](docs/PJZ110_ROADMAP.md).

The exact true-device acceptance contract is documented in [`docs/PJZ110_ABL_FAKE_LOCK_VALIDATION.md`](docs/PJZ110_ABL_FAKE_LOCK_VALIDATION.md).
