# PJZ110 / SM8750 adaptation roadmap

Target: **OnePlus 13 China (PJZ110), SM8750/Pakala, ColorOS PJZ110_16.0.10.501(CN01)**.

## Milestones

- [x] M0 — Freeze current firmware baseline hashes
- [x] M1 — Extract and identify the profiled ARM64 `LinuxLoader.efi`
- [x] M2 — Add fail-closed offline analyzer
- [x] M3 — Implement guarded `androidboot.vbmeta.device_state -> locked` software-visible patch
- [x] M4 — Implement guarded verified-state table `orange -> green` patch
- [x] M5 — Add binary-change allowlist and JSON patch manifest
- [x] M6 — Add unit tests and dedicated GitHub Actions checks
- [x] M7 — Block PJZ110 device-side `abl` / `efisp` writes and legacy ABL downgrade
- [ ] M8 — Rework OPlus unlock-warning suppression for PJZ110
- [ ] M9 — Identify the SM8750 GBL/EFISP loading path
- [x] M10 — Compare early ARB1 PJZ110 16.0.3.501 against 16.0.10.501
- [ ] M11 — Add exact-profile device-side read-only preflight
- [ ] M12 — Validate chainloader without fake-lock modifications
- [ ] M13 — Enable controlled device testing only after GBL/EFISP validation
- [ ] M14 — OTA/profile lifecycle and regression fixtures

## Current hard blocker

The profiled `PJZ110_16.0.10.501(CN01)` LinuxLoader contains neither ASCII nor UTF-16 `efisp`, while the legacy upstream GBL patch depends on that marker.

The next useful firmware input is therefore an early **ARB1** OnePlus 13 China build:

1. `PJZ110_16.0.3.501(CN01)`
2. `PJZ110_16.0.3.502(CN01)`

Priority input: `abl.img`. `xbl.img` and `xbl_config.img` are useful for boot-chain version comparison but are not required for the first ABL diff.

## Safety contract

Until M9–M12 pass:

- no PJZ110 `abl` downgrade;
- no PJZ110 `efisp` write;
- no automatic flashing;
- no modification of Qualcomm `DeviceInfo.is_unlocked`;
- no modification of KeyMaster/TEE RootOfTrust state;
- unknown firmware may be analyzed but must never be patched.

## Known profiled output

For the exact profiled `LinuxLoader.efi`:

- source SHA256: `4d4aaa42e86917e65c2b2c3fdd477851282a31d5c64f9ca9d20710a650da8b4b`
- patched SHA256: `34dbedd47b33acf4c131b5db927a5ef7cf9be214facbe6f98fe044dc448b61f0`
- changed byte count: **7**
