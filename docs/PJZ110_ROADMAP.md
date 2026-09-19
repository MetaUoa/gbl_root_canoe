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
- [x] M15 — Analyze ColorOS 15 launch-era PJZ110 15.0.0.702

## Current hard blocker

Three real PJZ110 boot-chain baselines have now been analyzed:

- `PJZ110_15.0.0.702(CN01)`
- `PJZ110_16.0.3.501(CN01)`
- `PJZ110_16.0.10.501(CN01)`

All three support the offline software-visible fake-lock patch, but **all three lack the legacy ASCII/UTF-16 `efisp` marker** used by the original direct EFISP loader patch.

The ColorOS 15 sample is especially important because its XBL is a genuinely older Pakala generation (`BOOT.MXF.2.5.1-00040.1-PAKALA-1.81269.25`), while the sampled ColorOS 16 builds use `00265`. Crossing this XBL generation boundary still did not reveal the legacy loader marker.

Therefore M9 remains open, but its research question has changed: instead of searching another nearby OTA for the same marker, investigate an alternative PJZ110 chainload/deployment path or determine that PJZ110 never shipped the direct loader used by the original SM8845/SM8850 exploit.

See `docs/PJZ110_THREE_GEN_DIFF.md`.

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
