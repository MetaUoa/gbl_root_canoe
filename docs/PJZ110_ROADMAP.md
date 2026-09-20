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
- [x] M9 — Resolve current SM8750 deployment path: legacy EFISP route absent; Retail Vol- removable EFI path replaces it
- [x] M10 — Compare early ARB1 PJZ110 16.0.3.501 against 16.0.10.501
- [x] M11 — Add exact-profile/read-only capture and true ABL-output validation tooling
- [ ] M12 — True-device validate the surviving Vol- -> removable FAT32 -> BOOTAA64.EFI path with the read-only probe
- [ ] M13 — True-device ABL fake-lock validation: bootconfig locked/green while real BL stays unlocked
- [ ] M14 — OTA/profile lifecycle and regression fixtures
- [x] M15 — Analyze ColorOS 15 launch-era PJZ110 15.0.0.702
- [x] M16 — Analyze current imagefv/toolsfv/uefi and identify stock BDS -> ToolsFV -> Shell candidate
- [x] M17 — Reverse exact Retail QcomBds entry paths; generic Shell route demoted, Vol- removable-media route confirmed
- [x] M18 — Close exact Retail Security2/DxeCore policy RE; removable EFI path reaches LoadImage with zero registered Security2 verify handlers
- [x] M19 — Build deterministic read-only AArch64 BOOTAA64.EFI probe for future non-flashing validation
- [x] M20 — Resolve dual hotkey-read timing; held Vol- re-detects after RESET_AFTER_READ
- [x] M21 — Close Pakala USB-host capability offline; XHCI + mass-storage stack present, only physical role negotiation remains
- [x] M22 — Finalize observable read-only probe with deterministic 5-second banner hold

## Current validation boundary

Three real PJZ110 boot-chain baselines have been analyzed:

- `PJZ110_15.0.0.702(CN01)`
- `PJZ110_16.0.3.501(CN01)`
- `PJZ110_16.0.10.501(CN01)`

All three support the offline software-visible fake-lock patch and all three lack the legacy ASCII/UTF-16 `efisp` marker. The real PJZ110 partition map also has no `efisp` partition.

For the current exact build, the legacy deployment question is resolved in practice: the usable stock Retail candidate is the independent removable-media path:

```text
Vol- / SCAN_DOWN
  -> QcomBds BootFromRemovableMedia
  -> removable FAT32
  -> \EFI\BOOT\BOOTAA64.EFI
  -> DxeCore LoadImage
  -> SecurityStub
  -> StartImage
```

Exact offline RE has closed the known software-policy gates: held Vol- survives the earlier input reset, Pakala USB-host/mass-storage drivers are present, the direct QcomBds boot path bypasses the previously suspected PlatformBdsPreLoadBootOption gate, the removable request occurs post-EndOfDxe, and the current SecurityStub has zero registered Security2 VerifyImage handlers.

The remaining uncertainty is a true-device hardware/runtime question only: whether the USB-C connection negotiates DFP/host mode and enumerates the chosen FAT32 device early enough.

No further boot-chain partition dump is currently required for R1.

See:
- `docs/PJZ110_RETAIL_QCOMBDS_RE.md`
- `docs/PJZ110_RETAIL_REMOVABLE_VALIDATION_PLAN.md`

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

## Canonical implementation

The canonical offline implementation is now:

```text
tools/pjz110_fake_lock.py
submodules/patcher/src/patchs/core.c
```

The three older per-build Python patchers are retained only as regression/reference implementations.

Offline ABL fake-lock logic is complete for the three known exact profiles. The current deployment blocker is no longer the fake-lock transformation itself; it is finding a temporary/non-flashing stock PJZ110 EFI execution path for the generated patched LinuxLoader.

Read-only deployment helpers:

```text
tools/pjz110_collect_bootchain.ps1
tools/pjz110_fv_analyze.py
tools/pjz110_capture_validation.ps1
```

Final acceptance is defined in `docs/PJZ110_ABL_FAKE_LOCK_VALIDATION.md`.


## True-device execution plan

The staged live-device procedure is documented in `docs/PJZ110_TRUE_DEVICE_VALIDATION_PLAN.md`.

The earlier BDS/ToolsFV Shell live stages are superseded. When live validation resumes, use `docs/PJZ110_RETAIL_REMOVABLE_VALIDATION_PLAN.md`: first the deterministic read-only `BOOTAA64.EFI` probe, then untouched LinuxLoader, then fake-locked LinuxLoader.

Retail QcomBds reverse-engineering report: `docs/PJZ110_RETAIL_QCOMBDS_RE.md`.
