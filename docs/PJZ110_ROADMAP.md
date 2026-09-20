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
- [x] M9 — Resolve legacy deployment mismatch: PJZ110 has no EFISP; stock Retail routes must be analyzed independently
- [x] M10 — Compare early ARB1 PJZ110 16.0.3.501 against 16.0.10.501
- [x] M11 — Add exact-profile/read-only capture and true ABL-output validation tooling
- [ ] M12 — True-device validation deferred until R4 staged/memory EFI obtains a proven non-flashing carrier
- [ ] M13 — True-device ABL fake-lock validation: bootconfig locked/green while real BL stays unlocked
- [ ] M14 — OTA/profile lifecycle and regression fixtures
- [x] M15 — Analyze ColorOS 15 launch-era PJZ110 15.0.0.702
- [x] M16 — Analyze current imagefv/toolsfv/uefi and identify stock BDS -> ToolsFV -> Shell candidate
- [x] M17 — Reverse exact Retail QcomBds entry paths; generic Shell route demoted, Vol- removable-media route confirmed
- [x] M18 — Close exact Retail Security2/DxeCore policy RE; removable EFI path reaches LoadImage with zero registered Security2 verify handlers
- [x] M19 — Build deterministic read-only AArch64 BOOTAA64.EFI probe for future non-flashing validation
- [x] M20 — Resolve dual hotkey-read timing; held Vol- re-detects after RESET_AFTER_READ
- [x] M21 — Analyze Pakala USB stack; drivers are present but current Retail DFP auto-start is gated off
- [x] M22 — Finalize observable read-only probe with deterministic 5-second banner hold
- [x] M23 — Close P0-P4: USB Host auto-start CLOSED, DFP->XHCI BLOCKED, late removable R3 CLOSED, LinuxLoader PASS-IN-PRINCIPLE
- [ ] M24 — Resolve R4 staged/memory EFI execution before the normal LinuxLoader handoff

## Current validation boundary

Three real PJZ110 boot-chain baselines have been analyzed:

- PJZ110_15.0.0.702(CN01)
- PJZ110_16.0.3.501(CN01)
- PJZ110_16.0.10.501(CN01)

All three support the guarded offline software-visible fake-lock patch and all
three lack the legacy efisp marker. The real partition map also has no efisp
partition.

For the exact current build, P0-P4 are now closed offline:

~~~text
P0 exact baseline             PASS
P1 USB Host auto-start        CLOSED
P2 normal DFP -> XHCI         BLOCKED
P3 late Vol- removable R3     CLOSED
P4 LinuxLoader load context   PASS-IN-PRINCIPLE
~~~

Two independent findings retire the previously proposed Vol-/OTG route:

1. exact UsbConfigDxe has InitUsbControllerOnBoot == 0, so a normal Type-C DFP
   attach does not call UsbStartController and does not create the host-mode
   controller handle required by XhciPciEmulation;
2. DefaultBDSBootApp is LinuxLoader, and the normal non-returning LinuxLoader
   launch happens before the later QcomBdsDetectBootHotKey / SCAN_DOWN path.

Therefore no live Vol- + OTG / BOOTAA64.EFI test should be performed for this
exact build.

LinuxLoader itself remains a normal AArch64 EFI application with no observed
LoadedImage-device-path or ABL-FV self-origin dependency. If a stock
pre-ExitBootServices path can LoadImage/StartImage it, external file origin is
not the identified blocker.

The deployment research target is now:

~~~text
R4:
stock staged/memory EFI execution
    ->
before normal PlatBdsLaunchDefaultApps -> LinuxLoader handoff
    ->
temporary, non-flashing carrier
~~~

See:

- docs/PJZ110_RETAIL_QCOMBDS_RE.md
- profiles/PJZ110_16.0.10.501_retail_path.json
- tools/pjz110_retail_path_check.py

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

The earlier BDS/ToolsFV Shell and removable-media live stages are superseded. Do not resume live EFI execution until R4 identifies a proven non-flashing staged/memory carrier. The read-only BOOTAA64.EFI probe remains available for that future carrier.

Retail QcomBds reverse-engineering report: `docs/PJZ110_RETAIL_QCOMBDS_RE.md`.
