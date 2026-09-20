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
- [ ] M12 — True-device validation deferred until a separately reviewed reversible execution carrier is proven
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
- [x] M24 — Close R4-A→R4-D: no stock non-flashing pre-LinuxLoader EFI carrier identified; R4-D CLOSED
- [ ] M25 — Separate deployment design review after stock-route closure; require a reversible A/B rollback plan before any persistent experiment
- [x] M25-A — Close direct patched-ABL path: exact PT_LOAD is SHA384-covered and its v7 hash table is OPLUS ECDSA-P384 signed; stock route CLOSED-BY-PIL-AUTH
- [ ] M25-B — Evaluate post-auth/pre-LinuxLoader substitution or already-authenticated carrier boundaries without modifying signed ABL bytes
- [ ] M25-C — Define A/B recovery and rollback contract for the first surviving deployment candidate

## Current validation boundary

Three real PJZ110 boot-chain baselines have been analyzed:

- `PJZ110_15.0.0.702(CN01)`
- `PJZ110_16.0.3.501(CN01)`
- `PJZ110_16.0.10.501(CN01)`

All three support the guarded offline software-visible fake-lock patch and all
three lack the legacy `efisp` marker. The real partition map also has no
`efisp` partition.

For the exact current build, P0-P4 and R4-A→R4-D are now closed offline:

~~~text
P0 exact baseline             PASS
P1 USB Host auto-start        CLOSED
P2 normal DFP -> XHCI         BLOCKED
P3 late Vol- removable R3     CLOSED
P4 LinuxLoader load context   PASS-IN-PRINCIPLE

R4-A stock RAM/FV/EFI search  PASS-ENUMERATED
R4-B pre-LinuxLoader carriers INTERNAL-ONLY
R4-C external pre-LL source   NONE-FOUND
R4-D stock non-flash carrier  CLOSED

M25-A direct patched ABL       CLOSED-BY-PIL-AUTH
ABL primary PT_LOAD SHA384     VERIFIED
v7 hash-table OEM signature    VERIFIED
~~~

R4 found genuine internal staging machinery, including the UFS PIL ABL
`ELF_FV` flow, the authenticated PIL buffer API, the flashless preloaded ABL
RAM-partition flow, and a 4 MiB `FV_Region` used by debug ToolsFV loading.
None provides a proven external, temporary, pre-LinuxLoader EFI carrier on the
current Retail/UFS configuration.

Fastboot download memory is externally controllable, but it exists inside the
already-running LinuxLoader and the stock `boot` command consumes an Android
boot image through `LoadImageAndAuth -> BootLinux`; it is not a pre-LinuxLoader
UEFI PE chainloader.

Therefore no live EFI execution test is currently justified. The read-only
`BOOTAA64.EFI` probe remains available only if a separately reviewed carrier is
found later.

M25-A has now closed the straightforward direct-ABL candidate. The exact current
LinuxLoader sits inside ABL's SHA384-covered PT_LOAD; the digest is present in the
ELF-v7 hash table, and the hash-table region verifies against the embedded OPLUS
P-384 leaf certificate. Repacking the 7-byte fake-lock payload therefore changes
signed metadata. XBL_CONFIG Unlock=1 is a post-authentication PIL/XPU unlock, not
an Android bootloader-unlock bypass.

M25-B is now the next research stage. It must look only for a post-authentication,
pre-LinuxLoader substitution point or an already-authenticated carrier, while the
same fail-closed safety boundary and future A/B rollback requirement remain in
force.

See:

- `docs/PJZ110_R4_STAGED_MEMORY_EFI_RE.md`
- `profiles/PJZ110_16.0.10.501_r4.json`
- `tools/pjz110_r4_check.py`
- `docs/PJZ110_RETAIL_QCOMBDS_RE.md`
- `docs/PJZ110_M25A_ABL_PIL_AUTH_RE.md`
- `profiles/PJZ110_16.0.10.501_m25a.json`
- `tools/pjz110_m25a_check.py`

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

The earlier BDS/ToolsFV Shell and removable-media live stages are superseded. R4 also closed the analyzed stock staged/memory candidates. Do not resume live EFI execution until a separately reviewed deployment design identifies a proven reversible carrier. The read-only BOOTAA64.EFI probe remains available for that future carrier.

Retail QcomBds reverse-engineering report: `docs/PJZ110_RETAIL_QCOMBDS_RE.md`.
