# PJZ110 ABL Fake-Lock — True-Device Validation Plan

Target: **OnePlus 13 China (PJZ110), SM8750/Pakala**

Primary build: **PJZ110_16.0.10.501(CN01)**

Purpose: carry the completed offline ABL fake-lock implementation through staged, reversible, non-flashing-first true-device validation.

Do not skip gates. Each stage proves exactly one new fact.

---

## 1. Final target

Keep the real bootloader unlocked while making the ABL/LinuxLoader boot parameters report:

~~~text
real bootloader: UNLOCKED

/proc/bootconfig:
  androidboot.vbmeta.device_state = "locked"
  androidboot.verifiedbootstate   = "green"
~~~

The following userspace-only condition is not a pass:

~~~text
/proc/bootconfig = unlocked / orange
getprop          = locked / green
~~~

The final acceptance source is /proc/bootconfig plus an independent fastboot check that the real bootloader remains unlocked.

---

## 2. Frozen baseline

Current device:

~~~text
Model: PJZ110
SoC: SM8750 / Pakala
Build: PJZ110_16.0.10.501(CN01)
Active slot observed during collection: _b
Real bootloader: unlocked
~~~

Current stock ABL/LinuxLoader baseline:

~~~text
ABL SHA256:
c6aa137b7e2b8c6f86040438022488eee6b2a69a1fad95f109a86c8a77d64bed

Original LinuxLoader SHA256:
4d4aaa42e86917e65c2b2c3fdd477851282a31d5c64f9ca9d20710a650da8b4b

Fake-locked LinuxLoader SHA256:
34dbedd47b33acf4c131b5db927a5ef7cf9be214facbe6f98fe044dc448b61f0

LinuxLoader size:
0xC3000

Changed bytes:
7
~~~

The fake-lock patch changes only the Android-visible state selection:

- unlocked operand -> existing locked string
- verified state orange -> existing green string

It does not modify Qualcomm DeviceInfo.is_unlocked, VBRwDeviceState, KeyMaster / TEE RootOfTrust, XBL / XBL_CONFIG, or partition tables.

---

## 3. Current firmware-volume findings

Read-only dumps from the current device:

| Partition | Size | SHA256 |
| --- | ---: | --- |
| imagefv_b | 2,097,152 | 432903b02644b404d3e19408e003ebea20e0acd416a0d486798d5056fa426451 |
| toolsfv | 1,048,576 | c5da520b05b736875170248d2c80e5060edfb435c1e394acfb5489c5fef12eb7 |
| uefi_b | 5,242,880 | 8d2670cb7790552c035bfa95896d561e7defb2414c8a6d538a3fdca2690879cc |

Current imagefv_b is primarily OPlus battery/charging/thermal bitmap content and is not the primary execution candidate.

Current stock toolsfv contains AArch64 UEFI applications including:

~~~text
Cmd
ListVars
Menu
Pgm
RPMBProvision
RPMBErase
UEFINVErase
DelBootVars
UsbfnMsdApp
SecurityToggleApp
DebugPolicyToggleApp
CapsuleApp
Ebl
Shell
~~~

Current stock uefi_b contains QcomBds, SecurityStubDxe, VerifiedBootDxe, PartitionDxe, Fat, FvSimpleFileSystem, UFSDxe, OplusSecurityDxe, Ebl and related components.

Its stock BDS_Menu.cfg includes:

~~~text
Label = "Enter Shell"
App = Shell
Arg = "-nomap -nostartup"
~~~

Therefore the current best stock execution candidate is:

~~~text
stock signed UEFI
        ->
QcomBds
        ->
BDS Menu
        ->
ToolsFV
        ->
Shell
        ->
external EFI payload
~~~

This path is present in firmware, but retail reachability and external-image policy are not yet proven on the real device.

---

## 4. Global safety contract

Until a stage explicitly changes this rule:

**Do not write any boot-chain partition.**

Do not run:

~~~text
fastboot flash abl ...
fastboot flash uefi ...
fastboot flash toolsfv ...
fastboot flash imagefv ...
fastboot flashing lock
fastboot oem lock
~~~

Do not modify or upload device-unique security partitions such as:

~~~text
persist
modemst1
modemst2
fsg
fsc
frp
keystore
devinfo
oplusreserve1
uefivarstore
~~~

Inside Qualcomm ToolsFV, do not execute these applications during reachability testing:

~~~text
RPMBProvision
RPMBErase
UEFINVErase
DelBootVars
Pgm
SecurityToggleApp
DebugPolicyToggleApp
~~~

They are not required for ABL fake-lock validation.

---

## 5. Required PC-side preparation

Prepare:

- Windows PC with current adb and fastboot
- known-good USB cable
- phone battery >= 60%
- FAT32 USB flash drive + USB-C OTG adapter if available
- current repo branch pjz110-sm8750
- the offline fake-lock payload bundle

Expected payload files:

~~~text
LinuxLoader.original.efi
LinuxLoader.fake_locked.efi
boot.efi
manifest.json
~~~

Verify:

~~~powershell
Get-FileHash .\LinuxLoader.original.efi -Algorithm SHA256
Get-FileHash .\LinuxLoader.fake_locked.efi -Algorithm SHA256
~~~

Expected:

~~~text
LinuxLoader.original.efi
4d4aaa42e86917e65c2b2c3fdd477851282a31d5c64f9ca9d20710a650da8b4b

LinuxLoader.fake_locked.efi
34dbedd47b33acf4c131b5db927a5ef7cf9be214facbe6f98fe044dc448b61f0
~~~

If hashes differ: stop.

---

## 6. Stage T0 — Preflight and evidence capture

Purpose: confirm the phone has not changed since the offline profile was built.

Run:

~~~powershell
adb shell getprop ro.product.model
adb shell getprop ro.build.display.id
adb shell getprop ro.boot.slot_suffix
adb shell cat /proc/bootconfig | Select-String "vbmeta.device_state|verifiedbootstate"
~~~

Expected baseline:

~~~text
PJZ110
PJZ110_16.0.10.501(CN01)
slot: _b   # or explicitly record if it changed

androidboot.vbmeta.device_state = "unlocked"
androidboot.verifiedbootstate   = "orange"
~~~

Capture the complete baseline:

~~~powershell
pwsh -ExecutionPolicy Bypass -File .\tools\pjz110_capture_validation.ps1
~~~

Expected result before ABL-level testing:

~~~text
FAIL
userspace/property spoof only
~~~

That is the correct stock/unpatched baseline for this project.

### T0 gate

Proceed only if:

- model is PJZ110
- build is still PJZ110_16.0.10.501(CN01)
- real bootloader is still unlocked
- stock /proc/bootconfig remains unlocked/orange

If the OTA/build changed, stop and create a new exact profile first.

---

## 7. Stage T1 — Confirm real bootloader state

Reboot:

~~~powershell
adb reboot bootloader
~~~

Read only:

~~~powershell
fastboot getvar unlocked
~~~

If unsupported:

~~~powershell
fastboot oem device-info
~~~

Required condition:

~~~text
real bootloader = unlocked
~~~

Return to Android:

~~~powershell
fastboot reboot
~~~

### T1 gate

If the bootloader is not actually unlocked, stop.

---

## 7.1 Runtime UEFI retail evidence

Current-device `/proc/bootloader_log` confirms the real shipping firmware reports:

~~~text
UEFI Ver     : 6.0.260728.BOOT.MXF.2.5.1-00265-PAKALA-1.104700.16
Retail       : TRUE
OplusSecurityDxeEntryPoint. Status:Success
INFO: UEFI NV tables are enabled as VOLATILE!
~~~

This is runtime evidence from the actual PJZ110, not merely a static string hit.

Implication: the generic Qualcomm BOOT.MXF physical-hotkey path that calls `LaunchBDSMenu()` only under `!RETAIL` should be treated as **low-probability** on this retail device. Do not spend repeated boot cycles brute-forcing key combinations. The next priority is read-only discovery of any OEMSetupApp / OsIndications / staged EFI route that remains reachable in retail mode.

## 8. Stage T2 — Stock BDS menu reachability

Purpose: determine whether the stock retail PJZ110 exposes the already-present QcomBds menu.

No EFI payload is executed in this stage.

### T2-A — passive physical-key test

Qualcomm BOOT.MXF reference code enters the BDS menu on a SCAN_HOME event before platform security is finalized. The exact PJZ110 retail input mapping is not yet proven.

Try only reversible boot-time inputs.

If a USB keyboard is recognized at this stage, test the Home key during early boot.

Do not edit uefivarstore and do not repeatedly change UEFI variables.

Collect photos/video of any:

- Qcom BDS menu
- text console
- Shell/EBL menu
- new boot warning/error

If Android boots normally, record:

~~~text
T2 physical-key route: NOT REACHED
~~~

That is a valid result.

### T2-B — fastboot command-surface observation

Enter fastboot and collect only read-only/help output.

Do not invoke an undocumented OEM action merely because its name appears plausible.

The offline project should first confirm whether the exact current ABL contains a staged EFI command such as a boot-efi family command. Only after that should an exact live command be added to this plan.

### T2 gate

Success:

~~~text
BDS menu or stock ToolsFV Shell/EBL becomes reachable
~~~

Failure:

~~~text
retail gate prevents BDS/Shell reachability
~~~

If T2 fails, stop true-device testing and return to offline RE. Do not compensate by flashing modified UEFI/ToolsFV.

---

## 9. Stage T3 — Enter stock ToolsFV Shell

Only perform T3 after T2 exposes the stock menu.

Choose:

~~~text
Enter Shell
~~~

Expected stock invocation from extracted configuration:

~~~text
Shell -nomap -nostartup
~~~

Inside Shell, run only read-only discovery commands:

~~~text
help
map
map -r
devices
drivers
~~~

Record:

- Shell version/banner
- whether filesystem mappings fs0:, fs1:, etc. appear
- whether a FAT32 USB drive is detected
- whether USB keyboard input works

Do not execute ToolsFV provisioning/security utilities.

### T3 gate

Success:

~~~text
stock Shell is interactive
and
a removable FAT32 filesystem is visible
~~~

If Shell is reachable but no external FAT filesystem is visible, stop and investigate USB/storage enumeration offline. Do not write an internal boot partition as a shortcut.

---

## 10. Stage T4 — External EFI policy probe

Purpose: answer one question:

> Can stock PJZ110 Shell load and start an external AArch64 EFI application?

Do not use the patched LinuxLoader as the first test.

Prepare a minimal pjz110_probe.efi that only:

1. prints a fixed identifier;
2. prints selected EFI environment information;
3. waits for a key;
4. returns to Shell;
5. performs no block writes and no variable writes.

Recommended USB layout:

~~~text
\PJZ110\pjz110_probe.efi
\PJZ110\LinuxLoader.original.efi
\PJZ110\LinuxLoader.fake_locked.efi
~~~

From Shell:

~~~text
map -r
fsN:
cd PJZ110
ls
pjz110_probe.efi
~~~

### T4 result: PASS

Probe prints its banner and returns to Shell.

Meaning:

~~~text
external AArch64 EFI execution is allowed on this unlocked PJZ110 path
~~~

Proceed to T5.

### T4 result: SECURITY BLOCK

Examples:

~~~text
Security Violation
Access Denied
Load Error
authentication failure
~~~

Record the exact status and stop.

Do not run SecurityToggleApp or modify security variables to bypass this result.

### T4 result: FILESYSTEM/USB FAILURE

Shell cannot see the USB device.

Stop and investigate enumeration. Do not copy the test image into an internal boot-chain partition.

---

## 11. Stage T5 — Chainload the untouched original LinuxLoader

Purpose: validate the execution environment before using any fake-lock modification.

Run the exact original profiled loader from removable media:

~~~text
LinuxLoader.original.efi
~~~

### T5-A — Android boots normally

After boot:

~~~powershell
adb shell cat /proc/bootconfig | Select-String "vbmeta.device_state|verifiedbootstate"
~~~

Expected:

~~~text
androidboot.vbmeta.device_state = "unlocked"
androidboot.verifiedbootstate   = "orange"
~~~

This proves:

~~~text
stock UEFI -> Shell -> original LinuxLoader -> Android
~~~

Proceed to T6.

### T5-B — loader returns to Shell

Capture exact status/output and stop for analysis.

### T5-C — reboot/hang

Do not write anything.

Recover with a normal forced reboot/power cycle and record what happened.

A hang here means the Shell execution context is not equivalent to the environment expected by LinuxLoader. Do not proceed to the patched image until understood.

---

## 12. Stage T6 — ABL fake-lock true-device test

Only run after T5 succeeds.

Execute:

~~~text
LinuxLoader.fake_locked.efi
~~~

or the identical prepared alias:

~~~text
boot.efi
~~~

After Android starts, immediately capture:

~~~powershell
adb shell cat /proc/bootconfig > bootconfig-after-fakelock.txt
adb shell cat /proc/cmdline > cmdline-after-fakelock.txt
adb shell getprop > getprop-after-fakelock.txt
~~~

Run project validator:

~~~powershell
pwsh -ExecutionPolicy Bypass -File .\tools\pjz110_capture_validation.ps1
~~~

### Required ABL-level PASS

~~~text
/proc/bootconfig:
androidboot.vbmeta.device_state = "locked"
androidboot.verifiedbootstate   = "green"
~~~

Userspace getprop is secondary evidence only.

---

## 13. Stage T7 — Confirm real bootloader stayed unlocked

After successful T6:

~~~powershell
adb reboot bootloader
fastboot getvar unlocked
~~~

or:

~~~powershell
fastboot oem device-info
~~~

Required:

~~~text
real bootloader = unlocked
~~~

Then:

~~~powershell
fastboot reboot
~~~

### Final core acceptance

Only mark ABL fake-lock core complete when both are true:

~~~text
real bootloader = UNLOCKED

/proc/bootconfig:
device_state = locked
verifiedbootstate = green
~~~

---

## 14. Stage T8 — OPlus unlock-warning follow-up

This is deliberately after the core fake-lock test.

The current 7-byte patch does not claim to suppress every OPlus visual unlock-warning path.

If T6/T7 pass but an unlock warning still appears:

1. capture the exact warning behavior;
2. use the existing OPlus warning string as semantic anchor;
3. implement a separate guarded patch;
4. rerun the original-vs-patched chainload regression.

Do not mix warning suppression into the first ABL-state validation.

---

## 15. Stage T9 — Persistent deployment decision

Persistent installation is not part of the first true-device validation.

Only design it after T4-T7 pass.

Preferred order:

1. reuse a stock staged/non-flashing EFI mechanism if one exists;
2. keep the original signed boot chain intact;
3. preserve A/B rollback;
4. require exact firmware/profile hashes;
5. fail closed after OTA changes.

Do not choose direct ABL/UEFI/ToolsFV flashing merely because temporary chainload works.

Persistent deployment gets a separate design review and rollback plan.

---

## 16. Failure decision tree

~~~text
T2 cannot reach BDS/Shell
    -> STOP
    -> offline RE of retail gating / staged fastboot EFI routes

T3 reaches Shell but USB/FAT absent
    -> STOP
    -> storage/USB enumeration analysis

T4 external probe rejected
    -> STOP
    -> identify Security2 / PE authentication policy
    -> do not toggle security state

T4 probe passes but T5 original LinuxLoader fails
    -> STOP
    -> analyze LinuxLoader execution-context assumptions

T5 original LinuxLoader boots Android
    -> execute T6 patched LinuxLoader

T6 boots but bootconfig still unlocked/orange
    -> fake-lock patch did not execute or wrong loader was invoked
    -> collect hashes and runtime evidence

T6 bootconfig locked/green + T7 real BL unlocked
    -> CORE ABL FAKE-LOCK PASS
~~~

---

## 17. Evidence bundle for every true-device run

Create one folder per attempt:

~~~text
pjz110-run-YYYYMMDD-HHMMSS/
~~~

Keep:

~~~text
notes.txt
phone-screen photos/video
shell-output.txt or photos
bootconfig.txt
cmdline.txt
getprop.txt
fastboot-unlocked.txt
payload-sha256.txt
~~~

Record:

- build number
- active slot
- exact payload filename
- payload SHA256
- exact stage being tested
- result
- recovery action if any

Never rely on memory when comparing repeated boot-chain experiments.

---

## 18. Definition of done

### Core ABL fake-lock

Complete when:

- [ ] stock BDS/EFI execution path is reachable
- [ ] harmless external EFI probe executes
- [ ] untouched original LinuxLoader chainloads successfully
- [ ] fake-locked LinuxLoader chainloads successfully
- [ ] /proc/bootconfig reports locked/green
- [ ] fastboot still reports real bootloader unlocked
- [ ] no boot-chain partition write was required

### Optional visual cleanup

- [ ] OPlus unlock warning suppressed without changing the real unlock bit

### Persistent deployment

Separate milestone; not required to prove ABL fake-lock itself.

---

## 19. Next user action

Do not start with the patched LinuxLoader.

The first live session should perform only:

~~~text
T0 -> T1 -> T2
~~~

The result needed from that session is simply:

> Can this retail PJZ110 reach the stock Qcom BDS / ToolsFV Shell path without flashing anything?

Only after that result should T3/T4 commands and the minimal diagnostic EFI probe be finalized.
