# PJZ110 bootloader runtime log analysis — 16.0.10.501

Source: real-device `/proc/bootloader_log` captured from the current unlocked PJZ110.

## Runtime platform/security state

The shipping firmware reports:

~~~text
UEFI Ver      : 6.0.260728.BOOT.MXF.2.5.1-00265-PAKALA-1.104700.16
PROD Mode     : TRUE
Retail        : TRUE
~~~

Earlier XBL logging also reports:

~~~text
Secure Boot: On
~~~

This confirms the live device is running the retail/production UEFI path, not merely carrying dormant retail strings.

## Input/menu evidence

The captured normal boot contains:

~~~text
vol_up_pressed:0,vol_down_pressed:0
ButtonsInit: VOL_DOWN(release)
ButtonsInit: CONFIG0/1(release)(release)
ButtonsDxeTest: Keypress SDAM data payload 0
KeyPress:0, BootReason:62
Fastboot=0, Recovery:0
~~~

No BDS-menu, ToolsFV-mount, Shell-launch, or hotkey-trigger event appears in this captured boot.

This does **not** prove the BDS menu is impossible, because no menu-trigger input was present in this run. It does show the captured boot followed the normal mission-mode path.

## UEFI variable-store mode

The runtime log reports:

~~~text
INFO: UEFI NV tables are enabled as VOLATILE!
~~~

Therefore variable-based BDS/OsIndications experiments must not assume ordinary persistent UEFI variable semantics. Read-only inspection should precede any attempt to set a firmware variable.

## Real unlock / Verified Boot state

The bootloader successfully accesses the Verified Boot device state through RPMB:

~~~text
VB: RWDeviceState: Succeed using rpmb!
~~~

Later it records:

~~~text
KeyMasterSetRotAndBootState Set RoT success
KeyMasterSetRotAndBootState Set Boot State success
set_boot_info_to_rpmb: secureboot_state:1 lock_state:0 boot_mode:62 tmp_boot_mode:0
VB2: Authenticate complete! boot state is: orange
VB2: boot state: orange(1)
~~~

For this project, `lock_state:0` and `orange(1)` are the important runtime baseline. They support keeping the real device/RPMB/KeyMaster state untouched while changing only the ABL/LinuxLoader Android-visible output.

## Current boot modification evidence

The log reports:

~~~text
avb_slot_verify.c:504: ERROR: init_boot_b: Hash of data does not match digest in descriptor.
~~~

The boot continues because the real bootloader/device state is unlocked.

This is consistent with the current rooted/unlocked test environment and is not the ABL fake-lock pass criterion.

## OPlus verified-state cmdline path

Late in ABL the device explicitly emits:

~~~text
[AddOplusCmdLineFromVBCmdLineLen]: Adding  oplusboot.verifiedbootstate=orange
~~~

and the final command line contains:

~~~text
oplusboot.verifiedbootstate=orange
~~~

This gives an additional secondary observation for true-device fake-lock validation.

Primary pass criteria remain:

~~~text
/proc/bootconfig:
androidboot.vbmeta.device_state = "locked"
androidboot.verifiedbootstate   = "green"
~~~

Secondary observation after the patched loader executes:

~~~text
/proc/cmdline:
oplusboot.verifiedbootstate=green
~~~

The secondary observation is useful for determining whether the verified-state table patch is shared by the OPlus cmdline generation path, but it is not required until verified on-device.

## Effect on BDS/Shell plan

Because the live device is `PROD Mode=TRUE` and `Retail=TRUE`, repeated brute-force physical-key attempts are no longer the preferred next step.

Next order:

1. read-only inspect Linux-exposed EFI variable interfaces;
2. determine whether `OsIndicationsSupported`, `OsIndications`, or `BDSHotKeyState` are visible;
3. continue static RE of the exact QcomBds/OplusSecurityDxe retail path;
4. only then decide whether a one-shot firmware-UI request is safe and meaningful.

Do not write `uefivarstore` and do not toggle security/debug policy as a shortcut.


## Linux EFI runtime interface result

On the current Android boot:

~~~text
/sys/firmware/efi            absent
/sys/firmware/efi/efivars    absent
efivarfs mount               absent
~~~

Therefore the standard Linux EFI Runtime Services / efivarfs path is not available to request firmware UI through `OsIndications` from Android.

This does not contradict the bootloader's UEFI variable support: the bootloader reports volatile UEFI NV tables, but the Android kernel is not exposing EFI Runtime Services to userspace.

Do not use raw `uefivarstore` partition edits as a substitute.

## Exact current ABL fastboot command surface

Static analysis of the profiled current LinuxLoader exposes these OEM command strings:

~~~text
oem audio-framework
oem device-info
oem disable-charger-screen
oem disable-uart
oem enable-charger-screen
oem enable-initlog
oem enable-uart
oem off-mode-charge
oem select-display-panel
oem set-gpu-preemption
oem set-hw-fence-value
~~~

Observed boot/reboot command strings:

~~~text
boot-fastboot
boot-recovery
reboot-bootloader
reboot-fastboot
reboot-recovery
~~~

No `boot-efi`, `reboot-uefi`, `oem shell`, or equivalent direct staged-EFI command string was found in the exact current LinuxLoader.

Implication: do not blindly invoke guessed fastboot OEM EFI commands. The remaining non-flashing path search should continue through exact QcomBds/OPlus retail-path RE and runtime input evidence.


## Physical volume-key validation

A second real-device boot was captured while Volume Up was held during reboot.

Runtime result:

~~~text
vol_up_pressed:1,vol_down_pressed:0
ButtonsDxeTest: Keypress SDAM data payload 4
KeyPress:0, BootReason:62
Fastboot=0, Recovery:0
~~~

This proves the physical Volume Up input is visible during the PJZ110 UEFI phase. The later LinuxLoader `KeyPress:0` is a different observation point and does not negate the earlier UEFI-level detection.

The corresponding Qualcomm BOOT.MXF.2.5.1 ButtonsLib reference mapping is:

~~~text
Vol+ alone        -> SCAN_UP
Vol- alone        -> SCAN_DOWN
Vol+ + Vol-       -> SCAN_ESC
Vol+ + Power      -> SCAN_HOME
Vol- + Power      -> SCAN_DELETE
~~~

`PlatformBdsDetectHotKey()` specifically tests for `SCAN_HOME`.

Therefore a PJZ110 does not require a USB Home keyboard merely to generate the reference BDS hotkey: the reference button stack maps **Vol+ + Power** to `SCAN_HOME`.

Important limitation: the same reference BDS code only launches the generic BDS menu through the non-retail branch. The real PJZ110 reports `Retail=TRUE`. The physical combo is therefore useful as a final non-writing runtime confirmation of hotkey handling, but a failure to display the menu would be consistent with the already-observed retail gate.

The vendor SDAM payload numeric value is retained as runtime evidence only; do not infer the physical-key bit assignment from that value without matching the exact OPlus SBL implementation.
