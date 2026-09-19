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
