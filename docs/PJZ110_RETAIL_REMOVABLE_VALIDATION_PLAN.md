# PJZ110 Retail removable EFI validation plan

Target: **PJZ110_16.0.10.501(CN01)**

This plan supersedes the earlier BDS-Menu/ToolsFV-Shell live route.

Offline RE now identifies the surviving stock Retail path as:

~~~text
Vol- / SCAN_DOWN
    -> QcomBds BootFromRemovableMedia
    -> removable FAT filesystem
    -> \EFI\BOOT\BOOTAA64.EFI
    -> DxeCore LoadImage(BootPolicy=TRUE)
    -> SecurityStub Security2
    -> StartImage
~~~

Exact current-binary analysis finds no registered Security2 VerifyImage handler and no active PlatformBdsPreLoadBootOption gate in this path. Hardware enumeration remains the true-device unknown.

## Gate R0 — baseline

Before any removable-media test, require the exact profiled build and real unlocked bootloader. Stock `/proc/bootconfig` must still be `unlocked/orange`.

## Gate R1 — read-only probe only

Use only the project probe first:

~~~text
tools/pjz110_probe/
~~~

Reference deterministic binary:

~~~text
BOOTAA64.EFI
SHA256 17305dd5136bafed35b39ec0b883c66f2f9d7ef78bffafb37fc88b9efb393931
~~~

Place it on a FAT32 removable device at:

~~~text
\EFI\BOOT\BOOTAA64.EFI
~~~

The probe prints three fixed lines through UEFI ConOut, waits five seconds through BootServices.Stall(), then returns EFI_SUCCESS. It performs no partition, disk, file, UEFI-variable, reset, security, or provisioning write.

The future true-device trigger is Vol- / SCAN_DOWN during the UEFI BDS sampling window. No Shell and no keyboard are required by this route.

### R1 pass

Any direct observation that the probe ran, such as the fixed `PJZ110 EFI PROBE: EXECUTION OK` banner remaining visible during the five-second hold, is sufficient to prove external AArch64 EFI execution.

After boot/recovery, also collect `/proc/bootloader_log` and search for:

~~~text
[QcomBds] Removable boot path
USB Media
Removable Media
Booting option
Authentication failed
~~~

### R1 fail categories

- no removable-media enumeration: investigate USB-C host/USB mass-storage enumeration;
- `Authentication failed`: stop and reconcile with the exact offline Security2 result;
- PE/load error: validate the probe/media format;
- unexpected reboot/hang: stop; do not move to LinuxLoader.

## Gate R2 — original LinuxLoader

Only after R1 passes, replace the probe on the removable FAT filesystem with the exact untouched current LinuxLoader, renamed to `BOOTAA64.EFI`.

Required hash before use:

~~~text
4d4aaa42e86917e65c2b2c3fdd477851282a31d5c64f9ca9d20710a650da8b4b
~~~

R2 passes only if Android boots and `/proc/bootconfig` remains:

~~~text
androidboot.vbmeta.device_state = "unlocked"
androidboot.verifiedbootstate   = "orange"
~~~

That proves the removable BDS execution context can run the untouched LinuxLoader.

## Gate R3 — fake-locked LinuxLoader

Only after R2 passes, use the exact fake-locked LinuxLoader as `BOOTAA64.EFI`:

~~~text
34dbedd47b33acf4c131b5db927a5ef7cf9be214facbe6f98fe044dc448b61f0
~~~

Required result:

~~~text
/proc/bootconfig:
androidboot.vbmeta.device_state = "locked"
androidboot.verifiedbootstate   = "green"
~~~

Then independently confirm fastboot still reports the real bootloader unlocked.

## Safety boundary

Throughout R0-R3:

- do not flash ABL, UEFI, ToolsFV, ImageFV, XBL, or XBL_CONFIG;
- do not edit uefivarstore;
- do not relock;
- do not invoke SecurityToggleApp / DebugPolicyToggleApp / RPMB tools;
- removable FAT media is the only payload carrier.

Persistent deployment remains a separate milestone after R3.


## Offline readiness

The current exact firmware path has been taken as far as it can be without another live-device run:

~~~text
physical Volume Down
  -> SCAN_DOWN re-detects after the earlier hotkey reset
  -> QcomBds removable-media path
  -> Pakala USB host/XHCI + USB mass-storage stack present
  -> \EFI\BOOT\BOOTAA64.EFI
  -> DxeCore LoadImage(BootPolicy=TRUE)
  -> SecurityStub Security2
  -> post-EndOfDxe third-party defer check: pass
  -> registered Security2 VerifyImage handlers: 0
  -> PE structural load
  -> StartImage
~~~

Current XBL_CONFIG additionally has `SecurityFlag=0xC4`, which does not contain Qualcomm `SEC_BOOT_ENABLE_FLAG (0x01)`.

The remaining uncertainty is runtime USB-C role negotiation / removable-media enumeration on the real handset. No further partition image is needed for Gate R1.
