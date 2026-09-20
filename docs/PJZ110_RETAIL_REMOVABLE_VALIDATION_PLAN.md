# PJZ110 Retail removable EFI validation plan — RETIRED

Target: **PJZ110_16.0.10.501(CN01)**

> [!CAUTION]
> **Do not execute the old Vol- + OTG / BOOTAA64.EFI procedure on the basis of this document.**
>
> P0-P4 exact-current-build reverse engineering has closed the stock Retail
> removable route for normal LA boot. This file is retained only to document the
> retired hypothesis and the evidence that invalidated it.

## Why the route was retired

The old hypothesis was:

~~~text
Vol- / SCAN_DOWN
    -> QcomBds BootFromRemovableMedia
    -> USB host / FAT
    -> \EFI\BOOT\BOOTAA64.EFI
    -> LoadImage / StartImage
~~~

Two independent exact-build blockers were found.

### Blocker 1 — USB Host auto-start is disabled

Exact current UsbConfigDxe:

~~~text
SHA256
83a9d176f3fbcf7c0040f78d571ada8baf14c3cb3696c116b46a47d961f38c44

UsbStartController RVA
0x4470

InitUsbControllerOnBoot byte
RVA 0xE456 = 0x00
~~~

The DFP attach call to UsbStartController is at RVA 0x4A60 and is skipped when
that byte is zero.

The exact current QcomBds does not contain the QcomUsbConfig/start/toggle GUIDs
needed to initiate the missing host-controller step itself.

Therefore a normal Type-C DFP attach does not create the host-mode controller
handle required by XhciPciEmulation.

### Blocker 2 — the removable hotkey detector is later than LinuxLoader

Current XBL_CONFIG:

~~~text
/sw/uefi/str_param:
DefaultBDSBootApp = LinuxLoader
~~~

Normal QcomBds ordering:

~~~text
BdsPlatformInit
  -> PlatBdsLaunchDefaultApps
       -> LinuxLoader
       -> normal Android boot does not return
  -> ...
  -> QcomBdsDetectBootHotKey
       -> Vol- / SCAN_DOWN removable request
~~~

Thus the late removable detector is not reached during a normal successful LA
boot.

## Final route status

~~~text
P1 USB Host auto-start : CLOSED
P2 DFP -> XHCI         : BLOCKED
P3 removable R3        : CLOSED
~~~

This supersedes the older PASS-CANDIDATE conclusion.

## What remains valid from the old work

The following results remain useful:

- the QcomBds late SCAN_DOWN/removable code really exists;
- the Pakala UEFI image contains XHCI, USB bus and USB mass-storage drivers;
- Security2 analysis did not identify a registered VerifyImage handler in the
  exact current SecurityStub;
- the deterministic read-only AArch64 BOOTAA64.EFI probe remains a valid future
  first payload if another stock temporary EFI carrier is found.

Probe reference:

~~~text
SHA256 17305dd5136bafed35b39ec0b883c66f2f9d7ef78bffafb37fc88b9efb393931
size   2048
~~~

## Current next route

Do not perform a live removable-media test.

Continue offline with:

~~~text
R4 — stock staged / memory EFI execution
     before the normal LinuxLoader handoff
~~~

The objective is a temporary, reversible, non-flashing path that can present an
EFI image to LoadImage/StartImage without modifying ABL, UEFI, ToolsFV,
XBL_CONFIG, uefivarstore, DeviceInfo, RPMB, KeyMaster or TEE state.

See:

- docs/PJZ110_RETAIL_QCOMBDS_RE.md
- docs/PJZ110_ROADMAP.md
- tools/pjz110_retail_path_check.py
- profiles/PJZ110_16.0.10.501_retail_path.json
