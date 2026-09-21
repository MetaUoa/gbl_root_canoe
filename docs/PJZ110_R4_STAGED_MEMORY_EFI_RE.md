# PJZ110 R4 — staged / memory EFI reverse engineering

Target: **OnePlus 13 China PJZ110 / SM8750 (Pakala)**  
Build: **PJZ110_16.0.10.501(CN01)**

This report closes the offline R4-A -> R4-D search for a stock temporary,
non-flashing EFI carrier that could execute before the normal LinuxLoader
handoff.

The goal remains narrowly scoped:

```text
real bootloader = UNLOCKED
    +
run the profiled LinuxLoader through a temporary stock path
    +
validate the 7-byte ABL-visible fake-lock transformation
```

No DeviceInfo/VBRwDeviceState/RPMB/KeyMaster/TEE state change is part of R4.

## 1. Final R4 result

```text
R4-A  stock RAM/FV/EFI mechanisms         PASS-ENUMERATED
R4-B  mechanisms usable before LinuxLoader INTERNAL-ONLY
R4-C  external controllable pre-LL source  NONE-FOUND
R4-D  stock non-flashing EFI carrier       CLOSED
```

`CLOSED` means **no stock non-flashing carrier is identified/proven in the
exact current build under the mechanisms analyzed here**. It is not a claim
that no unknown vulnerability or undocumented mechanism can exist.

No live EFI execution test is justified by R4.

## 2. Exact-current inputs

```text
ABL
c6aa137b7e2b8c6f86040438022488eee6b2a69a1fad95f109a86c8a77d64bed

UEFI
8d2670cb7790552c035bfa95896d561e7defb2414c8a6d538a3fdca2690879cc

XBL_CONFIG
9760062003776a481495286d6c0233bda307100ac2e95cb7b23fcb5aa17bf64d

LinuxLoader
4d4aaa42e86917e65c2b2c3fdd477851282a31d5c64f9ca9d20710a650da8b4b
```

Exact modules recursively extracted from the current `uefi_b`:

```text
QcomBds
426004d0eba512a0c33baf9f79e1c6ad723691e03a117f540dca79905dce1038
size 0x1A000

PILDxe
57459a87bf34e9979fc66a8ecb09180f409170a8cef69be8347f14d7b4c654ab
size 0x1C000

QcomChargerApp
ce3f13c278346a91b85dbd55e1ea1c6835ee3a905a43755b2150768d8459e468
size 0x18000
```

Runtime evidence from the supplied real-device log confirms:

```text
Boot Device   : UFS
PROD Mode     : TRUE
Retail        : TRUE
```

Therefore flashless-only branches are not treated as active paths on the
current handset.

# 3. R4-A — enumerate stock RAM/FV/EFI mechanisms

The search identified five relevant mechanism classes.

## A1. Normal guided-FV application launch

The matched Qualcomm BDS semantics are:

```text
LaunchAppFromGuidedFv
    -> resolve file inside an already-mounted FV
    -> LoadImage(... FilePath ..., SourceBuffer=NULL)
    -> StartImage
```

This is the mechanism used for `DefaultBDSBootApp=LinuxLoader` from the ABL FV.
It is a valid EFI execution mechanism but not an external buffer carrier.

## A2. PIL UFS ABL FV loading

Current XBL_CONFIG contains:

```text
/soc/pil/pil_images/ABL_CFG

Version         = 5
Type            = 1            # ELF_FV
FwName          = ABL
PartiLabel      = ""
PartiGuid       = a12869bd-e04c-38a0-4f3a-1495e3eddffb
ImagePath       = ""
SubsysID        = 21
ResvRegionStart = 0
ResvRegionSize  = 0
ImageLoadInfo   = 0
Unlock          = 1
OverrideElfAddr = 0
MediaType       = ""
IsFileCompressed= 0
NonFatal        = 0
```

`Type=1` is Qualcomm `ELF_FV`.

The `Unlock=1` field means unlock the subsystem/XPU after PIL authentication and
reset. It does **not** mean bypass image authentication.

Current `/soc/pil/RetailImages` includes `ABL`, so this PIL image is allowed in
Retail. The source is nevertheless fixed by the ABL configuration to the raw
partition GUID above; there is no `ImagePath`, network media type, or caller-
controlled filename in the active configuration.

The exact PILDxe also retains the protocol machinery for a caller to override a
PIL config, as shown by strings such as:

```text
Overriding PIL cfg by caller
ImagePath
PartiGuid
AutoStartImages
RetailImages
```

That only becomes useful to code that is already executing inside UEFI; it does
not itself provide an external entry point.

## A3. PIL buffer authentication API

The same-version PIL interface contains `AuthELFFVImageFromBuffer`.

Its semantic path is:

```text
caller-supplied buffer
    -> parse ELF_FV metadata
    -> validate metadata
    -> setup memory range
    -> TZ PIL authenticate/reset
    -> return authenticated FV image base
```

This is therefore a **buffer consumer**, but it is not a no-auth arbitrary EFI
PE loader. An external attacker/user still needs an already-running trusted UEFI
caller capable of supplying the buffer.

## A4. Flashless preloaded ABL RAM path

The BDS semantic reference contains a genuine pre-LinuxLoader RAM carrier:

```text
boot_from_flashless()
    -> ProcessFvLoadingForFlashless(RAM_PARTITION_ABL_MEMORY)
    -> GetPreloadedRamPartitionInfo(...)
    -> MountDesiredFVFromBuffer(...)
    -> gEfiAblFvNameGuid
```

This is important architecturally because it proves the platform can boot an ABL
FV supplied through a preloaded RAM-partition contract.

It is not active on the current device:

```text
runtime Boot Device = UFS
```

and the current XBL_CONFIG does not contain an `ABOOT FV` memory-map label.

So the flashless RAM partition mechanism is an internal alternate platform boot
mode, not a current PJZ110 live carrier.

## A5. Debug ToolsFV RAM region

Current XBL_CONFIG does contain:

```text
/soc/memorymap/memory@A7AD9000
mem-label = FV_Region
reg       = <0x0 0xA7AD9000 0x0 0x00400000>
```

Thus a 4 MiB `FV_Region` carveout physically exists.

The matched BDS source can call:

```text
GetMemRegionInfoByName("FV_Region")
    -> MountDesiredFVFromBuffer(... gToolsFvGuid ...)
```

inside `LoadDebugToolsFv()`.

However the stock call sites are development/debug flow:

```text
LaunchBDSMenu -> LoadDebugToolsFv
PlatformBdsBootHalt -> if (!RETAIL && EnableShellFlag) -> LoadDebugToolsFv
```

The current device is `Retail=TRUE`, and the earlier exact Retail analysis
already closed the generic BDS Menu / Shell path. No stock external producer
that fills `FV_Region` before LinuxLoader was identified.

The matched source also contains an old `AutoLaunchEx` partition/FV mechanism,
but the exact current QcomBds does not contain its `AutoLaunchCnt` / `AutoLaunch`
strings and the reference hotkey caller is compile-disabled. It is not treated
as a current-build carrier.

# 4. R4-B — which mechanisms run before normal LinuxLoader?

The current config says:

```text
DefaultChargerApp = QcomChargerApp
DefaultBDSBootApp = LinuxLoader
LoadAutoImageInPILFlag = absent
```

Matched BDS control flow is:

```text
PlatBdsLaunchDefaultApps
    -> optional internal QcomChargerApp
    -> query LoadAutoImageInPILFlag
    -> flag absent / error
    -> LoadAndProcessImages
         -> current UFS path: PIL ProcessPilImage(ABL)
         -> flashless-only alternative: RAM_PARTITION_ABL_MEMORY
    -> LaunchAppFromGuidedFv(gEfiAblFvNameGuid, "LinuxLoader")
    -> normal boot does not return
```

So there are pre-LinuxLoader staging mechanisms, but on this device they are
**internal/authenticated**:

```text
UFS raw ABL partition -> PIL -> authenticated/mounted ABL FV
                          or
flashless preloaded RAM -> inactive on current UFS device
```

R4-B status:

```text
INTERNAL-ONLY
```

# 5. R4-C — external controllable source search

The obvious external RAM source is Fastboot download memory. Exact current ABL
analysis rules it out for R4 timing.

All Fastboot implementation and command strings are inside the already-running
current `LinuxLoader.efi`. Therefore:

```text
QcomBds
    -> launches original LinuxLoader
       -> LinuxLoader enters/implements Fastboot
          -> host can download bytes to RAM
```

This is too late to replace the LinuxLoader instance which generated the Android
boot state.

## Exact `kernel = uefi` proof

The lone current-binary `uefi` string is not a hidden EFI command.

Exact LinuxLoader instructions:

```asm
0x2FFFC  adrp x0, ...
0x30000  add  x0, x0, #0xBEE   ; "kernel"
0x30004  adrp x1, ...
0x30008  add  x1, x1, #0x3CA   ; "uefi"
0x3000C  bl   0x34178
```

Strings:

```text
0x80BEE  kernel
0x893CA  uefi
```

This matches the standard Qualcomm operation:

```text
FastbootPublishVar("kernel", "uefi")
```

It is a Fastboot getvar value, not `boot-efi`, `reboot-uefi`, or `oem shell`.
None of those command strings exists in the exact current LinuxLoader.

## Exact Fastboot `boot` handler proof

The current LinuxLoader contains a single handler cluster beginning around
`0x32CD4` with references to:

```text
Invalid Boot image Header
Fastboot boot command is not available in locked device
Failed to load/authenticate boot image: %r
BootImage is Incomplete
BootImage: Size is greater than max download size
```

This matches Qualcomm's standard Fastboot `CmdBoot` flow:

```text
downloaded Data
    -> require Android boot_img_hdr
    -> LoadImageAndAuth
    -> BootLinux
```

It does not pass the downloaded bytes to UEFI `LoadImage/StartImage` as a PE
application.

Consequently:

```text
Fastboot download buffer = externally controllable RAM
                           but post-LinuxLoader and Android-boot-image-only
```

No other stock PC-controlled buffer source was identified feeding a
pre-LinuxLoader `LoadImage/StartImage` or ABL-FV mount path.

R4-C status:

```text
NONE-FOUND
```

# 6. R4-D — carrier decision

To qualify, a carrier had to satisfy all of:

```text
externally controllable
+ temporary / RAM-only
+ no boot-chain partition write
+ available before normal LinuxLoader handoff
+ able to reach EFI LoadImage/StartImage or mount a controllable ABL FV
```

The analyzed mechanisms fail as follows:

| Mechanism | Pre-LinuxLoader | Externally controllable | Temporary | Result |
| --- | --- | --- | --- | --- |
| Guided ABL FV | yes | no | yes | internal only |
| PIL ABL raw partition | yes | no | no | authenticated fixed source |
| PIL AuthELFFV buffer API | potentially | no external caller | yes | circular prerequisite |
| Flashless RAM ABL FV | yes | platform-preloaded only | yes | inactive on current UFS boot |
| `FV_Region` ToolsFV RAM | code exists | no stock producer found | yes | debug/non-retail path |
| Fastboot download RAM | **no** | yes | yes | too late; Android boot image path |
| Removable/USB R3 | later | external | yes | already closed by P1-P3 |

Final status:

```text
R4-D = CLOSED
```

There is currently no evidence-supported stock path equivalent to:

```text
PC
  -> RAM
  -> arbitrary AArch64 EFI PE
  -> UEFI LoadImage/StartImage
  -> before original LinuxLoader
```

# 7. Reproducible verifier

Added:

```text
profiles/PJZ110_16.0.10.501_r4.json
tools/pjz110_r4_check.py
tests/test_pjz110_r4_check.py
```

Example offline replay:

```powershell
python .\tools\pjz110_r4_check.py `
  --abl .\abl.img `
  --uefi .\uefi_b.img `
  --xbl-config .\xbl_config.img `
  --modules-dir .\extracted-uefi-modules `
  --linuxloader .\LinuxLoader.efi `
  --bootloader-log .\bootloader_log.txt
```

Expected:

```text
R4 exact profile        : PASS
R4-A                    : PASS-ENUMERATED
R4-B                    : INTERNAL-ONLY
R4-C                    : NONE-FOUND
R4-D                    : CLOSED
stock non-flash carrier : NOT FOUND / CLOSED
live EFI test           : DO NOT RUN
RESULT                  : PASS
```

`RESULT: PASS` means the exact-current-build conclusions reproduced. It does not
mean a carrier passed.

# 8. Deployment boundary after R4

Do not resume live EFI testing yet.

R4 closes the stock temporary execution search that began with BDS/Shell,
removable media and staged RAM candidates. The fake-lock transformation itself
remains complete and independently validated offline; the unresolved problem is
how to execute it without replacing a boot-chain component.

Any next deployment work must be a separately reviewed design milestone. It
must continue to preserve:

```text
real bootloader unlocked
no DeviceInfo/VBRwDeviceState modification
no RPMB/KeyMaster/TEE state modification
no blind ABL/UEFI/ToolsFV writes
A/B rollback requirements before any persistent experiment
```