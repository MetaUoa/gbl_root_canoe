# PJZ110 current-device FV analysis — 16.0.10.501

Input source: read-only dumps from the current unlocked OnePlus 13 China `PJZ110`, active slot `_b`.

## Input hashes

| Partition | Size | SHA256 |
| --- | ---: | --- |
| `imagefv_b` | 2,097,152 | `432903b02644b404d3e19408e003ebea20e0acd416a0d486798d5056fa426451` |
| `toolsfv` | 1,048,576 | `c5da520b05b736875170248d2c80e5060edfb435c1e394acfb5489c5fef12eb7` |
| `uefi_b` | 5,242,880 | `8d2670cb7790552c035bfa95896d561e7defb2414c8a6d538a3fdca2690879cc` |

No device partition was modified during collection or analysis.

## imagefv_b

The partition is an ELF wrapper with a firmware volume at `0x1000`. The outer FV contains an LZMA-guided section using GUID:

`ee4e5898-3914-4259-9d6e-dc7bd79403cf`

The decompressed inner FV is approximately `0x2365000` bytes and consists of OPlus battery/charging/thermal bitmap assets such as:

- `oplus_low_vbat_nocharger_pic1.bmp`
- `oplus_low_vbat_charging_pic1.bmp`
- `boot_tbatt_too_high.bmp`
- `battery_symbol_*.bmp`

No UEFI application payload was identified in this sampled ImageFV.

**Conclusion:** `imagefv_b` is not the direct EFI execution candidate for the ABL fake-lock payload.

## toolsfv

The partition is a firmware volume whose LZMA-guided inner FV expands to approximately `0x1F5000` bytes.

It contains stock AArch64 UEFI applications including:

- `Cmd`
- `ListVars`
- `Menu`
- `Pgm`
- `RPMBProvision`
- `RPMBErase`
- `UEFINVErase`
- `DelBootVars`
- `UsbfnMsdApp`
- `SecurityToggleApp`
- `DebugPolicyToggleApp`
- `CapsuleApp`
- `Ebl`
- **`Shell`**

The stock Shell is an AArch64 UEFI application. The stock ToolsFV also contains `Uefi_Menu.cfg`, which includes a `Toggle Enable Shell` action.

The stock Shell PE payload SHA256 is:

`487a4a702072e4f040cd503b74e762fef1d7cb0f55caabeab5cae09e8595456c`

The stock EBL PE payload SHA256 is:

`fdbdbaf4ff76c3b9d3d725c7b9d28451deefd6b8ff1a9c440dec6855d81f78f2`

## uefi_b

The partition is an ELF wrapper with its primary FV at `0x1000`. It contains multiple LZMA-guided nested firmware volumes.

The core nested FV contains real stock drivers/applications relevant to execution policy, including:

- `SecurityStubDxe`
- `VerifiedBootDxe`
- `VariableDxe`
- `PartitionDxe`
- `Fat`
- `FvSimpleFileSystem`
- `UFSDxe`
- USB host/mass-storage drivers
- `QcomBds`
- `QcomChargerApp`
- `Ebl`
- `OplusSecurityDxe`

The image contains a stock `BDS_Menu.cfg` with an explicit entry:

```text
Label = "Enter Shell"
App = Shell
Arg = "-nomap -nostartup"
```

The same stock menu also exposes a nested UEFI menu, while ToolsFV contains the corresponding `Shell`, `Menu`, and command applications.

This establishes a concrete stock firmware relationship:

```text
QcomBds
  -> BDS_Menu.cfg
  -> ToolsFV
  -> Shell / EBL / Cmd / Menu
```

## Important limitation

The presence of the stock BDS menu and stock Shell does **not** yet prove that a retail PJZ110 will expose the menu or allow an externally supplied unsigned `boot.efi` to execute.

Qualcomm BOOT.MXF.2.5.1 reference code has explicit retail/security gating around BDS hotkey and Shell paths, and UEFI image loading passes through Security2 handlers.

Therefore the remaining unknowns are now reduced to two true-device questions:

1. Is the stock BDS/ToolsFV Shell path reachable on this retail PJZ110?
2. If reachable on an already-unlocked device, will the Shell/LoadImage policy start the generated fake-locked `boot.efi`, or reject it with an authentication/security violation?

## Project status after these dumps

The ABL fake-lock transformation is offline-complete.

The deployment search has narrowed from an unknown `efisp` replacement to one concrete stock candidate:

**QcomBds -> ToolsFV -> Shell**

No flashing is required to test reachability. The next engineering stage is true-device, non-flashing validation of this stock path before attempting the patched LinuxLoader.
