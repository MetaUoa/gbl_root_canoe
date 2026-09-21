# PJZ110 ABL fake-lock validation contract

Target: **OnePlus 13 China (PJZ110), SM8750/Pakala**

Primary target build: **PJZ110_16.0.10.501(CN01)**

This document defines the exact boundary between the completed offline ABL fake-lock implementation and the remaining true-device validation.

## Goal

Keep the real bootloader unlock state unchanged while making the **ABL/LinuxLoader output** report:

```text
androidboot.vbmeta.device_state = "locked"
androidboot.verifiedbootstate   = "green"
```

This is intentionally different from userspace property spoofing.

## Current stock-device baseline

The supplied unlocked PJZ110 currently boots with:

```text
/proc/bootconfig:
  androidboot.vbmeta.device_state = "unlocked"
  androidboot.verifiedbootstate   = "orange"
```

A root/userspace module later makes Android properties appear as:

```text
ro.boot.vbmeta.device_state = locked
ro.boot.verifiedbootstate   = green
ro.boot.flash.locked        = 1
```

That userspace-only state is **not** a pass for this project.

## Offline implementation status

The canonical implementation is:

```text
tools/pjz110_fake_lock.py
submodules/patcher/src/patchs/core.c
```

The old per-build Python scripts remain regression/reference material.

The canonical Python patcher:

- accepts a raw profiled `abl.img` or extracted `LinuxLoader.efi`;
- extracts LinuxLoader from the ABL container;
- requires an exact known profile;
- semantically locates the `unlocked / locked / androidboot.vbmeta.device_state` ADRP+ADD triple;
- validates the following `CMP Wstate,#0` + `CSEL Xout,Xlocked,Xunlocked,EQ`;
- semantically locates the `0:green / 1:orange / 2:yellow / 3:red` state table;
- retargets only the Android-visible `unlocked` operand to the stock `locked` string;
- retargets only state 1 from the stock `orange` string to the stock `green` string;
- verifies the output against an allowlist of changed bytes and known output hash.

It does **not** modify:

- Qualcomm `DeviceInfo.is_unlocked`;
- `VBRwDeviceState`;
- KeyMaster / TEE RootOfTrust;
- XBL or XBL_CONFIG;
- any device partition.

## Current-build invariant

For `PJZ110_16.0.10.501(CN01)`:

```text
ABL SHA256:
c6aa137b7e2b8c6f86040438022488eee6b2a69a1fad95f109a86c8a77d64bed

Original LinuxLoader SHA256:
4d4aaa42e86917e65c2b2c3fdd477851282a31d5c64f9ca9d20710a650da8b4b

Fake-locked LinuxLoader SHA256:
34dbedd47b33acf4c131b5db927a5ef7cf9be214facbe6f98fe044dc448b61f0

Image size:
0xC3000

Changed byte count:
7

Changed offsets:
0x4AF3C
0x4AF3D
0x4AF3F
0x4AF41
0x4AF42
0xA2CA8
0xA2CA9
```

PE headers, entry point, image size and section table remain unchanged.

Post-patch AArch64 state selection is equivalent to:

```asm
ldrb    w8, [sp, #0x68]
adrp    x9,  "locked"
add     x9,  x9, ...
adrp    x10, "locked"
add     x10, x10, ...
...
cmp     w8, #0
csel    x2, x10, x9, eq
```

Thus the real state bit still participates in the original control flow, but both Android-visible string operands resolve to `locked`.

## Prepare true-device payload

Offline only:

```bash
python3 tools/pjz110_fake_lock.py prepare abl.img out/pjz110
```

This creates:

```text
LinuxLoader.original.efi
LinuxLoader.fake_locked.efi
boot.efi
manifest.json
```

No partition is written.

## Deployment research boundary

PJZ110 has no `efisp` partition and all three known ABL generations lack the legacy UTF-16 `efisp` marker used by the original SM8845/SM8850 path.

The current device exposes instead:

```text
imagefv_<slot>
toolsfv
uefi_<slot>
uefisecapp_<slot>
uefivarstore
```

Qualcomm BOOT.MXF.2.5.1 source shows that firmware-volume applications and ToolsFV exist in this platform family, but presence of a firmware volume does **not** prove an unauthenticated execution path. ImageFV in Qualcomm reference code is explicitly loaded through an authentication path.

Therefore the remaining engineering task is to identify a **temporary/non-flashing stock execution path** for the already-generated `boot.efi`.

## Read-only deployment input collection

Use:

```powershell
pwsh -ExecutionPolicy Bypass -File .\tools\pjz110_collect_bootchain.ps1
```

The collector reads only the active-slot:

```text
imagefv_<slot>
uefi_<slot>
toolsfv
```

and saves them on the PC with SHA256 hashes. It does not write any phone partition.

Analyze them with:

```bash
python3 tools/pjz110_fv_analyze.py imagefv_b.img uefi_b.img toolsfv.img
```

(adjust the slot suffix when needed).

## Final true-device pass criteria

After a temporary execution method is established, capture:

```powershell
pwsh -ExecutionPolicy Bypass -File .\tools\pjz110_capture_validation.ps1
```

A real ABL fake-lock pass requires:

```text
real bootloader: UNLOCKED

/proc/bootconfig:
  androidboot.vbmeta.device_state = "locked"
  androidboot.verifiedbootstate   = "green"
```

The validation script deliberately reports userspace-only `getprop=locked/green` with `bootconfig=unlocked/orange` as **FAIL**.

## Prohibited deployment shortcuts

Until a temporary loader is validated:

- do not flash the patched LinuxLoader directly as `abl`;
- do not flash modified `imagefv`;
- do not flash modified `uefi`;
- do not downgrade an ARB1 device to an ARB0 ABL;
- do not change the real DeviceInfo unlock bit.

At this point the ABL fake-lock transformation itself is offline-complete. The remaining unknown is exclusively how to execute the patched EFI under the stock signed PJZ110 boot chain.
