# PJZ110 read-only EFI probe

This directory contains the first true-device payload for the PJZ110 Retail removable-media path.

It is intentionally **not** LinuxLoader and contains no partition/variable write logic.

## Behavior

`BOOTAA64.EFI` does only four things:

1. obtains `SystemTable->ConOut`;
2. prints three fixed UTF-16 strings;
3. calls `BootServices->Stall(5000000)` so the result remains visible for five seconds;
4. returns `EFI_SUCCESS` to the firmware boot manager.

The exact visible strings are:

~~~text
PJZ110 EFI PROBE: EXECUTION OK
READ-ONLY PROBE: no block/variable writes performed
Holding for 5 seconds, then returning to firmware boot manager.
~~~

It does not call RuntimeServices `SetVariable`, BlockIo/DiskIo, file-write APIs, partition protocols, reset/shutdown, security/debug/provisioning services, or any device-specific Qualcomm protocol.

A base-relocation anchor is included so the PE contains a valid `.reloc` section.

## Build

Windows PowerShell with LLVM/Clang installed:

~~~powershell
pwsh -ExecutionPolicy Bypass -File .\tools\pjz110_probe\build.ps1
~~~

Reference deterministic build:

~~~text
PE32+ AArch64
Subsystem: EFI application
Entry RVA: 0x1000
.reloc: RVA 0x3000, size 0x0c
Import directory: empty
Security/certificate directory: empty
Size: 2048

SHA256:
17305dd5136bafed35b39ec0b883c66f2f9d7ef78bffafb37fc88b9efb393931
~~~

The reference binary was reproduced with LLVM/LLD 17 and `/timestamp:0`.

## Materialize the exact reference binary

For true-device validation, the repository stores the deterministic reference image as text:

~~~text
BOOTAA64.EFI.b64
~~~

This avoids depending on the user's local compiler version.

Windows PowerShell:

~~~powershell
pwsh -ExecutionPolicy Bypass -File .\tools\pjz110_probe\materialize_reference.ps1
~~~

The script decodes the reference image and refuses the output unless both invariants match:

~~~text
Size:   2048
SHA256: 17305dd5136bafed35b39ec0b883c66f2f9d7ef78bffafb37fc88b9efb393931
~~~

For live validation, prefer this exact reference binary over a locally rebuilt binary with a different LLVM version.

## Intended live use

Only after offline Retail-path review is complete, place the exact reference probe at:

~~~text
\EFI\BOOT\BOOTAA64.EFI
~~~

on removable FAT32 media.

The five-second stall is deliberate: a successful removable boot is visually distinguishable without requiring a Shell, keyboard, persistent log write, or EFI-variable write.

Use this probe before attempting either original or fake-locked LinuxLoader.
