# PJZ110 read-only EFI probe

This directory contains the first true-device payload for the PJZ110 Retail removable-media path.

It is intentionally **not** LinuxLoader and contains no partition/variable access.

## Behavior

`BOOTAA64.EFI` does only three things:

1. obtains `SystemTable->ConOut`;
2. prints three fixed UTF-16 strings;
3. returns `EFI_SUCCESS` to the firmware boot manager.

It does not call RuntimeServices `SetVariable`, BlockIo/DiskIo, file write APIs, partition protocols, reset/shutdown, or security/debug/provisioning services.

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
.reloc: present

SHA256:
2c7ef30661f8f09bfca56e481c84b1b18a8f4df9a92e2916fa75cb0d51047738
~~~

The build uses `/timestamp:0`. The reference hash was produced with LLVM/LLD 17.

## Intended live use

Only after offline Retail-path review is complete, place the probe at:

~~~text
\EFI\BOOT\BOOTAA64.EFI
~~~

on removable FAT32 media. Use this probe before attempting either original or fake-locked LinuxLoader.


## Materialize the exact reference binary

For true-device validation, the repository also stores the deterministic LLVM/LLD 17 reference image as text:

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
SHA256: 2c7ef30661f8f09bfca56e481c84b1b18a8f4df9a92e2916fa75cb0d51047738
~~~

For live validation, prefer this exact reference binary over a locally rebuilt binary with a different LLVM version.
