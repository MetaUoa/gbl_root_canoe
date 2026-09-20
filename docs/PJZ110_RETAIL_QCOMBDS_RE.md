# PJZ110 Retail QcomBds reverse engineering — 16.0.10.501

Target: **OnePlus 13 China PJZ110 / SM8750 Pakala**

Current build: **PJZ110_16.0.10.501(CN01)**

This report is based primarily on the current-device `uefi_b.img`, `toolsfv.img`, `abl.img`, and real-device bootloader logs. Qualcomm `BOOT.MXF.2.5.1` source is used only as a semantic reference where its control flow matches the extracted current binary.

## Exact QcomBds binary

Extracted from the current `uefi_b` nested firmware volume:

~~~text
FFS GUID:
5a50aa81-c3ae-4608-a0e3-41a2e69baf94

UI name:
QcomBds

SHA256:
426004d0eba512a0c33baf9f79e1c6ad723691e03a117f540dca79905dce1038

Format:
PE32+ / AArch64 / EFI boot-service driver

SizeOfImage:
0x1A000
~~~

Relevant exact strings:

~~~text
OsIndicationsSupported       @ 0x13B98
OsIndications                @ 0x13BC6
BDSHotKeyState               @ 0x13C0E
DefaultBDSBootApp            @ 0x13FE4
OEMSetupApp                  @ 0x14095
AllowNonPersistentVarsInRetail @ 0x14417
INFO: UEFI NV tables are enabled as VOLATILE! @ 0x14436
AttemptUSBFirst              @ 0x13508
Authentication failed       @ 0x135C1
[QcomBds] Removable boot path @ 0x136E0
~~~

## 1. Generic BDS Menu / ToolsFV Shell is not the retail entry

The current firmware physically contains:

~~~text
BDS_Menu.cfg
  -> Label = "Enter Shell"
  -> App = Shell

toolsfv
  -> Shell
  -> Ebl
  -> Cmd
  -> Menu
  -> other debug/provisioning applications
~~~

However these assets do not imply retail reachability.

The exact current QcomBds contains `PlatformBdsDetectHotKey()` at approximately RVA `0x6E40`.

Its current-binary control flow is:

~~~text
validate BDS state
  ->
GetVariable("BDSHotKeyState")
  ->
VarFlag == 1 : disable hotkey
  ->
ReadAnyKey(NO_BLOCKING | RESET_AFTER_READ)
  ->
SCAN_HOME : GotoMenu++
  ->
or VarFlag == 2 : GotoMenu++
  ->
or CheckBootToFWUIField() : GotoMenu++
  ->
or InfoBlock.BdsHotkey : GotoMenu++
~~~

This part still exists in the Retail binary.

But after `GotoMenu != 0`, the exact current binary only performs the setup/config lookup through `OEMSetupApp`; the generic `LaunchBDSMenu()` branch is absent from the retail-compiled control flow.

This matches the Qualcomm semantic source:

~~~c
if (!RETAIL && (Status != EFI_SUCCESS || DefaultApp[0] == '\0'))
    LaunchBDSMenu();
~~~

The real device reports:

~~~text
PROD Mode : TRUE
Retail    : TRUE
~~~

Therefore:

**The stock BDS_Menu.cfg + ToolsFV Shell should be treated as dormant development assets on this shipping build, not as the primary retail entry.**

Repeated SCAN_HOME / Home-key brute forcing is not the deployment strategy.

## 2. Retail entry A — OEMSetupApp

The exact current QcomBds retains `PlatBdsProcessOsIndicationsForOemSetupApp()` at approximately RVA `0x6B48`.

Exact current-binary behavior:

~~~text
GetConfigString("OEMSetupApp")
  ->
if GotoMenu != 0
   and config lookup succeeded
   and app name is non-empty:
      lock variable policy
      LaunchAppFromGuidedFv(MainFV, OEMSetupApp)
  ->
SetOsIndicationsSupported()
  ->
if BootToFWUI is requested:
      clear request bit
      LaunchAppFromGuidedFv(MainFV, OEMSetupApp)
      restore bit on launch failure
~~~

The current BDS initialization calls this function at approximately RVA `0x1E70`.

Important result:

**OEMSetupApp is a real retail-capable firmware-UI route.**

It is not guarded by the generic `!RETAIL -> LaunchBDSMenu` condition.

### Current unresolved item

The four currently analyzed artifacts prove the key exists but do **not** reveal the active value of `OEMSetupApp`.

The old `uefiplat.cfg` in the current UEFI image is no longer authoritative; current Qualcomm platforms source these settings from platform/device-tree configuration.

Therefore this route cannot yet be called reachable until the current active XBL configuration is inspected.

## 3. Retail entry B — Volume Down -> removable-media boot

This is the most important Retail finding.

The exact current QcomBds contains a second hotkey function at approximately RVA `0xD0C0`.

Exact disassembly:

~~~asm
D0D0  add   x0, x29, #0x1c
D0D4  mov   w1, #3
D0D8  str   wzr, [x29, #0x1c]
D0DC  bl    ReadAnyKey
D0E0  ldrh  w8, [x29, #0x1c]
D0E4  cmp   w8, #2
D0E8  cset  w8, eq
D0EC  str   w8, [x19]
~~~

UEFI scan code `2` is `SCAN_DOWN`.

The same-version Qualcomm source names this routine `QcomBdsDetectBootHotKey()` and documents:

~~~text
Volume Down hotkey pressed:
    Enumerate and boot from removable media
~~~

The current BDS initialization calls it at approximately RVA `0x1E80`.

The exact current BDS entry then checks the returned init option together with `AttemptUSBFirst` and calls the removable path.

Current binary around the decision:

~~~text
InitOption == BootFromRemovableMedia
       OR
AttemptUSBFirst != 0
       ->
AttemptBootFromRemovable(...)
~~~

The removable path starts at approximately RVA `0x21A0` and contains:

~~~text
[QcomBds] Removable boot path
~~~

Unlike the development BDS menu, this path is **not compiled behind !RETAIL**.

Therefore the real stock Retail external-boot candidate is:

~~~text
physical Vol-
    ->
UEFI SCAN_DOWN
    ->
QcomBdsDetectBootHotKey
    ->
BootFromRemovableMedia
    ->
enumerate removable EFI boot option
~~~

This is a materially better candidate than trying to enter the stock Shell.

## 4. Real-device input evidence

The current PJZ110 has already proved that its physical volume keys reach early UEFI.

A normal boot reports no volume key.

A controlled Volume-Up boot reports:

~~~text
vol_up_pressed:1,vol_down_pressed:0
ButtonsDxeTest: Keypress SDAM data payload 4
~~~

Therefore physical-key sampling is active in shipping UEFI.

Qualcomm same-version button semantics map:

~~~text
Vol+ alone      -> SCAN_UP
Vol- alone      -> SCAN_DOWN
Vol+ + Vol-     -> SCAN_ESC
Vol+ + Power    -> SCAN_HOME
Vol- + Power    -> SCAN_DELETE
~~~

For the newly identified Retail removable-media route, the relevant input is **Vol- alone / SCAN_DOWN**, not SCAN_HOME.

## 5. Retail variable-store gate

The real-device log reports:

~~~text
INFO: UEFI NV tables are enabled as VOLATILE!
~~~

Exact current QcomBds contains:

~~~text
VolatileTables
EnableVolatileBootOptions
AllowNonPersistentVarsInRetail
~~~

The exact current `PerformVariableActions()` matches the same-version Qualcomm logic:

~~~text
GetVariable("VolatileTables")
  ->
if VolatileTables != 0 and Retail:
    GetConfigValue("AllowNonPersistentVarsInRetail")
    if enabled:
        log INFO and continue
    else:
        shutdown
~~~

Because the real device reaches Android while reporting the INFO message, the active platform configuration necessarily permits the non-persistent variable condition in Retail.

However this does **not** automatically mean arbitrary volatile boot options are launchable.

The same-version PlatformBds pre-load policy contains an additional protection:

~~~c
if ((VolatileTables != 0) &&
    (ProdModeEnabled || (!EnableVolatileBootOptions)))
    return EFI_DEVICE_ERROR;
~~~

With `Retail=TRUE`, this policy would reject an ordinary BDS boot option while variable tables are volatile.

The current exact binary has the corresponding variable names and policy infrastructure, but this pre-load path should be treated as the next binary-level gate to validate before live removable-media testing.

## 6. UEFI image authentication gate

The removable-media path occurs **after** QcomBds calls platform-security setup.

The shipping `uefi_b` contains:

~~~text
SecurityStubDxe
VerifiedBootDxe
OplusSecurityDxe
~~~

Exact current hashes:

~~~text
SecurityStubDxe:
2e029953a561cb00133b67c415829567b67defb5dcaf99cef2519589927a3b7e

VerifiedBootDxe:
cb379fda2dc10c01d123c7e0a0640504580ac4bc4bd3405ba35dc641c61fe02f

OplusSecurityDxe:
9778820165fdb2a0e2c542dcb2cbd758e648b2dcb83f2b8430376c223b6c8020
~~~

The exact SecurityStubDxe contains the Security2 architecture protocol and `Security Violation` path.

The exact QcomBds removable boot path contains:

~~~text
Authentication failed
~~~

and the semantic source emits that when boot-option start returns `EFI_SECURITY_VIOLATION`.

Therefore the external-EFI route has at least two independent gates:

~~~text
Vol- / removable enumeration
        ->
BDS pre-load policy
        ->
Security2 / image authentication
        ->
external EFI execution
~~~

Do not infer that an unlocked Android bootloader automatically disables UEFI external-PE authentication.

## 7. VerifiedBootDxe unlock observation

The exact current VerifiedBootDxe contains:

~~~text
VB: DeviceInit: Device is unlocked! Skipping verification!
~~~

and the real bootloader log confirms the current device state is unlocked/orange.

This is relevant but is **not yet proof** that arbitrary removable UEFI applications bypass Security2 authentication. VerifiedBootDxe also implements Android Verified Boot functions, so its unlocked branch must be separated from the Security2 PE-authentication path before drawing that conclusion.

This remains the next offline RE target.

## 8. Current route ranking

### Route R1 — Generic BDS Menu -> ToolsFV Shell

~~~text
Status: effectively closed on the current Retail build
Reason: generic LaunchBDSMenu branch compiled behind !RETAIL
~~~

### Route R2 — OEMSetupApp

~~~text
Status: real retail-capable code path
Blocker: active OEMSetupApp configuration value is unresolved
Needed artifact: current xbl_config active-slot image / platform DT config
~~~

### Route R3 — Vol- -> removable EFI boot

~~~text
Status: real retail-capable QcomBds entry confirmed
Entry: SCAN_DOWN
No generic !RETAIL gate
Remaining gates:
  1. volatile BDS pre-load policy
  2. Security2 external-image authentication
~~~

**R3 is now the primary external-chainload candidate.**

## 9. Next offline work

Before any new true-device boot attempt:

1. finish exact-binary analysis of `PlatformBdsPreLoadBootOption`;
2. trace the current Security2 handler registration and external PE verification path;
3. determine whether real `DeviceInfo.is_unlocked` changes UEFI PE authorization or only Android Verified Boot;
4. inspect current active `xbl_config` to resolve `OEMSetupApp`, `AllowNonPersistentVarsInRetail`, and related BDS platform config.

Only if R3 survives both pre-load and Security2 analysis should the true-device plan move from BDS-menu testing to a harmless removable EFI probe.

## 10. Safety boundary

This analysis requires no partition writes.

Do not:

- modify `uefivarstore`;
- invoke SecurityToggleApp / DebugPolicyToggleApp;
- flash `uefi`, `toolsfv`, or `abl`;
- relock the bootloader;
- use provisioning/RPMB utilities.

The purpose is to locate an already-present stock Retail execution path, not to weaken platform security state.


# 11. Exact current XBL configuration

The current active `xbl_config.img` has SHA256:

~~~text
9760062003776a481495286d6c0233bda307100ac2e95cb7b23fcb5aa17bf64d
~~~

Its Pakala platform DTB is at file offset `0x8708`. The live `/sw/uefi` configuration contains:

~~~text
EnableShell                         = 1
SecurityFlag                        = 0xC4
DetectRetailUserAttentionHotkey     = 0
DetectRetailUserAttentionHotkeyCode = 0x17
EnableUefiSecAppDebugLogDump        = 0
AllowNonPersistentVarsInRetail      = 1
EnableDisplayImageFv                = 0
EnableVariablePolicyEngine          = 0

PlatConfigFileName = uefiplatLA.cfg
OsTypeString       = LA
DefaultChargerApp  = QcomChargerApp
DefaultBDSBootApp  = LinuxLoader
~~~

No `OEMSetupApp` property is present in the active current DT configuration.

Consequences:

- `AllowNonPersistentVarsInRetail=1` exactly explains the runtime log `UEFI NV tables are enabled as VOLATILE!` without shutdown.
- `EnableShell=1` does not make the Retail shell reachable: the exact BDS logic forces `EnableShellFlag=0` when `RETAIL=TRUE`.
- `OEMSetupApp` is not configured on this current build, so the otherwise Retail-capable OEMSetupApp route is not usable here.
- `DetectRetailUserAttentionHotkey=0` disables that separate platform feature. It does **not** remove the exact QcomBds `SCAN_DOWN` removable-media check, which is present and unconditionally called by the current BDS initialization path.

Therefore R2 (OEMSetupApp) is closed on the exact current build and R3 remains the primary candidate.

# 12. Exact current removable boot call path

The exact current QcomBds establishes the following path.

`BootOptionStart` at approximately `RVA 0x24FC` directly calls:

~~~text
BdsStartEfiApplication
RVA ~0xCC44
~~~

There is no call to `PlatformBdsPreLoadBootOption()` in this direct current path.

Inside the exact current `BdsStartEfiApplication`:

~~~text
gBS->LoadImage(
    BootPolicy = TRUE,
    ParentImageHandle,
    DevicePath,
    ...
)
~~~

is called at approximately `RVA 0xCCF4`.

If the initial device path is not directly loadable, the function obtains the bootable handle and falls back to the standard AArch64 removable path:

~~~text
\EFI\BOOT\BOOTAA64.EFI
~~~

The exact current QcomBds contains this UTF-16 path at `RVA 0x1398A`.

After a successful load it calls:

~~~text
gBS->StartImage(...)
~~~

at approximately `RVA 0xCE7C`.

Therefore the previously suspected volatile-table `PlatformBdsPreLoadBootOption` policy is **not an active blocker in this exact current QcomBds call path**.

The remaining policy gate is DxeCore/Security2 during `LoadImage`.

# 13. Exact current Security2 analysis

The current `SecurityStubDxe.efi` is:

~~~text
SHA256:
2e029953a561cb00133b67c415829567b67defb5dcaf99cef2519589927a3b7e

SizeOfImage:
0xD000
~~~

Its exact `Security2StubAuthenticate` is at approximately `RVA 0x1474`.

The function first calls the exact current third-party defer routine at approximately `RVA 0x198C`, then tail-calls exact `ExecuteSecurity2Handlers` at approximately `RVA 0x6F78` with operation mask `0x0F`:

~~~text
VERIFY_IMAGE |
DEFER_IMAGE_LOAD |
MEASURE_IMAGE |
CONNECT_POLICY
~~~

## 13.1 EndOfDxe behavior

The exact current SecurityStub uses byte `RVA 0xB2AC` as its EndOfDxe state.

- initialized value in the image: `0`
- callback at approximately `RVA 0x18C0` stores `1`
- defer routine at approximately `RVA 0x1A10` reads it

When this byte is set, the exact defer path returns `EFI_SUCCESS` for a non-FV image and marks it as loaded-after-EndOfDxe.

Before EndOfDxe, a new external image is queued/deferred and returns `EFI_ACCESS_DENIED`.

The exact QcomBds initialization invokes the platform post-firmware-config-security method **before** the `QcomBdsDetectBootHotKey` call at `RVA 0x1E80`. The same-version semantic source identifies that method as the point that signals `gEfiEndOfDxeEventGroupGuid`.

Therefore the Vol-/removable path occurs on the **post-EndOfDxe side** of SecurityStub's defer policy.

## 13.2 No registered Security2 verification handler

The exact current SecurityStub's Security2 handler state is located at:

~~~text
mNumberOfSecurity2Handler  -> RVA 0xB358
mSecurity2Table            -> RVA 0xB360
~~~

Both are zero in the shipped PE image.

More importantly, exhaustive disassembly references show:

~~~text
RVA 0xB358:
  read at 0x6FC4
  read at 0x7024
  no write reference

RVA 0xB360:
  read at 0x6FD8
  no write reference
~~~

Those reads are inside `ExecuteSecurity2Handlers`.

No linked function in the exact current SecurityStub writes the handler count/table. If the count is zero, the exact `ExecuteSecurity2Handlers` branch at `0x6FC8` returns success immediately.

The PE has no import/export mechanism by which another independent DXE image can directly mutate these module-local globals.

The current nested UEFI firmware contains the Security2 architectural protocol GUID only in:

1. current `DxeCore`, which consumes the protocol;
2. current `SecurityStubDxe`, which produces the protocol.

No other current nested module contains that protocol GUID.

The same-version Pakala DSC also includes SecurityStubDxe, SecRSADxe, ASN1X509Dxe and VerifiedBootDxe, but does **not** link `DxeImageVerificationLib` into SecurityStubDxe.

This matches the exact binary evidence: standard `DxeImageVerificationLib` diagnostic strings and SecureBoot/db/dbx verification policy strings are absent from the current SecurityStub.

**Conclusion:** the exact current SecurityStub has no registered `VERIFY_IMAGE` Security2 handler.

# 14. Exact DxeCore LoadImage security path

The current extracted `DxeCore.efi` is:

~~~text
SHA256:
c50728527212502367bfc39d5b7f0f7ccdb0db217edbb7b87505841a33d4e19f

SizeOfImage:
0x2F000
~~~

Its exact LoadImage implementation matches the standard EDK2 structure.

At approximately `RVA 0x6568`, the current binary obtains the installed Security2 interface and indirectly calls its first method, `FileAuthentication`.

For a non-FV removable image:

~~~text
DxeCore LoadImage
   ->
Security2->FileAuthentication
   ->
current SecurityStub Security2StubAuthenticate
   ->
Defer3rdPartyImageLoad
      post-EndOfDxe => SUCCESS
   ->
ExecuteSecurity2Handlers
      handler count == 0 => SUCCESS
   ->
CoreLoadPeImage
   ->
StartImage
~~~

The additional legacy Security Architectural Protocol check in the exact DxeCore is conditional on `ImageIsFromFv`; it does not form a second authentication check for the removable FAT file path.

No separate Qualcomm/OPlus PE-authentication call is visible in this exact DxeCore LoadImage path.

# 15. VerifiedBootDxe and OplusSecurityDxe are not the PE-auth gate

The exact current `VerifiedBootDxe.efi` contains:

~~~text
VB: DeviceInit: Device is unlocked! Skipping verification!
~~~

but the current binary does **not** contain the Security2 architectural protocol GUID.

The exact current `OplusSecurityDxe.efi` likewise does not contain the Security2 protocol GUID. Its observed logic reads VerifiedBoot device state and publishes OPlus/OEM lifecycle state; no Security2 handler registration path was identified.

Thus the VerifiedBoot unlocked shortcut should be treated as Android Verified Boot state handling, not as the reason removable EFI is accepted.

The removable-EFI conclusion instead follows from the exact SecurityStub/DxeCore path above.

# 16. Updated R3 conclusion

For the exact current `PJZ110_16.0.10.501(CN01)` firmware, the offline evidence now supports:

~~~text
Vol- / SCAN_DOWN
       ->
QcomBds BootFromRemovableMedia
       ->
enumerate removable FAT media
       ->
\EFI\BOOT\BOOTAA64.EFI
       ->
DxeCore LoadImage(BootPolicy=TRUE)
       ->
SecurityStub Security2
       ->
post-EndOfDxe defer: PASS
       ->
Security2 registered verify handlers: 0
       ->
PE structural load
       ->
StartImage
~~~

Remaining uncertainties are now hardware/runtime rather than a discovered firmware-policy denial:

1. whether the phone's USB-C port enters host mode early enough for a removable FAT device;
2. whether a specific FAT32 medium is enumerated by the stock USB mass-storage stack;
3. whether the external AArch64 PE itself is valid for this UEFI execution environment.

No partition modification is required to test these conditions.

**Offline R3 status: PASS-CANDIDATE.**

The next safe artifact should be a minimal read-only AArch64 `BOOTAA64.EFI` probe before using either original or fake-locked LinuxLoader.


# 17. Volume-Down key survives the earlier hotkey read

One remaining concern was whether the early `PlatformBdsDetectHotKey()` call would consume `SCAN_DOWN` before the later Retail `QcomBdsDetectBootHotKey()` call can use it.

The same-version Pakala input stack resolves this.

`ReadAnyKey(... RESET_AFTER_READ | NO_BLOCKING)` calls the SimpleTextInputEx `ReadKeyStrokeEx` method and then calls the input protocol `Reset` method.

The Pakala `ButtonsDxe` reset path clears:

~~~text
key buffers
pressed/released arrays
matrix A/B
isEfiKeyDetected
numKeyRead
~~~

It does **not** release or mask the physical PMIC volume-button state.

The physical polling path then reads the buttons again. If Volume Down remains physically held, the freshly-zeroed matrix changes back to pressed, and `ConvertEfiKeyCode()` emits a new `SCAN_DOWN` because `isEfiKeyDetected` was reset to false.

The exact current `ButtonsDxe.efi` is:

~~~text
SHA256:
931120fa700f135b70123f18833850e60856b2dba3772d89e9e9b74c2f3ef850

Build path embedded in image:
BOOT.MXF.2.5.1 / PakalaLAA / QcomPkg/Drivers/ButtonsDxe
~~~

The real-device Volume-Up experiment also proves that this same shipping input stack receives physical volume-key state during UEFI.

Therefore the two-stage read sequence is:

~~~text
Volume Down held
    ->
early PlatformBdsDetectHotKey reads SCAN_DOWN
    ->
RESET_AFTER_READ clears software keypad state
    ->
physical Volume Down still held
    ->
next PollForKey observes a fresh pressed transition
    ->
late QcomBdsDetectBootHotKey reads SCAN_DOWN
    ->
BootFromRemovableMedia
~~~

**Offline conclusion:** the earlier development-menu hotkey read is not a structural blocker to the later Retail removable-media hotkey, provided the physical key remains asserted across both sampling points.

This finding removes the last known input-consumption ambiguity from R3.

# 18. Current Pakala USB host stack is present

The exact current nested UEFI contains the complete pieces required for removable USB mass-storage boot:

~~~text
UsbConfigDxe
XhciPciEmulation
XhciDxe
UsbBusDxe
UsbMassStorageDxe
UsbMsdDxe
UsbPwrCtrlDxe
UsbInitDxe
~~~

Exact hashes for the additional host-side modules:

~~~text
UsbPwrCtrlDxe:
4812dae5ab9420102d2a04dedac5ff31a57e9edd6e9fc2f0808d36570badff6a

UsbInitDxe:
711ddb5f7da65c4b59c4b4fcf58416c0c07aa42191bf18a625d262603fcafbaf

UsbMsdDxe:
38a9ec1bdd4314bfd9a75eb361f5bd0dde340973219795723348c6997f41ddc5

UsbKbDxe:
b53cf66d601563ceabc775ea4d9f34245f11d6aadf0f7f4e68eda8b137b2f98e
~~~

The same-version Pakala `UsbConfigLib` explicitly supports the primary core in host mode:

~~~text
GetUsbHostConfig(USB_CORE_0_SOC) -> USB_CONFIG_SSUSB1
GetSupportedMode(primary)        -> USB_DEVICE_MODE | USB_HOST_MODE
~~~

For a Type-C partner attach in DFP mode, its dual-role handler selects:

~~~text
USB_HOST_MODE_XHCI
~~~

and marks the core for host-controller start.

The QcomBds removable path then calls `BdsConnectAllDrivers()` and enumerates removable SimpleFileSystem/BlockIo handles. Its USB boot-option logic is present in the exact current QcomBds.

Thus the firmware does not lack a USB-host or mass-storage stack.

The remaining USB uncertainty is strictly runtime/physical:

~~~text
Will the Type-C connection negotiate DFP/host mode early enough
with the specific OTG adapter + FAT32 storage device?
~~~

That cannot be proven from the offline images alone.

# 19. SecurityFlag decoding separates hardware Secure Boot from UEFI PE policy

The exact current Pakala XBL_CONFIG has:

~~~text
SecurityFlag = 0xC4
~~~

The matching `BOOT.MXF.2.5.1` Qualcomm definitions are:

~~~text
0x001 SEC_BOOT_ENABLE_FLAG
0x004 COMMON_MBN_LOAD_FLAG
0x040 LOAD_SEC_APPS_FLAG
0x080 KEYMASTER_LOAD_FLAG
~~~

Therefore:

~~~text
0xC4 = 0x80 | 0x40 | 0x04
~~~

and **does not contain** `SEC_BOOT_ENABLE_FLAG (0x01)`.

This is consistent with the exact SecurityStub result: the Security2 architectural protocol exists, but there is no registered standard VerifyImage handler in the current image.

This must not be confused with the earlier XBL runtime log:

~~~text
Secure Boot: On
~~~

That line describes the Qualcomm hardware/signing chain that authenticated the boot firmware itself. It does not, by itself, prove UEFI removable PE signature enforcement.

For the current profiled build, the offline evidence distinguishes the two layers as:

~~~text
Qualcomm hardware boot-chain authentication: ON

UEFI removable PE path:
  Security2 protocol present
  post-EndOfDxe defer gate passes
  registered VerifyImage handlers = 0
  SecurityFlag SEC_BOOT_ENABLE bit = 0
~~~

This materially strengthens the R3 PASS-CANDIDATE conclusion.

# 20. Deterministic probe reproduced offline

The project reference probe has now been independently rebuilt with the declared LLVM/LLD 17 toolchain and reproduced byte-for-byte:

~~~text
File:
BOOTAA64.EFI

Size:
2048 bytes

SHA256:
2c7ef30661f8f09bfca56e481c84b1b18a8f4df9a92e2916fa75cb0d51047738

Machine:
AArch64 (0xAA64)

Subsystem:
EFI application (10)

Entry RVA:
0x1000

Relocation directory:
present, RVA 0x3000, size 0x0C

Import directory:
empty

Security/certificate directory:
empty
~~~

Exact disassembly shows only three indirect calls through `SystemTable->ConOut->OutputString`, followed by `EFI_SUCCESS`.

The only embedded UTF-16 payload strings are:

~~~text
PJZ110 EFI PROBE: EXECUTION OK
READ-ONLY PROBE: no block/variable writes performed
Returning to firmware boot manager.
~~~

There is no RuntimeServices pointer dereference, no BlockIo/DiskIo access, no file-write call, no SetVariable call, and no reset/provisioning call.

Therefore the probe is ready as the first future true-device payload once the user resumes live validation.
