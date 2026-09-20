# PJZ110 M25-A — ABL / TZ-PIL authentication boundary

Target: **OnePlus 13 China PJZ110 / SM8750 (Pakala)**  
Build: **PJZ110_16.0.10.501(CN01)**

This stage answers one narrow deployment question:

> Can the existing 7-byte fake-lock LinuxLoader be repacked into the current
> stock abl.img and still execute through the normal PJZ110 ABL/PIL path?

Final result:

~~~text
M25-A                         PASS-CLOSED-DIRECT-ABL
outer ABL payload integrity   SHA384 covered
hash-table signature          valid OPLUS ECDSA-P384 / SHA384
current Android BL state      unlocked
hardware Secure Boot          On
stock direct patched ABL      CLOSED-BY-PIL-AUTH
~~~

This is an **offline conclusion**. No modified ABL was flashed.

# 1. Evidence classes

Two evidence classes are kept separate.

## Exact current-device artifacts

Derived directly from the supplied current:

~~~text
abl.img
xbl_config.img
bootloader_log.txt
LinuxLoader.original.efi
LinuxLoader.fake_locked.efi
~~~

These establish the actual PJZ110 image geometry, hashes, certificate chain,
signature validity, runtime Secure Boot state, and exact fake-lock delta.

## Matched Qualcomm BOOT.MXF.2.5.1 source

The public Pakala source is used only to name and explain the PIL control flow:

~~~text
QcomPkg/Drivers/PILDxe/pil_tz.c
QcomPkg/Drivers/PILDxe/pil_loader.c
QcomPkg/SocPkg/Pakala/Security_profile/pakala_security_profile.xml
~~~

It is not substituted for the exact device artifacts.

# 2. Exact current ABL outer image

Current image:

~~~text
size
278528 / 0x44000

SHA256
c6aa137b7e2b8c6f86040438022488eee6b2a69a1fad95f109a86c8a77d64bed
~~~

It is an ELF32 little-endian ARM executable:

~~~text
entry       0x9FA00000
e_phoff     0x34
e_phentsize 0x20
e_phnum     3
~~~

Exact program headers:

~~~text
PHDR 0
type    0
offset  0x00000
filesz  0x00094
memsz   0
flags   0x07000000

PHDR 1
type    PT_LOAD
offset  0x01000
vaddr   0x9FA00000
paddr   0x9FA00000
filesz  0x42000
memsz   0x42000
flags   0x7
align   0x1000

PHDR 2
type    0
offset  0x43000
filesz  0x0F38
memsz   0x0F38
flags   0x02000000
align   0x1000
~~~

PHDR 2 is the Qualcomm hash/authentication segment.

# 3. LinuxLoader is inside the covered PT_LOAD

The current ABL FV contains the LZMA stream beginning at:

~~~text
0x1078
~~~

Exact decode:

~~~text
compressed stream consumed  0x41233
stream end                  0x422AB
decompressed size           0xC30C8
PE offset in output          0xB8
~~~

The extracted PE is the profiled current LinuxLoader:

~~~text
size
798720

SHA256
4d4aaa42e86917e65c2b2c3fdd477851282a31d5c64f9ca9d20710a650da8b4b
~~~

The fake-lock output is:

~~~text
SHA256
34dbedd47b33acf4c131b5db927a5ef7cf9be214facbe6f98fe044dc448b61f0

changed bytes
7
~~~

Exact inner PE offsets:

~~~text
0x4AF3C
0x4AF3D
0x4AF3F
0x4AF41
0x4AF42
0xA2CA8
0xA2CA9
~~~

Therefore a repacked fake-locked LinuxLoader necessarily changes the compressed
bytes inside outer ABL PHDR 1. The original compressed byte sequence cannot
decode into a different LinuxLoader.

# 4. Exact SHA-384 coverage proof

The hash segment begins at:

~~~text
file offset 0x43000
size        0x0F38
~~~

Its v7 header decodes as:

~~~text
reserved                    0
version                     7
common metadata size        0x18
QTI metadata size           0
OEM metadata size           0xE0
hash table size             0x90
QTI signature size          0
QTI certificate-chain size  0
OEM signature slot size     0x68
OEM certificate-chain slot  0xD20
~~~

The hash table begins at hash-segment relative offset 0x120.

Calculated from the exact ELF header and program-header region:

~~~text
SHA384(abl[0x00000:0x00094])

12f998e42040b0f71e8a428b1e36ddef
56e08b71c170ebf37ae9e996d58f45f7
4b6589aed71cc3299f76df659e0f6140
~~~

The exact same 48 bytes are stored at 0x43120.

More importantly:

~~~text
SHA384(abl[0x01000:0x43000])

bf3783c6ca594f014528fe541b72f7ba
9f71ee298fad91f631d190639aec3a1e
2967795cdc4645f07a26b65528498f7d
~~~

The exact same digest is stored at 0x43150.

The third 48-byte hash-table entry at 0x43180 is zero for the hash segment
itself.

So the LinuxLoader-containing ABL PT_LOAD has an exact SHA-384 digest in the
current hash table. A one-byte in-memory mutation inside this PT_LOAD immediately
produces a different digest. The verifier reproduces that check without
producing a modified ABL image.

# 5. The current hash table is itself cryptographically signed

The signed v7 region is:

~~~text
ABL file range
0x43000 .. 0x431B0

size
0x1B0

SHA384
0156478f74e72b4ed1cbd1e42750e217
9b7a6690bce42ac2b37a6bee9356fc4a
2f0a3a2c6dbf48fefd1a91538cd8998d
~~~

That range consists of:

~~~text
v7 hash-segment header
+ common metadata
+ OEM metadata
+ the 3-entry SHA-384 hash table
~~~

The OEM signature slot starts at:

~~~text
0x431B0
slot size 0x68
~~~

The DER ECDSA signature itself is 103 bytes and is followed by one zero padding
byte.

Using the leaf certificate embedded in this exact ABL:

~~~text
openssl dgst -sha384 -verify leaf_pub.pem -signature sig.der signed_region.bin
~~~

returns:

~~~text
Verified OK
~~~

Therefore the current OPLUS signature directly authenticates the v7 region that
contains the PT_LOAD SHA-384 digest.

This closes the key ambiguity:

~~~text
change fake-lock LinuxLoader
    ->
compressed ABL PT_LOAD changes
    ->
PT_LOAD SHA384 changes
    ->
hash-table digest must change
    ->
signed hash-table region changes
    ->
existing OEM signature no longer verifies
~~~

Recomputing only the SHA-384 entry is therefore not sufficient.

# 6. Exact OPLUS certificate chain

The current ABL contains three DER certificates.

## Leaf

~~~text
offset 0x43218
size   0x290

CN = OPLUS SM8750 Attestation

SHA256
6BD69F80B3B896D213F5BF30766B3AFD
75841FC30598E36EE24BAC5E38433730
~~~

## Intermediate

~~~text
offset 0x434A8
size   0x29C

CN = OPLUS Attestation CA

SHA256
B830588727064A2ADAF94B9E9A4504D3
151582621368D181A878F4ACA60B1BED
~~~

## Root

~~~text
offset 0x43744
size   0x277

CN = OPLUS ROOT CA 1

SHA256
35609A6703E2F41A6FFDAC2E362C15E2
EE318B7BF561DA0770710941D84BDD89
~~~

OpenSSL verification confirms the leaf/intermediate/root chain. The leaf public
key is EC P-384 and the certificate signature algorithm is ECDSA-with-SHA384.

# 7. XBL_CONFIG confirms the active ABL PIL contract

Exact current XBL_CONFIG:

~~~text
SHA256
9760062003776a481495286d6c0233bda307100ac2e95cb7b23fcb5aa17bf64d
~~~

Active node:

~~~text
/soc/pil/pil_images/ABL_CFG

Version  = 5
Type     = 1       # ELF_FV
FwName   = ABL
SubsysID = 21
Unlock   = 1
~~~

The matched Pakala security profile identifies:

~~~text
image id = ABL
authenticator_oem = TZ-PIL
sw_id = 0x1C
ELF format = ELF-V7
segment hash = SHA384
signature = ECDSA384 / SHA384
~~~

# 8. What Unlock=1 means

The matched PILDxe control flow is:

~~~text
PilLoadElfFile
    ->
CopyMetaDataFromLoadedElf
    includes ELF header + PHDRs + hash segment
    ->
PilValidateMetadata
    -> TZ_PIL_INIT_ID
    ->
PilSetupMemoryRange
    -> TZ_PIL_MEM_ID
    ->
PilAuthAndReset
    -> TZ_PIL_AUTH_RESET_ID
    ->
PilPostLoad
    -> if (Cfg->Unlock)
           TZ_PIL_UNLOCK_XPU_ID
    -> mount authenticated FV
~~~

So ABL_CFG.Unlock = 1 is a **post-authentication subsystem/XPU unlock
operation**. It is not an Android bootloader-unlock bypass.

The matched PILDxe source contains no DeviceInfo/IsUnlocked gate in this
authentication path.

# 9. Runtime state confirms the layers are separate

The supplied bootloader log simultaneously shows:

~~~text
Secure Boot: On
PROD Mode     : TRUE
Retail        : TRUE
~~~

and later:

~~~text
lock_state:0
VB2 boot state: orange
~~~

So the handset itself demonstrates:

~~~text
hardware / early firmware Secure Boot = enabled
Android bootloader state              = unlocked
~~~

Being able to write a partition from an unlocked Fastboot context would not
establish that TZ-PIL will execute modified contents.

**Write permission and execution authentication are separate questions.**

# 10. M25-A decision

For the exact current build:

~~~text
repack 7-byte fake-lock LinuxLoader into abl.img
    ->
changes SHA384-covered outer PT_LOAD
    ->
requires a new digest in signed v7 hash table
    ->
invalidates current OPLUS ECDSA-P384 signature
    ->
stock TZ-PIL authentication contract is no longer satisfied
~~~

Final route state:

~~~text
C1 direct patched ABL on inactive slot
= CLOSED-BY-PIL-AUTH
~~~

This does not claim that no authentication vulnerability can exist. It means no
evidence-supported stock path was found in which the modified ABL preserves the
existing authenticated image contract.

No modified abl_a or abl_b should be written on the basis of M25-A.

# 11. Reproducible checker

Added:

~~~text
profiles/PJZ110_16.0.10.501_m25a.json
tools/pjz110_m25a_check.py
tests/test_pjz110_m25a_check.py
~~~

Example:

~~~powershell
python .\tools\pjz110_m25a_check.py `
  --abl .\abl.img `
  --xbl-config .\xbl_config.img `
  --original-linuxloader .\LinuxLoader.original.efi `
  --fake-linuxloader .\LinuxLoader.fake_locked.efi `
  --bootloader-log .\bootloader_log.txt `
  --require-openssl
~~~

Expected:

~~~text
M25-A exact profile       : PASS
ABL LOAD SHA384 coverage : PASS
LinuxLoader 7-byte delta : PASS
signed hash-table ECDSA  : PASS
direct patched ABL       : CLOSED-BY-PIL-AUTH
RESULT                   : PASS
~~~

RESULT: PASS means the **analysis conclusion reproduced**. It does not mean a
modified ABL passed authentication.

# 12. Next deployment work

M25-A closes the straightforward direct-ABL candidate.

M25-B should evaluate only candidates that do not require changing the signed
ABL PT_LOAD before TZ-PIL authentication, for example:

~~~text
post-auth / pre-LinuxLoader runtime substitution
reuse of an already authenticated carrier
a separately demonstrated authentication-bypass boundary
~~~

Any candidate must still preserve:

~~~text
real bootloader remains unlocked
no DeviceInfo/RPMB/KeyMaster/TEE state change
no blind boot-chain writes
no cross-ARB downgrade
A/B recovery plan before any persistent experiment
~~~
