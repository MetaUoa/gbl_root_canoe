# PJZ110 / SM8750 development branch

This branch contains the OnePlus 13 China (`PJZ110`) / Snapdragon 8 Elite
(`SM8750`, Pakala) adaptation work.

The ABL fake-lock transformation is complete offline for three exact PJZ110
firmware profiles, including the current `PJZ110_16.0.10.501(CN01)`. The
canonical semantic patcher is `tools/pjz110_fake_lock.py`; the C patcher also
contains the guarded PJZ110 semantic path.

The current exact output invariant is:

~~~text
original LinuxLoader
4d4aaa42e86917e65c2b2c3fdd477851282a31d5c64f9ca9d20710a650da8b4b

fake-locked LinuxLoader
34dbedd47b33acf4c131b5db927a5ef7cf9be214facbe6f98fe044dc448b61f0

changed bytes: 7
~~~

Deployment remains deliberately fail-closed. P0-P4 and R4-A→R4-D have now
closed the analyzed stock non-flashing execution routes for the exact current
Retail/UFS build:

~~~text
R1 generic BDS/ToolsFV Shell        CLOSED
R2 OEMSetupApp                       CLOSED / not configured
R3 Vol- removable-media EFI         CLOSED
R4 stock staged/memory EFI carrier  CLOSED
~~~

R4 found genuine internal staging mechanisms (PIL ABL `ELF_FV`, authenticated
PIL buffer loading, flashless RAM ABL FV support, and a debug `FV_Region`),
but no proven external, temporary, pre-LinuxLoader carrier for this shipping
configuration. Fastboot download memory is post-LinuxLoader and the stock
`boot` command consumes Android boot images, not arbitrary UEFI PE images.

Therefore **no live EFI execution or boot-chain write is currently requested**.
Do not flash ABL/UEFI/ToolsFV/XBL_CONFIG as a substitute.

The subsequent deployment review is also complete for the exact stock build:

~~~text
M25-A direct modified ABL            CLOSED-BY-PIL-AUTH
M25-B post-auth stock substitution   CLOSED-NO-STOCK-EXTERNAL-PRODUCER
M25-C rollback contract              DEFINED-BUT-UNAPPLIED
M25 overall                          NO-GO
~~~

OTA/profile lifecycle coverage is complete for the three known generations.
The OPlus warning path is closed separately as
`CLOSED-NO-SAFE-UI-ONLY-PATCH`; it is sourced from
`QCOM_VERIFIEDBOOT_PROTOCOL.VBIsDeviceSecure`, not a presentation-only flag.

See:

- [PJZ110 platform notes](docs/PJZ110_SM8750.md)
- [R4 staged/memory EFI analysis](docs/PJZ110_R4_STAGED_MEMORY_EFI_RE.md)
- [development roadmap](docs/PJZ110_ROADMAP.md)
- [true-device validation contract](docs/PJZ110_ABL_FAKE_LOCK_VALIDATION.md)
- [M25 deployment NO-GO](docs/PJZ110_M25_DEPLOYMENT_NO_GO.md)

Reproducible R4 exact-profile checker:

~~~text
profiles/PJZ110_16.0.10.501_r4.json
tools/pjz110_r4_check.py
tests/test_pjz110_r4_check.py
~~~
