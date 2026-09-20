# PJZ110 M25-B — post-authentication boundary review

Target: **OnePlus 13 China PJZ110 / SM8750 (Pakala)**
Build: **PJZ110_16.0.10.501(CN01)**

## Baseline result

The connected device was captured read-only on slot `_b`. The effective
payloads of `abl`, `xbl`, `xbl_config`, `uefi`, `imagefv`, and `toolsfv` match
the supplied firmware package byte-for-byte; the larger device partition files
contain only zero padding after the package payload.

The exact UEFI modules `QcomBds`, `PILDxe`, and `QcomChargerApp` were recovered
from the two nested decoded UEFI containers and match the existing R4 hashes.
The R4 verifier therefore reproduces `PASS / R4-D CLOSED` against the current
device capture.

## Runtime boundary

The device log reports `Secure Boot: On`, `Boot Interface: UFS`, and `Retail:
TRUE`. Runtime state remains split:

```text
/proc/bootconfig: unlocked / orange
Android properties: locked / green
```

This is the expected userspace-only spoof and is not an ABL fake-lock pass.

## M25-B candidate disposition

```text
direct patched ABL                         CLOSED-BY-PIL-AUTH
stock non-flashing carrier                CLOSED-BY-R4
post-auth/pre-LinuxLoader substitution    CLOSED-NO-STOCK-EXTERNAL-PRODUCER
already-authenticated carrier             CLOSED-NO-STOCK-EXTERNAL-PRODUCER
```

The exact baseline proves that the known authenticated UFS/PIL path and stock
Retail configuration are unchanged. `PILDxe` takes caller-provided buffers
through metadata validation, PAS/TZ authentication, `POST_AUTH_AND_RESET`, and
the optional XPU unlock before processing the authenticated FV. `QcomBds`
launches applications from an already-mounted guided FV. Neither path supplies
an external producer; using either API first requires an already-running trusted
UEFI caller, which is the missing carrier itself.

This closes the identified stock paths for the exact current build. It does not
prove an arbitrary post-authentication memory mutation or unknown vulnerability
is impossible. Consequently no live execution or persistent experiment is
authorized by this stage.

## Reproduction

```text
python tools/pjz110_m25b_check.py \
  --capture-dir <firmware-dir>/pjz110-m25b-capture-20260920
```

Expected result is `M25-B exact capture baseline : PASS`; both candidate
boundaries are closed for the exact current stock Retail/UFS path.

The exact module extraction is also reproducible without the unavailable
platform-specific FV tooling:

```text
python tools/pjz110_extract_exact_modules.py \
  --decoded-dir <firmware-dir> \
  --output-dir <capture-dir>/extracted-uefi-modules
```

Every extracted slice is verified against its profile SHA-256 before it is
written. Existing mismatched outputs are never replaced.
