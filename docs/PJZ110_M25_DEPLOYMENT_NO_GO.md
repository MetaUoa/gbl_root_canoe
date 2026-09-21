# PJZ110 M25 — deployment design review: NO-GO

Target: **OnePlus 13 China PJZ110 / SM8750 (Pakala)**
Build: **PJZ110_16.0.10.501(CN01)**

## Decision

The deployment design review is complete for the exact current stock
Retail/UFS build:

```text
M25-A direct modified ABL            CLOSED-BY-PIL-AUTH
M25-B post-auth stock substitution   CLOSED-NO-STOCK-EXTERNAL-PRODUCER
M25-C recovery contract              DEFINED-BUT-UNAPPLIED
surviving deployment candidate       NONE
live execution                       NO-GO
```

The LinuxLoader-containing ABL segment is SHA-384 covered and its ELF-v7 hash
table is protected by an OPLUS ECDSA-P384 signature. Known stock
post-authentication paths require an already-running trusted UEFI caller and do
not provide an external producer. The analyzed Retail BDS, removable-media,
staged-memory, fastboot, and direct-ABL routes are therefore closed.

## Consequences

- M12 true-device carrier validation is deferred with no executable stage.
- M13 true-device ABL fake-lock validation is deferred with no executable
  stage.
- The M25-C A/B rollback contract is retained as a gate for a future candidate,
  but no candidate currently satisfies its preconditions.
- `BOOTAA64.EFI` remains a dormant read-only probe and must not be executed via
  an invented or persistent carrier.
- No ABL, UEFI, ImageFV, ToolsFV, XBL_CONFIG, UEFI-variable, or security-state
  write is authorized.

This is a scoped NO-GO decision, not a claim that unknown vulnerabilities
cannot exist. Reopen M25 only when new evidence identifies both an external,
reversible execution carrier and a recovery path that passes the M25-C
contract.

## Reopen criteria

At least one of the following must materially change:

- a new OTA changes the exact PIL/UEFI authentication boundary;
- a documented temporary carrier becomes externally controllable before
  LinuxLoader;
- a legitimate signing/authentication capability becomes available;
- a reversible deployment mechanism is demonstrated without modifying real
  security state.

Until then, maintenance is limited to exact-profile regression checks and
read-only analysis.
