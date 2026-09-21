# PJZ110 M25-C — A/B recovery and rollback contract

This is a design gate, not authorization to flash or modify a boot-chain
partition. The current `.501` Retail/UFS analysis has no surviving deployment
candidate, so the contract remains unapplied.

## Required preconditions

An experiment cannot proceed unless all are true:

- the candidate is supported by an exact firmware profile and a reproducible
  offline checker;
- the original active and inactive boot-chain payloads have been hashed and
  archived off-device;
- the candidate does not alter RPMB, KeyMaster, TEE RootOfTrust,
  `DeviceInfo.is_unlocked`, or rollback-index state;
- the carrier is temporary, or the modified slot can be selected without
  overwriting the known-good slot;
- the recovery path is independently testable before the first modification.

## Slot contract

```text
known-good slot       preserved verbatim
candidate slot        isolated A/B target only
activation            explicit, reversible slot selection
failure detection     boot counter + boot-success evidence
rollback trigger      failed boot, wrong security state, or missing evidence
rollback action       select known-good slot; never rewrite both slots
```

The known-good slot must remain bootable without relying on the candidate's
modified code. No experiment may consume both A/B copies or alter a partition
shared by both paths without an independently verified recovery image.

## Abort conditions

Abort before execution if any of the following occurs:

- authentication status is unknown or differs from the exact profile;
- the device reports a changed ARB/rollback index;
- `/proc/bootconfig` is not collected before and after the experiment;
- the real bootloader state cannot be independently confirmed as unlocked;
- the candidate requires writing UEFI variables, security partitions, or
  undocumented fastboot commands;
- the recovery slot cannot be selected using a read-only preflight procedure.

## Evidence package

Before and after any future candidate test, retain only the minimum required
evidence:

- partition names, sizes, and SHA-256 hashes;
- `/proc/bootconfig`, `/proc/cmdline`, `getprop`, and bootloader log;
- active slot and boot-success state;
- candidate checker JSON output;
- a recovery transcript showing return to the known-good slot.

Until a candidate satisfies this contract, the correct result is **NO-GO**.
