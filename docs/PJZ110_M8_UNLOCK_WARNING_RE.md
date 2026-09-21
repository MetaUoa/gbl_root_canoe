# PJZ110 M8 — OPlus unlock-warning boundary

Target: **OnePlus 13 China PJZ110 / SM8750 (Pakala)**
Build: **PJZ110_16.0.10.501(CN01)**

## Exact `.501` result

The warning analyzer finds exactly one ADRP+ADD reference pair connecting:

```text
Orange State\n
Your device has been unlocked and can't be trusted\n
```

The warning resources are present at these exact LinuxLoader file offsets:

```text
Orange State                         0xA2CD0
OPlus warning title                  0x8C5ED
Long warning paragraph               0xA1D1E
warning ADRP+ADD pair                0x45A00
warning function                     0x45980..0x45A9C
caller BL                            0x0F0F4
```

The existing warning patcher searches backwards only 64 bytes for a `CBZ W`
that is sourced from the legacy global unlock-state byte. The expanded decoder
finds no such branch. The local warning function instead contains a
`B.LS` at `0x459FC` targeting its return path (`0x45A9C`), and is called from
`0x0F0F4`. The predicate feeding that condition is not the legacy global
unlock-state byte; it is derived from the function's preceding call/data path.
The legacy warning patch therefore has no proven target on this profile.

The current seven-byte semantic fake-lock transformation changes only:

```text
0x4AF3C  0x4AF3D  0x4AF3F  0x4AF41  0x4AF42
0xA2CA8  0xA2CA9
```

None overlaps the warning resource or warning-control region. The current
fake-lock output consequently does **not** suppress the OPlus warning.

## Decision

```text
warning resources present             PASS
unique warning reference              PASS
legacy CBZ/global-state target         NOT FOUND
7-byte patch suppresses warning       NO
M8 status                              CLOSED-NO-SAFE-UI-ONLY-PATCH
```

No warning-suppression patch is authorized. The legacy patch has no target,
the state source is the VerifiedBoot security protocol, and no alternative
UI-only state-machine transition has been proven safe. String replacement or
changing the protocol result would cross the established safety boundary.

The exact `.501` checker records the unresolved predicate and the local
`B.LS` gate without treating either as a patch target.

The older exact artifacts have now been supplied and checked. All three
generations share the same warning boundary shape:

| Build | Warning ADRL | Caller BL | Local gate | Legacy CBZ.W |
|---|---:|---:|---|---:|
| 15.0.0.702 | `0x368C0` | `0x0EF10` | `B.LS -> 0x3695C` | none |
| 16.0.3.501 | `0x46E50` | `0x0F29C` | `B.LS -> 0x46EEC` | none |
| 16.0.10.501 | `0x45A00` | `0x0F0F4` | `B.LS -> 0x45A9C` | none |

The matrix is recorded in `profiles/PJZ110_M8_WARNING_MATRIX.json`. The
cross-generation result strengthens the conclusion that the legacy warning
patcher is not applicable, but the underlying state predicate remains
unresolved; no warning patch is authorized.

The caller-side data flow is also stable. A helper return value is masked,
stored at `[SP+0x40]`, reloaded into a bounded jump-table switch, and warning
display is case index `1` in every generation. The exact helper calls are
`0xEE78`, `0xF20C`, and `0xF064`, targeting wrappers at `0x19E6C`,
`0x1A7CC`, and `0x1A9BC` respectively. This identifies the warning state enum
and its protocol-wrapper boundary, but not yet the semantic source of that enum; naming it as
`DeviceInfo.is_unlocked` or an OPlus unlock record would still be speculative.

Protocol attribution is now structural rather than string-only. Every exact
LinuxLoader contains one `QCOM_VERIFIEDBOOT_PROTOCOL` GUID
(`8e5eff91-21b6-47d3-af2b-c15a01e020ec`), and every wrapper calls vtable offset
`0x38`. In `EFIVerifiedBoot.h`, offset `0x38` is `VBIsDeviceSecure`. Therefore
the warning state source is identified as
`QCOM_VERIFIEDBOOT_PROTOCOL.VBIsDeviceSecure`; only the returned BOOLEAN's
polarity at this caller remains unresolved.

That remaining polarity does not change the patch decision. Either polarity is
a real VerifiedBoot security result, not an independent presentation-only
flag. M8 is therefore closed for the three exact profiles as
`CLOSED-NO-SAFE-UI-ONLY-PATCH`.

## Reproduction

```text
python tools/pjz110_warning_research.py \
  <capture-dir>/LinuxLoader.original.efi
```

The tool is read-only and refuses unknown exact profiles.

For the fully bound `.501` profile run:

```text
python tools/pjz110_m8_warning_check.py \
  <capture-dir>/LinuxLoader.original.efi
```
