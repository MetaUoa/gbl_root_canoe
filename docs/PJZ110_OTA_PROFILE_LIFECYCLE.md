# PJZ110 OTA/profile lifecycle

Every new OTA is a new exact profile. Existing offsets, hashes, module
boundaries, or deployment conclusions must not be reused by filename or
version similarity.

## Read-only intake

Collect the firmware package and, when available, a matching device capture.
At minimum the package directory must contain `abl.img`. Capture `xbl.img`
and `xbl_config.img` when the profile contains their hashes. Do not collect or
modify device-unique security partitions.

## Automated gate

Run:

```text
python tools/pjz110_ota_profile_check.py \
  --firmware-dir <firmware-directory>
```

The checker:

- matches `abl.img` to exactly one known PJZ110 profile;
- rejects unknown or ambiguous ABL hashes;
- verifies optional XBL/XBL_CONFIG hashes when present;
- extracts the profiled LinuxLoader read-only;
- re-runs the semantic fake-lock transformation;
- verifies the expected patched hash and exact seven-byte change count.

`PASS` means the known offline profile invariants reproduce. It does not mean
that a modified image is authenticated or safe to flash.

## New OTA procedure

1. Run the checker; an unknown image must be refused.
2. Analyze the new ABL and LinuxLoader independently.
3. Confirm the semantic candidate count is exactly one for each patch site.
4. Record original/patched hashes, changed offsets, and security-boundary
   observations in a new profile.
5. Add regression tests before accepting the profile.
6. Re-run the full PJZ110 test workflow.

No live validation or deployment route is reopened automatically by creating a
profile. Deployment requires a separate reviewed carrier and rollback contract.

## Supported-profile regression matrix

Run:

```text
python tools/pjz110_profile_matrix.py
```

The matrix requires unique profile IDs, builds, ABL hashes, original
LinuxLoader hashes, and patched hashes. It also verifies that every supported
generation retains both semantic patch descriptors and the seven-byte output
contract.
