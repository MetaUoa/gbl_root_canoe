# PJZ110 three-generation boot-chain comparison

Device: **OnePlus 13 China (PJZ110)**  
Platform: **SM8750 / Pakala**

Compared baselines:

1. `PJZ110_15.0.0.702(CN01)`
2. `PJZ110_16.0.3.501(CN01)`
3. `PJZ110_16.0.10.501(CN01)`

## Exact inputs

| Build | ABL SHA256 | XBL SHA256 | XBL_CONFIG SHA256 |
| --- | --- | --- | --- |
| 15.0.0.702 | `fa9a688137393b101d65b8833033d3ddbd9674abf546557e07d43bbe3ff6b6a2` | `74c196f99aba348e2eb478c8c5fa2d4361867dc597b14c6c44fc8c78cf75a20e` | `0f36036b2ab69b1b5eea79bb7bfa866cc6f773e8086de1df5346e48194d11b34` |
| 16.0.3.501 | `320615838af3094f56e90613172d8bf0a3ed8a81a9b4ea9663b92142508478ca` | `95167b7bbed3005427905f9bcc1f1e56e2ba273f5a7166605fa47c6de211e158` | `0ddc4b0d88290559ad7999154bbe24948b330c8170ded48fcd2ccde9f906ceed` |
| 16.0.10.501 | `c6aa137b7e2b8c6f86040438022488eee6b2a69a1fad95f109a86c8a77d64bed` | `fe5010f89c8da863032281c33a2a06f26ca799fa9f3eac61c81575176d504de2` | `9760062003776a481495286d6c0233bda307100ac2e95cb7b23fcb5aa17bf64d` |

## XBL generations

15.0.0.702:

`BOOT.MXF.2.5.1-00040.1-PAKALA-1.81269.25`

16.0.3.501 and 16.0.10.501:

`BOOT.MXF.2.5.1-00265-PAKALA-1.104700.25`

This is a real XBL generation jump between ColorOS 15 and ColorOS 16. In contrast, the two sampled ColorOS 16 XBL images differ by only about 200 bytes.

Sizes also change:

| Build | XBL size | XBL_CONFIG size |
| --- | ---: | ---: |
| 15.0.0.702 | 1,175,552 | 356,352 |
| 16.0.3.501 | 1,191,936 | 360,448 |
| 16.0.10.501 | 1,191,936 | 360,448 |

## LinuxLoader generations

| Build | Size | SHA256 | .text |
| --- | ---: | --- | ---: |
| 15.0.0.702 | `0xBE000` | `5401e5daeed7260066a6505a31f59470d07c57f27bc6871738866f713c03fed6` | `0x96000` |
| 16.0.3.501 | `0xC4000` | `1873bdfd2654decba1ac50d2c0d1d3aa61423f11123f7301743be78da7f63333` | `0x9C000` |
| 16.0.10.501 | `0xC3000` | `4d4aaa42e86917e65c2b2c3fdd477851282a31d5c64f9ca9d20710a650da8b4b` | `0x9B000` |

All three contain the software-visible state machinery needed for the offline fake-lock patch:

- `androidboot.vbmeta.device_state`
- `unlocked` / `locked`
- `androidboot.verifiedbootstate=`
- `orange` / `green`
- OPlus unlocked-state warning strings
- `KeyMasterSetRotAndBootState`

15.0.0.702 and 16.0.3.501 additionally retain:

- `LoadImageNoAuthWrapper`
- `LoadBootImageNoAuth`
- `LoadImageAndAuthVB1`

These disappear by 16.0.10.501.

## Legacy EFISP loader marker

All three extracted LinuxLoaders contain:

- ASCII `efisp`: **0**
- UTF-16 LE `efisp`: **0**

The original `gbl_root_canoe` legacy GBL patch searches this marker. Therefore none of these three exact PJZ110 ABLs can be accepted as a known legacy direct-EFISP loader by that mechanism.

This does **not** prove that every possible staged EFI development path is absent. It does mean the existing SM8845/SM8850 persistent-loader patch cannot simply be ported by adding PJZ110 offsets.

## 15.0.0.702 offline fake-lock profile

Device-state block:

- unlock ADRP/ADD: `0x3BDFC / 0x3BE00`
- lock ADRP/ADD: `0x3BE04 / 0x3BE08`
- key ADRP/ADD: `0x3BE0C / 0x3BE10`
- CMP/CSEL: `0x3BE18 / 0x3BE1C`

Verified-state table:

- table base: `0x9B9A8`
- green pointer: `0x9B9B0 -> 0x825A2`
- orange pointer: `0x9B9C0 -> 0x7F72B`

Patched output SHA256:

`e37df7c53963f524d05e751ffe17f04a7315b368cee8bfaf4ed55dc7fd7556f1`

Changed byte count: **7**.

The post-patch instruction sequence makes both CSEL inputs resolve to the stock `locked` string. Only the Android-visible state output and the orange->green table pointer are changed; Qualcomm DeviceInfo and KeyMaster/TEE are untouched.

## Practical conclusion

The project now has three exact offline fake-lock profiles spanning ColorOS 15 and 16, but **no sampled PJZ110 firmware exposes the legacy persistent EFISP loader marker**.

Therefore the next engineering step is no longer “find the same marker in one more OTA”. It is to investigate an alternative chainload/deployment mechanism for PJZ110 or establish that this device family never shipped the direct loader used by the original SM8845/SM8850 exploit path.

Device flashing remains disabled.
