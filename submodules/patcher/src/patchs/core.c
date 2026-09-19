#include "arm64_inst/utils.h"
#include "patchs/core.h"
#include <stdlib.h>
#include <string.h>

int32_t patch_abl_gbl(char* buffer, int32_t size) {
    char target[]      = { 'e',0, 'f',0, 'i',0, 's',0, 'p',0 };
    char replacement[] = { 'n',0, 'u',0, 'l',0, 'l',0, 's',0 };
    int32_t target_len = sizeof(target);
    for (int32_t i = 0; i < size - target_len; ++i) {
        if (memcmp(buffer + i, target, target_len) == 0) {
            memcpy(buffer + i, replacement, target_len);
            return 0;
        }
    }
    return -1;
}

int16_t Original[] = {
    -1, 0x00, 0x00, 0x34, 0x28, 0x00, 0x80, 0x52,
    0x06, 0x00, 0x00, 0x14, 0xE8, -1, 0x40, 0xF9,
    0x08, 0x01, 0x40, 0x39, 0x1F, 0x01, 0x00, 0x71,
    0xE8, 0x07, 0x9F, 0x1A, 0x08, 0x79, 0x1F, 0x53
};
int16_t Patched[] = {
    -1, -1, -1, -1, 0x08, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1
};

int32_t patch_abl_bootstate(char* buffer, int32_t size,
                          int8_t* lock_register_num, int32_t* offset) {
    int32_t pattern_len = sizeof(Original) / sizeof(int16_t);
    int32_t patched_count = 0;
    if (size < pattern_len) return 0;
    for (int32_t i = 0; i <= size - pattern_len; ++i) {
        bool match = true;
        for (int32_t j = 0; j < pattern_len; ++j) {
            if (Original[j] != -1 && (uint8_t)buffer[i + j] != (uint8_t)Original[j]) {
                match = false; break;
            }
        }
        if (match) {
            *lock_register_num = (int8_t)((uint8_t)buffer[i] & 0x1F);
            *offset = i;
            #ifndef DISABLE_PATCH_3
            for (int32_t j = 0; j < pattern_len; ++j)
                if (Patched[j] != -1) buffer[i + j] = (char)Patched[j];
            #endif
            patched_count++;
            i += pattern_len - 1;
        }
    }
    return patched_count;
}
// track_forward_patch_strb callback example: patch STRB to STR, so we can use the same register for 64-bit value instead of 8-bit, which is more likely to be used in real code and easier to track back to source.
int32_t patch_strb_to_str_forward_callback(char* buffer, int32_t size, int32_t off, DecodedInst d, int32_t anchor_offset) {
    if (d.type == INST_STRB_IMM || d.type == INST_STRB_POST || d.type == INST_STRB_PRE) {
        if (off > anchor_offset) {
            StrbInfo si = decode_any_strb(d.raw);
            if (si.rn == 31) {
                printf("  0x%X: STRB W%d,[SP,#0x%X] ** SINK (after anchor0x%X) **\n",
                    off, si.rt, si.imm, anchor_offset);
            } else {
                printf("  0x%X: STRB W%d,[X%d,#0x%X] ** SINK (after anchor0x%X) **\n",
                    off, si.rt, si.rn, si.imm, anchor_offset);
            }
            printf("  Before: %02X %02X %02X %02X\n",
                       (uint8_t)buffer[off], (uint8_t)buffer[off+1],
                       (uint8_t)buffer[off+2], (uint8_t)buffer[off+3]);
            write_instr(buffer, off, strb_with_reg(d.raw, 31));

            printf("  After : %02X %02X %02X %02X (Rt -> WZR)\n",
                       (uint8_t)buffer[off], (uint8_t)buffer[off+1],
                       (uint8_t)buffer[off+2], (uint8_t)buffer[off+3]);
            return SUCCESS;
        }
    }
    return NEED_MORE;
}
static int32_t track_forward_patch_strb(char* buffer, int32_t size, int32_t ldrb_off,
                                      int8_t src_reg, int32_t anchor_off) {
    return track_forward(buffer, size, ldrb_off, src_reg, anchor_off, patch_strb_to_str_forward_callback);
}
//
int32_t source_callback(char* buffer, int32_t size, int32_t now_offset, int8_t current_target, int32_t anchor_offset) {
    printf("  Before: %02X %02X %02X %02X\n",
        (uint8_t)buffer[now_offset], (uint8_t)buffer[now_offset+1],
        (uint8_t)buffer[now_offset+2], (uint8_t)buffer[now_offset+3]);
    #ifndef DISABLE_PATCH_4
    write_instr(buffer, now_offset, encode_movz_w((uint8_t)current_target, 1));
    printf("  After : %02X %02X %02X %02X (MOV W%d, #1)\n",
        (uint8_t)buffer[now_offset], (uint8_t)buffer[now_offset+1],
        (uint8_t)buffer[now_offset+2], (uint8_t)buffer[now_offset+3],
        (int)current_target);
    #endif
    #ifndef DISABLE_PATCH_5
    int32_t fwd = track_forward_patch_strb(buffer, size, now_offset, current_target, anchor_offset);
    if (fwd <= 0) {
        printf("Warning: sink STRB not found after anchor 0x%X\n", anchor_offset);
        return -1;
    }
    printf("Sink patched successfully.\n");
    #endif
    return 0;
}

static bool is_cmp_w_imm_zero(uint32_t raw, uint8_t* rn) {
    if ((raw & 0x7F00001FU) != 0x7100001FU) return false;
    if (((raw >> 10) & 0xFFFU) != 0) return false;
    if (rn) *rn = (uint8_t)((raw >> 5) & 0x1FU);
    return true;
}

static bool is_csel_x_eq(uint32_t raw, uint8_t* rd, uint8_t* rn, uint8_t* rm) {
    if ((raw & 0xFFE00C00U) != 0x9A800000U) return false;
    if (((raw >> 12) & 0xFU) != 0) return false;
    if (rd) *rd = (uint8_t)(raw & 0x1FU);
    if (rn) *rn = (uint8_t)((raw >> 5) & 0x1FU);
    if (rm) *rm = (uint8_t)((raw >> 16) & 0x1FU);
    return true;
}

/*
 * Locate the PJZ110-style Android-visible device-state selector without
 * changing the input buffer.  Require the exact semantic shape used by all
 * three known PJZ110 generations:
 *
 *   ADRP+ADD -> "unlocked"
 *   ADRP+ADD -> "locked"
 *   ADRP+ADD -> "androidboot.vbmeta.device_state"
 *   ...
 *   CMP Wstate,#0
 *   CSEL Xvalue,Xlocked,Xunlocked,EQ
 */
static int32_t find_adrl_unlocked_to_locked(const char* buffer, int32_t size,
                                            uint64_t load_base,
                                            int32_t* match_offset) {
    int32_t count = 0;
    if (match_offset) *match_offset = -1;
    if (size < 36) return 0;

    for (int32_t i = 0; i <= size - 36; i += 4) {
        DecodedInst a0 = decode_at((char*)buffer, i);
        DecodedInst a1 = decode_at((char*)buffer, i + 4);
        DecodedInst b0 = decode_at((char*)buffer, i + 8);
        DecodedInst b1 = decode_at((char*)buffer, i + 12);
        DecodedInst k0 = decode_at((char*)buffer, i + 16);
        DecodedInst k1 = decode_at((char*)buffer, i + 20);

        if (a0.type != INST_ADRP || a1.type != INST_ADD_X_IMM) continue;
        if (a1.rt != a0.rt || a1.rn != a0.rt) continue;
        if (b0.type != INST_ADRP || b1.type != INST_ADD_X_IMM) continue;
        if (b1.rt != b0.rt || b1.rn != b0.rt) continue;
        if (k0.type != INST_ADRP || k1.type != INST_ADD_X_IMM) continue;
        if (k1.rt != k0.rt || k1.rn != k0.rt) continue;
        if (a0.rt == b0.rt) continue;

        int64_t unlocked = calc_adrl_file_offset(buffer, i, load_base);
        int64_t locked = calc_adrl_file_offset(buffer, i + 8, load_base);
        int64_t key = calc_adrl_file_offset(buffer, i + 16, load_base);
        if (!str_at(buffer, size, unlocked, "unlocked")) continue;
        if (!str_at(buffer, size, locked, "locked")) continue;
        if (!str_at(buffer, size, key, "androidboot.vbmeta.device_state")) continue;

        uint8_t state_reg = 0, csel_rd = 0, csel_rn = 0, csel_rm = 0;
        if (!is_cmp_w_imm_zero(read_instr(buffer, i + 28), &state_reg)) continue;
        if (!is_csel_x_eq(read_instr(buffer, i + 32), &csel_rd, &csel_rn, &csel_rm)) continue;
        if (csel_rn != b0.rt || csel_rm != a0.rt) continue;

        printf("Found semantic device-state selector at 0x%X:\n", i);
        printf("  unlocked X%d -> file:0x%llX\n", a0.rt, (unsigned long long)unlocked);
        printf("  locked   X%d -> file:0x%llX\n", b0.rt, (unsigned long long)locked);
        printf("  state W%d, output X%d\n", state_reg, csel_rd);
        if (match_offset) *match_offset = i;
        count++;
    }
    return count;
}

static bool apply_adrl_unlocked_to_locked_at(char* buffer, int32_t size,
                                             int32_t i) {
    if (i < 0 || i + 16 > size) return false;
    DecodedInst a0 = decode_at(buffer, i);
    DecodedInst a1 = decode_at(buffer, i + 4);
    DecodedInst b0 = decode_at(buffer, i + 8);
    DecodedInst b1 = decode_at(buffer, i + 12);
    if (a0.type != INST_ADRP || a1.type != INST_ADD_X_IMM ||
        b0.type != INST_ADRP || b1.type != INST_ADD_X_IMM) {
        return false;
    }
    uint8_t unlocked_reg = a0.rt;
    uint32_t new_adrp = adrp_with_rd(b0.raw, unlocked_reg);
    uint32_t new_add = add_with_reg(b1.raw, unlocked_reg);
    printf("  device-state patch: 0x%X %08X->%08X, 0x%X %08X->%08X\n",
           i, a0.raw, new_adrp, i + 4, a1.raw, new_add);
    write_instr(buffer, i, new_adrp);
    write_instr(buffer, i + 4, new_add);
    return true;
}


static uint64_t read_u64_le(const char* buffer, int32_t off) {
    uint64_t value = 0;
    memcpy(&value, buffer + off, sizeof(value));
    return value;
}

static void write_u64_le(char* buffer, int32_t off, uint64_t value) {
    memcpy(buffer + off, &value, sizeof(value));
}

/*
 * Locate the PJZ110 verified-state enum/string table without modifying it:
 *   0 -> green, 1 -> orange, 2 -> yellow, 3 -> red.
 */
static int32_t find_verified_state_table(const char* buffer, int32_t size,
                                         int32_t* table_offset,
                                         uint64_t* green_value) {
    int32_t found = -1;
    int32_t count = 0;
    uint64_t found_green = 0;
    if (table_offset) *table_offset = -1;
    if (green_value) *green_value = 0;
    if (size < 64) return 0;

    for (int32_t i = 0; i <= size - 64; i += 8) {
        if (read_u64_le(buffer, i) != 0 ||
            read_u64_le(buffer, i + 16) != 1 ||
            read_u64_le(buffer, i + 32) != 2 ||
            read_u64_le(buffer, i + 48) != 3) {
            continue;
        }

        uint64_t green  = read_u64_le(buffer, i + 8);
        uint64_t orange = read_u64_le(buffer, i + 24);
        uint64_t yellow = read_u64_le(buffer, i + 40);
        uint64_t red    = read_u64_le(buffer, i + 56);
        if (green >= (uint64_t)size || orange >= (uint64_t)size ||
            yellow >= (uint64_t)size || red >= (uint64_t)size) {
            continue;
        }
        if (!str_at(buffer, size, (int64_t)green, "green") ||
            !str_at(buffer, size, (int64_t)orange, "orange") ||
            !str_at(buffer, size, (int64_t)yellow, "yellow") ||
            !str_at(buffer, size, (int64_t)red, "red")) {
            continue;
        }
        found = i;
        found_green = green;
        count++;
    }

    if (count == 1) {
        if (table_offset) *table_offset = found;
        if (green_value) *green_value = found_green;
        printf("Found semantic verified-state table at 0x%X\n", found);
    } else {
        printf("Verified-state table candidates: %d (expected exactly 1)\n", count);
    }
    return count;
}

static bool apply_verified_state_green_at(char* buffer, int32_t size,
                                          int32_t table_offset,
                                          uint64_t green_value) {
    if (table_offset < 0 || table_offset + 32 > size ||
        green_value >= (uint64_t)size) {
        return false;
    }
    uint64_t orange = read_u64_le(buffer, table_offset + 24);
    printf("  verified-state patch: state 1 0x%llX -> 0x%llX\n",
           (unsigned long long)orange, (unsigned long long)green_value);
    write_u64_le(buffer, table_offset + 24, green_value);
    return true;
}

static bool is_known_pjz110_semantic_profile(int32_t size,
                                              int32_t device_state_offset,
                                              int32_t verified_table_offset) {
    return
        (size == 798720 && device_state_offset == 0x4AF3C && verified_table_offset == 0xA2C90) ||
        (size == 802816 && device_state_offset == 0x4C38C && verified_table_offset == 0xA3CB0) ||
        (size == 778240 && device_state_offset == 0x3BDFC && verified_table_offset == 0x9B9A8);
}

#include "patchs/oplus/warning.h"
#include "patchs/oplus/forceenablefastboot.h"
bool PatchBuffer(char* data, int32_t size) {
    if (patch_abl_gbl(data, size) != 0)
        printf("Warning: Failed to patch ABL GBL\n");

    /*
     * Locate the Android-visible selector before writing it.  The legacy
     * SM8845/SM8850 path still uses this patch when available; the PJZ110 path
     * additionally requires a known semantic profile and verified-state table.
     */
    int32_t semantic_adrl_offset = -1;
    int32_t semantic_adrl_count =
        find_adrl_unlocked_to_locked(data, size, 0, &semantic_adrl_offset);
    if (semantic_adrl_count > 1) {
        printf("Error: Multiple semantic device-state selectors found (%d)\n",
               semantic_adrl_count);
        return false;
    }

    int32_t offset = -1;
    int8_t lock_register_num = -1;
    int32_t num_patches =
        patch_abl_bootstate(data, size, &lock_register_num, &offset);

    if (num_patches == 0) {
        int32_t verified_table_offset = -1;
        uint64_t green_value = 0;
        int32_t verified_count =
            find_verified_state_table(data, size,
                                      &verified_table_offset, &green_value);

        if (semantic_adrl_count != 1 || verified_count != 1) {
            printf("Error: Failed to find a unique PJZ110 semantic fake-lock path\n");
            return false;
        }
        if (!is_known_pjz110_semantic_profile(
                size, semantic_adrl_offset, verified_table_offset)) {
            printf("Error: Semantic layout is not a known PJZ110 firmware profile; refusing to patch\n");
            return false;
        }
        if (!apply_adrl_unlocked_to_locked_at(
                data, size, semantic_adrl_offset) ||
            !apply_verified_state_green_at(
                data, size, verified_table_offset, green_value)) {
            printf("Error: Failed to apply PJZ110 semantic fake-lock patch\n");
            return false;
        }

        printf("PJZ110 semantic ABL fake-lock applied successfully\n");
        printf("  androidboot.vbmeta.device_state -> locked\n");
        printf("  verified boot state 1 (orange) -> green\n");
        printf("  DeviceInfo / VBRwDeviceState: untouched\n");
        printf("  KeyMaster / TEE RootOfTrust: untouched\n");
        return true;
    }

    /* Original legacy path. */
    if (semantic_adrl_count == 1) {
        if (!apply_adrl_unlocked_to_locked_at(
                data, size, semantic_adrl_offset)) {
            printf("Warning: Failed to apply ADRL fake-lock selector patch\n");
        }
    } else {
        printf("Warning: ADRL triple not found, skipping\n");
    }

    printf("Anchor offset : 0x%X\n", offset);
    printf("Lock register : W%d\n", (int)lock_register_num);
    printf("Boot patches: %d\n", num_patches);

    int32_t global_var_offset = -1;
    if (find_ldrB_instructio_reverse(
            data, size, offset, lock_register_num,
            &global_var_offset, source_callback) != 0) {
        printf("Warning: Failed to patch LDRB->STRB chain for W%d\n",
               (int)lock_register_num);
    }
    printf("Global variable offset (for warning patch): 0x%X\n",
           global_var_offset);

    if (!patch_warning(data, size, global_var_offset)) {
        printf("OPlus Warning: patch_warning failed\n");
    }
    if (!patch_fastboot(data, size, global_var_offset)) {
        printf("OPlus Warning: patch_fastboot failed\n");
    }

    return true;
}
