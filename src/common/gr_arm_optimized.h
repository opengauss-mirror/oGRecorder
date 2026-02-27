/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * GR is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * gr_arm_optimized.h
 *
 * ARM instruction set optimizations (NEON SIMD, CRC32 hardware acceleration, etc.)
 *
 * IDENTIFICATION
 *    src/common/gr_arm_optimized.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_ARM_OPTIMIZED_H__
#define __GR_ARM_OPTIMIZED_H__

#include "gr_defs.h"
#include "gr_errno.h"
#include "gr_log.h"
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Compile-time macro control ====================
// ARM-specific optimizations are controlled via ENABLE_ARM_NEON and ENABLE_ARM_CRC32.
// Enable at build time with: -DENABLE_ARM_NEON or -DENABLE_ARM_CRC32.

#ifdef ENABLE_ARM_NEON
#include <arm_neon.h>
#endif

#ifdef ENABLE_ARM_CRC32
#include <arm_acle.h>
#endif

static inline status_t xor_sha256_hash_impl(
    const uint8_t *data_hash, const uint8_t *pre_hash, uint8_t *combine_hash)
{
    if (data_hash == NULL || pre_hash == NULL || combine_hash == NULL) {
        LOG_RUN_ERR("[hash]: invalid param.");
        return CM_ERROR;
    }
#ifdef ENABLE_ARM_NEON
    // ARM NEON: process 128 bits (16 bytes) per operation, 32 bytes need only 2 operations
    uint8x16_t data_vec1 = vld1q_u8(data_hash);        // load first 16 bytes
    uint8x16_t pre_vec1 = vld1q_u8(pre_hash);
    uint8x16_t result1 = veorq_u8(data_vec1, pre_vec1); // 128-bit XOR
    vst1q_u8(combine_hash, result1);                    // store result
    
    uint8x16_t data_vec2 = vld1q_u8(data_hash + 16);   // load next 16 bytes
    uint8x16_t pre_vec2 = vld1q_u8(pre_hash + 16);
    uint8x16_t result2 = veorq_u8(data_vec2, pre_vec2);
    vst1q_u8(combine_hash + 16, result2);
#else
    // Use 64-bit integers for batch XOR on generic platforms
    const uint64_t *data64 = (const uint64_t *)data_hash;
    const uint64_t *pre64 = (const uint64_t *)pre_hash;
    uint64_t *combine64 = (uint64_t *)combine_hash;
    
    combine64[0] = data64[0] ^ pre64[0];
    combine64[1] = data64[1] ^ pre64[1];
    combine64[2] = data64[2] ^ pre64[2];
    combine64[3] = data64[3] ^ pre64[3];
#endif
    return CM_SUCCESS;
}

static inline status_t compare_sha256_impl(
    const unsigned char *hash1, const unsigned char *hash2)
{
    if (hash1 == NULL || hash2 == NULL) {
        LOG_RUN_ERR("[hash]: invalid param, failed to compare hash");
        return CM_ERROR;
    }

#ifdef ENABLE_ARM_NEON
    // ARM NEON: use 128-bit vectors to compare 16 bytes at a time
    uint8x16_t h1_vec1 = vld1q_u8(hash1);
    uint8x16_t h2_vec1 = vld1q_u8(hash2);
    uint8x16_t diff1 = veorq_u8(h1_vec1, h2_vec1);  // XOR to get differences
    
    uint8x16_t h1_vec2 = vld1q_u8(hash1 + 16);
    uint8x16_t h2_vec2 = vld1q_u8(hash2 + 16);
    uint8x16_t diff2 = veorq_u8(h1_vec2, h2_vec2);
    
    // Merge differences from the two vectors (constant-time operation)
    uint8x16_t combined = vorrq_u8(diff1, diff2);
    
    // Check whether there is any non-zero byte (constant time).
    // Use vmaxvq_u8 to find the maximum value; if it is 0, hashes match.
    uint8_t max_diff = vmaxvq_u8(combined);
    
    if (max_diff != 0) {
        LOG_RUN_ERR("[hash]: hash comparison failed");
        GR_THROW_ERROR(ERR_GR_MEM_CMP_FAILED);
        return CM_ERROR;
    }
#else
    // Use 64-bit integers for batch comparison + constant-time semantics
    const uint64_t *h1_64 = (const uint64_t *)hash1;
    const uint64_t *h2_64 = (const uint64_t *)hash2;
    uint64_t diff = 0;
    
    diff |= (h1_64[0] ^ h2_64[0]);
    diff |= (h1_64[1] ^ h2_64[1]);
    diff |= (h1_64[2] ^ h2_64[2]);
    diff |= (h1_64[3] ^ h2_64[3]);
    
    if (diff != 0) {
        LOG_RUN_ERR("[hash]: hash comparison failed");
        GR_THROW_ERROR(ERR_GR_MEM_CMP_FAILED);
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

static inline void memcpy_arm_neon_impl(void *dest, const void *src, size_t n)
{
#ifdef ENABLE_ARM_NEON
    if (n >= 64) {
        uint8_t *d = (uint8_t *)dest;
        const uint8_t *s = (const uint8_t *)src;
        size_t i = 0;
        
        // Align to 16-byte boundary (required by NEON)
        size_t align = (16 - ((uintptr_t)d % 16)) % 16;
        for (i = 0; i < align && i < n; i++) {
            d[i] = s[i];
        }
        
        // NEON bulk copy: 128 bits (16 bytes) per iteration
        size_t neon_count = (n - i) / 16;
        for (size_t j = 0; j < neon_count; j++) {
            uint8x16_t vec = vld1q_u8(s + i + j * 16);
            vst1q_u8(d + i + j * 16, vec);
        }
        
        // Handle remaining tail bytes
        i += neon_count * 16;
        for (; i < n; i++) {
            d[i] = s[i];
        }
    } else {
        // For small blocks, use standard memcpy
        memcpy(dest, src, n);
    }
#else
    memcpy(dest, src, n);
#endif
}


#ifdef __cplusplus
}
#endif

#endif // __GR_ARM_OPTIMIZED_H__

