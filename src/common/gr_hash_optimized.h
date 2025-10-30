/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * GR is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * gr_hash_optimized.h
 *
 * Optimized hash calculation module providing high-performance SHA256 computation
 *
 * IDENTIFICATION
 *    src/common/gr_hash_optimized.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_HASH_OPTIMIZED_H__
#define __GR_HASH_OPTIMIZED_H__

#include "cm_base.h"
#include "gr_defs.h"
#include "gr_log.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Hash context pool size
#define GR_HASH_CTX_POOL_SIZE 8
#define GR_HASH_BATCH_SIZE 16
#define GR_HASH_ALIGN_SIZE 64  // Cache line alignment

// Optimized hash context structure
typedef struct st_gr_hash_ctx {
    EVP_MD_CTX *mdctx;
    bool32 in_use;
    uint64_t last_used_time;
    uint32_t ref_count;
} gr_hash_ctx_t;

// Batch hash calculation structure
typedef struct st_gr_hash_batch {
    const void *data[GR_HASH_BATCH_SIZE];
    size_t sizes[GR_HASH_BATCH_SIZE];
    uint8_t hashes[GR_HASH_BATCH_SIZE][SHA256_DIGEST_LENGTH];
    uint32_t count;
} gr_hash_batch_t;

// Thread-local hash manager
typedef struct st_gr_hash_mgr {
    gr_hash_ctx_t ctx_pool[GR_HASH_CTX_POOL_SIZE];
    pthread_mutex_t pool_mutex;
    uint32_t pool_usage;
    uint64_t total_operations;
    uint64_t total_bytes;
} gr_hash_mgr_t;

// Performance statistics structure
typedef struct st_gr_hash_stats {
    uint64_t total_calls;
    uint64_t total_bytes;
    uint64_t total_time_us;
    uint64_t batch_calls;
    uint64_t batch_bytes;
    uint64_t batch_time_us;
    uint64_t ctx_reuses;
    uint64_t ctx_creates;
} gr_hash_stats_t;

// Global function declarations
status_t gr_hash_optimized_init(void);
void gr_hash_optimized_cleanup(void);

// Optimized single hash calculation
status_t gr_calculate_hash_optimized(const void *data, size_t size, uint8_t *hash);

// Batch hash calculation
status_t gr_calculate_hash_batch(const void **data_array, const size_t *size_array, 
                                uint32_t count, uint8_t (*hashes)[SHA256_DIGEST_LENGTH]);

// Streaming hash calculation (for large files)
status_t gr_hash_stream_init(EVP_MD_CTX **stream_ctx);
status_t gr_hash_stream_update(EVP_MD_CTX *stream_ctx, const void *data, size_t size);
status_t gr_hash_stream_final(EVP_MD_CTX *stream_ctx, uint8_t *hash);
void gr_hash_stream_cleanup(EVP_MD_CTX *stream_ctx);

// Performance statistics
void gr_hash_get_stats(gr_hash_stats_t *stats);
void gr_hash_reset_stats(void);

// Memory-aligned hash calculation
status_t gr_calculate_hash_aligned(const void *data, size_t size, uint8_t *hash);

// Parallel hash calculation (multi-threaded)
status_t gr_calculate_hash_parallel(const void *data, size_t size, uint8_t *hash, uint32_t thread_count);

// Hardware acceleration detection
bool32 gr_hash_hw_acceleration_available(void);

// Context pool management
gr_hash_ctx_t* gr_hash_ctx_acquire(void);
void gr_hash_ctx_release(gr_hash_ctx_t *ctx);

// Inline optimization functions
static inline status_t gr_hash_ctx_init(gr_hash_ctx_t *ctx)
{
    if (ctx->mdctx == NULL) {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL) {
            LOG_RUN_ERR("[hash]: Failed to create EVP_MD_CTX.");
            return CM_ERROR;
        }
    }
    
    if (EVP_DigestInit_ex(ctx->mdctx, EVP_sha256(), NULL) != 1) {
        LOG_RUN_ERR("[hash]: Failed to init sha256.");
        return CM_ERROR;
    }
    
    ctx->in_use = CM_TRUE;
    ctx->last_used_time = 0; /* optional if cm_time not included */
    ctx->ref_count = 1;
    
    return CM_SUCCESS;
}

static inline status_t gr_hash_ctx_update(gr_hash_ctx_t *ctx, const void *data, size_t size)
{
    if (EVP_DigestUpdate(ctx->mdctx, data, size) != 1) {
        LOG_RUN_ERR("[hash]: Failed to update sha256.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline status_t gr_hash_ctx_final(gr_hash_ctx_t *ctx, uint8_t *hash)
{
    unsigned int digest_len = SHA256_DIGEST_LENGTH;
    if (EVP_DigestFinal_ex(ctx->mdctx, hash, &digest_len) != 1) {
        LOG_RUN_ERR("[hash]: Failed to calculate sha256.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

// Memory alignment check
static inline bool32 gr_is_aligned(const void *ptr, size_t alignment)
{
    return ((uintptr_t)ptr & (alignment - 1)) == 0;
}

// Fast path: small data block optimization
static inline status_t gr_calculate_hash_fast(const void *data, size_t size, uint8_t *hash)
{
    // For data smaller than 1KB, use direct calculation
    if (size <= 1024) {
        return gr_calculate_hash_optimized(data, size, hash);
    }
    
    // For large data blocks, use batch processing
    return gr_calculate_hash_optimized(data, size, hash);
}

// ================= Unified "simple" hash API (merged) =================
typedef struct {
    uint64_t total_calls;
    uint64_t total_bytes;
    uint64_t total_time_us;
    uint64_t batch_calls;
    uint64_t batch_bytes;
    uint64_t batch_time_us;
} gr_hash_stats_simple_t;

status_t gr_calculate_hash_optimized_simple(const void *data, size_t size, uint8_t *hash);
status_t gr_calculate_hash_batch_simple(const void **data_array, const size_t *size_array,
                                       uint32_t count, uint8_t (*hashes)[SHA256_DIGEST_LENGTH]);
status_t gr_calculate_hash_aligned_simple(const void *data, size_t size, uint8_t *hash);
bool32 gr_hash_hw_acceleration_available_simple(void);
void gr_hash_get_stats_simple(gr_hash_stats_simple_t *stats);
void gr_hash_reset_stats_simple(void);

#ifdef __cplusplus
}
#endif

#endif  // __GR_HASH_OPTIMIZED_H__
