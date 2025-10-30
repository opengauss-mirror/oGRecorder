/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * GR is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 * gr_hash_optimized.c
 * Minimal implementation: unified API, internally based on OpenSSL calculation, ensuring compilation.
 * -------------------------------------------------------------------------
 */

#include "gr_hash_optimized.h"
#include "gr_defs.h"
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>

status_t gr_hash_optimized_init(void)
{
    return CM_SUCCESS;
}

void gr_hash_optimized_cleanup(void)
{
}

status_t gr_calculate_hash_optimized(const void *data, size_t size, uint8_t *hash)
{
    if (data == NULL || hash == NULL || size == 0) {
        return CM_ERROR;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return CM_ERROR;
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return CM_ERROR;
    }
    if (EVP_DigestUpdate(mdctx, data, size) != 1) {
        EVP_MD_CTX_free(mdctx);
        return CM_ERROR;
    }
    unsigned int digest_len = SHA256_DIGEST_LENGTH;
    if (EVP_DigestFinal_ex(mdctx, hash, &digest_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return CM_ERROR;
    }
    EVP_MD_CTX_free(mdctx);
    return CM_SUCCESS;
}

status_t gr_calculate_hash_batch(const void **data_array, const size_t *size_array,
                                uint32_t count, uint8_t (*hashes)[SHA256_DIGEST_LENGTH])
{
    if (data_array == NULL || size_array == NULL || hashes == NULL) {
        return CM_ERROR;
    }
    for (uint32_t i = 0; i < count; i++) {
        status_t s = gr_calculate_hash_optimized(data_array[i], size_array[i], hashes[i]);
        if (s != CM_SUCCESS) {
            return s;
        }
    }
    return CM_SUCCESS;
}

status_t gr_hash_stream_init(EVP_MD_CTX **stream_ctx)
{
    if (stream_ctx == NULL) {
        return CM_ERROR;
    }
    *stream_ctx = EVP_MD_CTX_new();
    if (*stream_ctx == NULL) {
        return CM_ERROR;
    }
    if (EVP_DigestInit_ex(*stream_ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(*stream_ctx);
        *stream_ctx = NULL;
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_hash_stream_update(EVP_MD_CTX *stream_ctx, const void *data, size_t size)
{
    if (stream_ctx == NULL || data == NULL) {
        return CM_ERROR;
    }
    return (EVP_DigestUpdate(stream_ctx, data, size) == 1) ? CM_SUCCESS : CM_ERROR;
}

status_t gr_hash_stream_final(EVP_MD_CTX *stream_ctx, uint8_t *hash)
{
    if (stream_ctx == NULL || hash == NULL) {
        return CM_ERROR;
    }
    unsigned int digest_len = SHA256_DIGEST_LENGTH;
    return (EVP_DigestFinal_ex(stream_ctx, hash, &digest_len) == 1) ? CM_SUCCESS : CM_ERROR;
}

void gr_hash_stream_cleanup(EVP_MD_CTX *stream_ctx)
{
    if (stream_ctx != NULL) {
        EVP_MD_CTX_free(stream_ctx);
    }
}

void gr_hash_get_stats(gr_hash_stats_t *stats)
{
    if (stats == NULL) { return; }
    memset(stats, 0, sizeof(*stats));
}

void gr_hash_reset_stats(void)
{
}

bool32 gr_hash_hw_acceleration_available(void)
{
    return CM_FALSE;
}

status_t gr_calculate_hash_parallel(const void *data, size_t size, uint8_t *hash, uint32_t thread_count)
{
    (void)thread_count;
    return gr_calculate_hash_optimized(data, size, hash);
}

// Provide aligned helper implementation to satisfy unified simple API
status_t gr_calculate_hash_aligned(const void *data, size_t size, uint8_t *hash)
{
    if (data == NULL || hash == NULL || size == 0) {
        return CM_ERROR;
    }
    // If already 64-byte aligned, compute directly
    if (gr_is_aligned(data, GR_HASH_ALIGN_SIZE)) {
        return gr_calculate_hash_optimized(data, size, hash);
    }
    // Allocate aligned buffer, copy, and compute
    void *aligned_ptr = NULL;
#if defined(_ISOC11_SOURCE) || (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L)
    aligned_ptr = aligned_alloc(GR_HASH_ALIGN_SIZE, size);
    if (aligned_ptr == NULL) {
        return CM_ERROR;
    }
#else
    if (posix_memalign(&aligned_ptr, GR_HASH_ALIGN_SIZE, size) != 0 || aligned_ptr == NULL) {
        return CM_ERROR;
    }
#endif
    memcpy(aligned_ptr, data, size);
    status_t s = gr_calculate_hash_optimized(aligned_ptr, size, hash);
    free(aligned_ptr);
    return s;
}

// ===== Unified single-file implementation for "simple" hash API =====

// Local simple stats mirror
static gr_hash_stats_simple_t g_hash_simple_stats = {0};

static inline uint64_t gr_get_time_us_unified(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

status_t gr_calculate_hash_optimized_simple(const void *data, size_t size, uint8_t *hash)
{
    if (data == NULL || hash == NULL || size == 0) {
        return CM_ERROR;
    }
    uint64_t start = gr_get_time_us_unified();
    status_t s = gr_calculate_hash_optimized(data, size, hash);
    uint64_t endt = gr_get_time_us_unified();
    if (s == CM_SUCCESS) {
        g_hash_simple_stats.total_calls++;
        g_hash_simple_stats.total_bytes += size;
        g_hash_simple_stats.total_time_us += (endt - start);
    }
    return s;
}

status_t gr_calculate_hash_batch_simple(const void **data_array, const size_t *size_array,
                                       uint32_t count, uint8_t (*hashes)[SHA256_DIGEST_LENGTH])
{
    if (data_array == NULL || size_array == NULL || hashes == NULL || count == 0) {
        return CM_ERROR;
    }
    uint64_t start = gr_get_time_us_unified();
    status_t s = gr_calculate_hash_batch(data_array, size_array, count, hashes);
    uint64_t endt = gr_get_time_us_unified();
    if (s == CM_SUCCESS) {
        g_hash_simple_stats.batch_calls++;
        g_hash_simple_stats.batch_time_us += (endt - start);
        for (uint32_t i = 0; i < count; i++) {
            g_hash_simple_stats.batch_bytes += size_array[i];
        }
    }
    return s;
}

status_t gr_calculate_hash_aligned_simple(const void *data, size_t size, uint8_t *hash)
{
    return gr_calculate_hash_aligned(data, size, hash);
}

bool32 gr_hash_hw_acceleration_available_simple(void)
{
    return gr_hash_hw_acceleration_available();
}

void gr_hash_get_stats_simple(gr_hash_stats_simple_t *stats)
{
    if (stats == NULL) { return; }
    *stats = g_hash_simple_stats;
}

void gr_hash_reset_stats_simple(void)
{
    memset(&g_hash_simple_stats, 0, sizeof(g_hash_simple_stats));
}
