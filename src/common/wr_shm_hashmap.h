/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * WR is licensed under Mulan PSL v2.
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
 * wr_shm_hashmap.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_shm_hashmap.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_SHM_HASHMAP_H_
#define __WR_SHM_HASHMAP_H_

#include "cm_defs.h"
#include "cm_types.h"
#include "wr_hashmap.h"
#include "wr_shm.h"
#include "cm_latch.h"
#include "wr_latch.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_MAX_SEGMENT_NUM (1024)
#define WR_MAX_BUCKET_NUM (2097152)
#ifdef ENABLE_WRTEST
#define WR_INIT_BUCKET_NUM (2048)
#else
#define WR_INIT_BUCKET_NUM (32768)
#endif

#define WR_BUCKETS_PER_SEGMENT (WR_MAX_BUCKET_NUM / WR_MAX_SEGMENT_NUM)
#define WR_BUCKETS_SIZE_PER_SEGMENT (WR_BUCKETS_PER_SEGMENT * sizeof(shm_hashmap_bucket_t))
#define WR_EXTEND_BATCH (128)
#define WR_HASH_FILL_FACTOR ((float)0.75)
typedef struct st_shm_oamap_bucket {
    uint32_t hash : 30;
    uint32_t state : 2;
} shm_oamap_bucket_t;

typedef struct st_shm_oamap {
    sh_mem_p buckets_offset; /* ptr offset */
    sh_mem_p key_offset;     /* ptr offset */
    sh_mem_p value_offset;   /* ptr offset */
    uint32_t num;
    uint32_t used;
    uint32_t deleted;
    uint32_t not_extend : 1;
    uint32_t shm_id : 31;
    uint64 reserve;
} shm_oamap_t;

typedef struct st_shm_hashmap_bucket {
    wr_shared_latch_t enque_lock;
    sh_mem_p first;
    bool32 has_next;
    uint32_t entry_num;
} shm_hashmap_bucket_t;

typedef shm_hashmap_bucket_t *shm_hashmap_segment;
typedef struct st_shm_hash_ctrl {
    sh_mem_p dirs;
    uint32_t bucket_limits;
    uint32_t bucket_num;
    uint32_t max_bucket;
    uint32_t low_mask;
    uint32_t high_mask;
    uint32_t nsegments;
    cm_oamap_compare_t func;
} shm_hash_ctrl_t;
typedef struct st_shm_hashmap {
    shm_hash_ctrl_t hash_ctrl;
    uint32_t not_extend : 1;
    uint32_t shm_id : 31;
} shm_hashmap_t;

typedef struct st_shm_oamap_param {
    uint32_t hash;
    shm_oamap_t *map;
    void *key_acl;
    cm_oamap_compare_t compare_func;
} shm_oamap_param_t;

void shm_hashmap_destroy(shm_hashmap_t *map, uint32_t id);

#define SHM_HASH_BUCKET_INSERT(bucket, item, item_ctrl, first_ctrl) \
    do {                                                            \
        if ((bucket)->has_next) {                                   \
            (item_ctrl)->hash_next = (bucket)->first;               \
            (item_ctrl)->has_next = CM_TRUE;                        \
            (first_ctrl)->hash_prev = (item);                       \
            (first_ctrl)->has_prev = CM_TRUE;                       \
        } else {                                                    \
            (bucket)->has_next = CM_TRUE;                           \
        }                                                           \
        (bucket)->first = (item);                                   \
        (bucket)->entry_num++;                                      \
    } while (0)

#define SHM_HASH_BUCKET_REMOVE(bucket, item, item_ctrl, prev_ctrl, next_ctrl) \
    do {                                                                      \
        if ((prev_ctrl) != NULL) {                                            \
            (prev_ctrl)->hash_next = (item_ctrl)->hash_next;                  \
            (prev_ctrl)->has_next = (item_ctrl)->has_next;                    \
        }                                                                     \
        if ((next_ctrl) != NULL) {                                            \
            (next_ctrl)->hash_prev = (item_ctrl)->hash_prev;                  \
            (next_ctrl)->has_prev = (item_ctrl)->has_prev;                    \
        }                                                                     \
        if ((item) == (bucket)->first) {                                      \
            (bucket)->first = (item_ctrl)->hash_next;                         \
            (bucket)->has_next = (item_ctrl)->has_next;                       \
        }                                                                     \
        (item_ctrl)->has_next = CM_FALSE;                                     \
        (item_ctrl)->has_prev = CM_FALSE;                                     \
        (bucket)->entry_num--;                                                \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* _CM_SHM_HASHMAP_H_ */
