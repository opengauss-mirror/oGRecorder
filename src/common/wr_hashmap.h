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
 * wr_hashmap.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_hashmap.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_HASHMAP_H__
#define __WR_HASHMAP_H__

#include "cm_types.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

// should not too big.it will allow to insert max node in oa map is MAX_OAMAP_NUM
#define MAX_OAMAP_BUCKET_NUM (1024 * 1024 * 2)
typedef uint32_t (*cm_oamap_hash_t)(void *key);
typedef bool32 (*cm_oamap_compare_t)(void *key1, void *key2);
typedef uint32_t cm_oamap_iterator_t;

typedef enum tag_cm_oamap_bucket_state {
    FREE,
    USED,
    DELETED,
} cm_oamap_bucket_state_e;

// open address map is use for small numbers of key map
typedef struct tag_cm_oamap_bucket {
    uint32_t hash : 30;
    uint32_t state : 2;
} cm_oamap_bucket_t;

typedef struct tag_cm_oamap {
    cm_oamap_bucket_t *buckets;
    void **key;
    void **value;
    uint32_t num;
    uint32_t used;
    uint32_t deleted;
    cm_oamap_compare_t compare_func;
} cm_oamap_t;

int32_t cm_oamap_init(
    cm_oamap_t *map, uint32_t init_capacity, cm_oamap_compare_t compare_func /* , memory_context_t *mem_ctx */);

void cm_oamap_destroy(cm_oamap_t *map);

uint32_t cm_hash_uint32_shard(uint32_t val);

#ifdef __cplusplus
}
#endif

#endif /* __WR_HASHMAP_H__ */
