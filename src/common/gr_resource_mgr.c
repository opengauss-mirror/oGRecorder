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
 * gr_resource_mgr.c
 *
 * IDENTIFICATION
 *    src/common/gr_resource_mgr.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_resource_mgr.h"
#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t gr_mem_pool_init(gr_mem_pool_t *pool, uint32 block_size, uint32 capacity)
{
    if (pool == NULL || block_size == 0 || capacity == 0) {
        return CM_ERROR;
    }

    uint64 total_size = (uint64)block_size * (uint64)capacity;
    if (total_size == 0) {
        return CM_ERROR;
    }

    pool->buffer = cm_malloc((uint32)total_size);
    if (pool->buffer == NULL) {
        return CM_ERROR;
    }

    pool->block_size = block_size;
    pool->capacity = capacity;
    pool->used = 0;
    pool->free_list = NULL;
    return CM_SUCCESS;
}

void gr_mem_pool_destroy(gr_mem_pool_t *pool)
{
    if (pool == NULL) {
        return;
    }
    GR_FREE_NULL(pool->buffer);
    pool->block_size = 0;
    pool->capacity = 0;
    pool->used = 0;
    pool->free_list = NULL;
}

void *gr_mem_pool_alloc(gr_mem_pool_t *pool)
{
    if (pool == NULL) {
        return NULL;
    }

    /* Prefer using blocks returned to the freelist first */
    if (pool->free_list != NULL) {
        void *node = pool->free_list;
        pool->free_list = *(void **)node;
        return node;
    }

    /* If the freelist is empty, allocate sequentially from the pre-allocated buffer */
    if (pool->used < pool->capacity && pool->block_size != 0 && pool->buffer != NULL) {
        char *base = (char *)pool->buffer;
        void *node = (void *)(base + (uint64)pool->used * (uint64)pool->block_size);
        pool->used++;
        return node;
    }

    /* Pool is exhausted; the caller may decide whether to fall back to GR_MALLOC */
    return NULL;
}

void gr_mem_pool_free(gr_mem_pool_t *pool, void *ptr)
{
    if (pool == NULL || ptr == NULL) {
        return;
    }

    /* Use the first sizeof(void*) bytes of the block as the next pointer and push it to the freelist */
    *(void **)ptr = pool->free_list;
    pool->free_list = ptr;
}

#ifdef __cplusplus
}
#endif

