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
 * gr_resource_mgr.h
 *
 * IDENTIFICATION
 *    src/common/gr_resource_mgr.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_RESOURCE_MGR_H__
#define __GR_RESOURCE_MGR_H__

#include "gr_malloc.h"
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Unified resource management wrapper.
 *
 * Notes:
 * - The current implementation is a thin wrapper around existing cm_malloc/cm_free,
 *   mainly to unify naming and usage style;
 * - If we need to add statistics, leak detection or custom allocators in the future,
 *   we can extend the implementation here without changing callers;
 * - We start from memory allocation, and small-object memory pools can be gradually
 *   introduced into hot paths (such as session / hash / FD, etc.).
 */

/* Unified memory allocation/free interfaces */
#define GR_MALLOC(size)        cm_malloc((uint32)(size))
#define GR_FREE(ptr)           cm_free((void *)(ptr))

/* Helper macro for allocating a struct */
#define GR_MALLOC_STRUCT(type) (type *)cm_malloc((uint32)sizeof(type))

/* Free and nullify the pointer to avoid dangling references */
#define GR_FREE_NULL(ptr)      \
    do {                       \
        if ((ptr) != NULL) {   \
            cm_free((void *)(ptr)); \
            (ptr) = NULL;      \
        }                      \
    } while (0)

/*
 * Fixed-size memory pool for small objects.
 *
 * Typical usage:
 * - For small structs that are allocated/freed frequently, such as file handles,
 *   hash records, etc.;
 * - Prefer allocating from a pre-allocated buffer, and return blocks to a freelist
 *   on free, to reduce malloc/free jitter;
 * - When capacity is exceeded, it can return NULL and the caller may fall back to GR_MALLOC.
 */
typedef struct st_gr_mem_pool {
    void   *buffer;      /* Start address of the pre-allocated big memory block */
    uint32  block_size;  /* Size of a single block */
    uint32  capacity;    /* Maximum number of blocks */
    uint32  used;        /* Number of blocks allocated and not yet returned to the freelist */
    void   *free_list;   /* Singly-linked free list, using the block head to store next pointer */
} gr_mem_pool_t;

/*
 * Initialize memory pool.
 * - block_size: size of each block (bytes), must be > 0
 * - capacity:   number of pre-allocated blocks, must be > 0
 */
status_t gr_mem_pool_init(gr_mem_pool_t *pool, uint32 block_size, uint32 capacity);

/* Destroy memory pool and free internal buffer; the pool object itself is managed by the caller. */
void gr_mem_pool_destroy(gr_mem_pool_t *pool);

/*
 * Allocate one block from the memory pool.
 * Return:
 * - non-NULL: allocation succeeded;
 * - NULL    : pool is exhausted (caller may fall back to GR_MALLOC).
 */
void *gr_mem_pool_alloc(gr_mem_pool_t *pool);

/* Return a block back to the memory pool (ptr must come from this pool). */
void gr_mem_pool_free(gr_mem_pool_t *pool, void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* __GR_RESOURCE_MGR_H__ */

