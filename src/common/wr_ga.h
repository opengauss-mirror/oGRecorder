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
 * wr_ga.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_ga.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_GA_H_
#define __WR_GA_H_

#include "cm_types.h"
#include "cm_defs.h"
#include "cm_spinlock.h"
#include "cm_error.h"
#include "wr_shm.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GA_NULL (ulong)0
#define GA_MAX_EXTENDED_POOLS 1024
#define GA_MAX_8K_EXTENDED_POOLS 16
#define GA_MAX_SESSION_EXTENDED_POOLS (uint32_t)(WR_MAX_SESSIONS / WR_SESSION_NUM_PER_GROUP)

#define GA_SYS_AREA ((uint32_t)0x01000000) /* no extended pools */
#define GA_APP_AREA ((uint32_t)0x02000000) /* including extended pools */

#define GA_EXT_SHM_POOLID(id) ((id) - (GA_APP_AREA))

#define GA_APP_POOL_COUNT 6

#define GA_INSTANCE_POOL_SIZE (uint32_t)(1048576) /* 1M */

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
#define GA_USAGE_UNIT (CM_100X_FIXED * CM_100X_FIXED)
#else
#define GA_USAGE_UNIT (CM_100X_FIXED)
#endif

typedef uint64 ga_offset_t;

typedef enum tagga_pool_name {
    GA_INSTANCE_POOL = GA_APP_AREA,
    GA_SESSION_POOL = (GA_APP_AREA + 1),
    GA_8K_POOL = (GA_APP_AREA + 2),
    GA_16K_POOL = (GA_APP_AREA + 3),
    GA_FS_AUX_POOL = (GA_APP_AREA + 4),
    GA_SEGMENT_POOL = (GA_APP_AREA + 5),
} ga_pool_id_e;

typedef struct tagga_object_map {
    uint32_t next;
    uint32_t prior;
} ga_object_map_t;

typedef struct tagga_queue {
    uint32_t count;
    uint32_t first;
    uint32_t last;
} ga_queue_t;

#define GA_INIT_QUEUE(queue)              \
    do {                                  \
        (queue)->count = 0;               \
        (queue)->first = CM_INVALID_ID32; \
        (queue)->last = CM_INVALID_ID32;  \
    } while (0)

typedef struct tagga_pool_def {
    uint32_t object_count;
    uint32_t object_size;
    uint32_t ex_max; /* the max number of extended pools */
} ga_pool_def_t;

typedef struct tagga_pool_ctrl {
    spinlock_t mutex;
    ga_pool_def_t def;
    uint64 offset;
    ga_queue_t free_objects;
    uint32_t ex_count;
    int32_t ex_shm_id[GA_MAX_EXTENDED_POOLS];
} ga_pool_ctrl_t;

typedef struct tagga_pool {
    char *pool_name;
    char *addr;
    char *object_addr;
    ga_pool_ctrl_t *ctrl;
    ga_object_map_t *object_map;
    char *ex_pool_addr[GA_MAX_EXTENDED_POOLS];
    ga_pool_def_t def;
    uint64 capacity;
    uint32_t ex_attach_count;
} ga_pool_t;

/* text in global area */
typedef struct tagga_text {
    uint32_t len;
    ga_offset_t str;
} ga_text_t;

/* word in global area */
typedef struct tagga_word {
    ga_text_t word_name;
    uint32_t word_type;
    uint32_t id;
} ga_word_t;

#define GA_POOL_IDX(id) ((uint32_t)(id) & (uint32_t)0x00FFFFFF)

typedef struct st_ga_obj_id_t {
    ga_pool_id_e pool_id;
    uint32_t obj_id;
} ga_obj_id_t;

extern ga_pool_t g_app_pools[GA_APP_POOL_COUNT];
void ga_reset_app_pools();
void ga_set_pool_def(ga_pool_id_e pool_id, const ga_pool_def_t *def);
status_t ga_create_global_area(void);
void ga_destroy_global_area(void);
int32_t ga_attach_area(uint32_t attach_perm);
void ga_detach_area(void);

uint32_t ga_alloc_object(ga_pool_id_e pool_id, uint32_t specific_id);
char *ga_object_addr(ga_pool_id_e pool_id, uint32_t object_id);

#ifdef __cplusplus
}
#endif

#endif
