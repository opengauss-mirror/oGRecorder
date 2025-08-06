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
 * gr_latch.h
 *
 *
 * IDENTIFICATION
 *    src/common/gr_latch.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_LATCH_H__
#define __GR_LATCH_H__

#include "cm_latch.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef enum en_gr_latch_mode {
    LATCH_MODE_SHARE = 0,    /* SHARE */
    LATCH_MODE_EXCLUSIVE = 1 /* EXCLUSIVE*/
} gr_latch_mode_e;

typedef enum en_gr_latch_shared_op {
    LATCH_SHARED_OP_NONE = 0,
    LATCH_SHARED_OP_LATCH_S = 1,
    LATCH_SHARED_OP_LATCH_S_BEG = 2,
    LATCH_SHARED_OP_LATCH_S_END = 3,
    LATCH_SHARED_OP_UNLATCH = 4,
    LATCH_SHARED_OP_UNLATCH_BEG = 5,
    LATCH_SHARED_OP_UNLATCH_END = 6,
} gr_latch_shared_op_e;

typedef enum en_gr_latch_stat_type {
    LATCH_SWITCH = 0,
    LATCH_STAT_TYPE_COUNT
} gr_latch_stat_type_t;

extern latch_statis_t g_latch_stat[LATCH_STAT_TYPE_COUNT];
#define LATCH_STAT(stat_id) (&g_latch_stat[(stat_id)])

typedef struct st_gr_latch_extent {
    volatile uint16 shared_count_bak;
    volatile uint16 stat_bak;
    volatile uint64 shared_sid_count;
    volatile uint64 shared_sid_count_bak;
} gr_latch_extent_t;

typedef struct st_gr_shared_latch {
    latch_t latch;
    gr_latch_extent_t latch_extent;
} gr_shared_latch_t;

#define SPIN_SLEEP_TIME 500
#define SPIN_WAIT_FOREVER (-1)
#define GR_CLIENT_TIMEOUT_COUNT 30
#define GR_CLIENT_TIMEOUT 1000  // ms

#define GR_DEFAULT_SESSIONID (uint16)0xFFFF
#define GR_SESSIONID_IN_LOCK(sid) ((sid) + 1)

typedef bool32 (*latch_should_exit)(void);

void gr_latch_x(latch_t *latch);
void gr_unlatch(latch_t *latch);
void gr_latch_x2(latch_t *latch, uint32_t sid);
static inline void gr_latch(latch_t *latch, gr_latch_mode_e latch_mode, uint32_t sid)
{
    latch_mode == LATCH_MODE_SHARE ? cm_latch_s(latch, sid, CM_FALSE, NULL) : cm_latch_x(latch, sid, NULL);
}

void gr_set_latch_extent(gr_latch_extent_t *latch_extent, uint16 stat, uint16 shared_count);

#ifdef __cplusplus
}
#endif

#endif