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
 * wr_latch.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_latch.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_LATCH_H__
#define __WR_LATCH_H__

#include "cm_latch.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef enum en_wr_latch_mode {
    LATCH_MODE_SHARE = 0,    /* SHARE */
    LATCH_MODE_EXCLUSIVE = 1 /* EXCLUSIVE*/
} wr_latch_mode_e;

typedef enum en_wr_latch_shared_op {
    LATCH_SHARED_OP_NONE = 0,
    LATCH_SHARED_OP_LATCH_S = 1,
    LATCH_SHARED_OP_LATCH_S_BEG = 2,
    LATCH_SHARED_OP_LATCH_S_END = 3,
    LATCH_SHARED_OP_UNLATCH = 4,
    LATCH_SHARED_OP_UNLATCH_BEG = 5,
    LATCH_SHARED_OP_UNLATCH_END = 6,
} wr_latch_shared_op_e;

typedef enum en_wr_latch_stat_type {
    LATCH_SWITCH = 0,
    LATCH_STAT_TYPE_COUNT
} wr_latch_stat_type_t;

extern latch_statis_t g_latch_stat[LATCH_STAT_TYPE_COUNT];
#define LATCH_STAT(stat_id) (&g_latch_stat[(stat_id)])

typedef struct st_wr_latch_extent {
    volatile uint16 shared_count_bak;
    volatile uint16 stat_bak;
    volatile uint64 shared_sid_count;
    volatile uint64 shared_sid_count_bak;
} wr_latch_extent_t;

typedef struct st_wr_shared_latch {
    latch_t latch;
    wr_latch_extent_t latch_extent;
} wr_shared_latch_t;

#define SPIN_SLEEP_TIME 500
#define SPIN_WAIT_FOREVER (-1)
#define WR_CLIENT_TIMEOUT_COUNT 30
#define WR_CLIENT_TIMEOUT 1000  // ms

#define WR_DEFAULT_SESSIONID (uint16)0xFFFF
#define WR_SESSIONID_IN_LOCK(sid) ((sid) + 1)

typedef bool32 (*latch_should_exit)(void);

void wr_latch_x(latch_t *latch);
void wr_unlatch(latch_t *latch);
void wr_latch_x2(latch_t *latch, uint32_t sid);
static inline void wr_latch(latch_t *latch, wr_latch_mode_e latch_mode, uint32_t sid)
{
    latch_mode == LATCH_MODE_SHARE ? cm_latch_s(latch, sid, CM_FALSE, NULL) : cm_latch_x(latch, sid, NULL);
}

void wr_latch_s2(latch_t *latch, uint32_t sid, bool32 is_force, latch_statis_t *stat);

void wr_set_latch_extent(wr_latch_extent_t *latch_extent, uint16 stat, uint16 shared_count);

#ifdef __cplusplus
}
#endif

#endif