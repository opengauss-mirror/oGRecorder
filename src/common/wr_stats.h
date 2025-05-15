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
 * wr_stats.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_stats.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_STATS_H__
#define __WR_STATS_H__

#include "cm_defs.h"
#include "cm_date.h"
#include "cm_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_wr_wait_event {
    WR_PREAD = 0,
    WR_PWRITE,
    WR_PREAD_SYN_META,
    WR_PWRITE_SYN_META,
    WR_PREAD_DISK,
    WR_PWRITE_DISK,
    WR_FOPEN,
    WR_STAT,
    WR_FIND_FT_ON_SERVER,
    WR_EVT_COUNT,
} wr_wait_event_e;

typedef struct st_wr_stat_item {
    atomic_t total_wait_time;
    atomic_t max_single_time;
    atomic_t wait_count;
} wr_stat_item_t;

typedef struct st_wr_stat_ctx {
    bool32 enable_stat;
    wr_wait_event_e wait_event;
} wr_stat_ctx_t;

static inline void wr_begin_stat(timeval_t *begin_tv)
{
    (void)cm_gettimeofday(begin_tv);
}

static inline void wr_end_stat_base(wr_stat_item_t *stat_item, timeval_t *begin_tv)
{
    timeval_t end_tv;
    uint64 usecs;

    (void)cm_gettimeofday(&end_tv);
    usecs = (uint64)TIMEVAL_DIFF_US(begin_tv, &end_tv);
    (void)cm_atomic_add(&stat_item->total_wait_time, (int64)usecs);
    (void)cm_atomic_set(&stat_item->max_single_time, (int64)MAX((uint64)stat_item->max_single_time, usecs));
    (void)cm_atomic_inc(&stat_item->wait_count);
}

static inline void wr_end_stat_ex(wr_stat_ctx_t *stat_ctx, wr_stat_item_t *stat_item, timeval_t *begin_tv)
{
    if (stat_ctx->enable_stat) {
        wr_end_stat_base(stat_item, begin_tv);
    }
}

static inline void wr_set_stat(wr_stat_ctx_t *stat_ctx, wr_wait_event_e event)
{
    stat_ctx->enable_stat = CM_TRUE;
    stat_ctx->wait_event = event;
}

static inline void wr_unset_stat(wr_stat_ctx_t *stat_ctx)
{
    stat_ctx->enable_stat = CM_FALSE;
}

const char *wr_get_stat_event(wr_wait_event_e event);

#ifdef __cplusplus
}
#endif

#endif
