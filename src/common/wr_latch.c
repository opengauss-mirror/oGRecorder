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
 * wr_latch.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_latch.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_latch.h"
#include "wr_shm.h"
#include "cm_utils.h"

latch_statis_t g_latch_stat[LATCH_STAT_TYPE_COUNT] = {0};

void wr_latch_x(latch_t *latch)
{
    cm_latch_x(latch, WR_DEFAULT_SESSIONID, NULL);
}

void wr_unlatch(latch_t *latch)
{
    cm_unlatch(latch, NULL);
}

void wr_latch_x2(latch_t *latch, uint32_t sid)
{
    cm_latch_x(latch, sid, NULL);
}

void wr_latch_s2(latch_t *latch, uint32_t sid, bool32 is_force, latch_statis_t *stat)
{
    cm_latch_s(latch, sid, is_force, stat);
}

void wr_set_latch_extent(wr_latch_extent_t *latch_extent, uint16 stat, uint16 shared_count)
{
    latch_extent->stat_bak = stat;
    latch_extent->shared_count_bak = shared_count;
    latch_extent->shared_sid_count_bak = latch_extent->shared_sid_count;
}