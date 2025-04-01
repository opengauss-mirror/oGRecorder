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
 * wr_stats.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_stats.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_stats.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *g_wr_stat_events[WR_EVT_COUNT] = {
    [WR_PREAD] = "WR Pread",
    [WR_PWRITE] = "WR Pwrite",
    [WR_PREAD_SYN_META] = "WR Pread Sync Metadata",
    [WR_PWRITE_SYN_META] = "WR Pwrite Sync Metadata",
    [WR_PREAD_DISK] = "WR Pread Disk",
    [WR_PWRITE_DISK] = "WR Pwrite Disk",
    [WR_FOPEN] = "WR File Open",
    [WR_STAT] = "WR Stat",
    [WR_FIND_FT_ON_SERVER] = "Find File Node On Server",
};

const char *wr_get_stat_event(wr_wait_event_e event)
{
    return g_wr_stat_events[event];
}

#ifdef __cplusplus
}
#endif
