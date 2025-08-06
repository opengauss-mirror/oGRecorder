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
 * gr_stats.c
 *
 *
 * IDENTIFICATION
 *    src/common/gr_stats.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_stats.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *g_gr_stat_events[GR_EVT_COUNT] = {
    [GR_PREAD] = "GR Pread",
    [GR_PWRITE] = "GR Pwrite",
    [GR_PREAD_SYN_META] = "GR Pread Sync Metadata",
    [GR_PWRITE_SYN_META] = "GR Pwrite Sync Metadata",
    [GR_PREAD_DISK] = "GR Pread Disk",
    [GR_PWRITE_DISK] = "GR Pwrite Disk",
    [GR_FOPEN] = "GR File Open",
    [GR_STAT] = "GR Stat",
    [GR_FIND_FT_ON_SERVER] = "Find File Node On Server",
};

const char *gr_get_stat_event(gr_wait_event_e event)
{
    return g_gr_stat_events[event];
}

#ifdef __cplusplus
}
#endif
