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
#include "cm_defs.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *g_gr_stat_events[GR_EVT_COUNT] = {
    [GR_PREAD] = "GR Pread",
    [GR_PWRITE] = "GR Pwrite",
    [GR_PREAD_DISK] = "GR Pread Disk",
    [GR_PWRITE_DISK] = "GR Pwrite Disk",
    [GR_FOPEN] = "GR File Open",
    [GR_STAT] = "GR Stat",
};

/* Simple latency distribution bucket boundaries (microseconds): <1ms, <10ms, <100ms, <1s, <10s, >=10s */
static const uint64 g_gr_stat_hist_bounds[GR_STAT_HIST_BUCKETS] = {
    1000ULL,          /*   1ms */
    10000ULL,         /*  10ms */
    100000ULL,        /* 100ms */
    1000000ULL,       /*   1s  */
    10000000ULL,      /*  10s  */
    (uint64)-1        /*  >=10s */
};

atomic_t g_gr_stat_hist[GR_EVT_COUNT][GR_STAT_HIST_BUCKETS];

const char *gr_get_stat_event(gr_wait_event_e event)
{
    return g_gr_stat_events[event];
}

void gr_update_stat_hist(gr_wait_event_e event, uint64 usecs)
{
    if (event >= GR_EVT_COUNT) {
        return;
    }

    for (uint32 b = 0; b < GR_STAT_HIST_BUCKETS; b++) {
        if (usecs <= g_gr_stat_hist_bounds[b]) {
            (void)cm_atomic_inc(&g_gr_stat_hist[event][b]);
            break;
        }
    }
}

void gr_dump_stat_hist_to_log(void)
{
    for (uint32 i = 0; i < GR_EVT_COUNT; i++) {
        const char *event_name = gr_get_stat_event((gr_wait_event_e)i);
        uint64 bucket_counts[GR_STAT_HIST_BUCKETS] = {0};

        for (uint32 b = 0; b < GR_STAT_HIST_BUCKETS; b++) {
            bucket_counts[b] = (uint64)cm_atomic_get(&g_gr_stat_hist[i][b]);
        }

        LOG_RUN_INF("[STAT] Event=%s, <1ms=%llu, <10ms=%llu, <100ms=%llu, <1s=%llu, <10s=%llu, >=10s=%llu",
                    event_name,
                    (unsigned long long)bucket_counts[0],
                    (unsigned long long)bucket_counts[1],
                    (unsigned long long)bucket_counts[2],
                    (unsigned long long)bucket_counts[3],
                    (unsigned long long)bucket_counts[4],
                    (unsigned long long)bucket_counts[5]);
    }
}

#ifdef __cplusplus
}
#endif
