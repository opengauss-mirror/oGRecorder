/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * wr_simulation_cm.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_simulation_cm.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_SIMULATION_CM_H__
#define __WR_SIMULATION_CM_H__

#include "wr_defs.h"
#include "cm_config.h"
#include "cs_pipe.h"
#include "mes_metadata.h"
#include "ssl_metadata.h"
#include "wr_errno.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifdef ENABLE_WRTEST
#define CM_CONFIG_PATH        "CM_CONFIG_PATH"
#define CM_LOCK_OWNER_ID       "LOCK_OWNER_ID"
#define CM_BITMAP_ONLINE      "BITMAP_ONLINE"
#define WR_LONG_TIMEOUT   300

typedef enum en_cm_params {
    CM_PARAM_LOCK_OWNER_ID,
    CM_PARAM_BITMAP_ONLINE,
    /* add above here */
    CM_PARAM_COUNT
} cm_params_e;

typedef struct st_cm_params {
    uint64 bitmap_online;
    uint32_t lock_owner_id;
} cm_params_t;

typedef struct st_simulation_cm {
    thread_t thread;
    spinlock_t lock;
    config_t config;
    cm_params_t params;
    bool32 simulation;
} simulation_cm_t;
extern simulation_cm_t g_simulation_cm;
void wr_simulation_cm_res_mgr_uninit(cm_res_mgr_t *cm_res_mgr);
status_t wr_simulation_cm_res_mgr_init(const char *so_lib_path, cm_res_mgr_t *cm_res_mgr, cm_allocator_t *alloc);
#endif

#ifdef __cplusplus
}
#endif

#endif
