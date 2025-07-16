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
 * wr_diskgroup.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_diskgroup.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_api.h"
#include "wr_file.h"
#include "wr_malloc.h"
#include "cm_dlock.h"
#include "cm_disklock.h"
#include "cm_utils.h"
#include "wr_open_file.h"
#include "wr_diskgroup.h"

#ifndef WIN32
#include <sys/file.h>
#endif
#include "wr_meta_buf.h"
#include "wr_syn_meta.h"
#include "wr_thv.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
#define WR_SIMUFILE_NAME "wr_vglock"
#define WR_FP_FREE (0)
#define WR_FP_INUSE (1)
typedef struct st_vglock_fp {
    uint32_t state;
    char file_name[WR_MAX_FILE_LEN];
    FILE *fp;  // each process has itself fp
} vglock_fp_t;

vglock_fp_t g_fp_list[WR_MAX_OPEN_VG];
#endif

wr_vg_info_t *g_vgs_info = NULL;

bool32 g_is_wr_server = WR_FALSE;
static wr_rdwr_type_e g_is_wr_readwrite = WR_STATUS_NORMAL;
static uint32_t g_master_instance_id = WR_INVALID_ID32;
static uint32_t g_wr_recover_thread_id = 0;

// CAUTION: wr_admin manager command just like wr_create_vg,cannot call it,

bool32 wr_is_server(void)
{
    return g_is_wr_server;
}

bool32 wr_is_readwrite(void)
{
    return g_is_wr_readwrite == WR_STATUS_READWRITE;
}

bool32 wr_is_readonly(void)
{
    return g_is_wr_readwrite == WR_STATUS_READONLY;
}

uint32_t wr_get_master_id()
{
    return g_master_instance_id;
}

void wr_set_master_id(uint32_t id)
{
    g_master_instance_id = id;
    LOG_RUN_INF("set master id is %u.", id);
}

void wr_set_server_flag(void)
{
    g_is_wr_server = WR_TRUE;
}

int32_t wr_get_server_status_flag(void)
{
    return (int32_t)g_is_wr_readwrite;
}

void wr_set_server_status_flag(int32_t wr_status)
{
    g_is_wr_readwrite = wr_status;
}

void wr_set_recover_thread_id(uint32_t thread_id)
{
    g_wr_recover_thread_id = thread_id;
}

wr_get_instance_status_proc_t get_instance_status_proc = NULL;
void regist_get_instance_status_proc(wr_get_instance_status_proc_t proc)
{
    get_instance_status_proc = proc;
}

void wr_free_vg_info()
{
    LOG_RUN_INF("free g_vgs_info.");
    WR_FREE_POINT(g_vgs_info)
}

wr_vg_info_item_t *wr_find_vg_item(const char *vg_name)
{
    for (uint32_t i = 0; i < g_vgs_info->group_num; i++) {
        if (strcmp(g_vgs_info->volume_group[i].vg_name, vg_name) == 0) {
            return &g_vgs_info->volume_group[i];
        }
    }
    return NULL;
}

wr_remote_read_proc_t remote_read_proc = NULL;

bool32 wr_need_exec_local(void)
{
    wr_config_t *cfg = wr_get_inst_cfg();
    uint32_t master_id = wr_get_master_id();
    uint32_t curr_id = (uint32_t)(cfg->params.inst_id);
    return ((curr_id == master_id));
}

#ifdef __cplusplus
}
#endif
