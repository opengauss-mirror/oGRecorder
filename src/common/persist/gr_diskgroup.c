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
 * gr_diskgroup.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/gr_diskgroup.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_api.h"
#include "gr_file.h"
#include "gr_malloc.h"
#include "cm_dlock.h"
#include "cm_disklock.h"
#include "cm_utils.h"
#include "gr_diskgroup.h"

#ifndef WIN32
#include <sys/file.h>
#endif
#include "gr_meta_buf.h"
#include "gr_syn_meta.h"
#include "gr_thv.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
#define GR_SIMUFILE_NAME "gr_vglock"
#define GR_FP_FREE (0)
#define GR_FP_INUSE (1)
typedef struct st_vglock_fp {
    uint32_t state;
    char file_name[GR_MAX_FILE_LEN];
    FILE *fp;  // each process has itself fp
} vglock_fp_t;

vglock_fp_t g_fp_list[GR_MAX_OPEN_VG];
#endif

gr_vg_info_t *g_vgs_info = NULL;

bool32 g_is_gr_server = GR_FALSE;
static gr_rdgr_type_e g_is_gr_readwrite = GR_STATUS_NORMAL;
static uint32_t g_master_instance_id = GR_INVALID_ID32;
static uint32_t g_gr_recover_thread_id = 0;

// CAUTION: gr_admin manager command just like gr_create_vg,cannot call it,

bool32 gr_is_server(void)
{
    return g_is_gr_server;
}

bool32 gr_is_readwrite(void)
{
    return g_is_gr_readwrite == GR_STATUS_READWRITE;
}

bool32 gr_is_readonly(void)
{
    return g_is_gr_readwrite == GR_STATUS_READONLY;
}

uint32_t gr_get_master_id()
{
    return g_master_instance_id;
}

void gr_set_master_id(uint32_t id)
{
    g_master_instance_id = id;
    LOG_RUN_INF("set master id is %u.", id);
}

void gr_set_server_flag(void)
{
    g_is_gr_server = GR_TRUE;
}

int32_t gr_get_server_status_flag(void)
{
    return (int32_t)g_is_gr_readwrite;
}

void gr_set_server_status_flag(int32_t gr_status)
{
    g_is_gr_readwrite = gr_status;
}

void gr_set_recover_thread_id(uint32_t thread_id)
{
    g_gr_recover_thread_id = thread_id;
}

gr_get_instance_status_proc_t get_instance_status_proc = NULL;
void regist_get_instance_status_proc(gr_get_instance_status_proc_t proc)
{
    get_instance_status_proc = proc;
}

void gr_free_vg_info()
{
    LOG_RUN_INF("free g_vgs_info.");
    GR_FREE_POINT(g_vgs_info)
}

gr_vg_info_item_t *gr_find_vg_item(const char *vg_name)
{
    for (uint32_t i = 0; i < g_vgs_info->group_num; i++) {
        if (strcmp(g_vgs_info->volume_group[i].vg_name, vg_name) == 0) {
            return &g_vgs_info->volume_group[i];
        }
    }
    return NULL;
}

gr_remote_read_proc_t remote_read_proc = NULL;

bool32 gr_need_exec_local(void)
{
    gr_config_t *cfg = gr_get_inst_cfg();
    uint32_t master_id = gr_get_master_id();
    uint32_t curr_id = (uint32_t)(cfg->params.inst_id);
    return ((curr_id == master_id));
}

#ifdef __cplusplus
}
#endif
