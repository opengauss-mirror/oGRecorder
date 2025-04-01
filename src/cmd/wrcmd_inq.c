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
 * wrcmd_inq.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/wrcmd_inq.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_malloc.h"
#include "wr_latch.h"
#include "wrcmd_inq.h"

#ifdef __cplusplus
extern "C" {
#endif
#ifdef IOFENCE

static void print_dev_info(ptlist_t *devs)
{
    return;
}

static void print_reg_info(ptlist_t *regs)
{
    return;
}

static status_t wr_modify_cluster_node_info(
    wr_vg_info_item_t *vg_item, wr_config_t *inst_cfg, wr_inq_status_e inq_status, int64 host_id)
{
    return CM_SUCCESS;
}

status_t wr_get_vg_non_entry_info(
    wr_config_t *inst_cfg, wr_vg_info_item_t *vg_item, bool32 is_lock, bool32 check_redo)
{
    return CM_SUCCESS;
}

status_t wr_inq_lun(const char *home)
{
    return CM_SUCCESS;
}

status_t wr_inq_reg(const char *home)
{
    return CM_SUCCESS;
}

bool32 is_register(iof_reg_in_t *reg, int64 host_id, int64 *iofence_key)
{
    return WR_FALSE;
}

status_t wr_check_volume_register(char *entry_path, int64 host_id, bool32 *is_reg, int64 *iofence_key)
{
    return CM_SUCCESS;
}

static status_t wr_reghl_inner(wr_vg_info_item_t *item, int64 host_id)
{
    return CM_SUCCESS;
}

static void wr_printf_iofence_key(int64 *iofence_key)
{
    return;
}

status_t wr_reghl_core(const char *home)
{
    return CM_SUCCESS;
}

static status_t wr_unreghl_inner(wr_vg_info_item_t *item, int64 host_id)
{
    return CM_SUCCESS;
}

status_t wr_unreghl_core(const char *home, bool32 is_lock)
{
    return CM_SUCCESS;
}

static status_t wr_inq_reg_inner(wr_vg_info_t *vg_info, wr_config_t *inst_cfg, int64 host_id, int64 *iofence_key)
{
    return CM_PIPECLOSED;
}

status_t wr_inq_reg_core(const char *home, int64 host_id)
{
    return CM_PIPECLOSED;
}

static status_t wr_clean_inner(wr_vg_info_t *vg_info, wr_config_t *inst_cfg, int64 inst_id)
{
    return  CM_SUCCESS;
}

status_t wr_check_disk_latch_remain_inner(
    int64 inst_id, wr_vg_info_t *vg_info, bool32 *is_remain, uint64 *latch_status)
{
    return CM_SUCCESS;
}

status_t wr_check_lock_remain(wr_vg_info_t *vg_info, int32 wr_mode, int64 inst_id)
{
    return CM_SUCCESS;
}

status_t wr_check_disk_latch_remain(int64 inst_id, wr_vg_info_t *vg_info)
{
    return CM_SUCCESS;
}

static status_t wr_get_latch_flag(int64 type, uint64 *flags)
{
    return CM_SUCCESS;
}
status_t wr_query_latch_remain(const char *home, int64 inst_id, int64 type)
{
    return status;
}

status_t wr_clean_vg_lock(const char *home, int64 inst_id)
{

    return CM_SUCCESS;
}

static status_t wr_kickh_inner(wr_vg_info_t *vg_info, wr_config_t *inst_cfg, int64 host_id, bool32 is_lock)
{
    return CM_SUCCESS;
}

/*
 * 1. get vg entry info
 * 2. get vg non entry info without lock, then kick
 * 3. get vg non entry info with lock, then kick
 */
status_t wr_kickh_core(const char *home, int64 host_id)
{
    return CM_SUCCESS;
}
#endif

#ifdef __cplusplus
}
#endif
