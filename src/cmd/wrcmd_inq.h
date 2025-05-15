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
 * wrcmd_inq.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/wrcmd_inq.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WRCMD_INQ_H__
#define __WRCMD_INQ_H__

#include "wr_file_def.h"
#include "wr_io_fence.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef IOFENCE
typedef enum en_wr_inq_status {
    WR_INQ_STATUS_REG = 0,
    WR_INQ_STATUS_UNREG,
} wr_inq_status_e;

typedef enum en_wr_latch_remain_status {
    WR_NO_LATCH_STATUS = 0,
    WR_LATCH_STATUS_X = 1,
    WR_LATCH_STATUS_S = 2,
} wr_latch_remain_status_e;

typedef enum en_wr_query_latch_type {
    WR_LATCH_ALL = 0,
    WR_VG_LATCH = 1,
    WR_DISK_LATCH = 2,
} wr_query_latch_type_e;

#define WR_VG_LATCH_FLAG 0x00000001
#define WR_DISK_LATCH_FLAG 0x00000002
#define WR_ALL_LATCH_FLAG (WR_VG_LATCH_FLAG | WR_DISK_LATCH_FLAG)

status_t wr_inq_lun(const char *home);
status_t wr_inq_reg(const char *home);
status_t wr_check_volume_register(char *entry_path, int64 host_id, bool32 *is_reg, int64 *iofence_key);
status_t wr_unreghl_core(const char *home, bool32 is_lock);
status_t wr_reghl_core(const char *home);
status_t wr_inq_reg_core(const char *home, int64 host_id);
bool32 is_register(iof_reg_in_t *reg, int64 host_id, int64 *iofence_key);
status_t wr_clean_vg_lock(const char *home, int64 inst_id);
status_t wr_kickh_core(const char *home, int64 host_id);
status_t wr_get_vg_non_entry_info(
    wr_config_t *inst_cfg, wr_vg_info_item_t *vg_item, bool32 is_lock, bool32 check_redo);
status_t wr_inq_alloc_vg_info(const char *home, wr_config_t *inst_cfg, wr_vg_info_t **vg_info);
void wr_inq_free_vg_info(wr_vg_info_t *vg_info);
status_t wr_query_latch_remain(const char *home, int64 inst_id, int64 type);

#endif

#ifdef __cplusplus
}
#endif

#endif
