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
 * wr_io_fence.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_io_fence.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_IO_FENCE_H__
#define __WR_IO_FENCE_H__

#include "wr_defs.h"
#include "wr_session.h"
#include "wr_file.h"
#include "cm_scsi.h"
#include "cm_iofence.h"
#include "cm_list.h"

#ifdef __cplusplus
extern "C" {
#endif
#ifdef IOFENCE
typedef struct st_dev_info {
    char *dev;
    inquiry_data_t data;
} dev_info_t;

// because cm_destory_ptlist will NOT FRE ptlist->item[idx] memory
void wr_destroy_ptlist(ptlist_t *ptlist);

// kick/reg host with all devs
status_t wr_iof_kick_all_volumes(wr_vg_info_t *wr_vg_info, int64 rk, int64 rk_kick, ptlist_t *reg_list);
status_t wr_iof_sync_all_vginfo(wr_session_t *session, wr_vg_info_t *wr_vg_info);
status_t wr_iof_kick_all(wr_vg_info_t *vg_info, wr_config_t *inst_cfg, int64 rk, int64 rk_kick);
status_t wr_iof_register_core(int64 rk, wr_vg_info_t *wr_vg_info);
status_t wr_iof_unregister_core(int64 rk, wr_vg_info_t *wr_vg_info);

// inquire lun info
status_t wr_inquiry_luns_from_ctrl(wr_vg_info_item_t *item, ptlist_t *lunlist);
status_t wr_inquiry_luns(wr_vg_info_t *vg_info, ptlist_t *lunlist);
status_t wr_inquiry_lun(dev_info_t *dev_info);

// read keys and reservations
status_t wr_iof_inql_regs_core(ptlist_t *reglist, wr_vg_info_item_t *item);
status_t wr_iof_inql_regs(wr_vg_info_t *vg_info, ptlist_t *reglist);

status_t wr_iof_unregister_single(int64 rk, char *dev);
status_t wr_iof_register_single(int64 rk, char *dev);

#endif
#ifdef __cplusplus
}
#endif
#endif
