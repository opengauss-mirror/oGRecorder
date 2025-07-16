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
 * wr_meta_buf.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_meta_buf.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_META_BUF_H__
#define __WR_META_BUF_H__

#include "wr_ga.h"
#include "wr_au.h"
#include "wr_diskgroup.h"
#include "wr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

// this meta_addr should be formated as: block_ctrl(512) | meta(ft/fs/fs-aux)
#define WR_GET_META_FROM_BLOCK_CTRL(meta_type, block_ctrl) ((meta_type *)((char *)(block_ctrl) + WR_BLOCK_CTRL_SIZE))
#define WR_GET_BLOCK_CTRL_FROM_META(meta_addr) ((wr_block_ctrl_t *)((char *)(meta_addr)-WR_BLOCK_CTRL_SIZE))

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
#define WR_RECYCLE_META_RECYCLE_RATE_HWM 8000  // unit is 0.01%
#define WR_RECYCLE_META_RECYCLE_RATE_LWM 6000  // unit is 0.01%
#else
#define WR_RECYCLE_META_RECYCLE_RATE_HWM 80  // unit is 1%
#define WR_RECYCLE_META_RECYCLE_RATE_LWM 60  // unit is 1%
#endif

#define WR_RECYCLE_META_HOT_INC_STEP 3
#define WR_RECYCLE_META_TIME_CLEAN_BATCH_NUM 8
#define WR_RECYCLE_META_TRIGGER_CLEAN_BATCH_NUM 1
#define WR_RECYCLE_META_TRIGGER_WAIT_TIME 200  // ms

typedef struct st_wr_recycle_meta_args {
    wr_recycle_meta_pos_t *recyle_meta_pos;
    uint32_t time_clean_wait_time;     // ms
    uint32_t trigger_clean_wait_time;  // ms
    cm_thread_cond_t trigger_cond;   // for tigger recycle meta by other task
    bool32 trigger_enable;
    uint32_t last_bucket_id[WR_MAX_VOLUME_GROUP_NUM];  // for re-start from last recycle stop point
} wr_recycle_meta_args_t;

typedef struct st_wr_recycle_meta {
    wr_recycle_meta_args_t recycle_meta_args;
    wr_bg_task_info_t recycle_meta_task[WR_RECYLE_META_TASK_NUM_MAX];
} wr_recycle_meta_t;

#define WR_LOCK_SHM_META_TIMEOUT 200

char *wr_find_block_from_disk_and_refresh_shm(wr_session_t *session, wr_vg_info_item_t *vg_item,
    wr_block_id_t block_id, wr_block_type_t type, ga_obj_id_t *out_obj_id);

#ifdef __cplusplus
}
#endif
#endif
