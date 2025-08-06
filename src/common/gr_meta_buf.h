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
 * gr_meta_buf.h
 *
 *
 * IDENTIFICATION
 *    src/common/gr_meta_buf.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_META_BUF_H__
#define __GR_META_BUF_H__

#include "gr_ga.h"
#include "gr_au.h"
#include "gr_diskgroup.h"
#include "gr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

// this meta_addr should be formated as: block_ctrl(512) | meta(ft/fs/fs-aux)
#define GR_GET_META_FROM_BLOCK_CTRL(meta_type, block_ctrl) ((meta_type *)((char *)(block_ctrl) + GR_BLOCK_CTRL_SIZE))
#define GR_GET_BLOCK_CTRL_FROM_META(meta_addr) ((gr_block_ctrl_t *)((char *)(meta_addr)-GR_BLOCK_CTRL_SIZE))

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
#define GR_RECYCLE_META_RECYCLE_RATE_HWM 8000  // unit is 0.01%
#define GR_RECYCLE_META_RECYCLE_RATE_LWM 6000  // unit is 0.01%
#else
#define GR_RECYCLE_META_RECYCLE_RATE_HWM 80  // unit is 1%
#define GR_RECYCLE_META_RECYCLE_RATE_LWM 60  // unit is 1%
#endif

#define GR_RECYCLE_META_HOT_INC_STEP 3
#define GR_RECYCLE_META_TIME_CLEAN_BATCH_NUM 8
#define GR_RECYCLE_META_TRIGGER_CLEAN_BATCH_NUM 1
#define GR_RECYCLE_META_TRIGGER_WAIT_TIME 200  // ms

typedef struct st_gr_recycle_meta_args {
    gr_recycle_meta_pos_t *recyle_meta_pos;
    uint32_t time_clean_wait_time;     // ms
    uint32_t trigger_clean_wait_time;  // ms
    cm_thread_cond_t trigger_cond;   // for tigger recycle meta by other task
    bool32 trigger_enable;
    uint32_t last_bucket_id[GR_MAX_VOLUME_GROUP_NUM];  // for re-start from last recycle stop point
} gr_recycle_meta_args_t;

typedef struct st_gr_recycle_meta {
    gr_recycle_meta_args_t recycle_meta_args;
    gr_bg_task_info_t recycle_meta_task[GR_RECYLE_META_TASK_NUM_MAX];
} gr_recycle_meta_t;

#define GR_LOCK_SHM_META_TIMEOUT 200

char *gr_find_block_from_disk_and_refresh_shm(gr_session_t *session, gr_vg_info_item_t *vg_item,
    gr_block_id_t block_id, gr_block_type_t type, ga_obj_id_t *out_obj_id);

#ifdef __cplusplus
}
#endif
#endif
