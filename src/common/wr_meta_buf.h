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
#define WR_BUFFER_CACHE_HASH(block_id) cm_hash_int64((int64)WR_BLOCK_ID_IGNORE_UNINITED((block_id)))
void wr_enter_shm_x(wr_session_t *session, wr_vg_info_item_t *vg_item);
bool32 wr_enter_shm_time_x(wr_session_t *session, wr_vg_info_item_t *vg_item, uint32_t wait_ticks);
void wr_enter_shm_s(wr_session_t *session, wr_vg_info_item_t *vg_item, bool32 is_force, int32_t timeout);
void wr_leave_shm(wr_session_t *session, wr_vg_info_item_t *vg_item);

wr_block_ctrl_t *wr_buffer_get_block_ctrl_addr(ga_pool_id_e pool_id, uint32_t object_id);
char *wr_buffer_get_meta_addr(ga_pool_id_e pool_id, uint32_t object_id);

uint32_t wr_buffer_cache_get_block_size(uint32_t block_type);
bool32 wr_buffer_cache_key_compare(void *key, void *key2);

status_t wr_register_buffer_cache(wr_session_t *session, wr_vg_info_item_t *vg_item, const wr_block_id_t block_id,
    ga_obj_id_t obj_id, char *meta_addr, wr_block_type_t type);
void wr_unregister_buffer_cache(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id);
status_t wr_find_block_objid_in_shm(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id,
    wr_block_type_t type, ga_obj_id_t *objid);
char *wr_find_block_in_shm(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id,
    wr_block_type_t type, bool32 check_version, ga_obj_id_t *out_obj_id, bool32 active_refresh);
char *wr_find_block_from_disk_and_refresh_shm(wr_session_t *session, wr_vg_info_item_t *vg_item,
    wr_block_id_t block_id, wr_block_type_t type, ga_obj_id_t *out_obj_id);
char *wr_find_block_in_shm_no_refresh(
    wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id, ga_obj_id_t *out_obj_id);
// do not care content change, just care about exist
char *wr_find_block_in_shm_no_refresh_ex(
    wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id, ga_obj_id_t *out_obj_id);

status_t wr_refresh_buffer_cache(wr_session_t *session, wr_vg_info_item_t *vg_item, shm_hashmap_t *map);
status_t wr_get_block_from_disk(
    wr_vg_info_item_t *vg_item, wr_block_id_t block_id, char *buf, int64_t offset, int32_t size, bool32 calc_checksum);
status_t wr_check_block_version(wr_vg_info_item_t *vg_item, wr_block_id_t block_id, wr_block_type_t type,
    char *meta_addr, bool32 *is_changed, bool32 force_refresh);
status_t wr_refresh_block_in_shm(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id,
    wr_block_type_t type, char *buf, char **shm_buf);
static inline int64 wr_get_block_offset(wr_vg_info_item_t *vg_item, uint64 block_size, uint64 blockid, uint64 auid)
{
    return (int64)(block_size * blockid + wr_get_vg_au_size(vg_item->wr_ctrl) * auid);
}

void wr_init_wr_fs_block_cache_info(wr_fs_block_cache_info_t *fs_block_cache_info);
void wr_init_vg_cache_node_info(wr_vg_info_item_t *vg_item);
status_t wr_hashmap_extend_and_redistribute(wr_session_t *session, shm_hash_ctrl_t *hash_ctrl);
status_t wr_hashmap_extend_and_redistribute_batch(
    wr_session_t *session, shm_hash_ctrl_t *hash_ctrl, uint32_t extend_num);
void wr_hashmap_dynamic_extend_and_redistribute_per_vg(wr_vg_info_item_t *vg_item, wr_session_t *session);

// do not need control concurrence
void wr_inc_meta_ref_hot(wr_block_ctrl_t *block_ctrl);
// do not need control concurrence
void wr_desc_meta_ref_hot(wr_block_ctrl_t *block_ctrl);

void wr_buffer_recycle_disable(wr_block_ctrl_t *block_ctrl, bool8 recycle_disable);
void wr_set_recycle_meta_args_to_vg(wr_bg_task_info_t *bg_task_info);
void wr_recycle_meta(wr_session_t *session, wr_bg_task_info_t *bg_task_info, date_t *clean_time);
void wr_trigger_recycle_meta(wr_vg_info_item_t *vg_item);

#ifdef __cplusplus
}
#endif
#endif
