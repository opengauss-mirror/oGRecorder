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
 * gr_diskgroup.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/gr_diskgroup.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_DISK_GROUP_H__
#define __GR_DISK_GROUP_H__

#include "gr_defs.h"
#include "cm_types.h"
#include "gr_hashmap.h"
#include "gr_latch.h"
#include "cm_checksum.h"
#include "gr_file_def.h"
#include "cm_checksum.h"
#include "gr_log.h"
#include "gr_stack.h"
#include "gr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GR_READ4STANDBY_ERR (int32_t)3

/*
    1、when the node is standby, just send message to primary to read volume
    2、if the primary is just in recovery or switch, may wait the read request
    3、if read failed, just retry.
    4、may be standby switch to primary, just read volume from self;
    5、may be primary just change to standby, just read volume from new primary;
*/
#define GR_READ_REMOTE_INTERVAL 50

#pragma pack(8)
// for lsvg
typedef struct gr_volume_space_info_t {
    char volume_name[GR_MAX_VOLUME_PATH_LEN];
    double volume_free;
    double volume_size;
    double volume_used;
} volume_space_info_t;

typedef struct gr_vg_space_info_t {
    double gr_vg_free;
    double gr_vg_size;
} vg_space_info_t;

typedef struct gr_vg_vlm_space_info_t {
    char vg_name[GR_MAX_NAME_LEN];
    volume_space_info_t volume_space_info[GR_MAX_VOLUMES];
    vg_space_info_t vg_space_info;
    uint32_t volume_count;
} vg_vlm_space_info_t;

typedef struct st_gr_allvg_vlm_space_t {
    vg_vlm_space_info_t volume_group[GR_MAX_VOLUME_GROUP_NUM];
    uint32_t group_num;
} gr_allvg_vlm_space_t;
#pragma pack()

typedef handle_t gr_directory_t;  // gr_vfs_t

void gr_free_vg_info();
gr_vg_info_item_t *gr_find_vg_item(const char *vg_name);

status_t gr_lock_disk_vg(const char *entry_path, gr_config_t *inst_cfg);

status_t gr_unlock_vg_raid(gr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id);
status_t gr_unlock_vg_share_disk(gr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id);
status_t gr_unlock_vg(int32_t gr_mode, gr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id);
status_t gr_lock_vg_storage_r(gr_vg_info_item_t *vg_item, const char *entry_path, gr_config_t *inst_cfg);
status_t gr_unlock_vg_storage(gr_vg_info_item_t *vg_item, const char *entry_path, gr_config_t *inst_cfg);
status_t gr_lock_vg_storage_core(gr_vg_info_item_t *vg_item, const char *entry_path, gr_config_t *inst_cfg);
status_t gr_unlock_vg_storage_core(gr_vg_info_item_t *vg_item, const char *entry_path, gr_config_t *inst_cfg);

extern gr_vg_info_t *g_vgs_info;
#define VGS_INFO (g_vgs_info)
status_t gr_cmp_volume_head(gr_vg_info_item_t *vg_item, const char *volume_name, uint32_t id);
status_t gr_check_lock_remain_inner(
    int32_t gr_mode, gr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id, bool32 *is_remain);
static inline gr_vg_info_item_t *gr_get_first_vg_item()
{
    return &g_vgs_info->volume_group[0];
}

static inline uint64 gr_get_redo_log_lsn(gr_vg_info_item_t *vg_item)
{
    return vg_item->gr_ctrl->redo_ctrl.lsn;
}

static inline uint64 gr_inc_redo_log_lsn(gr_vg_info_item_t *vg_item)
{
    uint64 lsn = gr_get_redo_log_lsn(vg_item);
    lsn++;
    return lsn;
}

// NOTE:has minus checksum field.
static inline uint32_t gr_get_checksum(void *data, uint32_t len)
{
    char *buf = (char *)data;
    buf = buf + sizeof(uint32_t);  // checksum field
    CM_ASSERT(len - sizeof(uint32_t) > 0);
    uint32_t size = (uint32_t)(len - sizeof(uint32_t));
    return cm_get_checksum(buf, size);
}

static inline void gr_check_checksum(uint32_t checksum0, uint32_t checksum1)
{
    if (checksum0 != checksum1) {
        LOG_RUN_ERR("Failed to check checksum:%u,%u.", checksum0, checksum1);
        cm_panic(0);
    }
}

static inline bool32 gr_read_remote_checksum(void *buf, int32_t size)
{
    uint32_t sum1 = *(uint32_t *)buf;
    uint32_t sum2 = gr_get_checksum(buf, (uint32_t)size);
    LOG_DEBUG_INF("read remote checksum, checksum1 is %u, checksum2 is %u.", sum1, sum2);
    return sum1 == sum2;
}

static inline uint64 gr_get_vg_au_size(gr_ctrl_t *ctrl)
{
    return (uint64)(ctrl->core.au_size);
}

static inline void gr_set_vg_au_size(gr_ctrl_t *ctrl, uint32_t au_size)
{
    CM_ASSERT(au_size <= GR_MAX_AU_SIZE);
    ctrl->core.au_size = au_size;
}

static inline bool32 gr_check_volume_is_used(gr_vg_info_item_t *vg_item, uint32_t vid)
{
    return (CM_CALC_ALIGN(GR_VOLUME_HEAD_SIZE, gr_get_vg_au_size(vg_item->gr_ctrl)) <
            vg_item->gr_ctrl->core.volume_attrs[vid].hwm);
}

static inline bool32 gr_compare_version(uint64 disk_version, uint64 mem_version)
{
    return (disk_version > mem_version);
}

uint32_t gr_get_master_id();
void gr_set_master_id(uint32_t id);
bool32 gr_is_server(void);
bool32 gr_is_readwrite(void);
bool32 gr_is_readonly(void);
void gr_set_server_flag(void);
bool32 gr_need_exec_local(void);

typedef gr_instance_status_e (*gr_get_instance_status_proc_t)(void);
extern gr_get_instance_status_proc_t get_instance_status_proc;
void regist_get_instance_status_proc(gr_get_instance_status_proc_t proc);

int32_t gr_get_server_status_flag(void);
void gr_set_server_status_flag(int32_t gr_status);
void gr_set_recover_thread_id(uint32_t thread_id);

status_t gr_check_write_volume(gr_vg_info_item_t *vg_item, uint32_t volumeid, int64 offset, void *buf, uint32_t size);
typedef status_t (*gr_remote_read_proc_t)(
    const char *vg_name, gr_volume_t *volume, int64 offset, void *buf, int size);
status_t gr_add_volume_vg_ctrl(
    gr_ctrl_t *vg_ctrl, uint32_t id, uint64 vol_size, const char *volume_name, volume_slot_e volume_flag);
status_t gr_gen_volume_head(
    gr_volume_header_t *vol_head, gr_vg_info_item_t *vg_item, const char *volume_name, uint32_t id);
status_t gr_check_remove_volume(gr_vg_info_item_t *vg_item, const char *volume_name, uint32_t *volume_id);
void gr_remove_volume_vg_ctrl(gr_ctrl_t *vg_ctrl, uint32_t id);
bool32 gr_meta_syn(gr_session_t *session, gr_bg_task_info_t *bg_task_info);
status_t gr_update_redo_ctrl(gr_vg_info_item_t *vg_item, uint32_t index, uint64 offset, uint64 lsn);

#ifdef __cplusplus
}
#endif
#endif
