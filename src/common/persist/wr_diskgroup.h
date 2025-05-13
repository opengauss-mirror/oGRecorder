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
 * wr_diskgroup.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_diskgroup.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_DISK_GROUP_H__
#define __WR_DISK_GROUP_H__

#include "wr_defs.h"
#include "wr_volume.h"
#include "cm_types.h"
#include "wr_hashmap.h"
#include "wr_latch.h"
#include "cm_checksum.h"
#include "wr_file_def.h"
#include "cm_checksum.h"
#include "wr_log.h"
#include "wr_stack.h"
#include "wr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_READ4STANDBY_ERR (int32_t)3

/*
    1、when the node is standby, just send message to primary to read volume
    2、if the primary is just in recovery or switch, may wait the read request
    3、if read failed, just retry.
    4、may be standby switch to primary, just read volume from self;
    5、may be primary just change to standby, just read volume from new primary;
*/
#define WR_READ_REMOTE_INTERVAL 50

#pragma pack(8)
// for lsvg
typedef struct wr_volume_space_info_t {
    char volume_name[WR_MAX_VOLUME_PATH_LEN];
    double volume_free;
    double volume_size;
    double volume_used;
} volume_space_info_t;

typedef struct wr_vg_space_info_t {
    double wr_vg_free;
    double wr_vg_size;
} vg_space_info_t;

typedef struct wr_vg_vlm_space_info_t {
    char vg_name[WR_MAX_NAME_LEN];
    volume_space_info_t volume_space_info[WR_MAX_VOLUMES];
    vg_space_info_t vg_space_info;
    uint32_t volume_count;
} vg_vlm_space_info_t;

typedef struct st_wr_allvg_vlm_space_t {
    vg_vlm_space_info_t volume_group[WR_MAX_VOLUME_GROUP_NUM];
    uint32_t group_num;
} wr_allvg_vlm_space_t;
#pragma pack()

typedef handle_t wr_directory_t;  // wr_vfs_t

void wr_free_vg_info();
wr_vg_info_item_t *wr_find_vg_item(const char *vg_name);
wr_vg_info_item_t *wr_find_vg_item_by_id(uint32_t vg_id);


status_t wr_load_vg_ctrl_part(wr_vg_info_item_t *vg_item, int64 offset, void *buf, int32_t size, bool32 *remote);

void wr_lock_vg_mem_x(wr_vg_info_item_t *vg_item);
void wr_lock_vg_mem_s(wr_vg_info_item_t *vg_item);
void wr_lock_vg_mem_s_force(wr_vg_info_item_t *vg_item);
void wr_unlock_vg_mem(wr_vg_info_item_t *vg_item);

status_t wr_file_lock_vg_w(wr_config_t *inst_cfg);
void wr_file_unlock_vg(void);

status_t wr_lock_disk_vg(const char *entry_path, wr_config_t *inst_cfg);
status_t wr_lock_share_disk_vg(const char *entry_path, wr_config_t *inst_cfg);

status_t wr_unlock_vg_raid(wr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id);
status_t wr_unlock_vg_share_disk(wr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id);
status_t wr_unlock_vg(int32_t wr_mode, wr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id);
status_t wr_lock_vg_storage_r(wr_vg_info_item_t *vg_item, const char *entry_path, wr_config_t *inst_cfg);
status_t wr_unlock_vg_storage(wr_vg_info_item_t *vg_item, const char *entry_path, wr_config_t *inst_cfg);
status_t wr_lock_vg_storage_core(wr_vg_info_item_t *vg_item, const char *entry_path, wr_config_t *inst_cfg);
status_t wr_unlock_vg_storage_core(wr_vg_info_item_t *vg_item, const char *entry_path, wr_config_t *inst_cfg);
status_t wr_add_volume(wr_session_t *session, const char *vg_name, const char *volume_name);
status_t wr_remove_volume(wr_session_t *session, const char *vg_name, const char *volume_name);
status_t wr_refresh_meta_info(wr_session_t *session);

status_t wr_write_ctrl_to_disk(wr_vg_info_item_t *vg_item, int64 offset, void *buf, uint32_t size);
status_t wr_update_core_ctrl_disk(wr_vg_info_item_t *vg_item);
status_t wr_update_volume_ctrl(wr_vg_info_item_t *vg_item);
status_t wr_update_volume_id_info(wr_vg_info_item_t *vg_item, uint32_t id);

status_t wr_write_volume_inst(
    wr_vg_info_item_t *vg_item, wr_volume_t *volume, int64 offset, const void *buf, uint32_t size);
status_t wr_read_volume_inst(
    wr_vg_info_item_t *vg_item, wr_volume_t *volume, int64 offset, void *buf, int32_t size, bool32 *remote);
status_t wr_init_vol_handle(wr_vg_info_item_t *vg_item, int32_t flags, wr_vol_handles_t *vol_handles);
void wr_destroy_vol_handle(wr_vg_info_item_t *vg_item, wr_vol_handles_t *vol_handles, uint32_t size);
extern wr_vg_info_t *g_vgs_info;
#define VGS_INFO (g_vgs_info)
status_t wr_check_volume(wr_vg_info_item_t *vg_item, uint32_t volumeid);
uint32_t wr_find_volume(wr_vg_info_item_t *vg_item, const char *volume_name);
uint32_t wr_find_free_volume_id(const wr_vg_info_item_t *vg_item);
status_t wr_cmp_volume_head(wr_vg_info_item_t *vg_item, const char *volume_name, uint32_t id);
status_t wr_check_lock_remain_inner(
    int32_t wr_mode, wr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id, bool32 *is_remain);
static inline wr_vg_info_item_t *wr_get_first_vg_item()
{
    return &g_vgs_info->volume_group[0];
}

static inline uint64 wr_get_redo_log_lsn(wr_vg_info_item_t *vg_item)
{
    return vg_item->wr_ctrl->redo_ctrl.lsn;
}

static inline uint64 wr_inc_redo_log_lsn(wr_vg_info_item_t *vg_item)
{
    uint64 lsn = wr_get_redo_log_lsn(vg_item);
    lsn++;
    return lsn;
}

// NOTE:has minus checksum field.
static inline uint32_t wr_get_checksum(void *data, uint32_t len)
{
    char *buf = (char *)data;
    buf = buf + sizeof(uint32_t);  // checksum field
    CM_ASSERT(len - sizeof(uint32_t) > 0);
    uint32_t size = (uint32_t)(len - sizeof(uint32_t));
    return cm_get_checksum(buf, size);
}

static inline void wr_check_checksum(uint32_t checksum0, uint32_t checksum1)
{
    if (checksum0 != checksum1) {
        LOG_RUN_ERR("Failed to check checksum:%u,%u.", checksum0, checksum1);
        cm_panic(0);
    }
}

static inline bool32 wr_read_remote_checksum(void *buf, int32_t size)
{
    uint32_t sum1 = *(uint32_t *)buf;
    uint32_t sum2 = wr_get_checksum(buf, (uint32_t)size);
    LOG_DEBUG_INF("read remote checksum, checksum1 is %u, checksum2 is %u.", sum1, sum2);
    return sum1 == sum2;
}

uint64 wr_get_vg_latch_shm_offset(wr_vg_info_item_t *vg_item);

static inline uint64 wr_get_vg_au_size(wr_ctrl_t *ctrl)
{
    return (uint64)(ctrl->core.au_size);
}

static inline void wr_set_vg_au_size(wr_ctrl_t *ctrl, uint32_t au_size)
{
    CM_ASSERT(au_size <= WR_MAX_AU_SIZE);
    ctrl->core.au_size = au_size;
}

static inline bool32 wr_check_volume_is_used(wr_vg_info_item_t *vg_item, uint32_t vid)
{
    return (CM_CALC_ALIGN(WR_VOLUME_HEAD_SIZE, wr_get_vg_au_size(vg_item->wr_ctrl)) <
            vg_item->wr_ctrl->core.volume_attrs[vid].hwm);
}

static inline bool32 wr_compare_version(uint64 disk_version, uint64 mem_version)
{
    return (disk_version > mem_version);
}

uint32_t wr_get_master_id();
void wr_set_master_id(uint32_t id);
bool32 wr_is_server(void);
bool32 wr_is_readwrite(void);
bool32 wr_is_readonly(void);
void wr_set_server_flag(void);
bool32 wr_need_exec_local(void);
wr_vg_info_t *wr_malloc_vg_info(void);

typedef wr_instance_status_e (*wr_get_instance_status_proc_t)(void);
extern wr_get_instance_status_proc_t get_instance_status_proc;
void regist_get_instance_status_proc(wr_get_instance_status_proc_t proc);

int32_t wr_get_server_status_flag(void);
void wr_set_server_status_flag(int32_t wr_status);
void wr_set_recover_thread_id(uint32_t thread_id);
uint32_t wr_get_recover_thread_id(void);

status_t wr_check_write_volume(wr_vg_info_item_t *vg_item, uint32_t volumeid, int64 offset, void *buf, uint32_t size);
status_t wr_check_read_volume(
    wr_vg_info_item_t *vg_item, uint32_t volumeid, int64 offset, void *buf, int32_t size, bool32 *remote);
typedef status_t (*wr_remote_read_proc_t)(
    const char *vg_name, wr_volume_t *volume, int64 offset, void *buf, int size);
void regist_remote_read_proc(wr_remote_read_proc_t proc);
status_t wr_read_volume_4standby(const char *vg_name, uint32_t volume_id, int64 offset, void *buf, uint32_t size);
status_t wr_add_volume_vg_ctrl(
    wr_ctrl_t *vg_ctrl, uint32_t id, uint64 vol_size, const char *volume_name, volume_slot_e volume_flag);
status_t wr_gen_volume_head(
    wr_volume_header_t *vol_head, wr_vg_info_item_t *vg_item, const char *volume_name, uint32_t id);
status_t wr_check_remove_volume(wr_vg_info_item_t *vg_item, const char *volume_name, uint32_t *volume_id);
void wr_remove_volume_vg_ctrl(wr_ctrl_t *vg_ctrl, uint32_t id);
bool32 wr_meta_syn(wr_session_t *session, wr_bg_task_info_t *bg_task_info);
status_t wr_update_redo_ctrl(wr_vg_info_item_t *vg_item, uint32_t index, uint64 offset, uint64 lsn);

#ifdef __cplusplus
}
#endif
#endif
