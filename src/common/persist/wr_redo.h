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
 * wr_redo.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_redo.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_REDO_H__
#define __WR_REDO_H__

#include "cm_defs.h"
#include "cm_date.h"
#include "wr_diskgroup.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_LOG_OFFSET OFFSET_OF(wr_ctrl_t, log_buf)

#define WR_INSTANCE_LOG_BUFFER_SIZE_V0 SIZE_M(8)
#define WR_LOG_BUF_SLOT_COUNT_V0 16
#define WR_INSTANCE_LOG_SPLIT_SIZE_V0 ((WR_INSTANCE_LOG_BUFFER_SIZE_V0) / (WR_LOG_BUF_SLOT_COUNT_V0))
#define WR_INSTANCE_LOG_SPLIT_SIZE                                                          \
    ((WR_INSTANCE_LOG_BUFFER_SIZE_V0) / (WR_MAX_VOLUME_GROUP_NUM) / (WR_DISK_UNIT_SIZE) * \
        (WR_DISK_UNIT_SIZE))  // 126KB
#define WR_VG_LOG_SPLIT_SIZE SIZE_K(64)
#define WR_VG_LOG_BUFFER_SIZE SIZE_M(64)

#pragma pack(8)

typedef enum en_wr_redo_type {
    // wr_ctrl
    WR_RT_UPDATE_CORE_CTRL = 0,  // start with 0, step 1, type id as index of handler array
    // volume
    WR_RT_ADD_OR_REMOVE_VOLUME,
    WR_RT_UPDATE_VOLHEAD,
    // ft_block && gft_node
    WR_RT_FORMAT_AU_FILE_TABLE,
    WR_RT_ALLOC_FILE_TABLE_NODE,
    WR_RT_FREE_FILE_TABLE_NODE,
    WR_RT_RECYCLE_FILE_TABLE_NODE,
    WR_RT_SET_FILE_SIZE,
    WR_RT_RENAME_FILE,
    // fs_block
    WR_RT_FORMAT_AU_FILE_SPACE,
    WR_RT_ALLOC_FS_BLOCK,
    WR_RT_FREE_FS_BLOCK,
    WR_RT_INIT_FILE_FS_BLOCK,
    WR_RT_SET_FILE_FS_BLOCK,

    // gft_node
    WR_RT_SET_NODE_FLAG,

    // fs aux
    WR_RT_ALLOC_FS_AUX,
    WR_RT_FREE_FS_AUX,
    WR_RT_INIT_FS_AUX,
    WR_RT_SET_FS_BLOCK_BATCH,
    WR_RT_SET_FS_AUX_BLOCK_BATCH,
    WR_RT_TRUNCATE_FS_BLOCK_BATCH,
} wr_redo_type_t;

// redo struct allocate file table node
typedef enum st_wr_redo_alloc_ft_node_index {
    WR_REDO_ALLOC_FT_NODE_SELF_INDEX = 0,
    WR_REDO_ALLOC_FT_NODE_PREV_INDEX = 1,
    WR_REDO_ALLOC_FT_NODE_PARENT_INDEX = 2,
    WR_REDO_ALLOC_FT_NODE_NUM = 3
} wr_redo_alloc_ft_node_index_e;
typedef struct st_wr_redo_alloc_ft_node_t {
    gft_root_t ft_root;
    gft_node_t node[WR_REDO_ALLOC_FT_NODE_NUM];
} wr_redo_alloc_ft_node_t;

typedef enum st_wr_redo_free_ft_node_index {
    WR_REDO_FREE_FT_NODE_PARENT_INDEX = 0,
    WR_REDO_FREE_FT_NODE_PREV_INDEX = 1,
    WR_REDO_FREE_FT_NODE_NEXT_INDEX = 2,
    WR_REDO_FREE_FT_NODE_SELF_INDEX = 3,
    WR_REDO_FREE_FT_NODE_NUM = 4
} wr_redo_free_ft_node_index_e;
typedef struct st_wr_redo_free_ft_node_t {
    gft_root_t ft_root;
    gft_node_t node[WR_REDO_FREE_FT_NODE_NUM];
} wr_redo_free_ft_node_t;

typedef enum st_wr_redo_recycle_ft_node_index {
    WR_REDO_RECYCLE_FT_NODE_SELF_INDEX = 0,
    WR_REDO_RECYCLE_FT_NODE_LAST_INDEX = 1,
    WR_REDO_RECYCLE_FT_NODE_RECYCLE_INDEX = 2,
    WR_REDO_RECYCLE_FT_NODE_NUM = 3
} wr_redo_recycle_ft_node_index_e;
typedef struct st_wr_redo_recycle_ft_node_t {
    gft_node_t node[WR_REDO_RECYCLE_FT_NODE_NUM];
} wr_redo_recycle_ft_node_t;

typedef struct st_wr_redo_format_ft_t {
    auid_t auid;
    uint32 obj_id;
    uint32 count;
    wr_block_id_t old_last_block;
    gft_list_t old_free_list;
} wr_redo_format_ft_t;

typedef struct st_wr_redo_free_fs_block_t {
    char head[WR_DISK_UNIT_SIZE];
} wr_redo_free_fs_block_t;

typedef struct st_wr_redo_alloc_fs_block_t {
    wr_block_id_t id;
    wr_block_id_t ftid;
    wr_fs_block_root_t root;
    uint16_t index;
    uint16_t reserve;
} wr_redo_alloc_fs_block_t;

typedef struct st_wr_redo_rename_t {
    gft_node_t node;
    char name[WR_MAX_NAME_LEN];
    char old_name[WR_MAX_NAME_LEN];
} wr_redo_rename_t;

typedef struct st_wr_redo_volhead_t {
    char head[WR_DISK_UNIT_SIZE];
    char name[WR_MAX_NAME_LEN];
} wr_redo_volhead_t;

typedef struct st_wr_redo_volop_t {
    char attr[WR_DISK_UNIT_SIZE];
    char def[WR_DISK_UNIT_SIZE];
    bool32 is_add;
    uint32 volume_count;
    uint64 core_version;
    uint64 volume_version;
} wr_redo_volop_t;

typedef struct st_wr_redo_format_fs_t {
    auid_t auid;
    uint32 obj_id;
    uint32 count;
    wr_fs_block_list_t old_free_list;
} wr_redo_format_fs_t;

typedef struct st_wr_redo_init_fs_block_t {
    wr_block_id_t id;
    wr_block_id_t second_id;
    uint16 index;
    uint16 used_num;
    uint16 reserve[2];
} wr_redo_init_fs_block_t;

typedef struct st_wr_redo_set_fs_block_t {
    wr_block_id_t id;
    wr_block_id_t value;
    wr_block_id_t old_value;
    uint16 index;
    uint16 used_num;
    uint16 old_used_num;
    uint16 reserve;
} wr_redo_set_fs_block_t;

typedef struct st_wr_redo_set_fs_block_batch_t {
    wr_block_id_t id;
    uint16 used_num;
    uint16 old_used_num;
    uint16 reserve;
    wr_block_id_t id_set[WR_FILE_SPACE_BLOCK_BITMAP_COUNT];
} wr_redo_set_fs_block_batch_t;

typedef struct st_wr_redo_set_fs_aux_block_batch_t {
    wr_block_id_t fs_block_id;
    auid_t first_batch_au;
    ftid_t node_id;
    uint16 old_used_num;
    uint16 batch_count;
    wr_fs_block_list_t new_free_list;
    wr_block_id_t id_set[WR_FILE_SPACE_BLOCK_BITMAP_COUNT];
} wr_redo_set_fs_aux_block_batch_t;

typedef struct st_wr_redo_truncate_fs_block_batch_t {
    wr_block_id_t src_id;
    wr_block_id_t dst_id;
    uint16 src_begin;
    uint16 dst_begin;
    uint16 src_old_used_num;
    uint16 dst_old_used_num;
    uint16 count;
    uint16 reserve;
    wr_block_id_t id_set[WR_FILE_SPACE_BLOCK_BITMAP_COUNT];
} wr_redo_truncate_fs_block_batch_t;
typedef struct st_wr_redo_set_file_size_t {
    ftid_t ftid;
    uint64 size;
    uint64 oldsize;  // old size
} wr_redo_set_file_size_t;

typedef struct st_wr_redo_set_fs_block_list_t {
    wr_block_id_t id;
    wr_block_id_t next;
    uint16 reserve[4];
} wr_redo_set_fs_block_list_t;

typedef struct st_wr_redo_set_file_flag_t {
    ftid_t ftid;
    uint32 flags;
    uint32 old_flags;
} wr_redo_set_file_flag_t;

typedef struct st_wr_redo_entry {
    wr_redo_type_t type;
    uint32 size;
    char data[0];
} wr_redo_entry_t;

#define WR_REDO_ENTRY_HEAD_SIZE OFFSET_OF(wr_redo_entry_t, data)

// sizeof(wr_redo_batch_t) should be eight-byte aligned
typedef struct st_wr_redo_batch {
    uint32 size;
    uint32 hash_code;
    date_t time;
    uint64 lsn;
    uint32 count;  // entry count;
    char reverse[4];
    char data[0];
} wr_redo_batch_t;
#pragma pack()

// todo: deleteredo log begin in disk
static inline uint64 wr_get_redo_log_v0_start(wr_ctrl_t *wr_ctrl, uint32 vg_id)
{
    uint64 au_size = wr_get_vg_au_size(wr_ctrl);
    uint64 redo_start = CM_CALC_ALIGN(WR_VOLUME_HEAD_SIZE, au_size) + vg_id * WR_INSTANCE_LOG_SPLIT_SIZE;
    return redo_start;
}

static inline uint32 wr_get_log_size(uint64 au_size)
{
    if (au_size < WR_VG_LOG_BUFFER_SIZE && au_size > 0) {
        uint64 m = WR_VG_LOG_BUFFER_SIZE / au_size;
        uint64 n = WR_VG_LOG_BUFFER_SIZE % au_size;
        return (n == 0) ? (uint32)WR_VG_LOG_BUFFER_SIZE : (uint32)((m + 1) * au_size);
    }
    return (uint32)au_size;
}

#define WR_REDO_BATCH_HEAD_SIZE OFFSET_OF(wr_redo_batch_t, data)
#define WR_REDO_PRINT_HEAD "wr redo detail:"

typedef status_t (*wr_replay_proc)(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry);
typedef status_t (*wr_rollback_proc)(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry);
typedef status_t (*wr_flush_proc)(wr_session_t *session, wr_vg_info_item_t *vg_item, void *data, uint32 size);
typedef void (*wr_print_proc)(wr_redo_entry_t *entry);

typedef struct st_wr_redo_handler {
    wr_redo_type_t type;
    wr_replay_proc replay;
    wr_rollback_proc rollback;  // only rollback memory operation.
    wr_print_proc print;
} wr_redo_handler_t;

#define WR_MAX_BLOCK_ADDR_NUM 10
typedef struct st_wr_block_addr_his_t {
    void *addrs[WR_MAX_BLOCK_ADDR_NUM];
    uint32 count;
} wr_block_addr_his_t;
void rp_init_block_addr_history(wr_block_addr_his_t *addr_his);
void rp_insert_block_addr_history(wr_block_addr_his_t *addr_his, void *block);
bool32 rp_check_block_addr(const wr_block_addr_his_t *addr_his, const void *block);

status_t wr_write_redolog_to_disk(wr_vg_info_item_t *item, uint32 volume_id, int64 offset, char *buf, uint32 size);
void wr_put_log(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_type_t type, void *data, uint32 size);
status_t wr_flush_log(wr_vg_info_item_t *vg_item, char *log_buf);
status_t wr_process_redo_log(wr_session_t *session, wr_vg_info_item_t *vg_item);
status_t wr_reset_log_slot_head(uint32 vg_id, char *log_buf);
void wr_rollback_mem_update(wr_session_t *session, wr_vg_info_item_t *vg_item);
void rb_redo_clean_resource(
    wr_session_t *session, wr_vg_info_item_t *item, auid_t auid, ga_pool_id_e pool_id, uint32 first, uint32 count);

#ifdef __cplusplus
}
#endif

#endif
