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
 * wr_file.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_file.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_FILE_H_
#define __WR_FILE_H_

#include "wr_file_def.h"
#include "wr_diskgroup.h"
#include "wr_alloc_unit.h"
#include "wr_param.h"
#include "wr_meta_buf.h"
#include "wr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_wr_node_data {
    uint64 fid;
    ftid_t ftid;
    int64 offset;
    int64 size;
    int32 mode;
    uint32 vgid;
    char *vg_name;
} wr_node_data_t;

status_t wr_make_dir(wr_session_t *session, const char *dir_name);
status_t wr_open_dir(wr_session_t *session, const char *dir_path, bool32 is_refresh, wr_find_node_t *find_info);
void wr_close_dir(wr_session_t *session, char *vg_name, uint64 ftid);
status_t wr_find_vg_by_dir(const char *dir_path, char *name, wr_vg_info_item_t **vg_item);

void wr_lock_vg_mem_s_and_shm_x(wr_session_t *session, wr_vg_info_item_t *vg_item);
void wr_lock_vg_mem_and_shm_x(wr_session_t *session, wr_vg_info_item_t *vg_item);
void wr_lock_vg_mem_and_shm_x2ix(wr_session_t *session, wr_vg_info_item_t *vg_item);
void wr_lock_vg_mem_and_shm_ix2x(wr_session_t *session, wr_vg_info_item_t *vg_item);
void wr_lock_vg_mem_and_shm_s(wr_session_t *session, wr_vg_info_item_t *vg_item);
void wr_lock_vg_mem_and_shm_s_force(wr_session_t *session, wr_vg_info_item_t *vg_item);
void wr_unlock_vg_mem_and_shm(wr_session_t *session, wr_vg_info_item_t *vg_item);
void wr_lock_vg_mem_and_shm_ex_s(wr_session_t *session, char *vg_name);
void wr_unlock_vg_mem_and_shm_ex(wr_session_t *session, char *vg_name);

status_t wr_create_file(wr_session_t *session, const char *parent, const char *name, int32_t flag);
status_t wr_exist_item(wr_session_t *session, const char *item, bool32 *result, gft_item_type_t *output_type);
status_t wr_open_file(wr_session_t *session, const char *file, int32_t flag, wr_find_node_t *find_info);
status_t wr_close_file(wr_session_t *session, wr_vg_info_item_t *vg_item, uint64 ftid);
status_t wr_extend_inner(wr_session_t *session, wr_node_data_t *node_data);
status_t wr_extend(wr_session_t *session, wr_node_data_t *node_data);
status_t wr_do_fallocate(wr_session_t *session, wr_node_data_t *node_data);
status_t wr_truncate(wr_session_t *session, uint64 fid, ftid_t ftid, int64 length, char *vg_name);
status_t wr_refresh_file(wr_session_t *session, uint64 fid, ftid_t ftid, char *vg_name, int64 offset);
status_t wr_refresh_volume(wr_session_t *session, const char *name_str, uint32 vgid, uint32 volumeid);
status_t wr_refresh_ft_block(wr_session_t *session, char *vg_name, uint32 vgid, wr_block_id_t blockid);
status_t wr_update_file_written_size(
    wr_session_t *session, uint32 vg_id, int64 offset, int64 size, wr_block_id_t ftid, uint64 fid);
status_t wr_get_ftid_by_path(wr_session_t *session, const char *path, ftid_t *ftid, wr_vg_info_item_t **dir_vg_item);
gft_node_t *wr_get_gft_node_by_path(
    wr_session_t *session, wr_vg_info_item_t *vg_item, const char *path, wr_vg_info_item_t **dir_vg_item);
// for wr internal call
status_t wr_alloc_ft_au_when_no_free(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_root_t *gft, bool32 *check_version);
void wr_check_ft_node_free(gft_node_t *node);
status_t wr_alloc_ft_node_when_create_vg(
    wr_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, gft_item_type_t type, uint32 flags);

status_t wr_format_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t auid);
void wr_free_ft_node_inner(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node, bool32 real_del);
void wr_free_ft_node(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node, bool32 real_del);
gft_node_t *wr_get_next_node(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node);
bool32 wr_is_last_tree_node(gft_node_t *node);
void wr_delay_clean_all_vg(wr_session_t *session);
gft_node_t *wr_find_ft_node(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, bool8 skip_del);
gft_node_t *wr_get_ft_node_by_ftid(
    wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t id, bool32 check_version, bool32 active_refresh);
gft_node_t *wr_get_ft_node_by_ftid_from_disk_and_refresh_shm(
    wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t id);
gft_node_t *wr_get_ft_node_by_ftid_no_refresh(wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t id);
status_t wr_update_ft_block_disk(wr_vg_info_item_t *vg_item, wr_ft_block_t *block, ftid_t id);
int64 wr_get_ft_block_offset(wr_vg_info_item_t *vg_item, ftid_t id);
char *wr_get_ft_block_by_ftid(wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t id);
status_t wr_refresh_root_ft(wr_vg_info_item_t *vg_item, bool32 check_version, bool32 active_refresh);

status_t wr_update_au_disk(
    wr_vg_info_item_t *vg_item, auid_t auid, ga_pool_id_e pool_id, uint32 first, uint32 count, uint32 size);
// for tool or instance
void wr_init_ft_root(wr_ctrl_t *wr_ctrl, gft_node_t **out_node);
status_t wr_update_ft_root(wr_vg_info_item_t *vg_item);
status_t wr_refresh_ft(wr_session_t *session, wr_vg_info_item_t *vg_item);
status_t wr_check_refresh_ft(wr_vg_info_item_t *vg_item);
status_t wr_alloc_ft_au(wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t *id);

typedef struct st_wr_alloc_fs_block_info {
    bool8 is_extend;
    bool8 is_new_au;
    uint16_t index;
    gft_node_t *node;
} wr_alloc_fs_block_info_t;
status_t wr_alloc_fs_block(
    wr_session_t *session, wr_vg_info_item_t *vg_item, char **block, wr_alloc_fs_block_info_t *info);
void wr_free_fs_block_addr(wr_session_t *session, wr_vg_info_item_t *vg_item, char *block, ga_obj_id_t obj_id);
int64 wr_get_fs_block_offset(wr_vg_info_item_t *vg_item, wr_block_id_t blockid);
status_t wr_update_fs_bitmap_block_disk(
    wr_vg_info_item_t *item, wr_fs_block_t *block, uint32 size, bool32 had_checksum);
status_t wr_format_bitmap_node(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t auid);
status_t wr_check_refresh_fs_block(
    wr_vg_info_item_t *vg_item, wr_block_id_t blockid, char *block, bool32 *is_changed);
void wr_init_root_fs_block(wr_ctrl_t *wr_ctrl);
status_t wr_load_fs_block_by_blockid(
    wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t blockid, int32 size);

void wr_init_fs_block_head(wr_fs_block_t *fs_block);

status_t wr_check_rename_path(wr_session_t *session, const char *src_path, const char *dst_path, text_t *dst_name);
status_t wr_get_name_from_path(const char *path, uint32_t *beg_pos, char *name);
status_t wr_check_dir(wr_session_t *session, const char *dir_path, gft_item_type_t type,
    wr_check_dir_output_t *output_info, bool32 is_throw_err);

wr_env_t *wr_get_env(void);
wr_config_t *wr_get_inst_cfg(void);
status_t wr_get_root_version(wr_vg_info_item_t *vg_item, uint64 *version);
status_t wr_check_name(const char *name);
status_t wr_check_path(const char *path);
status_t wr_check_volume_path(const char *path);
status_t wr_check_device_path(const char *path);
status_t wr_check_path_both(const char *path);

status_t wr_refresh_vginfo(wr_vg_info_item_t *vg_item);

/* AU is usually NOT serial/continuous within a single file, judged from R/W file behaviors */
status_t wr_get_fs_block_info_by_offset(
    int64 offset, uint64 au_size, uint32 *block_count, uint32 *block_au_count, uint32 *au_offset);
status_t wr_check_open_file_remote(wr_session_t *session, const char *vg_name, uint64 ftid, bool32 *is_open);
status_t wr_check_file(wr_vg_info_item_t *vg_item);

status_t wr_check_rm_file(
    wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t ftid, bool32 *should_rm_file, gft_node_t **file_node);

void wr_set_node_flag(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, bool32 is_set, uint32 flags);
void wr_validate_fs_meta(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node);
status_t wr_invalidate_fs_meta(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node);

static inline bool32 wr_is_node_deleted(gft_node_t *node)
{
    return (node->flags & WR_FT_NODE_FLAG_DEL);
}

static inline bool32 wr_is_fs_meta_valid(gft_node_t *node)
{
    return !(node->flags & WR_FT_NODE_FLAG_INVALID_FS_META);
}

static inline bool32 wr_is_fs_block_valid(gft_node_t *node, wr_fs_block_t *fs_block)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_block);
    return ((node->fid == block_ctrl->fid) && (node->file_ver == block_ctrl->file_ver) &&
            (block_ctrl->ftid == WR_ID_TO_U64(node->id)));
}

static inline void wr_set_fs_block_file_ver(gft_node_t *node, wr_fs_block_t *fs_block)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_block);
    block_ctrl->fid = node->fid;
    block_ctrl->ftid = WR_ID_TO_U64(node->id);
    block_ctrl->file_ver = node->file_ver;
    block_ctrl->node = (char *)node;
}

static inline uint64 wr_get_fs_block_fid(wr_fs_block_t *fs_block)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_block);
    return block_ctrl->fid;
}

static inline uint64 wr_get_fs_block_file_ver(wr_fs_block_t *fs_block)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_block);
    return block_ctrl->file_ver;
}

static inline int64 wr_get_fsb_offset(uint32 au_size, const wr_block_id_t *id)
{
    return ((int64)id->au * au_size + (int64)WR_FILE_SPACE_BLOCK_SIZE * id->block);
}

static inline int64 wr_get_ftb_offset(uint32 au_size, const wr_block_id_t *id)
{
    if ((id->au) == 0) {
        return (int64)WR_CTRL_ROOT_OFFSET;
    }
    return (int64)((uint64)id->au * au_size + (uint64)WR_BLOCK_SIZE * id->block);
}

static inline int64 wr_get_fab_offset(uint32 au_size, wr_block_id_t block_id)
{
    return (int64)(WR_FS_AUX_SIZE * block_id.block + au_size * block_id.au);
}

static inline wr_ft_block_t *wr_get_ft_by_node(gft_node_t *node)
{
    CM_ASSERT(node != NULL);

    if ((node->id.au) == 0 && node->id.block == 0) {
        return (wr_ft_block_t *)(((char *)node - sizeof(wr_root_ft_block_t)) - (node->id.item * sizeof(gft_node_t)));
    }

    return (wr_ft_block_t *)(((char *)node - sizeof(wr_ft_block_t)) - (node->id.item * sizeof(gft_node_t)));
}

static inline gft_node_t *wr_get_node_by_ft(wr_ft_block_t *block, uint32 item)
{
    return (gft_node_t *)(((char *)block + sizeof(wr_ft_block_t)) + item * sizeof(gft_node_t));
}

static inline gft_node_t *wr_get_node_by_block_ctrl(wr_block_ctrl_t *block, uint32 item)
{
    wr_ft_block_t *ft_block = WR_GET_META_FROM_BLOCK_CTRL(wr_ft_block_t, block);
    return (gft_node_t *)((((char *)ft_block) + sizeof(wr_ft_block_t)) + item * sizeof(gft_node_t));
}

static inline bool32 wr_is_ft_block_valid(gft_node_t *node, wr_ft_block_t *ft_block)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(ft_block);
    return ((block_ctrl->node != NULL) && (node->fid == block_ctrl->fid) && (node->file_ver == block_ctrl->file_ver) &&
            (block_ctrl->ftid == WR_ID_TO_U64(node->id)));
}

static inline void wr_set_ft_block_file_ver(gft_node_t *node, wr_ft_block_t *ft_block)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(ft_block);
    block_ctrl->fid = node->fid;
    block_ctrl->ftid = WR_ID_TO_U64(node->id);
    block_ctrl->file_ver = node->file_ver;
    block_ctrl->node = (char *)node;
}

static inline uint64 wr_get_ft_block_fid(wr_ft_block_t *ft_block)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(ft_block);
    return block_ctrl->fid;
}

static inline uint64 wr_get_ft_block_file_ver(wr_ft_block_t *ft_block)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(ft_block);
    return block_ctrl->file_ver;
}

static inline bool32 wr_is_block_ctrl_valid(wr_block_ctrl_t *block_ctrl)
{
    gft_node_t *node = NULL;
    if (block_ctrl->type == WR_BLOCK_TYPE_FT) {
        node = wr_get_node_by_block_ctrl(block_ctrl, 0);
        return (((node->flags & WR_FT_NODE_FLAG_DEL) == 0) && (node->fid == block_ctrl->fid));
    } else {
        node = (gft_node_t *)block_ctrl->node;
        return ((node != NULL) && ((node->flags & WR_FT_NODE_FLAG_DEL) == 0) && (node->fid == block_ctrl->fid) &&
                (node->file_ver == block_ctrl->file_ver) && (block_ctrl->ftid == WR_ID_TO_U64(node->id)));
    }
}

static inline bool32 wr_get_is_refresh_ftid(gft_node_t *node)
{
    wr_ft_block_t *ft_block = wr_get_ft_by_node(node);
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(ft_block);
    return block_ctrl->is_refresh_ftid;
}

static inline void wr_set_is_refresh_ftid(gft_node_t *node, bool32 is_refresh_ftid)
{
    wr_ft_block_t *ft_block = wr_get_ft_by_node(node);
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(ft_block);
    block_ctrl->is_refresh_ftid = is_refresh_ftid;
}

static inline bool32 is_ft_root_block(ftid_t ftid)
{
    return ftid.au == 0 && ftid.block == 0;
}

static inline wr_block_ctrl_t *wr_get_block_ctrl_by_node(gft_node_t *node)
{
    if (is_ft_root_block(node->id)) {
        return NULL;
    }
    wr_ft_block_t *ft_block =
        (wr_ft_block_t *)(((char *)node - node->id.item * sizeof(gft_node_t)) - sizeof(wr_ft_block_t));
    return WR_GET_BLOCK_CTRL_FROM_META(ft_block);
}

static inline void wr_latch_node_init(gft_node_t *node)
{
    wr_block_ctrl_t *block_ctrl = wr_get_block_ctrl_by_node(node);
    WR_ASSERT_LOG(block_ctrl != NULL, "block_ctrl is NULL when init latch because node is root block");
    cm_latch_init(&block_ctrl->latch);
}

static inline void wr_latch_s_node(wr_session_t *session, gft_node_t *node, latch_statis_t *stat)
{
    wr_block_ctrl_t *block_ctrl = wr_get_block_ctrl_by_node(node);
    WR_ASSERT_LOG(block_ctrl != NULL, "block_ctrl is NULL when latch s node because node is root block");
    wr_latch_s2(&block_ctrl->latch, WR_SESSIONID_IN_LOCK(session->id), CM_FALSE, stat);
}

static inline void wr_latch_x_node(wr_session_t *session, gft_node_t *node, latch_statis_t *stat)
{
    wr_block_ctrl_t *block_ctrl = wr_get_block_ctrl_by_node(node);
    WR_ASSERT_LOG(block_ctrl != NULL, "block_ctrl is NULL when latch x node because node is root block");
    cm_latch_x(&block_ctrl->latch, WR_SESSIONID_IN_LOCK(session->id), stat);
}

static inline void wr_unlatch_node(gft_node_t *node)
{
    wr_block_ctrl_t *block_ctrl = wr_get_block_ctrl_by_node(node);
    WR_ASSERT_LOG(block_ctrl != NULL, "block_ctrl is NULL when unlatch node because node is root block");
    wr_unlatch(&block_ctrl->latch);
}
static inline wr_file_context_t *wr_get_file_context_by_handle(wr_file_run_ctx_t *file_run_ctx, int32 handle)
{
    return &file_run_ctx->files.files_group[handle / WR_FILE_CONTEXT_PER_GROUP][handle % WR_FILE_CONTEXT_PER_GROUP];
}
// this is need to re-consturct the code-file-place
typedef status_t (*wr_invalidate_other_nodes_proc_t)(
    wr_vg_info_item_t *vg_item, char *meta_info, uint32 meta_info_size, bool32 *cmd_ack);
status_t wr_invalidate_other_nodes_proc(
    wr_vg_info_item_t *vg_item, char *meta_info, uint32 meta_info_size, bool32 *cmd_ack);
void regist_invalidate_other_nodes_proc(wr_invalidate_other_nodes_proc_t proc);
typedef status_t (*wr_broadcast_check_file_open_proc_t)(wr_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack);
void regist_broadcast_check_file_open_proc(wr_broadcast_check_file_open_proc_t proc);

void wr_clean_all_sessions_latch();

status_t wr_block_data_oper(char *op_desc, bool32 is_write, wr_vg_info_item_t *vg_item, wr_block_id_t block_id,
    uint64 offset, char *data_buf, int32 size);
status_t wr_data_oper(char *op_desc, bool32 is_write, wr_vg_info_item_t *vg_item, auid_t auid, uint32 au_offset,
    char *data_buf, int32 size);
status_t wr_write_zero2au(char *op_desc, wr_vg_info_item_t *vg_item, uint64 fid, auid_t auid, uint32 au_offset);
status_t wr_try_write_zero_one_au(
    char *desc, wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, int64 offset);
void wr_alarm_check_vg_usage(wr_session_t *session);
#ifdef __cplusplus
}
#endif
#endif
