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
 * IDENTIFICATION
 *    src/common/wr_file.h
 * -------------------------------------------------------------------------
 */

#ifndef __WR_FILE_H__
#define __WR_FILE_H__

#include "wr_file_def.h"
#include "wr_diskgroup.h"
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
    int32_t mode;
    uint32_t vgid;
    char *vg_name;
} wr_node_data_t;

int wr_check_readwrite(const char *name);

status_t wr_exist_item(wr_session_t *session, const char *item, bool32 *result, gft_item_type_t *output_type);
status_t wr_open_file(wr_session_t *session, const char *file, int32_t flag, int *fd);
status_t wr_truncate(wr_session_t *session, uint64 fid, ftid_t ftid, int64 length, char *vg_name);
status_t wr_update_file_written_size(
    wr_session_t *session, uint32_t vg_id, int64 offset, int64 size, wr_block_id_t ftid, uint64 fid);
void wr_check_ft_node_free(gft_node_t *node);
status_t wr_postpone_file(wr_session_t *session, const char *file, const char *time);

void wr_delay_clean_all_vg(wr_session_t *session);

typedef struct st_wr_alloc_fs_block_info {
    bool8 is_extend;
    bool8 is_new_au;
    uint16_t index;
    gft_node_t *node;
} wr_alloc_fs_block_info_t;

wr_env_t *wr_get_env(void);
wr_config_t *wr_get_inst_cfg(void);
status_t wr_get_root_version(wr_vg_info_item_t *vg_item, uint64 *version);
status_t wr_check_name(const char *name);
status_t wr_check_attr_flag(uint64 attrFlag);
status_t wr_check_volume_path(const char *path);
status_t wr_check_device_path(const char *path);

/* AU is usually NOT serial/continuous within a single file, judged from R/W file behaviors */
status_t wr_check_open_file_remote(wr_session_t *session, const char *vg_name, uint64 ftid, bool32 *is_open);

static inline bool32 wr_is_node_deleted(gft_node_t *node)
{
    return (node->flags & WR_FT_NODE_FLAG_DEL);
}

static inline bool32 wr_is_fs_meta_valid(gft_node_t *node)
{
    return !(node->flags & WR_FT_NODE_FLAG_INVALID_FS_META);
}

static inline void wr_set_fs_block_file_ver(gft_node_t *node, wr_fs_block_t *fs_block)
{
    (void)node;
    (void)fs_block;
    return;
}

static inline int64_t wr_get_fsb_offset(uint32_t au_size, const wr_block_id_t *id)
{
    return ((int64_t)id->au * au_size + (int64_t)WR_FILE_SPACE_BLOCK_SIZE * id->block);
}

static inline int64_t wr_get_ftb_offset(uint32_t au_size, const wr_block_id_t *id)
{
    if ((id->au) == 0) {
        return (int64_t)WR_CTRL_ROOT_OFFSET;
    }
    return (int64_t)((uint64)id->au * au_size + (uint64)WR_BLOCK_SIZE * id->block);
}

static inline int64_t wr_get_fab_offset(uint32_t au_size, wr_block_id_t block_id)
{
    return (int64_t)(WR_FS_AUX_SIZE * block_id.block + au_size * block_id.au);
}

static inline wr_ft_block_t *wr_get_ft_by_node(gft_node_t *node)
{
    CM_ASSERT(node != NULL);

    if ((node->id.au) == 0 && node->id.block == 0) {
        return (wr_ft_block_t *)(((char *)node - sizeof(wr_root_ft_block_t)) - (node->id.item * sizeof(gft_node_t)));
    }

    return (wr_ft_block_t *)(((char *)node - sizeof(wr_ft_block_t)) - (node->id.item * sizeof(gft_node_t)));
}

static inline gft_node_t *wr_get_node_by_ft(wr_ft_block_t *block, uint32_t item)
{
    return (gft_node_t *)(((char *)block + sizeof(wr_ft_block_t)) + item * sizeof(gft_node_t));
}

static inline gft_node_t *wr_get_node_by_block_ctrl(wr_block_ctrl_t *block, uint32_t item)
{
    wr_ft_block_t *ft_block = WR_GET_META_FROM_BLOCK_CTRL(wr_ft_block_t, block);
    return (gft_node_t *)((((char *)ft_block) + sizeof(wr_ft_block_t)) + item * sizeof(gft_node_t));
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

static inline wr_file_context_t *wr_get_file_context_by_handle(wr_file_run_ctx_t *file_run_ctx, int32_t handle)
{
    return &file_run_ctx->files.files_group[handle / WR_FILE_CONTEXT_PER_GROUP][handle % WR_FILE_CONTEXT_PER_GROUP];
}

// 回调函数类型定义及注册
typedef status_t (*wr_invalidate_other_nodes_proc_t)(
    wr_vg_info_item_t *vg_item, char *meta_info, uint32_t meta_info_size, bool32 *cmd_ack);

void regist_invalidate_other_nodes_proc(wr_invalidate_other_nodes_proc_t proc);

typedef status_t (*wr_broadcast_check_file_open_proc_t)(wr_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack);
void regist_broadcast_check_file_open_proc(wr_broadcast_check_file_open_proc_t proc);

void wr_clean_all_sessions_latch(void);

status_t wr_block_data_oper(char *op_desc, bool32 is_write, wr_vg_info_item_t *vg_item, wr_block_id_t block_id,
    uint64 offset, char *data_buf, int32_t size);
status_t wr_data_oper(char *op_desc, bool32 is_write, wr_vg_info_item_t *vg_item, auid_t auid, uint32_t au_offset,
    char *data_buf, int32_t size);
status_t wr_write_zero2au(char *op_desc, wr_vg_info_item_t *vg_item, uint64 fid, auid_t auid, uint32_t au_offset);
status_t wr_try_write_zero_one_au(
    char *desc, wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, int64 offset);

#ifdef __cplusplus
}
#endif
#endif  // __WR_FILE_H__