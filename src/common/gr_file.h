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
 * gr_file.h
 *
 * IDENTIFICATION
 *    src/common/gr_file.h
 * -------------------------------------------------------------------------
 */

#ifndef __GR_FILE_H__
#define __GR_FILE_H__

#include "gr_file_def.h"
#include "gr_diskgroup.h"
#include "gr_param.h"
#include "gr_meta_buf.h"
#include "gr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_gr_node_data {
    uint64 fid;
    ftid_t ftid;
    int64 offset;
    int64 size;
    int32_t mode;
    uint32_t vgid;
    char *vg_name;
} gr_node_data_t;

int gr_check_readwrite(const char *name);

status_t gr_exist_item(gr_session_t *session, const char *item, bool32 *result, gft_item_type_t *output_type);
status_t gr_open_file(gr_session_t *session, const char *file, int32_t flag, int *fd);
status_t gr_truncate(gr_session_t *session, uint64 fid, ftid_t ftid, int64 length, char *vg_name);
status_t gr_update_file_written_size(
    gr_session_t *session, uint32_t vg_id, int64 offset, int64 size, gr_block_id_t ftid, uint64 fid);
void gr_check_ft_node_free(gft_node_t *node);
status_t gr_postpone_file(gr_session_t *session, const char *file, const char *time);

void gr_delay_clean_all_vg(gr_session_t *session);

typedef struct st_gr_alloc_fs_block_info {
    bool8 is_extend;
    bool8 is_new_au;
    uint16_t index;
    gft_node_t *node;
} gr_alloc_fs_block_info_t;

gr_env_t *gr_get_env(void);
gr_config_t *gr_get_inst_cfg(void);
status_t gr_get_root_version(gr_vg_info_item_t *vg_item, uint64 *version);
status_t gr_check_str_not_null(const char *str, const char *desc);
status_t gr_check_name(const char *name);
status_t gr_check_attr_flag(uint64 attrFlag);
status_t gr_check_volume_path(const char *path);
status_t gr_check_device_path(const char *path);

/* AU is usually NOT serial/continuous within a single file, judged from R/W file behaviors */
status_t gr_check_open_file_remote(gr_session_t *session, const char *vg_name, uint64 ftid, bool32 *is_open);

static inline bool32 gr_is_node_deleted(gft_node_t *node)
{
    return (node->flags & GR_FT_NODE_FLAG_DEL);
}

static inline bool32 gr_is_fs_meta_valid(gft_node_t *node)
{
    return !(node->flags & GR_FT_NODE_FLAG_INVALID_FS_META);
}

static inline void gr_set_fs_block_file_ver(gft_node_t *node, gr_fs_block_t *fs_block)
{
    (void)node;
    (void)fs_block;
    return;
}

static inline int64_t gr_get_fsb_offset(uint32_t au_size, const gr_block_id_t *id)
{
    return ((int64_t)id->au * au_size + (int64_t)GR_FILE_SPACE_BLOCK_SIZE * id->block);
}

static inline int64_t gr_get_ftb_offset(uint32_t au_size, const gr_block_id_t *id)
{
    if ((id->au) == 0) {
        return (int64_t)GR_CTRL_ROOT_OFFSET;
    }
    return (int64_t)((uint64)id->au * au_size + (uint64)GR_BLOCK_SIZE * id->block);
}

static inline int64_t gr_get_fab_offset(uint32_t au_size, gr_block_id_t block_id)
{
    return (int64_t)(GR_FS_AUX_SIZE * block_id.block + au_size * block_id.au);
}

static inline gr_ft_block_t *gr_get_ft_by_node(gft_node_t *node)
{
    CM_ASSERT(node != NULL);

    if ((node->id.au) == 0 && node->id.block == 0) {
        return (gr_ft_block_t *)(((char *)node - sizeof(gr_root_ft_block_t)) - (node->id.item * sizeof(gft_node_t)));
    }

    return (gr_ft_block_t *)(((char *)node - sizeof(gr_ft_block_t)) - (node->id.item * sizeof(gft_node_t)));
}

static inline gft_node_t *gr_get_node_by_ft(gr_ft_block_t *block, uint32_t item)
{
    return (gft_node_t *)(((char *)block + sizeof(gr_ft_block_t)) + item * sizeof(gft_node_t));
}

static inline gft_node_t *gr_get_node_by_block_ctrl(gr_block_ctrl_t *block, uint32_t item)
{
    gr_ft_block_t *ft_block = GR_GET_META_FROM_BLOCK_CTRL(gr_ft_block_t, block);
    return (gft_node_t *)((((char *)ft_block) + sizeof(gr_ft_block_t)) + item * sizeof(gft_node_t));
}

static inline bool32 gr_is_block_ctrl_valid(gr_block_ctrl_t *block_ctrl)
{
    gft_node_t *node = NULL;
    if (block_ctrl->type == GR_BLOCK_TYPE_FT) {
        node = gr_get_node_by_block_ctrl(block_ctrl, 0);
        return (((node->flags & GR_FT_NODE_FLAG_DEL) == 0) && (node->fid == block_ctrl->fid));
    } else {
        node = (gft_node_t *)block_ctrl->node;
        return ((node != NULL) && ((node->flags & GR_FT_NODE_FLAG_DEL) == 0) && (node->fid == block_ctrl->fid) &&
                (node->file_ver == block_ctrl->file_ver) && (block_ctrl->ftid == GR_ID_TO_U64(node->id)));
    }
}

static inline bool32 gr_get_is_refresh_ftid(gft_node_t *node)
{
    gr_ft_block_t *ft_block = gr_get_ft_by_node(node);
    gr_block_ctrl_t *block_ctrl = GR_GET_BLOCK_CTRL_FROM_META(ft_block);
    return block_ctrl->is_refresh_ftid;
}

static inline void gr_set_is_refresh_ftid(gft_node_t *node, bool32 is_refresh_ftid)
{
    gr_ft_block_t *ft_block = gr_get_ft_by_node(node);
    gr_block_ctrl_t *block_ctrl = GR_GET_BLOCK_CTRL_FROM_META(ft_block);
    block_ctrl->is_refresh_ftid = is_refresh_ftid;
}

static inline bool32 is_ft_root_block(ftid_t ftid)
{
    return ftid.au == 0 && ftid.block == 0;
}

static inline gr_block_ctrl_t *gr_get_block_ctrl_by_node(gft_node_t *node)
{
    if (is_ft_root_block(node->id)) {
        return NULL;
    }
    gr_ft_block_t *ft_block =
        (gr_ft_block_t *)(((char *)node - node->id.item * sizeof(gft_node_t)) - sizeof(gr_ft_block_t));
    return GR_GET_BLOCK_CTRL_FROM_META(ft_block);
}

static inline void gr_latch_node_init(gft_node_t *node)
{
    gr_block_ctrl_t *block_ctrl = gr_get_block_ctrl_by_node(node);
    GR_ASSERT_LOG(block_ctrl != NULL, "block_ctrl is NULL when init latch because node is root block");
    cm_latch_init(&block_ctrl->latch);
}

static inline void gr_latch_x_node(gr_session_t *session, gft_node_t *node, latch_statis_t *stat)
{
    gr_block_ctrl_t *block_ctrl = gr_get_block_ctrl_by_node(node);
    GR_ASSERT_LOG(block_ctrl != NULL, "block_ctrl is NULL when latch x node because node is root block");
    cm_latch_x(&block_ctrl->latch, GR_SESSIONID_IN_LOCK(session->id), stat);
}

static inline void gr_unlatch_node(gft_node_t *node)
{
    gr_block_ctrl_t *block_ctrl = gr_get_block_ctrl_by_node(node);
    GR_ASSERT_LOG(block_ctrl != NULL, "block_ctrl is NULL when unlatch node because node is root block");
    gr_unlatch(&block_ctrl->latch);
}

static inline gr_file_context_t *gr_get_file_context_by_handle(gr_file_run_ctx_t *file_run_ctx, int32_t handle)
{
    return &file_run_ctx->files.files_group[handle / GR_FILE_CONTEXT_PER_GROUP][handle % GR_FILE_CONTEXT_PER_GROUP];
}

// 回调函数类型定义及注册
typedef status_t (*gr_invalidate_other_nodes_proc_t)(
    gr_vg_info_item_t *vg_item, char *meta_info, uint32_t meta_info_size, bool32 *cmd_ack);

void regist_invalidate_other_nodes_proc(gr_invalidate_other_nodes_proc_t proc);

typedef status_t (*gr_broadcast_check_file_open_proc_t)(gr_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack);
void regist_broadcast_check_file_open_proc(gr_broadcast_check_file_open_proc_t proc);

void gr_clean_all_sessions_latch(void);

status_t gr_block_data_oper(char *op_desc, bool32 is_write, gr_vg_info_item_t *vg_item, gr_block_id_t block_id,
    uint64 offset, char *data_buf, int32_t size);
status_t gr_data_oper(char *op_desc, bool32 is_write, gr_vg_info_item_t *vg_item, auid_t auid, uint32_t au_offset,
    char *data_buf, int32_t size);
status_t gr_write_zero2au(char *op_desc, gr_vg_info_item_t *vg_item, uint64 fid, auid_t auid, uint32_t au_offset);
status_t gr_try_write_zero_one_au(
    char *desc, gr_session_t *session, gr_vg_info_item_t *vg_item, gft_node_t *node, int64 offset);

void gr_get_disk_usage_info(gr_disk_usage_info_t *info);
void gr_alarm_check_disk_usage();

#ifdef __cplusplus
}
#endif
#endif  // __GR_FILE_H__