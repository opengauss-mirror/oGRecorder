/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * wr_fs_aux.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_fs_aux.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_FS_AUX_H__
#define __WR_FS_AUX_H__

#include "wr_file_def.h"
#include "wr_file.h"
#include "wr_redo.h"
#include "wr_latch.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(8)
#define WR_REFRESH_FS_AUX_BATCH_MAX 8U
typedef struct st_wr_fs_aux_root_t {
    uint64 version;
    wr_fs_block_list_t free;
} wr_fs_aux_root_t;

typedef struct st_wr_fs_aux_header_t {
    wr_common_block_t common;
    wr_block_id_t next;
    wr_block_id_t ftid;
    wr_block_id_t data_id;  // when data_id.item & 0x1 is 1, means the au is parted write
                             // when data_id.item & 0x1 is 0, means the au is fully write
    uint32 bitmap_num;
    uint16_t index;
    uint16_t resv;
} wr_fs_aux_header_t;

typedef struct st_wr_fs_aux_t {
    wr_fs_aux_header_t head;
    uchar bitmap[0];
} wr_fs_aux_t;

typedef struct st_wr_fs_aux_pos_desc_t {
    uint32 byte_index;
    uint8 bit_index;
    uint8 rsv[3];
} wr_fs_aux_pos_desc_t;

typedef struct st_wr_fs_aux_range_desc_t {
    wr_fs_aux_pos_desc_t beg;
    wr_fs_aux_pos_desc_t end;
} wr_fs_aux_range_desc_t;

typedef struct st_wr_fs_pos_desc {
    bool32 is_valid;
    bool32 is_exist_aux;
    wr_fs_block_t *entry_fs_block;
    wr_fs_block_t *second_fs_block;
    wr_fs_aux_t *fs_aux;
    uint32 block_count;
    uint32 block_au_count;
    uint32 au_offset;
    wr_block_id_t data_auid;
} wr_fs_pos_desc_t;

// for redo ------------------------------
typedef struct st_wr_redo_format_fs_aux_t {
    auid_t auid;
    uint32 obj_id;
    uint32 count;
    wr_fs_block_list_t old_free_list;
} wr_redo_format_fs_aux_t;

typedef struct st_wr_redo_free_fs_aux_t {
    wr_block_id_t id;
    wr_block_id_t next;
    wr_fs_aux_root_t root;
} wr_redo_free_fs_aux_t;

typedef struct st_wr_redo_alloc_fs_aux_t {
    wr_block_id_t id;
    wr_block_id_t ftid;
    uint16 index;
    wr_fs_aux_root_t root;
} wr_redo_alloc_fs_aux_t;

typedef struct st_wr_redo_init_fs_aux_t {
    wr_block_id_t id;
    wr_block_id_t data_id;
    wr_block_id_t ftid;
    wr_block_id_t parent_id;
    uint16 reserve[2];
} wr_redo_init_fs_aux_t;

typedef struct st_wr_redo_updt_fs_block_t {
    wr_block_id_t id;
    wr_block_id_t data_id;
    uint16 index;
    uint16 reserve;
} wr_redo_updt_fs_block_t;

#pragma pack()
// end for redo<-----------------

void wr_check_fs_aux_affiliation(wr_fs_aux_header_t *block, ftid_t id, uint16_t index);

static inline bool32 wr_is_fs_aux_valid(gft_node_t *node, wr_fs_aux_t *fs_aux)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_aux);
    return ((node->fid == block_ctrl->fid) && (node->file_ver == block_ctrl->file_ver) &&
            (block_ctrl->ftid == WR_ID_TO_U64(node->id)));
}

static inline bool32 wr_is_fs_aux_valid_all(gft_node_t *node, wr_fs_aux_t *fs_aux, uint16_t index)
{
    bool32 is_valid_shm = wr_is_fs_aux_valid(node, fs_aux);
    if (is_valid_shm) {
        wr_check_fs_aux_affiliation(&fs_aux->head, node->id, index);
    }
    return is_valid_shm;
}

static inline void wr_updt_fs_aux_file_ver(gft_node_t *node, wr_fs_aux_t *fs_aux)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_aux);
    block_ctrl->fid = node->fid;
    block_ctrl->file_ver = node->file_ver;
    block_ctrl->ftid = WR_ID_TO_U64(node->id);
    block_ctrl->node = (char *)node;
}

static inline uint64 wr_get_fs_aux_fid(wr_fs_aux_t *fs_aux)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_aux);
    return block_ctrl->fid;
}

static inline uint64 wr_get_fs_aux_file_ver(wr_fs_aux_t *fs_aux)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_aux);
    return block_ctrl->file_ver;
}

static inline void wr_latch_fs_aux_init(wr_fs_aux_t *fs_aux)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_aux);
    cm_latch_init(&block_ctrl->latch);
}

static inline void wr_latch_s_fs_aux(wr_session_t *session, wr_fs_aux_t *fs_aux, latch_statis_t *stat)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_aux);
    wr_latch_s2(&block_ctrl->latch, WR_SESSIONID_IN_LOCK(session->id), CM_FALSE, stat);
}

static inline void wr_latch_x_fs_aux(wr_session_t *session, wr_fs_aux_t *fs_aux, latch_statis_t *stat)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_aux);
    cm_latch_x(&block_ctrl->latch, WR_SESSIONID_IN_LOCK(session->id), stat);
}

static inline void wr_unlatch_fs_aux(wr_fs_aux_t *fs_aux)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(fs_aux);
    wr_unlatch(&block_ctrl->latch);
}

void wr_calc_fs_aux_pos(uint64 au_size, int64 offset, wr_fs_aux_pos_desc_t *pos, bool32 is_end);
void wr_calc_fs_aux_range(wr_vg_info_item_t *vg_item, int64 offset, int64 size, wr_fs_aux_range_desc_t *range);
void wr_calc_fs_aux_bitmap_value(uint8 bit_beg, uint8 bit_end, uint8 *value);

status_t wr_format_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t auid);
status_t wr_alloc_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node,
    wr_alloc_fs_block_info_t *info, wr_fs_aux_t **block);
void wr_free_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_fs_aux_t *block, wr_fs_aux_root_t *root);

void wr_init_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_fs_aux_t *block, wr_block_id_t data_id,
    wr_block_id_t ftid);
wr_fs_aux_t *wr_find_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node,
    wr_block_id_t block_id, bool32 check_version, ga_obj_id_t *out_obj_id, uint16 index);
status_t wr_updt_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, int64 offset,
    int64 size, bool32 is_init_tail);

bool32 wr_check_fs_aux_inited(wr_vg_info_item_t *vg_item, wr_fs_aux_t *fs_aux, int64 offset, int64 size);

void wr_get_inited_size_with_fs_aux(
    wr_vg_info_item_t *vg_item, wr_fs_aux_t *fs_aux, int64 offset, int32 size, int32 *inited_size);

status_t wr_try_find_data_au_batch(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node,
    wr_fs_block_t *second_block, uint32 block_au_count_beg);
status_t wr_find_data_au_by_offset(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, int64 offset, wr_fs_pos_desc_t *fs_pos);
status_t wr_read_volume_with_fs_aux(wr_vg_info_item_t *vg_item, gft_node_t *node, wr_fs_aux_t *fs_aux,
    wr_volume_t *volume, int64 vol_offset, int64 offset, void *buf, int32 size);

status_t wr_get_gft_node_with_cache(
    wr_session_t *session, wr_vg_info_item_t *vg_item, uint64 fid, wr_block_id_t ftid, gft_node_t **node_out);
status_t wr_get_entry_block_with_cache(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, wr_fs_block_t **fs_block_out);
status_t wr_get_fs_aux_with_cache(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node,
    wr_block_id_t block_id, uint32 block_au_count, wr_fs_aux_t **fs_aux_out);
void wr_check_fs_aux_free(wr_fs_aux_header_t *block);
void wr_init_fs_aux_head(wr_fs_aux_t *fs_aux, wr_block_id_t ftid, uint16 index);
// for redo
status_t rp_redo_format_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry);
status_t rb_redo_format_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry);
status_t rp_redo_alloc_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry);
status_t rb_redo_alloc_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry);
status_t rp_redo_free_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry);
status_t rb_redo_free_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry);
status_t rp_redo_init_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry);
status_t rb_redo_init_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry);
status_t rb_reload_fs_aux_root(wr_vg_info_item_t *vg_item);
void print_redo_format_fs_aux(wr_redo_entry_t *entry);
void print_redo_alloc_fs_aux(wr_redo_entry_t *entry);
void print_redo_free_fs_aux(wr_redo_entry_t *entry);
void print_redo_init_fs_aux(wr_redo_entry_t *entry);
status_t wr_update_fs_aux_bitmap2disk(wr_vg_info_item_t *item, wr_fs_aux_t *block, uint32 size, bool32 had_checksum);
#ifdef __cplusplus
}
#endif

#endif