/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * gr_block_ctrl.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/gr_block_ctrl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_BLOCK_CTRL_H
#define __GR_BLOCK_CTRL_H

#include "gr_defs.h"
#include "gr_au.h"
#include "cm_latch.h"
#include "cm_bilist.h"
#include "gr_shm.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_gr_block_type {
    GR_BLOCK_TYPE_FT,
    GR_BLOCK_TYPE_FS,
    GR_BLOCK_TYPE_FS_AUX,
    GR_BLOCK_TYPE_MAX,  // should be the end
} gr_block_type_t;

#pragma pack(8)
typedef union st_gr_fs_block_cache_info {
    // this for cache gft_node_t
    struct {
        char *entry_block_addr;
        char *fs_block_addr;
        char *fs_aux_addr;
        uint64 entry_block_id;
        uint64 fs_block_id;
        uint64 fs_aux_block_id;

        // for find the owner vg and cache slot
        uint32_t owner_vg_id;
        uint32_t owner_ftid_cache_index;
    };
    // this for cache fs_block_t and fs_aux_block_t
    struct {
        char *owner_node_addr;
        uint64 owner_node_id;
    };
} gr_fs_block_cache_info_t;

typedef struct st_gr_block_ctrl {
    latch_t latch;
    gr_block_type_t type;
    gr_block_id_t block_id;
    sh_mem_p hash_next;
    sh_mem_p hash_prev;
    uint32_t hash;
    bool32 has_next;
    bool32 has_prev;
    ga_obj_id_t my_obj_id;

    // the follow data setted or unsetted by uplayer, not by meta buf
    // the follow info need not to make sure be seen by cli-api, such as point
    // this section indentify the block owner
    // every bg task using the ctrl should check (node != NULL), (fid, file_ver) and (node->fid, node->file_ver) first
    // with the latch
    bool32 is_refresh_ftid;  // just for gr_ft_block_t
    uint64 fid;              // it's the owner's gft_node_t.fid
    uint64 ftid;
    uint64 file_ver;  // it's the owner's gft_node_t.file_ver
    char *node;       // it's the owner's gft_node_t mem pointer

    uint64 bg_task_ref_cnt;  // every bg task should inc this cnt with the latch
    bool32 reserve;

    // this section using for cache
    gr_fs_block_cache_info_t fs_block_cache_info;  // only save in ft block ctrl now

    // this section using for ctrl syn meta bg task
    int64 syn_meta_ref_cnt;
    bilist_node_t syn_meta_node;  // for syn meta

    // this section using for ctrl recycle meta
    int64 ref_hot;
    bilist_node_t recycle_meta_node;
    bool8 recycle_disable;
} gr_block_ctrl_t;

typedef struct st_gr_block_ctrl_task_desc_t {
    latch_t latch;
    bilist_t bilist;
    void *task_args;
} gr_block_ctrl_task_desc_t;
#pragma pack()

#ifdef __cplusplus
}
#endif

#endif