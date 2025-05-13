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
 * wr_syn_meta.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_syn_meta.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_SYN_META_H__
#define __WR_SYN_META_H__

#include "wr_defs.h"
#include "wr_file_def.h"
#include "wr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_wr_meta_syn_msg {
    uint64 ftid;
    uint64 fid;       // it's the owner's gft_node_t.fid
    uint64 file_ver;  // it's the owner's gft_node_t.file_ver
    uint64 syn_meta_version;
    uint64 meta_block_id;
    uint32_t vg_id;
    uint32_t meta_type;
    uint32_t meta_len;
    char meta[WR_MAX_META_BLOCK_SIZE];
} wr_meta_syn_t;

typedef struct st_wr_invalidate_meta_msg {
    uint32_t vg_id;
    uint32_t meta_type;
    uint64 meta_block_id;
} wr_invalidate_meta_msg_t;

void wr_del_syn_meta(wr_vg_info_item_t *vg_item, wr_block_ctrl_t *block_ctrl, int64 syn_meta_ref_cnt);
bool32 wr_syn_buffer_cache(wr_session_t *session, wr_vg_info_item_t *vg_item);
status_t wr_meta_syn_remote(wr_session_t *session, wr_meta_syn_t *meta_syn, uint32_t size, bool32 *ack);
status_t wr_invalidate_meta_remote(
    wr_session_t *session, wr_invalidate_meta_msg_t *invalidate_meta_msg, uint32_t size, bool32 *invalid_ack);

typedef status_t (*wr_meta_syn2other_nodes_proc_t)(
    wr_vg_info_item_t *vg_item, char *meta_syn, uint32_t meta_syn_size, bool32 *cmd_ack);
void regist_meta_syn2other_nodes_proc(wr_meta_syn2other_nodes_proc_t proc);

#ifdef __cplusplus
}
#endif

#endif