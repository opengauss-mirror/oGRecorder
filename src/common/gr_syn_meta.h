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
 * gr_syn_meta.h
 *
 *
 * IDENTIFICATION
 *    src/common/gr_syn_meta.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_SYN_META_H__
#define __GR_SYN_META_H__

#include "gr_defs.h"
#include "gr_file_def.h"
#include "gr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_gr_meta_syn_msg {
    uint64 ftid;
    uint64 fid;       // it's the owner's gft_node_t.fid
    uint64 file_ver;  // it's the owner's gft_node_t.file_ver
    uint64 syn_meta_version;
    uint64 meta_block_id;
    uint32_t vg_id;
    uint32_t meta_type;
    uint32_t meta_len;
    char meta[GR_MAX_META_BLOCK_SIZE];
} gr_meta_syn_t;

typedef struct st_gr_invalidate_meta_msg {
    uint32_t vg_id;
    uint32_t meta_type;
    uint64 meta_block_id;
} gr_invalidate_meta_msg_t;

status_t gr_meta_syn_remote(gr_session_t *session, gr_meta_syn_t *meta_syn, uint32_t size, bool32 *ack);
status_t gr_invalidate_meta_remote(
    gr_session_t *session, gr_invalidate_meta_msg_t *invalidate_meta_msg, uint32_t size, bool32 *invalid_ack);

#ifdef __cplusplus
}
#endif

#endif