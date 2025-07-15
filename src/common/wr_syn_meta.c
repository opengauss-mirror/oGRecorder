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
 * wr_syn_meta.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_syn_meta.c
 *
 * -------------------------------------------------------------------------
 */
#include "wr_syn_meta.h"
#include "wr_file.h"

#ifdef __cplusplus
extern "C" {
#endif

static bool32 enable_syn_meta = CM_TRUE;

wr_meta_syn2other_nodes_proc_t meta_syn2other_nodes_proc = NULL;
void regist_meta_syn2other_nodes_proc(wr_meta_syn2other_nodes_proc_t proc)
{
    meta_syn2other_nodes_proc = proc;
}

void wr_del_syn_meta(wr_vg_info_item_t *vg_item, wr_block_ctrl_t *block_ctrl, int64 syn_meta_ref_cnt)
{
    if (!enable_syn_meta || meta_syn2other_nodes_proc == NULL) {
        return;
    }

    // syn_meta_ref_cnt at most eq block_ctrl->syn_meta_ref_cnt, may less
    if ((uint64)cm_atomic_get((atomic_t *)&block_ctrl->syn_meta_ref_cnt) > 0) {
        (void)cm_atomic_add((atomic_t *)&block_ctrl->syn_meta_ref_cnt, (0 - syn_meta_ref_cnt));
    }
    if ((uint64)cm_atomic_get((atomic_t *)&block_ctrl->syn_meta_ref_cnt) != 0) {
        return;
    }
    wr_latch_x(&vg_item->syn_meta_desc.latch);
    LOG_DEBUG_INF("del syn meta for fid:%llu, ftid:%llu, file_ver:%llu, type:%u, id:%llu, ref_cnt:%llu",
        block_ctrl->fid, block_ctrl->ftid, block_ctrl->file_ver, (uint32_t)block_ctrl->type,
        WR_ID_TO_U64(block_ctrl->block_id), block_ctrl->syn_meta_ref_cnt);
    cm_bilist_del(&block_ctrl->syn_meta_node, &vg_item->syn_meta_desc.bilist);
    wr_buffer_recycle_disable(block_ctrl, CM_FALSE);
    wr_unlatch(&vg_item->syn_meta_desc.latch);
}

void wr_syn_meta(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_ctrl_t *block_ctrl)
{
    if (wr_need_exec_local() && wr_is_readwrite()) {
        wr_meta_syn_t meta_syn;
        // too many place to change the value of block_ctrl->data
        wr_lock_vg_mem_and_shm_s(session, vg_item);
        char *meta_addr = WR_GET_META_FROM_BLOCK_CTRL(char, block_ctrl);
        wr_common_block_t *block = (wr_common_block_t *)meta_addr;
        meta_syn.ftid = block_ctrl->ftid;
        meta_syn.fid = block_ctrl->fid;
        meta_syn.file_ver = block_ctrl->file_ver;
        meta_syn.syn_meta_version = block->version;
        meta_syn.meta_block_id = WR_ID_TO_U64(block->id);
        meta_syn.vg_id = vg_item->id;
        meta_syn.meta_type = block_ctrl->type;
        meta_syn.meta_len = wr_buffer_cache_get_block_size(block_ctrl->type);
        errno_t errcode = memcpy_s(meta_syn.meta, meta_syn.meta_len, (char *)block, meta_syn.meta_len);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            wr_unlock_vg_mem_and_shm(session, vg_item);
            WR_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return;
        }
        wr_unlock_vg_mem_and_shm(session, vg_item);

        (void)meta_syn2other_nodes_proc(
            vg_item, (char *)&meta_syn, (OFFSET_OF(wr_meta_syn_t, meta) + meta_syn.meta_len), NULL);
        LOG_DEBUG_INF("syn meta file:%llu file_ver:%llu, vg:%u, block:%llu type:%u, with version:%llu.", meta_syn.fid,
            meta_syn.file_ver, meta_syn.vg_id, meta_syn.meta_block_id, meta_syn.meta_type, meta_syn.syn_meta_version);
    }
}

// if primary, syn meta, if not, just clean the link
bool32 wr_syn_buffer_cache(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    if (!enable_syn_meta || meta_syn2other_nodes_proc == NULL) {
        return CM_TRUE;
    }

    if (cm_bilist_empty(&vg_item->syn_meta_desc.bilist)) {
        return CM_TRUE;
    }

    bool32 is_valid;
    wr_block_ctrl_t *block_ctrl = NULL;
    wr_block_ctrl_t *onwer_block_ctrl = NULL;

    bilist_node_t *bilist_node = NULL;
    bilist_node_t *bilist_node_tail = NULL;
    bilist_node_t *bilist_node_next = NULL;

    // without latch here, may miss this time, but can get next time
    bilist_node = cm_bilist_head(&vg_item->syn_meta_desc.bilist);
    bilist_node_tail = cm_bilist_tail(&vg_item->syn_meta_desc.bilist);
    while (bilist_node != NULL) {
        block_ctrl = BILIST_NODE_OF(wr_block_ctrl_t, bilist_node, syn_meta_node);
        // forbid delay node recycle task recycle node
        if (block_ctrl->type == WR_BLOCK_TYPE_FT) {
            (void)cm_atomic_inc((atomic_t *)&block_ctrl->bg_task_ref_cnt);
        } else {
            onwer_block_ctrl = wr_get_block_ctrl_by_node((gft_node_t *)block_ctrl->node);
            WR_ASSERT_LOG(onwer_block_ctrl != NULL, "owner block ctrl is NULL because it is root block");
            (void)cm_atomic_inc((atomic_t *)&onwer_block_ctrl->bg_task_ref_cnt);
        }

        int64 syn_meta_ref_cnt = (int64)cm_atomic_get((atomic_t *)&block_ctrl->syn_meta_ref_cnt);

        LOG_DEBUG_INF("try syn meta for fid:%llu, ftid:%llu, file_ver:%llu, type:%u, id:%llu, ref_cnt:%llu",
            block_ctrl->fid, block_ctrl->ftid, block_ctrl->file_ver, (uint32_t)block_ctrl->type,
            WR_ID_TO_U64(block_ctrl->block_id), block_ctrl->syn_meta_ref_cnt);

        is_valid = wr_is_block_ctrl_valid(block_ctrl);
        if (!is_valid) {
            if (bilist_node_tail == bilist_node) {
                bilist_node_next = NULL;
            } else {
                bilist_node_next = BINODE_NEXT(bilist_node);
            }
            wr_del_syn_meta(vg_item, block_ctrl, syn_meta_ref_cnt);
            if (block_ctrl->type == WR_BLOCK_TYPE_FT) {
                (void)cm_atomic_dec((atomic_t *)&block_ctrl->bg_task_ref_cnt);
            } else {
                (void)cm_atomic_dec((atomic_t *)&onwer_block_ctrl->bg_task_ref_cnt);
            }

            bilist_node = bilist_node_next;
            continue;
        }

        wr_syn_meta(session, vg_item, block_ctrl);

        if (bilist_node_tail != bilist_node) {
            bilist_node_next = BINODE_NEXT(bilist_node);
        } else {
            bilist_node_next = NULL;
        }
        wr_del_syn_meta(vg_item, block_ctrl, syn_meta_ref_cnt);

        if (block_ctrl->type == WR_BLOCK_TYPE_FT) {
            (void)cm_atomic_dec((atomic_t *)&block_ctrl->bg_task_ref_cnt);
        } else {
            (void)cm_atomic_dec((atomic_t *)&onwer_block_ctrl->bg_task_ref_cnt);
        }
        bilist_node = bilist_node_next;
    }

    return cm_bilist_empty(&vg_item->syn_meta_desc.bilist);
}

status_t wr_meta_syn_remote(wr_session_t *session, wr_meta_syn_t *meta_syn, uint32_t size, bool32 *ack)
{
    return CM_SUCCESS;
}

status_t wr_invalidate_meta_remote(
    wr_session_t *session, wr_invalidate_meta_msg_t *invalidate_meta_msg, uint32_t size, bool32 *invalid_ack)
{
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif