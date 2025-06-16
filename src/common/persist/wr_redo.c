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
 * wr_redo.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_redo.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_debug.h"
#include "wr_ga.h"
#include "cm_hash.h"
#include "wr_defs.h"
#include "wr_errno.h"
#include "wr_file.h"
#include "wr_malloc.h"
#include "wr_redo.h"
#include "wr_fs_aux.h"
#include "wr_syn_meta.h"
#include "wr_defs_print.h"

status_t wr_reset_log_slot_head(uint32_t vg_id, char *log_buf)
{
    CM_ASSERT(vg_id < WR_MAX_VOLUME_GROUP_NUM);
    wr_vg_info_item_t *first_vg_item = wr_get_first_vg_item();
    uint64 redo_start = wr_get_redo_log_v0_start(first_vg_item->wr_ctrl, vg_id);
    errno_t errcode = memset_s(log_buf, WR_DISK_UNIT_SIZE, 0, WR_DISK_UNIT_SIZE);
    securec_check_ret(errcode);
    status_t status = wr_write_redolog_to_disk(first_vg_item, 0, (int64)redo_start, log_buf, WR_DISK_UNIT_SIZE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR(
            "[REDO][RESET]Failed to reset redo log, offset is %lld, size is %u.", redo_start, WR_DISK_UNIT_SIZE);
        return status;
    }
    LOG_DEBUG_INF(
        "[REDO][RESET] Reset head of redo log, first vg is %s, actural vg id is %u, offset is %lld, size is %u.",
        first_vg_item->vg_name, vg_id, redo_start, WR_DISK_UNIT_SIZE);
    return status;
}
void wr_put_log(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_type_t type, void *data, uint32_t size)
{
    return;
}

status_t wr_write_redolog_to_disk(wr_vg_info_item_t *vg_item, uint32_t volume_id, int64 offset, char *buf, uint32_t size)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(buf != NULL);
    status_t status;
    if (vg_item->volume_handle[volume_id].handle != WR_INVALID_HANDLE) {
        return wr_write_volume_inst(vg_item, &vg_item->volume_handle[volume_id], offset, buf, size);
    }
    status = wr_open_volume(vg_item->wr_ctrl->volume.defs[volume_id].name, NULL, WR_INSTANCE_OPEN_FLAG,
        &vg_item->volume_handle[volume_id]);
    if (status != CM_SUCCESS) {
        return status;
    }
    status = wr_write_volume_inst(vg_item, &vg_item->volume_handle[volume_id], offset, buf, size);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to read write file, offset:%lld, size:%u.", offset, size);
        return status;
    }
    return CM_SUCCESS;
}

status_t wr_flush_log_v0_inner(wr_vg_info_item_t *vg_item, char *log_buf, uint32_t flush_size)
{
    wr_vg_info_item_t *first_vg_item = wr_get_first_vg_item();
    uint64 redo_start = wr_get_redo_log_v0_start(first_vg_item->wr_ctrl, vg_item->id);
    if (flush_size > WR_INSTANCE_LOG_SPLIT_SIZE) {
        LOG_RUN_ERR("redo log size %u is bigger than %u", flush_size, (uint32_t)WR_INSTANCE_LOG_SPLIT_SIZE);
        return CM_ERROR;
    }
    status_t status = wr_write_redolog_to_disk(first_vg_item, 0, redo_start, log_buf, flush_size);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to flush redo log, offset is %lld, size is %u.", redo_start, flush_size);
        return status;
    }
    return status;
}

status_t wr_flush_log_inner(wr_vg_info_item_t *vg_item, char *log_buf, uint32_t flush_size)
{
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    wr_redo_ctrl_t *redo_ctrl = &wr_ctrl->redo_ctrl;
    uint32_t redo_index = redo_ctrl->redo_index;
    auid_t redo_au = redo_ctrl->redo_start_au[redo_index];
    uint64 redo_size = (uint64)redo_ctrl->redo_size[redo_index];
    uint32_t count = redo_ctrl->count;
    CM_ASSERT(flush_size < WR_VG_LOG_SPLIT_SIZE);
    uint64 log_start = wr_get_vg_au_size(wr_ctrl) * redo_au.au;
    uint64 offset = redo_ctrl->offset;
    uint64 log_offset = log_start + offset;
    wr_log_file_ctrl_t *log_ctrl = &vg_item->log_file_ctrl;
    status_t status;
    // redo_au0 | redo_au1 | redo_au2 |...|redo_aun
    if (offset + flush_size > redo_size) {
        uint64 flush_size_2 = (flush_size + offset) % redo_size;
        uint64 flush_size_1 = flush_size - flush_size_2;
        auid_t redo_au_next;
        if (redo_index == count - 1) {
            redo_au_next = redo_ctrl->redo_start_au[0];
            log_ctrl->index = 0;
        } else {
            redo_au_next = redo_ctrl->redo_start_au[redo_index + 1];
            log_ctrl->index = redo_index + 1;
        }
        uint64 log_start_next = wr_get_vg_au_size(wr_ctrl) * redo_au_next.au;
        LOG_DEBUG_INF("Begin to flush redo log, offset is %lld, size is %llu.", offset, flush_size_1);
        status = wr_write_redolog_to_disk(vg_item, redo_au.volume, (int64)log_offset, log_buf, (uint32_t)flush_size_1);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to flush redo log, offset is %lld, size is %u.", log_offset, (uint32_t)flush_size_1);
            return status;
        }
        LOG_DEBUG_INF("Begin to flush redo log, offset is %d, size is %llu.", 0, flush_size_2);
        status = wr_write_redolog_to_disk(
            vg_item, redo_au_next.volume, (int64)log_start_next, log_buf + flush_size_1, (uint32_t)flush_size_2);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to flush redo log, offset is %d, size is %u.", 0, (uint32_t)flush_size_2);
            return status;
        }
        log_ctrl->offset = flush_size_2;
        return status;
    }
    LOG_DEBUG_INF("Begin to flush redo log, offset is %lld, size is %u.", offset, flush_size);
    status = wr_write_redolog_to_disk(vg_item, redo_au.volume, (int64)log_offset, log_buf, flush_size);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to flush redo log, offset is %llu, size is %u.", log_offset, flush_size);
        return status;
    }
    if (offset + flush_size == redo_size) {
        log_ctrl->index = (redo_index == count - 1) ? 0 : redo_index + 1;
        log_ctrl->offset = 0;
    } else {
        log_ctrl->index = redo_index;
        log_ctrl->offset = offset + flush_size;
    }
    return status;
}

status_t wr_flush_log(wr_vg_info_item_t *vg_item, char *log_buf)
{
    errno_t errcode = 0;
    wr_redo_batch_t *batch = (wr_redo_batch_t *)(log_buf);
    uint32_t data_size;
    uint32_t flush_size;
    if (batch->size == sizeof(wr_redo_batch_t) || vg_item->status == WR_VG_STATUS_RECOVERY) {
        return CM_SUCCESS;
    }
    data_size = batch->size - sizeof(wr_redo_batch_t);
    batch->hash_code = cm_hash_bytes((uint8 *)log_buf + sizeof(wr_redo_batch_t), data_size, INFINITE_HASH_RANGE);
    batch->time = cm_now();
    flush_size = CM_CALC_ALIGN(batch->size + sizeof(wr_redo_batch_t), WR_DISK_UNIT_SIZE);  // align with 512
    // batch_head|entry1|entry2|reserve|batch_tail   --align with 512
    uint64 tail = (uint64)(flush_size - sizeof(wr_redo_batch_t));
    errcode = memcpy_s(log_buf + tail, sizeof(wr_redo_batch_t), batch, sizeof(wr_redo_batch_t));
    securec_check_ret(errcode);
    uint32_t software_version = wr_get_software_version(&vg_item->wr_ctrl->vg_info);
    LOG_DEBUG_INF("[REDO] Before flush log, batch size is %u, count is %d, flush size is %u.", batch->size,
        batch->count, flush_size);
    if (software_version < WR_SOFTWARE_VERSION_2) {
        return wr_flush_log_v0_inner(vg_item, log_buf, flush_size);
    }
    status_t status = wr_flush_log_inner(vg_item, log_buf, flush_size);
    return status;
}

void rp_init_block_addr_history(wr_block_addr_his_t *addr_his)
{
    CM_ASSERT(addr_his != NULL);
    addr_his->count = 0;
}
void rp_insert_block_addr_history(wr_block_addr_his_t *addr_his, void *block)
{
    CM_ASSERT(addr_his != NULL);
    CM_ASSERT(block != NULL);
    CM_ASSERT(addr_his->count < WR_MAX_BLOCK_ADDR_NUM);
    addr_his->addrs[addr_his->count] = block;
    addr_his->count++;
}

bool32 rp_check_block_addr(const wr_block_addr_his_t *addr_his, const void *block)
{
    CM_ASSERT(addr_his != NULL);
    CM_ASSERT(block != NULL);

    for (uint32_t i = 0; i < addr_his->count; i++) {
        if (addr_his->addrs[i] == block) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

status_t rb_redo_free_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rp_redo_init_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rb_redo_init_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rp_redo_rename_file(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    if (entry->size == 0) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_REDO_ILL, "invalid entry log size 0."));
    }

    bool32 check_version = CM_FALSE;
    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    wr_redo_rename_t *data = (wr_redo_rename_t *)entry->data;
    if (wr_cmp_auid(data->node.id, CM_INVALID_ID64)) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid node 0xFFFFFFFF"));
    }

    gft_node_t *node = wr_get_ft_node_by_ftid(session, vg_item, data->node.id, check_version, CM_FALSE);
    if (!node) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid node"));
    }

    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        int32_t ret = snprintf_s(node->name, WR_MAX_NAME_LEN, strlen(data->name), "%s", data->name);
        WR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    }

    wr_ft_block_t *cur_block = wr_get_ft_by_node(node);
    if (cur_block == NULL) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid block"));
    }

    status_t status = wr_update_ft_block_disk(vg_item, cur_block, data->node.id);
    WR_RETURN_IFERR2(
        status, LOG_RUN_ERR("[REDO] Failed to update fs block: %s to disk.", wr_display_metaid(data->node.id)));

    LOG_DEBUG_INF(
        "Succeed to replay rename file:%s, old_name:%s, name:%s.", data->name, data->old_name, vg_item->vg_name);
    return CM_SUCCESS;
}
status_t rb_redo_rename_file(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    wr_redo_rename_t *data = (wr_redo_rename_t *)entry->data;
    bool32 check_version = CM_FALSE;

    if (entry->size == 0) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_REDO_ILL, "invalid entry log size 0."));
    }
    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    if (wr_cmp_auid(data->node.id, CM_INVALID_ID64)) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid node 0xFFFFFFFF"));
    }

    gft_node_t *node = wr_get_ft_node_by_ftid(session, vg_item, data->node.id, check_version, CM_FALSE);
    if (!node) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid node"));
    }

    int32_t ret = snprintf_s(node->name, WR_MAX_NAME_LEN, strlen(data->old_name), "%s", data->old_name);
    WR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    return CM_SUCCESS;
}

status_t rp_redo_set_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rb_redo_set_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rp_redo_free_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rb_redo_free_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rp_redo_recycle_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rb_redo_recycle_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rp_redo_set_file_size(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rp_redo_format_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

void rb_redo_clean_resource(
    wr_session_t *session, wr_vg_info_item_t *item, auid_t auid, ga_pool_id_e pool_id, uint32_t first, uint32_t count)
{
    wr_fs_block_header *block;
    uint32_t obj_id = first;
    uint32_t last = first;
    CM_ASSERT(count > 0);
    for (uint32_t i = 0; i < count; i++) {
        block = (wr_fs_block_header *)wr_buffer_get_meta_addr(pool_id, obj_id);
        CM_ASSERT(block != NULL);
        wr_unregister_buffer_cache(session, item, block->common.id);
        if (i == count - 1) {
            last = obj_id;
        }
        obj_id = ga_next_object(pool_id, obj_id);
    }
    ga_queue_t queue;
    queue.count = count;
    queue.first = first;
    queue.last = last;
    ga_free_object_list(pool_id, &queue);
}

status_t rb_redo_format_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t wr_process_redo_log(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    return CM_SUCCESS;
}

void wr_rollback_mem_update(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    return;
}
