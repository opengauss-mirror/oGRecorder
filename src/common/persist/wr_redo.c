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

status_t wr_reset_log_slot_head(uint32 vg_id, char *log_buf)
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
void wr_put_log(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_type_t type, void *data, uint32 size)
{
    return;
}

status_t wr_write_redolog_to_disk(wr_vg_info_item_t *vg_item, uint32 volume_id, int64 offset, char *buf, uint32 size)
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

status_t wr_flush_log_v0_inner(wr_vg_info_item_t *vg_item, char *log_buf, uint32 flush_size)
{
    wr_vg_info_item_t *first_vg_item = wr_get_first_vg_item();
    uint64 redo_start = wr_get_redo_log_v0_start(first_vg_item->wr_ctrl, vg_item->id);
    if (flush_size > WR_INSTANCE_LOG_SPLIT_SIZE) {
        LOG_RUN_ERR("redo log size %u is bigger than %u", flush_size, (uint32)WR_INSTANCE_LOG_SPLIT_SIZE);
        return CM_ERROR;
    }
    status_t status = wr_write_redolog_to_disk(first_vg_item, 0, redo_start, log_buf, flush_size);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to flush redo log, offset is %lld, size is %u.", redo_start, flush_size);
        return status;
    }
    return status;
}

status_t wr_flush_log_inner(wr_vg_info_item_t *vg_item, char *log_buf, uint32 flush_size)
{
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    wr_redo_ctrl_t *redo_ctrl = &wr_ctrl->redo_ctrl;
    uint32 redo_index = redo_ctrl->redo_index;
    auid_t redo_au = redo_ctrl->redo_start_au[redo_index];
    uint64 redo_size = (uint64)redo_ctrl->redo_size[redo_index];
    uint32 count = redo_ctrl->count;
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
        status = wr_write_redolog_to_disk(vg_item, redo_au.volume, (int64)log_offset, log_buf, (uint32)flush_size_1);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to flush redo log, offset is %lld, size is %u.", log_offset, (uint32)flush_size_1);
            return status;
        }
        LOG_DEBUG_INF("Begin to flush redo log, offset is %d, size is %llu.", 0, flush_size_2);
        status = wr_write_redolog_to_disk(
            vg_item, redo_au_next.volume, (int64)log_start_next, log_buf + flush_size_1, (uint32)flush_size_2);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to flush redo log, offset is %d, size is %u.", 0, (uint32)flush_size_2);
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
    uint32 data_size;
    uint32 flush_size;
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
    uint32 software_version = wr_get_software_version(&vg_item->wr_ctrl->vg_info);
    LOG_DEBUG_INF("[REDO] Before flush log, batch size is %u, count is %d, flush size is %u.", batch->size,
        batch->count, flush_size);
    if (software_version < WR_SOFTWARE_VERSION_2) {
        return wr_flush_log_v0_inner(vg_item, log_buf, flush_size);
    }
    status_t status = wr_flush_log_inner(vg_item, log_buf, flush_size);
    return status;
}

static status_t rp_redo_update_volhead(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
#ifndef WIN32
    char align_buf[WR_DISK_UNIT_SIZE] __attribute__((__aligned__(WR_DISK_UNIT_SIZE)));
#else
    char align_buf[WR_DISK_UNIT_SIZE];
#endif
    wr_redo_volhead_t *redo = (wr_redo_volhead_t *)entry->data;
    if (entry->size == 0) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_REDO_ILL, "invalid entry log size 0."));
    }
    int32 errcode = memcpy_sp(align_buf, WR_DISK_UNIT_SIZE, redo->head, WR_DISK_UNIT_SIZE);
    securec_check_ret(errcode);
    wr_volume_t volume;
    if (wr_open_volume(redo->name, NULL, WR_INSTANCE_OPEN_FLAG, &volume) != CM_SUCCESS) {
        return CM_ERROR;
    }
    status_t status = wr_write_volume(&volume, 0, align_buf, (int32)WR_ALIGN_SIZE);
    wr_close_volume(&volume);
    return status;
}

static status_t rp_redo_add_or_remove_volume(
    wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    errno_t errcode = 0;
    wr_redo_volop_t *redo = (wr_redo_volop_t *)entry->data;
    if (entry->size == 0) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_REDO_ILL, "invalid entry log size 0."));
    }
    wr_volume_attr_t *attr = (wr_volume_attr_t *)redo->attr;
    uint32 id = attr->id;

    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        if (wr_refresh_vginfo(vg_item) != CM_SUCCESS) {
            WR_RETURN_IFERR2(
                CM_ERROR, LOG_DEBUG_ERR("[REDO][REPLAY][ADD_OR_REMOVE_VOLUME] %s", "refresh vginfo failed."));
        }

        // in recovery
        if (redo->is_add) {
            CM_ASSERT((vg_item->wr_ctrl->core.volume_count + 1 == redo->volume_count) ||
                      (vg_item->wr_ctrl->core.volume_count == redo->volume_count));
        } else {
            CM_ASSERT((vg_item->wr_ctrl->core.volume_count - 1 == redo->volume_count) ||
                      (vg_item->wr_ctrl->core.volume_count == redo->volume_count));
        }

        errcode = memcpy_s(&vg_item->wr_ctrl->core.volume_attrs[id], sizeof(wr_volume_attr_t), redo->attr,
            sizeof(wr_volume_attr_t));
        securec_check_ret(errcode);
        errcode = memcpy_s(
            &vg_item->wr_ctrl->volume.defs[id], sizeof(wr_volume_def_t), redo->def, sizeof(wr_volume_def_t));
        securec_check_ret(errcode);

        LOG_RUN_INF("[REDO][REPLAY][ADD_OR_REMOVE_VOLUME] recovery add volume core\n"
                    "[before]core version:%llu, volume version:%llu, volume count:%u.\n"
                    "[after]core version:%llu, volume version:%llu, volume count:%u.",
            vg_item->wr_ctrl->core.version, vg_item->wr_ctrl->volume.version, vg_item->wr_ctrl->core.volume_count,
            redo->core_version, redo->volume_version, redo->volume_count);

        vg_item->wr_ctrl->core.version = redo->core_version;
        vg_item->wr_ctrl->core.volume_count = redo->volume_count;
        vg_item->wr_ctrl->volume.version = redo->volume_version;
    }
    status_t status = wr_update_volume_id_info(vg_item, id);
    WR_RETURN_IFERR2(status,
        LOG_DEBUG_ERR("[REDO][REPLAY][ADD_OR_REMOVE_VOLUME] Failed to update core ctrl and volume to disk, vg:%s.",
            vg_item->vg_name));
    WR_LOG_DEBUG_OP("[REDO][REPLAY][ADD_OR_REMOVE_VOLUME] Succeed to replay add or remove volume:%u.", id);
    return CM_SUCCESS;
}

static status_t rb_redo_update_volhead(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    // no need to update volume head.
    return CM_SUCCESS;
}

static void print_redo_update_volhead(wr_redo_entry_t *entry)
{
    wr_redo_volhead_t *redo = (wr_redo_volhead_t *)entry->data;
    (void)printf("    redo_volhead = {\n");
    (void)printf("      head = %s\n", redo->head);
    (void)printf("      name = %s\n", redo->name);
    (void)printf("    }\n");
}
static status_t rb_redo_add_or_remove_volume(
    wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    bool32 remote = CM_FALSE;
    wr_redo_volop_t *redo = (wr_redo_volop_t *)entry->data;
    WR_LOG_DEBUG_OP(
        "[REDO][ROLLBACK][ADD_OR_REMOVE_VOL] rollback %s volume operate", (redo->is_add) ? "add" : "remove");
    return wr_load_vg_ctrl_part(vg_item, (int64)WR_CTRL_CORE_OFFSET, vg_item->wr_ctrl->core_data,
        (int32)(WR_CORE_CTRL_SIZE + WR_VOLUME_CTRL_SIZE), &remote);
}

static void print_redo_add_or_remove_volume(wr_redo_entry_t *entry)
{
    wr_redo_volop_t *data = (wr_redo_volop_t *)entry->data;
    (void)printf("    redo_volop = {\n");
    (void)printf("      attr = %s\n", data->attr);
    (void)printf("      def = %s\n", data->def);
    (void)printf("      is_add = %u\n", data->is_add);
    (void)printf("      volume_count = %u\n", data->volume_count);
    (void)printf("      core_version = %llu\n", data->core_version);
    (void)printf("      volume_version = %llu\n", data->volume_version);
    (void)printf("    }\n");
}

static status_t rp_update_core_ctrl(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    errno_t errcode = 0;
    wr_core_ctrl_t *data = (wr_core_ctrl_t *)entry->data;
    if (entry->size != 0 && vg_item->status == WR_VG_STATUS_RECOVERY) {
        errcode =
            memcpy_s(vg_item->wr_ctrl->core_data, WR_CORE_CTRL_SIZE, data, entry->size - sizeof(wr_redo_entry_t));
        securec_check_ret(errcode);
    }
    LOG_DEBUG_INF("[REDO] replay to update core ctrl, hwm:%llu.", vg_item->wr_ctrl->core.volume_attrs[0].hwm);
    status_t status = wr_update_core_ctrl_disk(vg_item);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to update core ctrl to disk, vg:%s.", vg_item->vg_name));
    WR_LOG_DEBUG_OP("[REDO] Succeed to replay update core ctrl:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_update_core_ctrl(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    bool32 remote = CM_FALSE;
    WR_LOG_DEBUG_OP(
        "[REDO][ROLLBACK] rollback update core ctrl, hwm:%llu.", vg_item->wr_ctrl->core.volume_attrs[0].hwm);
    return wr_load_vg_ctrl_part(
        vg_item, (int64)WR_CTRL_CORE_OFFSET, vg_item->wr_ctrl->core_data, (int32)WR_CORE_CTRL_SIZE, &remote);
}

static void print_redo_update_core_ctrl(wr_redo_entry_t *entry)
{
    wr_core_ctrl_t *data = (wr_core_ctrl_t *)entry->data;
    wr_printf_core_ctrl_base(data);
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

    for (uint32 i = 0; i < addr_his->count; i++) {
        if (addr_his->addrs[i] == block) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}
static status_t rp_redo_alloc_ft_node_core(wr_session_t *session, wr_vg_info_item_t *vg_item,
    wr_redo_alloc_ft_node_t *data, wr_root_ft_block_t *ft_block, bool32 check_version)
{
    bool32 cmp;
    status_t status;
    gft_node_t *node;
    wr_ft_block_t *cur_block;
    wr_block_addr_his_t addr_his;
    rp_init_block_addr_history(&addr_his);
    rp_insert_block_addr_history(&addr_his, ft_block);
    for (uint32 i = 0; i < WR_REDO_ALLOC_FT_NODE_NUM; i++) {
        cmp = wr_cmp_auid(data->node[i].id, CM_INVALID_ID64);
        if (cmp) {
            continue;
        }
        node = wr_get_ft_node_by_ftid(session, vg_item, data->node[i].id, check_version, CM_FALSE);
        if (node == NULL) {
            WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid ft node."));
        }
        cur_block = wr_get_ft_by_node(node);
        if (vg_item->status == WR_VG_STATUS_RECOVERY) {
            *node = data->node[i];
            if (i == WR_REDO_ALLOC_FT_NODE_SELF_INDEX) {
                cur_block->common.flags = WR_BLOCK_FLAG_USED;
            }
        }

        LOG_DEBUG_INF("[REDO] replay alloc file table node, name:%s.", node->name);

        cur_block = wr_get_ft_by_node(node);
        if (rp_check_block_addr(&addr_his, cur_block) && vg_item->status != WR_VG_STATUS_RECOVERY) {
            continue;  // already update the block to disk
        }
        status = wr_update_ft_block_disk(vg_item, cur_block, data->node[i].id);
        WR_RETURN_IF_ERROR(status);
        rp_insert_block_addr_history(&addr_his, cur_block);
    }
    return CM_SUCCESS;
}

static status_t rp_redo_alloc_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);
    status_t status;
    wr_redo_alloc_ft_node_t *data = (wr_redo_alloc_ft_node_t *)entry->data;
    wr_root_ft_block_t *ft_block = WR_GET_ROOT_BLOCK(vg_item->wr_ctrl);
    gft_root_t *gft = &ft_block->ft_root;
    bool32 check_version = CM_FALSE;

    if (entry->size == 0) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_REDO_ILL, "invalid entry log size 0."));
    }
    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        status = wr_refresh_root_ft(vg_item, CM_TRUE, CM_FALSE);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("[REDO] Failed to refresh file table root, vg:%s.", vg_item->vg_name);
            return status;
        }

        *gft = data->ft_root;
        check_version = CM_TRUE;
        LOG_DEBUG_INF("[REDO] replay alloc file table node when recovery.");
    }

    status = wr_update_ft_root(vg_item);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_REDO_ILL, "Failed to update file table root."));
    WR_RETURN_IF_ERROR(rp_redo_alloc_ft_node_core(session, vg_item, data, ft_block, check_version));
    LOG_DEBUG_INF("[REDO] Succeed to replay alloc ft node, vg name:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_rollback_ft_block(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, uint32 node_num)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(node != NULL);
    status_t status;
    bool32 check_version = CM_FALSE;
    bool32 remote = CM_FALSE;

    status = wr_load_vg_ctrl_part(
        vg_item, (int64)WR_CTRL_ROOT_OFFSET, vg_item->wr_ctrl->root, (int32)WR_BLOCK_SIZE, &remote);
    if (status != CM_SUCCESS) {
        return status;
    }

    gft_node_t *cur_node;
    wr_ft_block_t *cur_block = NULL;
    bool32 cmp;
    int64 offset = 0;
    for (uint32 i = 0; i < node_num; i++) {
        cmp = wr_cmp_auid(node[i].id, CM_INVALID_ID64);
        if (cmp) {
            continue;
        }
        cur_node = wr_get_ft_node_by_ftid(session, vg_item, node[i].id, check_version, CM_FALSE);
        if (!cur_node) {
            WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid ft node."));
        }

        cur_block = wr_get_ft_by_node(cur_node);
        offset = wr_get_ft_block_offset(vg_item, node[i].id);
        status =
            wr_get_block_from_disk(vg_item, node[i].id, (char *)cur_block, offset, (int32)WR_BLOCK_SIZE, CM_TRUE);
        if (status != CM_SUCCESS) {
            return status;
        }
    }
    return CM_SUCCESS;
}

static status_t rb_redo_alloc_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);
    wr_redo_alloc_ft_node_t *data = (wr_redo_alloc_ft_node_t *)entry->data;

    if (entry->size == 0) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_REDO_ILL, "invalid entry log size 0."));
    }

    return rb_rollback_ft_block(session, vg_item, data->node, WR_REDO_ALLOC_FT_NODE_NUM);
}

static void print_redo_alloc_ft_node(wr_redo_entry_t *entry)
{
    wr_redo_alloc_ft_node_t *data = (wr_redo_alloc_ft_node_t *)entry->data;
    (void)printf("    alloc_ft_node = {\n");
    (void)printf("      ft_root = {\n");
    printf_gft_root(&data->ft_root);
    (void)printf("      }\n");
    for (uint32 i = 0; i < WR_REDO_ALLOC_FT_NODE_NUM; i++) {
        if (wr_cmp_auid(data->node[i].id, CM_INVALID_ID64)) {
            continue;
        }
        (void)printf("    gft_node[%u] = {\n", i);
        printf_gft_node(&data->node[i], "    ");
        (void)printf("    }\n");
    }
    (void)printf("    }\n");
}

static status_t wr_update_ft_info(wr_vg_info_item_t *vg_item, wr_ft_block_t *block, wr_redo_format_ft_t *data)
{
    status_t status = wr_update_ft_block_disk(vg_item, block, data->old_last_block);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR(
            "[REDO] Failed to update file table block to disk, %s.", wr_display_metaid(data->old_last_block));
        return status;
    }
    status = wr_update_ft_root(vg_item);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to update file table root, vg:%s.", vg_item->vg_name));
    return CM_SUCCESS;
}

static status_t rp_redo_format_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL && entry != NULL);

    status_t status;
    wr_redo_format_ft_t *data = (wr_redo_format_ft_t *)entry->data;
    wr_ft_block_t *block = NULL;
    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        status = wr_refresh_root_ft(vg_item, CM_TRUE, CM_FALSE);
        WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to refresh file table root, vg:%s.", vg_item->vg_name));
        // note:first load
        block = (wr_ft_block_t *)wr_get_ft_block_by_ftid(session, vg_item, data->old_last_block);
        if (block == NULL) {
            WR_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("[REDO]Failed to get last file table block, blockid: %s.",
                                            wr_display_metaid(data->old_last_block)));
        }
        wr_root_ft_block_t *root_block = WR_GET_ROOT_BLOCK(vg_item->wr_ctrl);
        root_block->ft_root.free_list = data->old_free_list;
        root_block->ft_root.last = data->old_last_block;
        status = wr_format_ft_node(session, vg_item, data->auid);
        WR_RETURN_IFERR2(
            status, LOG_DEBUG_ERR("[REDO] Failed to format file table node, %s.", wr_display_metaid(data->auid)));
    }
    // when recover, has load old last block.
    if (vg_item->status != WR_VG_STATUS_RECOVERY) {  // just find the block, it has already in memory.
        block = (wr_ft_block_t *)wr_get_ft_block_by_ftid(session, vg_item, data->old_last_block);
        if (block == NULL) {
            WR_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("[REDO]Failed to get last file table block, blockid: %s.",
                                            wr_display_metaid(data->old_last_block)));
        }
    }
    CM_RETURN_IFERR(wr_update_ft_info(vg_item, block, data));
    wr_block_id_t first = data->auid;
    ga_obj_id_t obj_id;
    status = wr_find_block_objid_in_shm(session, vg_item, first, WR_BLOCK_TYPE_FT, &obj_id);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to find block: %s.", wr_display_metaid(first)));
    status = wr_update_au_disk(vg_item, data->auid, GA_8K_POOL, obj_id.obj_id, data->count, WR_BLOCK_SIZE);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to update au to disk, %s.", wr_display_metaid(data->auid)));
    WR_LOG_DEBUG_OP("[REDO] Succeed to replay formate ft node: %s , obj_id:%u, count:%u.",
        wr_display_metaid(data->auid), data->obj_id, data->count);
    LOG_DEBUG_INF("[REDO] old_last_block: %s", wr_display_metaid(data->old_last_block));
    return CM_SUCCESS;
}

static status_t rb_redo_format_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    // format file table node only when new au, if fail, just free the memory, no need to rollback.
    return CM_SUCCESS;
}

static void print_redo_format_ft_node(wr_redo_entry_t *entry)
{
    wr_redo_format_ft_t *data = (wr_redo_format_ft_t *)entry->data;
    (void)printf("    format_ft = {\n");
    (void)printf("     auid = {\n");
    printf_auid(&data->auid);
    (void)printf("      }\n");
    (void)printf("      obj_id = %u\n", data->obj_id);
    (void)printf("      count = %u\n", data->count);
    (void)printf("     old_last_block = {\n");
    printf_auid(&data->old_last_block);
    (void)printf("      }\n");
    (void)printf("     old_free_list = {\n");
    printf_gft_list(&data->old_free_list);
    (void)printf("      }\n");
    (void)printf("      obj_id = %u\n", data->obj_id);
    (void)printf("    }\n");
}

static status_t rp_redo_free_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    wr_redo_free_fs_block_t *data = (wr_redo_free_fs_block_t *)entry->data;

    wr_fs_block_t *block;
    wr_fs_block_t *log_block = (wr_fs_block_t *)data->head;
    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        ga_obj_id_t obj_id;
        block = (wr_fs_block_t *)wr_find_block_in_shm(
            session, vg_item, log_block->head.common.id, WR_BLOCK_TYPE_FS, CM_TRUE, &obj_id, CM_FALSE);
        if (block == NULL) {
            WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid block"));
        }
        block->head.next = log_block->head.next;
        block->head.index = WR_FS_INDEX_INIT;
        block->head.common.flags = WR_BLOCK_FLAG_FREE;
        wr_set_auid(&block->head.ftid, WR_BLOCK_ID_INIT);
        status = wr_update_fs_bitmap_block_disk(vg_item, block, WR_DISK_UNIT_SIZE, CM_FALSE);
        WR_RETURN_IF_ERROR(status);
        wr_unregister_buffer_cache(session, vg_item, log_block->head.common.id);
        ga_free_object(obj_id.pool_id, obj_id.obj_id);
        return CM_SUCCESS;
    }

    status = wr_update_fs_bitmap_block_disk(vg_item, log_block, WR_DISK_UNIT_SIZE, CM_TRUE);
    WR_RETURN_IFERR2(status,
        LOG_DEBUG_ERR("[REDO] Failed to update fs bitmap block: %s.", wr_display_metaid(log_block->head.common.id)));
    LOG_DEBUG_INF("[REDO] Succeed to replay free fs block: %s, vg name:%s.",
        wr_display_metaid(log_block->head.common.id), vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_free_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    wr_redo_free_fs_block_t *data = (wr_redo_free_fs_block_t *)entry->data;
    wr_fs_block_t *log_block = (wr_fs_block_t *)data->head;

    return wr_load_fs_block_by_blockid(session, vg_item, log_block->head.common.id, (int32)WR_FILE_SPACE_BLOCK_SIZE);
}
static void print_redo_free_fs_block(wr_redo_entry_t *entry)
{
    wr_redo_free_fs_block_t *data = (wr_redo_free_fs_block_t *)entry->data;
    (void)printf("    free_fs_block = {\n");
    (void)printf("     head = %s\n", data->head);
    (void)printf("    }\n");
}
static status_t rp_redo_alloc_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    wr_redo_alloc_fs_block_t *data = (wr_redo_alloc_fs_block_t *)entry->data;
    wr_fs_block_root_t *root = WR_GET_FS_BLOCK_ROOT(vg_item->wr_ctrl);
    wr_fs_block_t *block = NULL;

    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        status = wr_check_refresh_core(vg_item);
        WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to refresh vg core:%s.", vg_item->vg_name));
        block = (wr_fs_block_t *)wr_find_block_in_shm(
            session, vg_item, data->id, WR_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
        if (block == NULL) {
            WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid block"));
        }

        wr_init_fs_block_head(block);
        block->head.ftid = data->ftid;
        block->head.index = data->index;
        block->head.common.flags = WR_BLOCK_FLAG_USED;
        *root = data->root;
    }
    status = wr_update_core_ctrl_disk(vg_item);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to update vg core:%s to disk.", vg_item->vg_name));

    if (block == NULL) {
        block = (wr_fs_block_t *)wr_find_block_in_shm(
            session, vg_item, data->id, WR_BLOCK_TYPE_FS, CM_FALSE, NULL, CM_FALSE);
    }

    if (block == NULL) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid block"));
    }

    status = wr_update_fs_bitmap_block_disk(vg_item, block, WR_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    WR_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("[REDO] Failed to update fs bitmap block: %s.", wr_display_metaid(data->id)));
    LOG_DEBUG_INF(
        "[REDO] Succeed to replay alloc fs block: %s, vg name:%s.", wr_display_metaid(data->id), vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_redo_alloc_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    bool32 remote = CM_FALSE;
    wr_redo_alloc_fs_block_t *data = (wr_redo_alloc_fs_block_t *)entry->data;

    ga_obj_id_t obj_id;
    wr_fs_block_t *block = (wr_fs_block_t *)wr_find_block_in_shm(
        session, vg_item, data->id, WR_BLOCK_TYPE_FS, CM_FALSE, &obj_id, CM_FALSE);
    CM_ASSERT(block != NULL);
    wr_unregister_buffer_cache(session, vg_item, block->head.common.id);
    ga_free_object(obj_id.pool_id, obj_id.obj_id);
    status = wr_load_vg_ctrl_part(
        vg_item, (int64)WR_CTRL_CORE_OFFSET, vg_item->wr_ctrl->core_data, WR_DISK_UNIT_SIZE, &remote);
    CM_ASSERT(status == CM_SUCCESS);
    return status;
}

static void print_redo_alloc_fs_block(wr_redo_entry_t *entry)
{
    wr_redo_alloc_fs_block_t *data = (wr_redo_alloc_fs_block_t *)entry->data;
    (void)printf("    alloc_fs_block = {\n");
    (void)printf("     id = {\n");
    printf_auid(&data->id);
    (void)printf("      }\n");
    (void)printf("     ftid = {\n");
    printf_auid(&data->ftid);
    (void)printf("      }\n");
    (void)printf("     root = {\n");
    printf_wr_fs_block_root(&data->root);
    (void)printf("      }\n");
    (void)printf("     index = %hu\n", data->index);
    (void)printf("    }\n");
}
status_t rp_redo_init_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    wr_redo_init_fs_block_t *data = (wr_redo_init_fs_block_t *)entry->data;

    wr_fs_block_t *block = NULL;

    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        block = (wr_fs_block_t *)wr_find_block_in_shm(
            session, vg_item, data->id, WR_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
        if (block == NULL) {
            WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid block"));
        }
        block->bitmap[data->index] = data->second_id;
        block->head.used_num = data->used_num;
    }

    if (block == NULL) {
        block = (wr_fs_block_t *)wr_find_block_in_shm(
            session, vg_item, data->id, WR_BLOCK_TYPE_FS, CM_FALSE, NULL, CM_FALSE);
        if (block == NULL) {
            WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid block"));
        }
    }

    status = wr_update_fs_bitmap_block_disk(vg_item, block, WR_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    WR_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("[REDO] Failed to update fs bitmap block: %s to disk.", wr_display_metaid(data->id)));
    LOG_DEBUG_INF(
        "[REDO] Succeed to replay init fs block: %s, vg name:%s.", wr_display_metaid(data->id), vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_init_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    wr_redo_init_fs_block_t *data = (wr_redo_init_fs_block_t *)entry->data;

    wr_fs_block_t *block = (wr_fs_block_t *)wr_find_block_in_shm(
        session, vg_item, data->id, WR_BLOCK_TYPE_FS, CM_FALSE, NULL, CM_FALSE);
    if (block == NULL) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid block"));
    }

    wr_set_blockid(&block->bitmap[data->index], CM_INVALID_ID64);
    block->head.used_num = 0;

    return CM_SUCCESS;
}
static void print_redo_init_fs_block(wr_redo_entry_t *entry)
{
    wr_redo_init_fs_block_t *data = (wr_redo_init_fs_block_t *)entry->data;
    (void)printf("    init_fs_block = {\n");
    (void)printf("     id = {\n");
    printf_auid(&data->id);
    (void)printf("      }\n");
    (void)printf("     second_id = {\n");
    printf_auid(&data->second_id);
    (void)printf("      }\n");
    (void)printf("     index = %hu\n", data->index);
    (void)printf("     used_num = %hu\n", data->used_num);
    (void)printf("    }\n");
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
        int32 ret = snprintf_s(node->name, WR_MAX_NAME_LEN, strlen(data->name), "%s", data->name);
        WR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    }

    wr_ft_block_t *cur_block = wr_get_ft_by_node(node);
    if (cur_block == NULL) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid block"));
    }

    status_t status = wr_update_ft_block_disk(vg_item, cur_block, data->node.id);
    WR_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("[REDO] Failed to update fs block: %s to disk.", wr_display_metaid(data->node.id)));

    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(cur_block);

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

    int32 ret = snprintf_s(node->name, WR_MAX_NAME_LEN, strlen(data->old_name), "%s", data->old_name);
    WR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    return CM_SUCCESS;
}
static void print_redo_rename_file(wr_redo_entry_t *entry)
{
    wr_redo_rename_t *data = (wr_redo_rename_t *)entry->data;
    (void)printf("    set_file_size = {\n");
    (void)printf("     node = {\n");
    printf_gft_node(&data->node, "    ");
    (void)printf("      }\n");
    (void)printf("     name = %s\n", data->name);
    (void)printf("     old_name = %s\n", data->old_name);
    (void)printf("    }\n");
}
status_t rp_redo_set_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    wr_redo_set_fs_block_t *data = (wr_redo_set_fs_block_t *)entry->data;

    bool32 check_version = CM_FALSE;
    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    wr_fs_block_t *block = (wr_fs_block_t *)wr_find_block_in_shm(
        session, vg_item, data->id, WR_BLOCK_TYPE_FS, check_version, NULL, CM_FALSE);
    if (block == NULL) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid block"));
    }

    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        block->bitmap[data->index] = data->value;
        block->head.used_num = data->used_num;
    }

    status = wr_update_fs_bitmap_block_disk(vg_item, block, WR_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update fs block: %s to disk.", wr_display_metaid(data->id)));

    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(block);
    LOG_DEBUG_INF("[REDO] Succeed to replay set fs block: %s, used_num:%hu, vg name:%s.", wr_display_metaid(data->id),
        block->head.used_num, vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_set_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    wr_redo_set_fs_block_t *data = (wr_redo_set_fs_block_t *)entry->data;

    wr_fs_block_t *block;
    bool32 check_version = CM_FALSE;

    block = (wr_fs_block_t *)wr_find_block_in_shm(
        session, vg_item, data->id, WR_BLOCK_TYPE_FS, check_version, NULL, CM_FALSE);
    if (block == NULL) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FNODE_CHECK, "invalid block"));
    }

    block->bitmap[data->index] = data->old_value;
    block->head.used_num = data->old_used_num;

    return CM_SUCCESS;
}

static void print_redo_set_fs_block(wr_redo_entry_t *entry)
{
    wr_redo_set_fs_block_t *data = (wr_redo_set_fs_block_t *)entry->data;
    (void)printf("    set_fs_block = {\n");
    (void)printf("     id = {\n");
    printf_auid(&data->id);
    (void)printf("      }\n");
    (void)printf("     value = {\n");
    printf_auid(&data->value);
    (void)printf("      }\n");
    (void)printf("     old_value = {\n");
    printf_auid(&data->old_value);
    (void)printf("      }\n");
    (void)printf("     index = %hu\n", data->index);
    (void)printf("     used_num = %hu\n", data->used_num);
    (void)printf("     old_used_num = %hu\n", data->old_used_num);
    (void)printf("    }\n");
}

static status_t rp_redo_free_ft_node_core(wr_session_t *session, wr_vg_info_item_t *vg_item,
    wr_root_ft_block_t *ft_block, wr_redo_free_ft_node_t *data, bool32 check_version)
{
    return CM_SUCCESS;
}

status_t rp_redo_free_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    wr_redo_free_ft_node_t *data = (wr_redo_free_ft_node_t *)entry->data;
    wr_root_ft_block_t *ft_block = WR_GET_ROOT_BLOCK(vg_item->wr_ctrl);
    gft_root_t *gft = &ft_block->ft_root;
    bool32 check_version = CM_FALSE;

    if (entry->size == 0) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_REDO_ILL, "invalid entry log size 0."));
    }
    if (vg_item->status == WR_VG_STATUS_RECOVERY) {
        CM_RETURN_IFERR_EX(wr_refresh_root_ft(vg_item, CM_TRUE, CM_FALSE),
            LOG_DEBUG_ERR("[REDO] Failed to refresh file table root, vg:%s.", vg_item->vg_name));

        *gft = data->ft_root;
        check_version = CM_TRUE;
    }
    return rp_redo_free_ft_node_core(session, vg_item, ft_block, data, check_version);
}

status_t rb_redo_free_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    wr_redo_free_ft_node_t *data = (wr_redo_free_ft_node_t *)entry->data;

    if (entry->size == 0) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_REDO_ILL, "invalid entry log size 0."));
    }

    return rb_rollback_ft_block(session, vg_item, data->node, WR_REDO_FREE_FT_NODE_NUM);
}

static void print_redo_free_ft_node(wr_redo_entry_t *entry)
{
    wr_redo_free_ft_node_t *data = (wr_redo_free_ft_node_t *)entry->data;
    (void)printf("    free_ft_node = {\n");
    (void)printf("      ft_root = {\n");
    printf_gft_root(&data->ft_root);
    (void)printf("      }\n");
    for (uint32 i = 0; i < WR_REDO_FREE_FT_NODE_NUM; i++) {
        if (wr_cmp_auid(data->node[i].id, CM_INVALID_ID64)) {
            continue;
        }
        (void)printf("    gft_node[%u] = {\n", i);
        printf_gft_node(&data->node[i], "    ");
        (void)printf("    }\n");
    }
    (void)printf("    }\n");
}

status_t rp_redo_recycle_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rb_redo_recycle_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

static void print_redo_recycle_ft_node(wr_redo_entry_t *entry)
{
    wr_redo_recycle_ft_node_t *data = (wr_redo_recycle_ft_node_t *)entry->data;
    (void)printf("    recycle_ft_node = {\n");
    for (uint32 i = 0; i < WR_REDO_RECYCLE_FT_NODE_NUM; i++) {
        if (wr_cmp_auid(data->node[i].id, CM_INVALID_ID64)) {
            continue;
        }
        (void)printf("    gft_node[%u] = {\n", i);
        printf_gft_node(&data->node[i], "    ");
        (void)printf("    }\n");
    }
    (void)printf("    }\n");
}

status_t rp_redo_set_file_size(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

static status_t rb_redo_get_ft_node(
    wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry, ftid_t ftid, gft_node_t **node)
{
    return CM_SUCCESS;
}

status_t rb_redo_set_file_size(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);
    wr_redo_set_file_size_t *data = (wr_redo_set_file_size_t *)entry->data;
    gft_node_t *node;
    WR_RETURN_IF_ERROR(rb_redo_get_ft_node(session, vg_item, entry, data->ftid, &node));
    node->size = data->oldsize;
    return CM_SUCCESS;
}

static void print_redo_set_file_size(wr_redo_entry_t *entry)
{
    wr_redo_set_file_size_t *data = (wr_redo_set_file_size_t *)entry->data;
    (void)printf("    set_file_size = {\n");
    (void)printf("     ftid = {\n");
    printf_auid(&data->ftid);
    (void)printf("      }\n");
    (void)printf("     size = %llu\n", data->size);
    (void)printf("     oldsize = %llu\n", data->oldsize);
    (void)printf("    }\n");
}

status_t rp_redo_format_fs_block(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

void rb_redo_clean_resource(
    wr_session_t *session, wr_vg_info_item_t *item, auid_t auid, ga_pool_id_e pool_id, uint32 first, uint32 count)
{
    wr_fs_block_header *block;
    uint32 obj_id = first;
    uint32 last = first;
    CM_ASSERT(count > 0);
    for (uint32 i = 0; i < count; i++) {
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

static void print_redo_format_fs_block(wr_redo_entry_t *entry)
{
    wr_redo_format_fs_t *data = (wr_redo_format_fs_t *)entry->data;
    (void)printf("    format_fs = {\n");
    (void)printf("     auid = {\n");
    printf_auid(&data->auid);
    (void)printf("      }\n");
    (void)printf("     obj_id = %u\n", data->obj_id);
    (void)printf("     count = %u\n", data->count);
    (void)printf("     old_free_list = {\n");
    printf_wr_fs_block_list(&data->old_free_list);
    (void)printf("      }\n");
    (void)printf("    }\n");
}

static status_t rp_redo_set_node_flag(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

static status_t rb_redo_set_node_flag(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

static void print_redo_set_node_flag(wr_redo_entry_t *entry)
{
    wr_redo_set_file_flag_t *data = (wr_redo_set_file_flag_t *)entry->data;
    (void)printf("    set_file_flag = {\n");
    (void)printf("     id = {\n");
    printf_auid(&data->ftid);
    (void)printf("      }\n");
    (void)printf("     flags = %u\n", data->flags);
    (void)printf("     old_flags = %u\n", data->old_flags);
    (void)printf("    }\n");
}

status_t rp_redo_set_fs_block_batch(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rb_redo_set_fs_block_batch(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rp_redo_set_fs_aux_block_batch_in_recovery(wr_session_t *session, wr_vg_info_item_t *vg_item,
    wr_redo_entry_t *entry, wr_fs_block_t *second_block, gft_node_t *node)
{
    return CM_SUCCESS;
}

status_t rp_redo_set_fs_aux_block_batch_inner(wr_session_t *session, wr_vg_info_item_t *vg_item,
    wr_redo_entry_t *entry, wr_fs_block_t *second_block, gft_node_t *node)
{
    return CM_SUCCESS;
}

status_t rp_redo_set_fs_aux_block_batch(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rb_redo_set_fs_aux_block_batch(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

static void print_redo_set_fs_aux_block_batch(wr_redo_entry_t *entry)
{
    wr_redo_set_fs_aux_block_batch_t *data = (wr_redo_set_fs_aux_block_batch_t *)entry->data;
    (void)printf("    fs_aux_block_batch = {\n");
    (void)printf("     fs_block_id = {\n");
    printf_auid(&data->fs_block_id);
    (void)printf("      }\n");
    (void)printf("     first_batch_au = {\n");
    printf_auid(&data->first_batch_au);
    (void)printf("      }\n");
    (void)printf("     node_id = {\n");
    printf_auid(&data->node_id);
    (void)printf("      }\n");
    (void)printf("     old_used_num = %hu\n", data->old_used_num);
    (void)printf("     batch_count = %hu\n", data->batch_count);
    (void)printf("     new_free_list = {\n");
    printf_wr_fs_block_list(&data->new_free_list);
    (void)printf("      }\n");
    for (uint16 i = 0; i < data->batch_count; i++) {
        (void)printf("     id_set[%hu] = {\n", i);
        printf_auid(&data->id_set[i]);
        (void)printf("      }\n");
    }
    (void)printf("    }\n");
}

status_t rp_redo_truncate_fs_block_batch(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}

status_t rb_redo_truncate_fs_block_batch(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    return CM_SUCCESS;
}
static void print_redo_truncate_fs_block_batch(wr_redo_entry_t *entry)
{
    wr_redo_truncate_fs_block_batch_t *data = (wr_redo_truncate_fs_block_batch_t *)entry->data;
    (void)printf("    truncate_fs_block_batch = {\n");
    (void)printf("     src_id = {\n");
    printf_auid(&data->src_id);
    (void)printf("      }\n");
    (void)printf("     dst_id = {\n");
    printf_auid(&data->dst_id);
    (void)printf("      }\n");
    (void)printf("     src_begin = %hu\n", data->src_begin);
    (void)printf("     dst_begin = %hu\n", data->dst_begin);
    (void)printf("     src_old_used_num = %hu\n", data->src_old_used_num);
    (void)printf("     dst_old_used_num = %hu\n", data->dst_old_used_num);
    (void)printf("     count = %hu\n", data->count);
    for (uint16 i = 0; i < data->count; i++) {
        (void)printf("     id_set[%hu] = {\n", i);
        printf_auid(&data->id_set[i]);
        (void)printf("      }\n");
    }
    (void)printf("    }\n");
}

static wr_redo_handler_t g_wr_handlers[] = {
    {WR_RT_UPDATE_CORE_CTRL, rp_update_core_ctrl, rb_update_core_ctrl, print_redo_update_core_ctrl},
    {WR_RT_ADD_OR_REMOVE_VOLUME, rp_redo_add_or_remove_volume, rb_redo_add_or_remove_volume,
        print_redo_add_or_remove_volume},
    {WR_RT_UPDATE_VOLHEAD, rp_redo_update_volhead, rb_redo_update_volhead, print_redo_update_volhead},
    // ft_au initializes multiple ft_blocks and mounts them to gft->free_list
    {WR_RT_FORMAT_AU_FILE_TABLE, rp_redo_format_ft_node, rb_redo_format_ft_node, print_redo_format_ft_node},
    // mount a gft_node to a directory
    {WR_RT_ALLOC_FILE_TABLE_NODE, rp_redo_alloc_ft_node, rb_redo_alloc_ft_node, print_redo_alloc_ft_node},
    // recycle gft_node to gft->free_list
    {WR_RT_FREE_FILE_TABLE_NODE, rp_redo_free_ft_node, rb_redo_free_ft_node, print_redo_free_ft_node},
    // recycle gft_node to wr_ctrl->core.au_root->free_root
    {WR_RT_RECYCLE_FILE_TABLE_NODE, rp_redo_recycle_ft_node, rb_redo_recycle_ft_node, print_redo_recycle_ft_node},
    {WR_RT_SET_FILE_SIZE, rp_redo_set_file_size, rb_redo_set_file_size, print_redo_set_file_size},
    {WR_RT_RENAME_FILE, rp_redo_rename_file, rb_redo_rename_file, print_redo_rename_file},

    // bitmap_au is initialized to multiple fs_blocks and mounted to wr_ctrl->core.fs_block_root
    {WR_RT_FORMAT_AU_FILE_SPACE, rp_redo_format_fs_block, rb_redo_format_fs_block, print_redo_format_fs_block},
    // allocate an idle fs_block from the wr_ctrl->core.fs_block_root
    {WR_RT_ALLOC_FS_BLOCK, rp_redo_alloc_fs_block, rb_redo_alloc_fs_block, print_redo_alloc_fs_block},
    // recycle fs_block to wr_ctrl->core.fs_block_root->free
    {WR_RT_FREE_FS_BLOCK, rp_redo_free_fs_block, rb_redo_free_fs_block, print_redo_free_fs_block},
    // initialize fs_block on gft_node
    {WR_RT_INIT_FILE_FS_BLOCK, rp_redo_init_fs_block, rb_redo_init_fs_block, print_redo_init_fs_block},
    // adds or removes a managed object of fs_block
    {WR_RT_SET_FILE_FS_BLOCK, rp_redo_set_fs_block, rb_redo_set_fs_block, print_redo_set_fs_block},
    {WR_RT_SET_NODE_FLAG, rp_redo_set_node_flag, rb_redo_set_node_flag, print_redo_set_node_flag},
};

void wr_print_redo_entry(wr_redo_entry_t *entry)
{
    (void)printf("    redo entry type = %u\n", entry->type);
    (void)printf("    redo entry size = %u\n", entry->size);
    wr_redo_handler_t *handler = &g_wr_handlers[entry->type];
    handler->print(entry);
}

// apply log to update meta
status_t wr_apply_log(wr_session_t *session, wr_vg_info_item_t *vg_item, char *log_buf)
{

    return CM_SUCCESS;
}

status_t wr_update_redo_info(wr_vg_info_item_t *vg_item, char *log_buf)
{
    return CM_SUCCESS;
}

status_t wr_process_redo_log_inner(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    return CM_SUCCESS;
}

status_t wr_process_redo_log(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    return CM_SUCCESS;
}

static status_t wr_rollback(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_redo_entry_t *entry)
{
    WR_LOG_DEBUG_OP("[REDO][ROLLBACK] rollback redo, type:%u.", entry->type);
    wr_redo_handler_t *handler = &g_wr_handlers[entry->type];
    return handler->rollback(session, vg_item, entry);
}

status_t wr_rollback_log(wr_session_t *session, wr_vg_info_item_t *vg_item, char *log_buf)
{
    return CM_SUCCESS;
}

void wr_rollback_mem_update(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    return;
}
