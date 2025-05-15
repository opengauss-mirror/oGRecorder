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
 * wr_alloc_unit.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_alloc_unit.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_defs.h"
#include "wr_alloc_unit.h"
#include "wr_file.h"
#include "wr_redo.h"
#include "wr_fs_aux.h"

#ifdef __cplusplus
extern "C" {
#endif

void wr_init_au_root(wr_ctrl_t *wr_ctrl)
{
    CM_ASSERT(wr_ctrl != NULL);
    wr_au_root_t *au_root = WR_GET_AU_ROOT(wr_ctrl);
    au_root->count = 0;
    au_root->free_root = CM_INVALID_ID64;
    au_root->free_vol_id = 0;

    return;
}

bool32 wr_can_alloc_from_recycle(const gft_node_t *root_node, bool32 is_before)
{
    if ((is_before && root_node->items.count >= WR_MIN_FILE_NUM_IN_RECYCLE) ||
        (!is_before && root_node->items.count > 0)) {
        return WR_TRUE;
    }

    return CM_FALSE;
}

status_t wr_alloc_au(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t *auid)
{
    return CM_SUCCESS;
}

void wr_update_core_ctrl(
    wr_session_t *session, wr_vg_info_item_t *item, wr_core_ctrl_t *core, uint32_t volume_id, bool32 is_only_root)
{
    CM_ASSERT(item != NULL);
    CM_ASSERT(core != NULL);

    char *buf;
    uint32_t size;

    if (is_only_root) {
        buf = (char *)core;
        size = WR_DISK_UNIT_SIZE;
    } else {
        buf = (char *)core;
        size = sizeof(wr_core_ctrl_t);
    }

    // when update core ctrl ,handle should be valid.
    wr_put_log(session, item, WR_RT_UPDATE_CORE_CTRL, buf, size);
}

int64 wr_get_au_offset(wr_vg_info_item_t *item, auid_t auid)
{
    return (int64)((uint64)auid.au * (uint64)wr_get_vg_au_size(item->wr_ctrl));
}

status_t wr_get_au(wr_vg_info_item_t *item, auid_t auid, char *buf, int32_t size)
{
    if (auid.volume >= WR_MAX_VOLUMES) {
        return CM_ERROR;
    }

    bool32 remote = CM_FALSE;
    int64_t offset = wr_get_au_offset(item, auid);
    return wr_check_read_volume(item, (uint32_t)auid.volume, offset, buf, size, &remote);
}

status_t wr_get_au_head(wr_vg_info_item_t *item, auid_t auid, wr_au_head_t *au_head)
{
    CM_ASSERT(item != NULL);
    CM_ASSERT(au_head != NULL);

    if (auid.volume >= WR_MAX_VOLUMES) {
        return CM_ERROR;
    }

    return wr_get_au(item, auid, (char *)au_head, sizeof(wr_au_head_t));
}

bool32 wr_cmp_auid(auid_t auid, uint64 id)
{
    return *(uint64 *)&auid == id;
}

void wr_set_auid(auid_t *auid, uint64 id)
{
    *(uint64 *)auid = id;
}

void wr_set_blockid(wr_block_id_t *blockid, uint64 id)
{
    *(uint64 *)blockid = id;
}

bool32 wr_cmp_blockid(wr_block_id_t blockid, uint64 id)
{
    return *(uint64 *)&blockid == id;
}

uint64 wr_get_au_id(wr_vg_info_item_t *item, uint64 offset)
{
    return offset / (uint64)wr_get_vg_au_size(item->wr_ctrl);
}

status_t wr_get_volume_version(wr_vg_info_item_t *item, uint64 *version)
{
    CM_ASSERT(item != NULL);
    CM_ASSERT(version != NULL);
#ifndef WIN32
    char temp[WR_DISK_UNIT_SIZE] __attribute__((__aligned__(WR_DISK_UNIT_SIZE)));
#else
    char temp[WR_DISK_UNIT_SIZE];
#endif
    bool32 remote = CM_FALSE;
    status_t status =
        wr_load_vg_ctrl_part(item, (int64)WR_CTRL_VOLUME_OFFSET, temp, (int32_t)WR_DISK_UNIT_SIZE, &remote);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg core version %s.", item->entry_path);
        return status;
    }
    *version = ((wr_core_ctrl_t *)temp)->version;
    return CM_SUCCESS;
}
#ifdef __cplusplus
}
#endif
