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
 * wr_alloc_unit.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_alloc_unit.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_ALLOC_UNIT_H__
#define __WR_ALLOC_UNIT_H__

#include "cm_defs.h"
#include "wr_defs.h"
#include "wr_au.h"
#include "wr_diskgroup.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_GET_AU_ROOT(wr_ctrl_p) ((wr_au_root_t *)((wr_ctrl_p)->core.au_root))
#define WR_MIN_FILE_NUM_IN_RECYCLE 32

typedef enum en_wr_au_type {
    WR_AU_TYPE_FILE,
    WR_AU_TYPE_META_FT,
    WR_AU_TYPE_META_BITMAP,
    WR_AU_TYPE_META_FREE,
} wr_au_type_t;

#pragma pack(8)
typedef struct st_wr_au_t {
    uint32_t checksum;
    uint32_t type : 4;  // au type:file,meta
    uint32_t size : 28;
    auid_t id;
    auid_t next;        // next free au
    char reserve[488];  // 512 align
} wr_au_head_t;

typedef struct st_wr_au_list_t {
    uint32_t count;
    auid_t first;
    auid_t last;
} wr_au_list_t;

typedef struct st_wr_au_root_t {
    uint64 version;
    uint64 free_root;  // .recycle ftid;
    uint64 count;
    uint32_t free_vol_id;  // the first volume that has free space.
    uint32_t reserve;
    wr_au_list_t free_list;
} wr_au_root_t;
#pragma pack()

bool32 wr_can_alloc_from_recycle(const gft_node_t *root_node, bool32 is_before);
void wr_init_au_root(wr_ctrl_t *wr_ctrl);
status_t wr_alloc_au(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t *auid);

void wr_update_core_ctrl(
    wr_session_t *session, wr_vg_info_item_t *item, wr_core_ctrl_t *core, uint32_t volume_id, bool32 is_only_root);
status_t wr_get_au_head(wr_vg_info_item_t *item, auid_t auid, wr_au_head_t *au_head);
status_t wr_get_au(wr_vg_info_item_t *item, auid_t auid, char *buf, int32_t size);
bool32 wr_cmp_auid(auid_t auid, uint64 id);
void wr_set_auid(auid_t *auid, uint64 id);
int64 wr_get_au_offset(wr_vg_info_item_t *item, auid_t auid);
uint64 wr_get_au_id(wr_vg_info_item_t *item, uint64 offset);
void wr_set_blockid(wr_block_id_t *blockid, uint64 id);
bool32 wr_cmp_blockid(wr_block_id_t blockid, uint64 id);
status_t wr_get_volume_version(wr_vg_info_item_t *item, uint64 *version);

#ifdef __cplusplus
}
#endif

#endif
