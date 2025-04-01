/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * wr_au.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_au.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_AU_H__
#define __WR_AU_H__

#include "wr_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(8)
typedef struct st_auid_t {  // id of allocation unit, 8 Bytes
    uint64 volume : WR_MAX_BIT_NUM_VOLUME;
    uint64 au : WR_MAX_BIT_NUM_AU;
    uint64 block : WR_MAX_BIT_NUM_BLOCK;
    uint64 item : WR_MAX_BIT_NUM_ITEM;
} auid_t;

typedef struct st_wr_addr_t {
    uint64 volumeid : 10;
    uint64 offset : 54;
} wr_addr_t;

#pragma pack()

typedef auid_t wr_block_id_t;
typedef auid_t ftid_t;

extern auid_t wr_invalid_auid;
#define WR_INVALID_AUID (wr_invalid_auid)
#define WR_INVALID_BLOCK_ID (wr_invalid_auid)
#define WR_INVALID_FTID (wr_invalid_auid)

extern auid_t wr_set_inited_mask;
extern auid_t wr_unset_inited_mask;

#define WR_AU_UNINITED_MARK 0x1
static inline void wr_auid_set_uninit(auid_t *auid)
{
    auid->item |= WR_AU_UNINITED_MARK;
}

static inline void wr_auid_unset_uninit(auid_t *auid)
{
    auid->item &= ~WR_AU_UNINITED_MARK;
}

static inline bool32 wr_auid_is_uninit(auid_t *auid)
{
    return ((auid->item & WR_AU_UNINITED_MARK) != 0);
}

#define WR_BLOCK_ID_SET_INITED(block_id) ((*(uint64 *)&block_id) & (*(uint64 *)&wr_unset_inited_mask))
#define WR_BLOCK_ID_SET_UNINITED(block_id) ((*(uint64 *)&block_id) | (*(uint64 *)&wr_set_inited_mask))
#define WR_BLOCK_ID_IGNORE_UNINITED(block_id) ((*(uint64 *)&block_id) & (*(uint64 *)&wr_unset_inited_mask))
#define WR_BLOCK_ID_IS_INITED(block_id) (((block_id).item & WR_AU_UNINITED_MARK) == 0)

#define WR_BLOCK_ID_SET_AUX(block_id) ((*(uint64 *)&block_id) | (*(uint64 *)&wr_set_inited_mask))
#define WR_BLOCK_ID_SET_NOT_AUX(block_id) ((*(uint64 *)&block_id) & (*(uint64 *)&wr_unset_inited_mask))
#define WR_BLOCK_ID_IS_AUX(block_id) (((block_id).item & WR_AU_UNINITED_MARK) == 1)

char *wr_display_metaid(auid_t id);

#ifdef __cplusplus
}
#endif

#endif