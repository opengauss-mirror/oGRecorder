/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * gr_au.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/gr_au.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_AU_H__
#define __GR_AU_H__

#include "gr_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(8)
typedef struct st_auid_t {  // id of allocation unit, 8 Bytes
    uint64 volume : GR_MAX_BIT_NUM_VOLUME;
    uint64 au : GR_MAX_BIT_NUM_AU;
    uint64 block : GR_MAX_BIT_NUM_BLOCK;
    uint64 item : GR_MAX_BIT_NUM_ITEM;
} auid_t;

typedef struct st_gr_addr_t {
    uint64 volumeid : 10;
    uint64 offset : 54;
} gr_addr_t;

#pragma pack()

typedef auid_t gr_block_id_t;
typedef auid_t ftid_t;

extern auid_t gr_invalid_auid;
#define GR_INVALID_AUID (gr_invalid_auid)
#define GR_INVALID_BLOCK_ID (gr_invalid_auid)
#define GR_INVALID_FTID (gr_invalid_auid)

extern auid_t gr_set_inited_mask;
extern auid_t gr_unset_inited_mask;

#define GR_AU_UNINITED_MARK 0x1
static inline void gr_auid_set_uninit(auid_t *auid)
{
    auid->item |= GR_AU_UNINITED_MARK;
}

static inline void gr_auid_unset_uninit(auid_t *auid)
{
    auid->item &= ~GR_AU_UNINITED_MARK;
}

static inline bool32 gr_auid_is_uninit(auid_t *auid)
{
    return ((auid->item & GR_AU_UNINITED_MARK) != 0);
}

#define GR_BLOCK_ID_SET_INITED(block_id) ((*(uint64 *)&block_id) & (*(uint64 *)&gr_unset_inited_mask))
#define GR_BLOCK_ID_SET_UNINITED(block_id) ((*(uint64 *)&block_id) | (*(uint64 *)&gr_set_inited_mask))
#define GR_BLOCK_ID_IGNORE_UNINITED(block_id) ((*(uint64 *)&block_id) & (*(uint64 *)&gr_unset_inited_mask))
#define GR_BLOCK_ID_IS_INITED(block_id) (((block_id).item & GR_AU_UNINITED_MARK) == 0)

#define GR_BLOCK_ID_SET_AUX(block_id) ((*(uint64 *)&block_id) | (*(uint64 *)&gr_set_inited_mask))
#define GR_BLOCK_ID_SET_NOT_AUX(block_id) ((*(uint64 *)&block_id) & (*(uint64 *)&gr_unset_inited_mask))
#define GR_BLOCK_ID_IS_AUX(block_id) (((block_id).item & GR_AU_UNINITED_MARK) == 1)


#ifdef __cplusplus
}
#endif

#endif