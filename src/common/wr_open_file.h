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
 * wr_open_file.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_open_file.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_OPEN_FILE_H__
#define __WR_OPEN_FILE_H__

#include "wr_diskgroup.h"
#include "wr_file_def.h"
#include "wr_malloc.h"
#include "wr_session.h"

typedef struct st_wr_open_file_info_t {
    uint64 ftid;
    uint64 pid;
    uint64 ref;
    int64 start_time;
    bilist_node_t link;
} wr_open_file_info_t;

status_t wr_init_open_file_index(wr_vg_info_item_t *vg_item);
void wr_destroy_open_file_index(wr_vg_info_item_t *vg_item);

status_t wr_check_open_file(wr_session_t *session, wr_vg_info_item_t *vg_item, uint64 ftid, bool32 *is_open);
static inline void wr_free_open_file_node(bilist_node_t *node, bilist_t *bilist)
{
    cm_bilist_del(node, bilist);
    wr_open_file_info_t *open_file = BILIST_NODE_OF(wr_open_file_info_t, node, link);
    cm_free(open_file);
}
#endif
