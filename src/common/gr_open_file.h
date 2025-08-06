/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
 * gr_open_file.h
 *
 *
 * IDENTIFICATION
 *    src/common/gr_open_file.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_OPEN_FILE_H__
#define __GR_OPEN_FILE_H__

#include "gr_diskgroup.h"
#include "gr_file_def.h"
#include "gr_malloc.h"
#include "gr_session.h"

typedef struct st_gr_open_file_info_t {
    uint64 ftid;
    uint64 pid;
    uint64 ref;
    int64 start_time;
    bilist_node_t link;
} gr_open_file_info_t;

status_t gr_init_open_file_index(gr_vg_info_item_t *vg_item);
void gr_destroy_open_file_index(gr_vg_info_item_t *vg_item);

status_t gr_check_open_file(gr_session_t *session, gr_vg_info_item_t *vg_item, uint64 ftid, bool32 *is_open);
static inline void gr_free_open_file_node(bilist_node_t *node, bilist_t *bilist)
{
    cm_bilist_del(node, bilist);
    gr_open_file_info_t *open_file = BILIST_NODE_OF(gr_open_file_info_t, node, link);
    cm_free(open_file);
}
#endif
