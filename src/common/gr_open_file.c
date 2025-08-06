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
 * gr_open_file.c
 *
 *
 * IDENTIFICATION
 *    src/common/gr_open_file.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_open_file.h"
#include "cm_system.h"

status_t gr_check_open_file(gr_session_t *session, gr_vg_info_item_t *vg_item, uint64 ftid, bool32 *is_open)
{
    *is_open = CM_FALSE;
    gr_open_file_info_t *open_file = NULL;

    gr_latch_x2(&vg_item->open_file_latch, session->id);
    bilist_node_t *curr_node = cm_bilist_head(&vg_item->open_file_list);
    bilist_node_t *next_node = NULL;
    while (curr_node != NULL) {
        open_file = BILIST_NODE_OF(gr_open_file_info_t, curr_node, link);
        next_node = curr_node->next;
        if (!cm_sys_process_alived(open_file->pid, open_file->start_time)) {
            gr_free_open_file_node(curr_node, &vg_item->open_file_list);
            curr_node = next_node;
            continue;
        }
        if (open_file->ftid == ftid) {
            *is_open = CM_TRUE;
            break;
        }
        curr_node = next_node;
    }

    gr_unlatch(&vg_item->open_file_latch);
    return CM_SUCCESS;
}
