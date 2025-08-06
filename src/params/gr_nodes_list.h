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
 * gr_nodes_list.h
 *
 *
 * IDENTIFICATION
 *    src/params/gr_nodes_list.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_NODES_LIST_H__
#define __GR_NODES_LIST_H__

#include "cm_types.h"
#include "cm_defs.h"
#include "gr_defs.h"

typedef struct st_gr_nodes_list {
    uint32_t inst_cnt;
    uint64 inst_map;
    char nodes[GR_MAX_INSTANCES][CM_MAX_IP_LEN];
    uint16 ports[GR_MAX_INSTANCES];
} gr_nodes_list_t;

typedef struct st_gr_listen_addr {
    char host[CM_MAX_IP_LEN];
    uint16 port;
} gr_listen_addr_t;

status_t gr_extract_nodes_list(char *nodes_list_str, gr_nodes_list_t *nodes_list);
status_t gr_verify_nodes_list(void *lex, void *def);
status_t gr_notify_gr_nodes_list(void *se, void *item, char *value);

#endif