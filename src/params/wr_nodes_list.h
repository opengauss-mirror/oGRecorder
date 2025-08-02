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
 * wr_nodes_list.h
 *
 *
 * IDENTIFICATION
 *    src/params/wr_nodes_list.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_NODES_LIST_H__
#define __WR_NODES_LIST_H__

#include "cm_types.h"
#include "cm_defs.h"
#include "wr_defs.h"

typedef struct st_wr_nodes_list {
    uint32_t inst_cnt;
    uint64 inst_map;
    char nodes[WR_MAX_INSTANCES][CM_MAX_IP_LEN];
    uint16 ports[WR_MAX_INSTANCES];
} wr_nodes_list_t;

typedef struct st_wr_listen_addr {
    char host[CM_MAX_IP_LEN];
    uint16 port;
} wr_listen_addr_t;

status_t wr_extract_nodes_list(char *nodes_list_str, wr_nodes_list_t *nodes_list);
status_t wr_verify_nodes_list(void *lex, void *def);
status_t wr_notify_wr_nodes_list(void *se, void *item, char *value);

#endif