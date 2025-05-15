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
 * wr_nodes_list.c
 *
 *
 * IDENTIFICATION
 *    src/params/wr_nodes_list.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_nodes_list.h"
#include "cm_log.h"
#include "cm_ip.h"
#include "cm_defs.h"
#include "cm_config.h"
#include "mes_interface.h"
#include "wr_param.h"
#include "wr_param_verify.h"
#include "wr_malloc.h"
#include "wr_errno.h"
#include "wr_log.h"
#include "wr_diskgroup.h"

status_t wr_extract_nodes_list(char *nodes_list_str, wr_nodes_list_t *nodes_list)
{
    status_t status = cm_split_mes_urls(nodes_list->nodes, nodes_list->ports, nodes_list_str);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "WR_NODES_LIST format is wrong"));
    int32_t node_cnt = 0;
    for (int i = 0; i < WR_MAX_INSTANCES; i++) {
        if (nodes_list->ports[i] != 0) {
            nodes_list->inst_map |= ((uint64)1 << i);
            node_cnt++;
        }
    }
    nodes_list->inst_cnt = (uint32_t)node_cnt;
    LOG_RUN_INF("There are %d instances in incoming WR_NODES_LIST.", node_cnt);
    return CM_SUCCESS;
}

static status_t wr_alloc_and_extract_inst_addrs(char *nodes_list_str, uint32_t *inst_cnt, mes_addr_t **inst_addrs)
{
    wr_nodes_list_t nodes_list;
    securec_check_ret(memset_sp(&nodes_list, sizeof(wr_nodes_list_t), 0, sizeof(wr_nodes_list_t)));
    CM_RETURN_IFERR(wr_extract_nodes_list(nodes_list_str, &nodes_list));
    size_t mes_addrs_size = nodes_list.inst_cnt * sizeof(mes_addr_t);
    *inst_addrs = (mes_addr_t *)cm_malloc(mes_addrs_size);
    if (*inst_addrs == NULL) {
        WR_THROW_ERROR(ERR_ALLOC_MEMORY, mes_addrs_size, "wr_extract_inst_addrs");
        return CM_ERROR;
    }
    errno_t err = memset_sp(*inst_addrs, mes_addrs_size, 0, mes_addrs_size);
    if (err != 0) {
        CM_FREE_PTR(*inst_addrs);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }
    mes_addr_t *inst_addr = &((*inst_addrs)[0]);
    for (uint32_t i = 0; i < WR_MAX_INSTANCES; ++i) {
        if (nodes_list.ports[i] != 0) {
            inst_addr->inst_id = i;
            err = strcpy_sp(inst_addr->ip, sizeof(inst_addr->ip), nodes_list.nodes[i]);
            if (err != EOK) {
                CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
                CM_FREE_PTR(*inst_addrs);
                return CM_ERROR;
            }
            inst_addr->port = nodes_list.ports[i];
            inst_addr->need_connect = CM_TRUE;
            ++inst_addr;
        }
    }
    *inst_cnt = nodes_list.inst_cnt;
    return CM_SUCCESS;
}

status_t wr_verify_nodes_list(void *lex, void *def)
{
    const char *nodes_list_str = (const char *)lex;
    size_t len = strlen(nodes_list_str);
    for (size_t i = 0; i < len; ++i) {
        if ((nodes_list_str[i] != '|') && (!(CM_IS_DIGIT(nodes_list_str[i]))) && (nodes_list_str[i] != '.') &&
            (nodes_list_str[i] != ',')) {
            WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "WR_NODES_LIST contains invalid characters");
            return CM_ERROR;
        }
    }

    securec_check_ret(strcpy_sp(((wr_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, nodes_list_str));
    return CM_SUCCESS;
}

// addition or deletion of new instances is not allowed.
// only replacement of old instances is allowed.
static status_t check_nodes_list_validity(uint32_t inst_cnt, const mes_addr_t *inst_addrs)
{
    if (inst_cnt != g_inst_cfg->params.nodes_list.inst_cnt) {
        WR_THROW_ERROR(
            ERR_WR_INVALID_PARAM, "instance_ids in WR_NODES_LIST are not allowed to be changed dynamically");
        return CM_ERROR;
    }
    for (uint32_t i = 0; i < inst_cnt; ++i) {
        uint32_t inst_id = inst_addrs[i].inst_id;
        if (inst_addrs[i].port == 0) {
            WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "IP ports in WR_NODES_LIST cannot be zero");
            return CM_ERROR;
        }
        // If some instance's IP port in params is 0, it doesnot exist in this cluster.
        // Meantime, IP port of this instance in the new WR_NODES_LIST is not zero, which means
        // the user is trying to add new instances.
        if (g_inst_cfg->params.nodes_list.ports[inst_id] == 0) {
            WR_THROW_ERROR(
                ERR_WR_INVALID_PARAM, "instance_ids in WR_NODES_LIST are not allowed to be changed dynamically");
            return CM_ERROR;
        }
    }
    LOG_RUN_INF("the user-inputted WR_NODES_LIST is valid.");
    return CM_SUCCESS;
}

static status_t modify_ips_in_params(uint32_t inst_cnt, const mes_addr_t *inst_addrs)
{
    for (uint32_t i = 0; i < inst_cnt; ++i) {
        uint32_t inst_id = inst_addrs[i].inst_id;
        g_inst_cfg->params.nodes_list.ports[inst_id] = inst_addrs[i].port;
        if (strcmp(g_inst_cfg->params.nodes_list.nodes[inst_id], inst_addrs[i].ip) != 0) {
            securec_check_ret(strcpy_sp(g_inst_cfg->params.nodes_list.nodes[inst_id], CM_MAX_IP_LEN, inst_addrs[i].ip));
        }
    }
    return CM_SUCCESS;
}

status_t wr_update_local_nodes_list(char *nodes_list_str)
{
    uint32_t inst_cnt = 0;
    mes_addr_t *inst_addrs = NULL;
    CM_RETURN_IFERR(wr_alloc_and_extract_inst_addrs(nodes_list_str, &inst_cnt, &inst_addrs));
    CM_RETURN_IFERR(check_nodes_list_validity(inst_cnt, inst_addrs));
    status_t status = mes_update_instance(inst_cnt, inst_addrs);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update local mes connections.");
        CM_FREE_PTR(inst_addrs);
        return status;
    }
    CM_RETURN_IFERR(modify_ips_in_params(inst_cnt, inst_addrs));
    LOG_RUN_INF("Success to update local mes connections.");
    CM_FREE_PTR(inst_addrs);
    return CM_SUCCESS;
}

status_t wr_notify_wr_nodes_list(void *se, void *item, char *value)
{
    return wr_update_local_nodes_list(value);
}