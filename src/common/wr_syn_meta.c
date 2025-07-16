/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * wr_syn_meta.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_syn_meta.c
 *
 * -------------------------------------------------------------------------
 */
#include "wr_syn_meta.h"
#include "wr_file.h"

#ifdef __cplusplus
extern "C" {
#endif

wr_meta_syn2other_nodes_proc_t meta_syn2other_nodes_proc = NULL;
void regist_meta_syn2other_nodes_proc(wr_meta_syn2other_nodes_proc_t proc)
{
    meta_syn2other_nodes_proc = proc;
}

status_t wr_meta_syn_remote(wr_session_t *session, wr_meta_syn_t *meta_syn, uint32_t size, bool32 *ack)
{
    return CM_SUCCESS;
}

status_t wr_invalidate_meta_remote(
    wr_session_t *session, wr_invalidate_meta_msg_t *invalidate_meta_msg, uint32_t size, bool32 *invalid_ack)
{
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif