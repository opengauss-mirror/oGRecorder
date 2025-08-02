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
 * wr_service.h
 *
 *
 * IDENTIFICATION
 *    src/service/wr_service.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_SERVICE_H__
#define __WR_SERVICE_H__
#include "wr_latch.h"
#include "wr_session.h"
#include "wr_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef status_t (*wr_srv_proc)(wr_session_t *session);
typedef status_t (*wr_srv_proc_err)(wr_session_t *session);

typedef struct st_wr_cmd_hdl {
    int32_t cmd;
    wr_srv_proc proc;
    wr_srv_proc_err proc_err;
    bool32 exec_on_active;
} wr_cmd_hdl_t;

#define WR_PROCESS_GET_MASTER_ID 50
static inline void wr_inc_active_sessions(wr_session_t *session)
{
    if (session->recv_pack.head->cmd != WR_CMD_SWITCH_LOCK) {
        (void)cm_atomic_inc(&g_wr_instance.active_sessions);
        LOG_DEBUG_INF("session:%u inc active_sessions to:%lld for cmd:%u", session->id, g_wr_instance.active_sessions,
            (uint32_t)session->recv_pack.head->cmd);
    }
}

static inline void wr_dec_active_sessions(wr_session_t *session)
{
    if (session->recv_pack.head->cmd != WR_CMD_SWITCH_LOCK) {
        (void)cm_atomic_dec(&g_wr_instance.active_sessions);
        LOG_DEBUG_INF("session:%u dec active_sessions to:%lld for cmd:%u", session->id, g_wr_instance.active_sessions,
            (uint32_t)session->recv_pack.head->cmd);
    }
}

status_t wr_get_exec_nodeid(wr_session_t *session, uint32_t *currid, uint32_t *remoteid);
void wr_wait_session_pause(wr_instance_t *inst);
void wr_wait_background_pause(wr_instance_t *inst);
void wr_set_session_running(wr_instance_t *inst, uint32_t sid);
status_t wr_diag_proto_type(wr_session_t *session);
status_t wr_process_handshake_cmd(wr_session_t *session, wr_cmd_type_e cmd);
status_t wr_process_command(wr_session_t *session);
status_t wr_proc_standby_req(wr_session_t *session);
status_t wr_process_single_cmd(wr_session_t **session);
void wr_release_session_res(wr_session_t *session);

#ifdef __cplusplus
}
#endif
#endif
