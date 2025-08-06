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
 * gr_service.h
 *
 *
 * IDENTIFICATION
 *    src/service/gr_service.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_SERVICE_H__
#define __GR_SERVICE_H__
#include "gr_latch.h"
#include "gr_session.h"
#include "gr_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef status_t (*gr_srv_proc)(gr_session_t *session);
typedef status_t (*gr_srv_proc_err)(gr_session_t *session);

typedef struct st_gr_cmd_hdl {
    int32_t cmd;
    gr_srv_proc proc;
    gr_srv_proc_err proc_err;
    bool32 exec_on_active;
} gr_cmd_hdl_t;

#define GR_PROCESS_GET_MASTER_ID 50
static inline void gr_inc_active_sessions(gr_session_t *session)
{
    if (session->recv_pack.head->cmd != GR_CMD_SWITCH_LOCK) {
        (void)cm_atomic_inc(&g_gr_instance.active_sessions);
        LOG_DEBUG_INF("session:%u inc active_sessions to:%lld for cmd:%u", session->id, g_gr_instance.active_sessions,
            (uint32_t)session->recv_pack.head->cmd);
    }
}

static inline void gr_dec_active_sessions(gr_session_t *session)
{
    if (session->recv_pack.head->cmd != GR_CMD_SWITCH_LOCK) {
        (void)cm_atomic_dec(&g_gr_instance.active_sessions);
        LOG_DEBUG_INF("session:%u dec active_sessions to:%lld for cmd:%u", session->id, g_gr_instance.active_sessions,
            (uint32_t)session->recv_pack.head->cmd);
    }
}

status_t gr_get_exec_nodeid(gr_session_t *session, uint32_t *currid, uint32_t *remoteid);
void gr_wait_session_pause(gr_instance_t *inst);
void gr_wait_background_pause(gr_instance_t *inst);
void gr_set_session_running(gr_instance_t *inst, uint32_t sid);
status_t gr_diag_proto_type(gr_session_t *session);
status_t gr_process_handshake_cmd(gr_session_t *session, gr_cmd_type_e cmd);
status_t gr_process_command(gr_session_t *session);
status_t gr_proc_standby_req(gr_session_t *session);
status_t gr_process_single_cmd(gr_session_t **session);
void gr_release_session_res(gr_session_t *session);

#ifdef __cplusplus
}
#endif
#endif
