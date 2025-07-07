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
 * wr_session.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_session.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_session.h"
#include "cm_utils.h"
#include "wr_diskgroup.h"
#include "wr_malloc.h"
#include "wr_file.h"
#include "wr_redo.h"
#include "cm_system.h"
#include "wr_thv.h"

#ifdef __cplusplus
extern "C" {
#endif

wr_session_ctrl_t g_wr_session_ctrl = {0};

status_t wr_extend_session(uint32_t extend_num)
{
    uint32_t objectid;
    uint32_t old_alloc_sessions = g_wr_session_ctrl.alloc_sessions;
    uint32_t new_alloc_sessions = g_wr_session_ctrl.alloc_sessions + extend_num;
    if (new_alloc_sessions > g_wr_session_ctrl.total) {
        LOG_RUN_ERR("Failed to extend session, expect new alloc sessions %u, but max is %u.", new_alloc_sessions,
            g_wr_session_ctrl.total);
        WR_THROW_ERROR(ERR_WR_SESSION_EXTEND, "expect new alloc sessions %u, but max is %u.", new_alloc_sessions,
            g_wr_session_ctrl.total);
        return CM_ERROR;
    }
    for (uint32_t i = old_alloc_sessions; i < new_alloc_sessions; i++) {
        objectid = ga_alloc_object(GA_SESSION_POOL, WR_INVALID_ID32);
        if (objectid == WR_INVALID_ID32) {
            LOG_RUN_ERR("Failed to alloc object for session %u.", i);
            WR_THROW_ERROR(ERR_WR_SESSION_EXTEND, "Failed to alloc object for session %u.", i);
            return CM_ERROR;
        }
        LOG_DEBUG_INF("Alloc object %u for session %u.", objectid, i);
        g_wr_session_ctrl.sessions[i] = (wr_session_t *)ga_object_addr(GA_SESSION_POOL, objectid);
        g_wr_session_ctrl.sessions[i]->id = i;
        g_wr_session_ctrl.sessions[i]->is_used = CM_FALSE;
        g_wr_session_ctrl.sessions[i]->is_closed = CM_TRUE;
        g_wr_session_ctrl.sessions[i]->put_log = CM_FALSE;
        g_wr_session_ctrl.sessions[i]->objectid = objectid;
        g_wr_session_ctrl.sessions[i]->is_holding_hotpatch_latch = CM_FALSE;
        g_wr_session_ctrl.alloc_sessions++;
    }
    LOG_RUN_INF("Succeed to extend sessions to %u.", g_wr_session_ctrl.alloc_sessions);
    return CM_SUCCESS;
}

status_t wr_init_session_pool(uint32_t max_session_num)
{
    uint32_t wr_session_size = (uint32_t)(max_session_num * sizeof(wr_session_t *));
    g_wr_session_ctrl.sessions = cm_malloc(wr_session_size);
    if (g_wr_session_ctrl.sessions == NULL) {
        return ERR_WR_GA_INIT;
    }
    errno_t errcode = memset_s(g_wr_session_ctrl.sessions, wr_session_size, 0, wr_session_size);
    securec_check_ret(errcode);
    g_wr_session_ctrl.alloc_sessions = 0;
    uint32_t extend_num = max_session_num >= WR_SESSION_NUM_PER_GROUP ? WR_SESSION_NUM_PER_GROUP : max_session_num;
    g_wr_session_ctrl.total = max_session_num;
    status_t status = wr_extend_session(extend_num);
    if (status != CM_SUCCESS) {
        return status;
    }
    g_wr_session_ctrl.is_inited = CM_TRUE;
    return CM_SUCCESS;
}

wr_session_ctrl_t *wr_get_session_ctrl(void)
{
    return &g_wr_session_ctrl;
}

uint32_t wr_get_uwression_startid(void)
{
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32_t start_sid = (uint32_t)WR_BACKGROUND_TASK_NUM;
    if (inst_cfg->params.nodes_list.inst_cnt > 1) {
        start_sid = start_sid + inst_cfg->params.channel_num + inst_cfg->params.work_thread_cnt;
    }
    return start_sid;
}

uint32_t wr_get_max_total_session_cnt(void)
{
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    return wr_get_uwression_startid() + inst_cfg->params.cfg_session_num;
}

uint32_t wr_get_recover_task_idx(void)
{
    return (wr_get_uwression_startid() - (uint32_t)WR_BACKGROUND_TASK_NUM);
}

uint32_t wr_get_delay_clean_task_idx(void)
{
    return (wr_get_uwression_startid() - (uint32_t)WR_BACKGROUND_TASK_NUM) + WR_DELAY_CLEAN_BACKGROUND_TASK;
}

uint32_t wr_get_hashmap_dynamic_extend_task_idx(void)
{
    return (wr_get_uwression_startid() - (uint32_t)WR_BACKGROUND_TASK_NUM) + WR_HASHMAP_DYNAMIC_EXTEND_TASK;
}

uint32_t wr_get_bg_task_set_idx(uint32_t task_id_base, uint32_t idx)
{
    return (wr_get_uwression_startid() - (uint32_t)WR_BACKGROUND_TASK_NUM) + task_id_base + idx;
}

uint32_t wr_get_meta_syn_task_idx(uint32_t idx)
{
    return wr_get_bg_task_set_idx(WR_META_SYN_BG_TASK_BASE, idx);
}

uint32_t wr_get_recycle_meta_task_idx(uint32_t idx)
{
    return wr_get_bg_task_set_idx(WR_RECYCLE_META_TASK_BASE, idx);
}

uint32_t wr_get_alarm_check_task_idx(void)
{
    return (wr_get_uwression_startid() - (uint32_t)WR_BACKGROUND_TASK_NUM) + WR_ALARM_CHECK_TASK;
}

static status_t wr_init_session(wr_session_t *session, const cs_pipe_t *pipe)
{
    wr_latch_stack_t *latch_stack = &session->latch_stack;
    errno_t errcode = memset_s(latch_stack, sizeof(wr_latch_stack_t), 0, sizeof(wr_latch_stack_t));
    securec_check_ret(errcode);
    session->is_direct = CM_TRUE;
    session->connected = CM_FALSE;
    if (pipe != NULL) {
        session->pipe = *pipe;
        session->connected = CM_TRUE;
    }
    session->is_closed = CM_FALSE;
    session->proto_type = PROTO_TYPE_UNKNOWN;
    session->status = WR_SESSION_STATUS_IDLE;
    session->client_version = WR_PROTO_VERSION;
    session->proto_version = WR_PROTO_VERSION;
    errcode = memset_s(
        session->wr_session_stat, WR_EVT_COUNT * sizeof(wr_stat_item_t), 0, WR_EVT_COUNT * sizeof(wr_stat_item_t));
    securec_check_ret(errcode);
    session->is_holding_hotpatch_latch = CM_FALSE;
    WR_RETURN_IF_ERROR(init_session_hash_mgr(session));
    return CM_SUCCESS;
}

wr_session_t *wr_get_reserv_session(uint32_t idx)
{
    wr_session_ctrl_t *session_ctrl = wr_get_session_ctrl();
    wr_session_t *session = session_ctrl->sessions[idx];
    return session;
}

status_t wr_create_session(const cs_pipe_t *pipe, wr_session_t **session)
{
    uint32_t i, id;

    *session = NULL;
    id = WR_INVALID_ID32;
    cm_spin_lock(&g_wr_session_ctrl.lock, NULL);

    uint32_t start_sid = wr_get_uwression_startid();
    uint32_t end_sid = wr_get_max_total_session_cnt();
    status_t status;
    for (i = start_sid; i < end_sid; i++) {
        if (i >= g_wr_session_ctrl.alloc_sessions) {
            uint32_t extend_num =
                g_wr_session_ctrl.total - g_wr_session_ctrl.alloc_sessions >= WR_SESSION_NUM_PER_GROUP ?
                    WR_SESSION_NUM_PER_GROUP :
                    g_wr_session_ctrl.total - g_wr_session_ctrl.alloc_sessions;
            status = wr_extend_session(extend_num);
            if (status != CM_SUCCESS) {
                cm_spin_unlock(&g_wr_session_ctrl.lock);
                return status;
            }
        }
        if (g_wr_session_ctrl.sessions[i]->is_used == CM_FALSE) {
            id = i;
            break;
        }
    }
    if (id == WR_INVALID_ID32) {
        LOG_DEBUG_INF("No sessions are available.");
        cm_spin_unlock(&g_wr_session_ctrl.lock);
        return ERR_WR_SESSION_CREATE;
    }
    *session = g_wr_session_ctrl.sessions[i];
    LOG_DEBUG_INF("Session[%u] is available.", id);
    cm_spin_lock(&(*session)->lock, NULL);
    g_wr_session_ctrl.used_count++;
    (*session)->is_used = CM_TRUE;
    cm_spin_unlock(&(*session)->lock);
    cm_spin_unlock(&g_wr_session_ctrl.lock);
    WR_RETURN_IF_ERROR(wr_init_session(*session, pipe));
    return CM_SUCCESS;
}

void wr_destroy_session_inner(wr_session_t *session)
{
    if (session->connected == CM_TRUE) {
        cs_disconnect(&session->pipe);
        session->connected = CM_FALSE;
    }
    g_wr_session_ctrl.used_count--;
    session->is_closed = CM_TRUE;
    session->is_used = CM_FALSE;
    errno_t ret = memset_sp(&session->cli_info, sizeof(session->cli_info), 0, sizeof(session->cli_info));
    securec_check_panic(ret);
    session->client_version = WR_PROTO_VERSION;
    session->proto_version = WR_PROTO_VERSION;
    session->put_log = CM_FALSE;
    session->is_holding_hotpatch_latch = CM_FALSE;
    CM_FREE_PTR(session->hash_mgr.hash_items);
}
void wr_destroy_session(wr_session_t *session)
{
    cm_spin_lock(&g_wr_session_ctrl.lock, NULL);
    cm_spin_lock(&session->shm_lock, NULL);
    LOG_DEBUG_INF("Succeed to lock session %u shm lock", session->id);
    wr_destroy_session_inner(session);
    cm_spin_unlock(&session->shm_lock);
    LOG_DEBUG_INF("Succeed to unlock session %u shm lock", session->id);
    cm_spin_unlock(&g_wr_session_ctrl.lock);
}

wr_session_t *wr_get_session(uint32_t sid)
{
    if (sid >= g_wr_session_ctrl.alloc_sessions || sid >= g_wr_session_ctrl.total) {
        return NULL;
    }
    return g_wr_session_ctrl.sessions[sid];
}

static bool32 wr_is_timeout(int32_t timeout, int32_t sleep_times, int32_t sleeps)
{
    if ((timeout == SPIN_WAIT_FOREVER) || (sleeps == 0)) {
        return CM_FALSE;
    }

    /* ms --> us, and translate to times */
    return (bool32)(((timeout * 1000) / (sleeps)) < sleep_times);
}

status_t wr_lock_shm_meta_s_without_stack(
    wr_session_t *session, wr_shared_latch_t *shared_latch, bool32 is_force, int32_t timeout)
{
    cm_panic_log(wr_is_server(), "can not op shared latch without session latch stack in client");
    int32_t sleep_times = 0;
    latch_statis_t *stat = NULL;
    uint32_t count = 0;
    uint32_t sid = WR_SESSIONID_IN_LOCK(session->id);
    do {
        cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, (stat != NULL) ? &stat->s_spin : NULL);
        if (shared_latch->latch.stat == LATCH_STATUS_IDLE) {
            shared_latch->latch.stat = LATCH_STATUS_S;
            shared_latch->latch.shared_count = 1;
            shared_latch->latch.sid = (uint16)sid;
            shared_latch->latch_extent.shared_sid_count += sid;
            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_stat_inc(stat, count);
            return CM_SUCCESS;
        }
        if ((shared_latch->latch.stat == LATCH_STATUS_S) || (shared_latch->latch.stat == LATCH_STATUS_IX && is_force)) {
            shared_latch->latch.shared_count++;
            shared_latch->latch_extent.shared_sid_count += sid;
            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_stat_inc(stat, count);
            return CM_SUCCESS;
        }

        cm_spin_unlock(&shared_latch->latch.lock);
        if (stat != NULL) {
            stat->misses++;
        }
        while (shared_latch->latch.stat != LATCH_STATUS_IDLE && shared_latch->latch.stat != LATCH_STATUS_S) {
            count++;
            if (count < GS_SPIN_COUNT) {
                continue;
            }

            SPIN_STAT_INC(stat, s_sleeps);
            cm_usleep(SPIN_SLEEP_TIME);
            sleep_times++;

            if (wr_is_timeout(timeout, sleep_times, SPIN_SLEEP_TIME)) {
                return CM_ERROR;
            }
            count = 0;
        }
    } while (1);
    return CM_SUCCESS;
}

// only used by api-client
status_t wr_lock_shm_meta_s_with_stack(
    wr_session_t *session, wr_latch_offset_t *offset, wr_shared_latch_t *shared_latch, int32_t timeout)
{
    cm_panic_log(!(wr_is_server()), "can not op shared latch with session latch stack in server");
    WR_ASSERT_LOG(session != NULL, "session ptr is NULL");
    WR_ASSERT_LOG(session->latch_stack.stack_top < WR_MAX_LATCH_STACK_DEPTH, "latch_stack overflow");

    session->latch_stack.stack_top_bak = session->latch_stack.stack_top;
    session->latch_stack.op = LATCH_SHARED_OP_LATCH_S;
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top] = *offset;

    int32_t sleep_times = 0;
    latch_statis_t *stat = NULL;
    uint32_t count = 0;
    uint32_t sid = WR_SESSIONID_IN_LOCK(session->id);
    bool32 is_force = CM_FALSE;
    do {
        cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, (stat != NULL) ? &stat->s_spin : NULL);

        // for shared latch in shm, need to backup first
        wr_set_latch_extent(&shared_latch->latch_extent, shared_latch->latch.stat, shared_latch->latch.shared_count);

        if (shared_latch->latch.stat == LATCH_STATUS_IDLE) {
            session->latch_stack.op = LATCH_SHARED_OP_LATCH_S_BEG;

            shared_latch->latch.stat = LATCH_STATUS_S;
            shared_latch->latch.shared_count = 1;
            shared_latch->latch.sid = (uint16)sid;
            shared_latch->latch_extent.shared_sid_count += sid;

            // put this before the unlock to make sure: whn error happen, no one else can change the status of this
            // latch
            session->latch_stack.stack_top++;
            session->latch_stack.op = LATCH_SHARED_OP_LATCH_S_END;

            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_stat_inc(stat, count);
            return CM_SUCCESS;
        }
        if ((shared_latch->latch.stat == LATCH_STATUS_S) || (shared_latch->latch.stat == LATCH_STATUS_IX && is_force)) {
            session->latch_stack.op = LATCH_SHARED_OP_LATCH_S_BEG;

            shared_latch->latch.shared_count++;
            shared_latch->latch_extent.shared_sid_count += sid;

            // put this before the unlock to make sure: whn error happen, no one else can change the status of this
            // latch
            session->latch_stack.stack_top++;
            session->latch_stack.op = LATCH_SHARED_OP_LATCH_S_END;

            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_stat_inc(stat, count);
            return CM_SUCCESS;
        }

        cm_spin_unlock(&shared_latch->latch.lock);
        if (stat != NULL) {
            stat->misses++;
        }
        while (shared_latch->latch.stat != LATCH_STATUS_IDLE && shared_latch->latch.stat != LATCH_STATUS_S) {
            count++;
            if (count < GS_SPIN_COUNT) {
                continue;
            }

            SPIN_STAT_INC(stat, s_sleeps);
            cm_usleep(SPIN_SLEEP_TIME);
            sleep_times++;

            if (wr_is_timeout(timeout, sleep_times, SPIN_SLEEP_TIME)) {
                if (session != NULL) {
                    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top].type =
                        WR_LATCH_OFFSET_INVALID;
                    session->latch_stack.op = LATCH_SHARED_OP_NONE;
                }

                return CM_ERROR;
            }
            count = 0;
        }
    } while (1);
    return CM_SUCCESS;
}

status_t wr_lock_shm_meta_bucket_s(wr_session_t *session, uint32_t id, wr_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    if (wr_is_server()) {
        return wr_lock_shm_meta_s_without_stack(session, shared_latch, CM_FALSE, SPIN_WAIT_FOREVER);
    }
    wr_latch_offset_t latch_offset;
    latch_offset.type = WR_LATCH_OFFSET_SHMOFFSET;
    cm_shm_key_t key = ga_object_key(GA_SEGMENT_POOL, id);
    latch_offset.offset.shm_offset = cm_trans_shm_offset(key, &shared_latch->latch);
    return wr_lock_shm_meta_s_with_stack(session, &latch_offset, shared_latch, SPIN_WAIT_FOREVER);
}

status_t wr_cli_lock_shm_meta_s(
    wr_session_t *session, wr_latch_offset_t *offset, wr_shared_latch_t *shared_latch, latch_should_exit should_exit)
{
    for (int i = 0; i < WR_CLIENT_TIMEOUT_COUNT; i++) {
        if (session->is_closed) {
            WR_THROW_ERROR(ERR_WR_SHM_LOCK, "uds connection is closed.");
            LOG_RUN_ERR("[WR] ABORT INFO: Failed to lock vg share memery because uds connection is closed.");
            cm_fync_logfile();
            wr_exit_error();
        }
        if (wr_lock_shm_meta_s_with_stack(session, offset, shared_latch, SPIN_WAIT_FOREVER) == CM_SUCCESS) {
            return CM_SUCCESS;
        }

        if (should_exit && should_exit()) {
            LOG_RUN_ERR("Caller want to exit when waiting for shared_latch!!");
            return ERR_WR_LOCK_TIMEOUT;
        }
    }
    LOG_RUN_ERR("The client want to lock meta timeout.");
    return ERR_WR_LOCK_TIMEOUT;
}

void wr_lock_shm_meta_x(const wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(wr_is_server(), "can not op x latch in client");
    latch_statis_t *stat = NULL;
    uint32_t count = 0;
    uint32_t sid = WR_SESSIONID_IN_LOCK(session->id);

    do {
        cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, (stat != NULL) ? &stat->x_spin : NULL);
        if (shared_latch->latch.stat == LATCH_STATUS_IDLE) {
            shared_latch->latch.sid = (uint16)sid;
            shared_latch->latch.stat = LATCH_STATUS_X;
            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_stat_inc(stat, count);
            return;
        }
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IX;
            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_ix2x(&shared_latch->latch, sid, stat);
            return;
        }
        cm_spin_unlock(&shared_latch->latch.lock);
        if (stat != NULL) {
            stat->misses++;
        }
        while (shared_latch->latch.stat != LATCH_STATUS_IDLE && shared_latch->latch.stat != LATCH_STATUS_S) {
            count++;
            if (count >= GS_SPIN_COUNT) {
                SPIN_STAT_INC(stat, x_sleeps);
                cm_spin_sleep();
                count = 0;
            }
        }
    } while (CM_TRUE);
}

bool32 wr_lock_shm_meta_timed_x(const wr_session_t *session, wr_shared_latch_t *shared_latch, uint32_t wait_ticks)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(wr_is_server(), "can not op x latch in client");
    latch_statis_t *stat = NULL;
    uint32_t count = 0;
    uint32_t sid = WR_SESSIONID_IN_LOCK(session->id);
    uint32_t actual_ticks = 0;
    do {
        cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, (stat != NULL) ? &stat->x_spin : NULL);
        if (shared_latch->latch.stat == LATCH_STATUS_IDLE) {
            shared_latch->latch.sid = (uint16)sid;
            shared_latch->latch.stat = LATCH_STATUS_X;
            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_stat_inc(stat, count);
            return CM_TRUE;
        }
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IX;
            cm_spin_unlock(&shared_latch->latch.lock);
            if (!cm_latch_timed_ix2x(&shared_latch->latch, sid, wait_ticks, stat)) {
                cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, (stat != NULL) ? &stat->x_spin : NULL);
                shared_latch->latch.stat = shared_latch->latch.shared_count > 0 ? LATCH_STATUS_S : LATCH_STATUS_IDLE;
                cm_spin_unlock(&shared_latch->latch.lock);
                return CM_FALSE;
            }
            return CM_TRUE;
        }
        cm_spin_unlock(&shared_latch->latch.lock);
        if (stat != NULL) {
            stat->misses++;
        }
        while (shared_latch->latch.stat != LATCH_STATUS_IDLE && shared_latch->latch.stat != LATCH_STATUS_S) {
            if (actual_ticks >= wait_ticks) {
                return CM_FALSE;
            }
            count++;
            if (count >= GS_SPIN_COUNT) {
                SPIN_STAT_INC(stat, x_sleeps);
                cm_spin_sleep();
                count = 0;
                actual_ticks++;
            }
        }
    } while (CM_TRUE);
    return CM_FALSE;
}

void wr_lock_shm_meta_x2ix(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(wr_is_server(), "can not op x latch in client");
    CM_ASSERT(shared_latch->latch.stat == LATCH_STATUS_X);
    latch_statis_t *stat = NULL;
    uint32_t sid = WR_SESSIONID_IN_LOCK(session->id);
    wr_latch_x2ix(&shared_latch->latch, sid, stat);
}

void wr_lock_shm_meta_ix2x(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(wr_is_server(), "can not op x latch in client");
    CM_ASSERT(shared_latch->latch.stat == LATCH_STATUS_IX);
    latch_statis_t *stat = NULL;
    uint32_t sid = WR_SESSIONID_IN_LOCK(session->id);
    wr_latch_ix2x(&shared_latch->latch, sid, stat);
}

void wr_lock_shm_meta_degrade(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(wr_is_server(), "can not op x latch degradation in client.");
    uint32_t sid = (session == NULL) ? WR_DEFAULT_SESSIONID : WR_SESSIONID_IN_LOCK(session->id);
    cm_panic_log(sid == shared_latch->latch.sid && shared_latch->latch.stat == LATCH_STATUS_X,
        "Invalid degradation: sid:%u, sid on latch:%u, latch status:%u.", sid, shared_latch->latch.sid,
        shared_latch->latch.stat);
    cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, NULL);
    shared_latch->latch.stat = LATCH_STATUS_S;
    shared_latch->latch.shared_count = 1;
    shared_latch->latch_extent.shared_sid_count += sid;
    cm_spin_unlock(&shared_latch->latch.lock);
}

void wr_lock_shm_meta_bucket_x(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    wr_lock_shm_meta_x(session, shared_latch);
}

// only used by wrserver
void wr_unlock_shm_meta_without_stack(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(wr_is_server(), "can not op shared latch without session latch stack in client");
    CM_ASSERT(shared_latch->latch.stat != LATCH_STATUS_IDLE);

    spin_statis_t *stat_spin = NULL;
    uint32_t sid = WR_SESSIONID_IN_LOCK(session->id);
    cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, stat_spin);

    if (shared_latch->latch.stat == LATCH_STATUS_S || shared_latch->latch.stat == LATCH_STATUS_IX) {
        CM_ASSERT(shared_latch->latch.shared_count > 0);
        shared_latch->latch.shared_count--;
        if (shared_latch->latch.shared_count == 0) {
            if (shared_latch->latch.stat == LATCH_STATUS_S) {
                shared_latch->latch.stat = LATCH_STATUS_IDLE;
            }
            shared_latch->latch.sid = 0;
        }
        shared_latch->latch_extent.shared_sid_count -= sid;
    } else if (shared_latch->latch.stat == LATCH_STATUS_X) {
        CM_ASSERT(shared_latch->latch.shared_count == 0);
        shared_latch->latch.stat = LATCH_STATUS_IDLE;
        shared_latch->latch.sid = 0;
    }
    cm_spin_unlock(&shared_latch->latch.lock);
}

// only used by api-client or by clean
bool32 wr_unlock_shm_meta_s_with_stack(wr_session_t *session, wr_shared_latch_t *shared_latch, bool32 is_try_lock)
{
    CM_ASSERT(session != NULL);
    // can not call checkcm_paninc_log with wr_is_server
    CM_ASSERT(shared_latch->latch.stat != LATCH_STATUS_IDLE);
    session->latch_stack.stack_top_bak = session->latch_stack.stack_top;
    session->latch_stack.op = LATCH_SHARED_OP_UNLATCH;

    spin_statis_t *stat_spin = NULL;
    uint32_t sid = WR_SESSIONID_IN_LOCK(session->id);
    if (!is_try_lock) {
        cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, stat_spin);
    } else {
        bool32 is_locked = cm_spin_try_lock(&shared_latch->latch.lock);
        if (!is_locked) {
            return CM_FALSE;
        }
    }
    // for shared latch in shm, need to backup first
    wr_set_latch_extent(&shared_latch->latch_extent, shared_latch->latch.stat, shared_latch->latch.shared_count);

    // begin to change latch
    session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_BEG;

    CM_ASSERT(shared_latch->latch.shared_count > 0);
    shared_latch->latch.shared_count--;
    if (shared_latch->latch.shared_count == 0) {
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IDLE;
        }
        shared_latch->latch.sid = 0;
    }
    shared_latch->latch_extent.shared_sid_count -= sid;

    cm_spin_unlock(&shared_latch->latch.lock);

    // put this after the unlock to make sure:when error happen after unlock, do NOT op the unlatch-ed latch
    // begin to change stack
    CM_ASSERT(session->latch_stack.stack_top);
    // in the normal, should be stack_top-- first, then set [stack_top].typ = WR_LATCH_OFFSET_INVALID
    // but may NOT do [stack_top].typ = WR_LATCH_OFFSET_INVALID when some error happen,
    // so leave the stack_top-- on the second step
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top - 1].type = WR_LATCH_OFFSET_INVALID;
    session->latch_stack.stack_top--;
    session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_END;
    return CM_TRUE;
}

void wr_unlock_shm_meta_bucket(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    if (wr_is_server()) {
        wr_unlock_shm_meta_without_stack(session, shared_latch);
        return;
    } else {
        (void)wr_unlock_shm_meta_s_with_stack(session, shared_latch, CM_FALSE);
    }
}

static void wr_clean_latch_s_without_bak(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    LOG_DEBUG_INF("Clean sid:%u latch_stack old stack_top:%u.", WR_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top].type = WR_LATCH_OFFSET_INVALID;
    LOG_DEBUG_INF("Clean sid:%u latch_stack new stack_top:%u.", WR_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
}

static void wr_clean_latch_s_with_bak(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    LOG_DEBUG_INF("Clean sid:%u shared_latch old count:%hu, old stat:%u.", WR_SESSIONID_IN_LOCK(session->id),
        shared_latch->latch.shared_count, shared_latch->latch.stat);

    // do not care about the new value, just using the shared_count_bak
    shared_latch->latch.shared_count = shared_latch->latch_extent.shared_count_bak;
    shared_latch->latch.stat = shared_latch->latch_extent.stat_bak;
    shared_latch->latch_extent.shared_sid_count = shared_latch->latch_extent.shared_sid_count_bak;

    if (shared_latch->latch.shared_count == 0) {
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IDLE;
        }
        shared_latch->latch.sid = 0;
    }

    LOG_DEBUG_INF("Clean sid:%u latch_stack old stack_top:%u.", WR_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);

    LOG_DEBUG_INF("Clean sid:%u shared_latch new count:%hu, new stat:%u.", WR_SESSIONID_IN_LOCK(session->id),
        shared_latch->latch.shared_count, shared_latch->latch.stat);

    // not sure last latch finish, so using the stack_top_bak
    session->latch_stack.stack_top = session->latch_stack.stack_top_bak;
    // when latch first, and not finish, the stack_top may be zero
    if (session->latch_stack.stack_top > 0) {
        session->latch_stack.latch_offset_stack[session->latch_stack.stack_top - 1].type = WR_LATCH_OFFSET_INVALID;
        session->latch_stack.stack_top--;
    } else {
        session->latch_stack.latch_offset_stack[session->latch_stack.stack_top].type = WR_LATCH_OFFSET_INVALID;
    }
    LOG_DEBUG_INF("Clean sid:%u latch_stack new stack_top:%u.", WR_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
}

static void wr_clean_unlatch_without_bak(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    LOG_DEBUG_INF("Clean sid:%u unlatch shared_latch without bak, old count:%hu, old stat:%u.",
        WR_SESSIONID_IN_LOCK(session->id), shared_latch->latch.shared_count, shared_latch->latch.stat);

    CM_ASSERT(shared_latch->latch.shared_count > 0);
    shared_latch->latch.shared_count--;
    shared_latch->latch_extent.shared_sid_count -= WR_SESSIONID_IN_LOCK(session->id);

    if (shared_latch->latch.shared_count == 0) {
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IDLE;
        }
        shared_latch->latch.sid = 0;
    }

    LOG_DEBUG_INF("Clean sid:%u shared_latch new count:%hu, new stat:%u.", WR_SESSIONID_IN_LOCK(session->id),
        shared_latch->latch.shared_count, shared_latch->latch.stat);

    LOG_DEBUG_INF("Clean sid:%u latch_stack old stack_top:%u.", WR_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
    CM_ASSERT(session->latch_stack.stack_top > 0);
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top - 1].type = WR_LATCH_OFFSET_INVALID;
    session->latch_stack.stack_top--;
    LOG_DEBUG_INF("Clean sid:%u latch_stack new stack_top:%u.", WR_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
}

static void wr_clean_unlatch_with_bak(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    LOG_DEBUG_INF("Clean sid:%u unlatch shared_latch with bak, old count:%hu, old stat:%u.",
        WR_SESSIONID_IN_LOCK(session->id), shared_latch->latch.shared_count, shared_latch->latch.stat);
    // not sure last unlatch finsh, using the shared_count_bak first
    shared_latch->latch.shared_count = shared_latch->latch_extent.shared_count_bak;
    shared_latch->latch.stat = shared_latch->latch_extent.stat_bak;
    shared_latch->latch_extent.shared_sid_count = shared_latch->latch_extent.shared_sid_count_bak;

    CM_ASSERT(shared_latch->latch.shared_count > 0);
    shared_latch->latch.shared_count--;
    shared_latch->latch_extent.shared_sid_count -= WR_SESSIONID_IN_LOCK(session->id);

    if (shared_latch->latch.shared_count == 0) {
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IDLE;
        }
        shared_latch->latch.sid = 0;
    }
    LOG_DEBUG_INF("Clean sid:%u shared_latch new count:%hu, new stat:%u.", WR_SESSIONID_IN_LOCK(session->id),
        shared_latch->latch.shared_count, shared_latch->latch.stat);

    LOG_DEBUG_INF("Clean sid:%u latch_stack old stack_top:%u.", WR_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
    // not sure last unlatch finish, so using the stack_top_bak
    session->latch_stack.stack_top = session->latch_stack.stack_top_bak;
    CM_ASSERT(session->latch_stack.stack_top > 0);
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top - 1].type = WR_LATCH_OFFSET_INVALID;
    session->latch_stack.stack_top--;
    LOG_DEBUG_INF("Clean sid:%u latch_stack new stack_top:%u.", WR_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
}

static void wr_clean_last_op_with_lock(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    CM_ASSERT(WR_SESSIONID_IN_LOCK(session->id) == shared_latch->latch.lock);

    LOG_DEBUG_INF("Clean sid:%u last op with lock latch_stack op:%u, stack_top_bak:%hu.",
        WR_SESSIONID_IN_LOCK(session->id), session->latch_stack.op, session->latch_stack.stack_top_bak);

    LOG_DEBUG_INF("Clean sid:%u latch_extent stat_bak:%hu, shared_count_bak:%hu.", WR_SESSIONID_IN_LOCK(session->id),
        shared_latch->latch_extent.stat_bak, shared_latch->latch_extent.shared_count_bak);

    // step 1, try to clean
    // no backup, no change
    if (session->latch_stack.op == LATCH_SHARED_OP_LATCH_S) {
        wr_clean_latch_s_without_bak(session, shared_latch);
        // when latch with backup, undo the latch witch backup
    } else if (session->latch_stack.op == LATCH_SHARED_OP_LATCH_S_BEG ||
               session->latch_stack.op == LATCH_SHARED_OP_LATCH_S_END) {
        wr_clean_latch_s_with_bak(session, shared_latch);
        // when unlatch, no backup, no change, redo the unlatch without backup
    } else if (session->latch_stack.op == LATCH_SHARED_OP_UNLATCH) {
        wr_clean_unlatch_without_bak(session, shared_latch);
        // when unlatch not finish with backup, redo unlatch with backup
    } else if (session->latch_stack.op == LATCH_SHARED_OP_UNLATCH_BEG) {
        wr_clean_unlatch_with_bak(session, shared_latch);
    }

    session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_END;
    // step2
    cm_spin_unlock(&shared_latch->latch.lock);
}

static void wr_clean_last_op_without_lock(wr_session_t *session, wr_shared_latch_t *shared_latch)
{
    if (session->latch_stack.op == LATCH_SHARED_OP_NONE || session->latch_stack.op == LATCH_SHARED_OP_LATCH_S) {
        session->latch_stack.latch_offset_stack[session->latch_stack.stack_top].type = WR_LATCH_OFFSET_INVALID;
        session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_END;
        LOG_DEBUG_INF("Clean sid:%u reset to latch_stack op:%u, stack_top:%hu.", WR_SESSIONID_IN_LOCK(session->id),
            session->latch_stack.op, session->latch_stack.stack_top);
        // LATCH_SHARED_OP_UNLATCH_BEG and not in lock, means has finished to unlatch the latch,
        // but not finished to set lack_stack[stack_top].type
    } else if (session->latch_stack.op == LATCH_SHARED_OP_UNLATCH_BEG) {
        CM_ASSERT(session->latch_stack.stack_top > 0);
        session->latch_stack.latch_offset_stack[session->latch_stack.stack_top - 1].type = WR_LATCH_OFFSET_INVALID;
        session->latch_stack.stack_top--;
        session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_END;
        LOG_DEBUG_INF("Clean sid:%u reset to latch_stack op:%u, stack_top:%hu.", WR_SESSIONID_IN_LOCK(session->id),
            session->latch_stack.op, session->latch_stack.stack_top);
    }
}

static bool32 wr_clean_lock_for_shm_meta(wr_session_t *session, wr_shared_latch_t *shared_latch, bool32 is_daemon)
{
    LOG_DEBUG_INF("Clean sid:%u latch_stack op:%u, stack_top:%hu.", WR_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.op, session->latch_stack.stack_top);
    // last op between lock & unlock for this latch not finish
    if (WR_SESSIONID_IN_LOCK(session->id) == shared_latch->latch.lock) {
        wr_clean_last_op_with_lock(session, shared_latch);
        // if last op not happen, or latch not begin
    } else if (session->latch_stack.op == LATCH_SHARED_OP_NONE || session->latch_stack.op == LATCH_SHARED_OP_LATCH_S ||
               session->latch_stack.op == LATCH_SHARED_OP_UNLATCH_BEG) {
        wr_clean_last_op_without_lock(session, shared_latch);
        // otherwise unlatch the latch
    } else {
        // may exist other session lock but dead after last check the lsat->spin_lock, so if it's daemon, do lock with
        // try this
        if (is_daemon) {
            LOG_DEBUG_INF("Clean sid:%u latch_stack op:%u, stack_top:%hu wait next try.",
                WR_SESSIONID_IN_LOCK(session->id), session->latch_stack.op, session->latch_stack.stack_top);
            return wr_unlock_shm_meta_s_with_stack(session, shared_latch, CM_TRUE);
        }
        (void)wr_unlock_shm_meta_s_with_stack(session, shared_latch, CM_FALSE);
    }
    return CM_TRUE;
}

static bool32 wr_need_clean_session_latch(wr_session_t *session, uint64 cli_pid, int64 start_time)
{
    if (cli_pid == 0 || !session->is_used || !session->connected || cm_sys_process_alived(cli_pid, start_time)) {
        return CM_FALSE;
    }
    return CM_TRUE;
}

void wr_clean_session_latch(wr_session_t *session, bool32 is_daemon)
{
    int32_t i = 0;
    sh_mem_p offset;
    int32_t latch_place;
    wr_latch_offset_type_e offset_type;
    wr_shared_latch_t *shared_latch = NULL;
    if (!session->is_direct) {
        LOG_DEBUG_INF("Clean sid:%u is not direct.", WR_SESSIONID_IN_LOCK(session->id));
        return;
    }
    uint64 cli_pid = session->cli_info.cli_pid;
    int64 start_time = session->cli_info.start_time;
    if (is_daemon && !wr_need_clean_session_latch(session, cli_pid, start_time)) {
        LOG_RUN_INF("[CLEAN_LATCH]session id %u, pid %llu, start_time %lld, process name:%s need check next time.",
            session->id, cli_pid, start_time, session->cli_info.process_name);
        return;
    }
    LOG_RUN_INF("[CLEAN_LATCH]session id %u, pid %llu, start_time %lld, process name:%s in lock.", session->id, cli_pid,
        start_time, session->cli_info.process_name);
    LOG_DEBUG_INF("Clean sid:%u latch_stack op:%u, stack_top:%hu.", WR_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.op, session->latch_stack.stack_top);
    for (i = (int32_t)session->latch_stack.stack_top; i >= WR_MAX_LATCH_STACK_BOTTON; i--) {
        // the stack_top may NOT be moveed to the right place
        if (i == WR_MAX_LATCH_STACK_DEPTH) {
            latch_place = i - 1;
        } else {
            latch_place = i;
        }
        offset_type = session->latch_stack.latch_offset_stack[latch_place].type;
        // the stack_top may be the right invalid or latch not finish to set offset_type
        // or unlatch not over, just finish unlatch the latch, but not set offset_type
        if (offset_type != WR_LATCH_OFFSET_SHMOFFSET) {
            LOG_RUN_ERR("Clean sid:%u shared_latch offset type is invalid %u,latch_place:%d.",
                WR_SESSIONID_IN_LOCK(session->id), session->latch_stack.latch_offset_stack[latch_place].type,
                latch_place);
            if (session->latch_stack.op == LATCH_SHARED_OP_UNLATCH_BEG && i != (int32_t)session->latch_stack.stack_top) {
                session->latch_stack.stack_top = latch_place;
                session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_END;
            }
            LOG_DEBUG_INF("Clean sid:%u reset to latch_stack op:%u, stack_top:%hu.", WR_SESSIONID_IN_LOCK(session->id),
                session->latch_stack.op, session->latch_stack.stack_top);
            continue;
        } else {
            offset = session->latch_stack.latch_offset_stack[latch_place].offset.shm_offset;
            CM_ASSERT(offset != SHM_INVALID_ADDR);
            shared_latch = (wr_shared_latch_t *)OFFSET_TO_ADDR(offset);
            LOG_DEBUG_INF("Clean sid:%u shared_latch,latch_place:%d, offset:%llu.", WR_SESSIONID_IN_LOCK(session->id),
                latch_place, (uint64)offset);
        }
        // the lock is locked by this session in the dead-client,
        if (is_daemon && shared_latch->latch.lock != 0 &&
            WR_SESSIONID_IN_LOCK(session->id) != shared_latch->latch.lock) {
            LOG_DEBUG_INF("Clean sid:%u daemon wait next time to clean.", WR_SESSIONID_IN_LOCK(session->id));
            return;
        } else {
            bool32 is_clean = wr_clean_lock_for_shm_meta(session, shared_latch, is_daemon);
            if (!is_clean) {
                LOG_DEBUG_INF("Clean sid:%u daemon wait next time to clean.", WR_SESSIONID_IN_LOCK(session->id));
                return;
            }
        }
    }
    session->latch_stack.op = LATCH_SHARED_OP_NONE;
    session->latch_stack.stack_top = WR_MAX_LATCH_STACK_BOTTON;
}

void wr_server_session_lock(wr_session_t *session)
{
    // session->lock to contrl the concurrency of cleaning session latch thread
    cm_spin_lock(&session->lock, NULL);
    while (!cm_spin_timed_lock(&session->shm_lock, WR_SERVER_SESS_TIMEOUT)) {
        bool32 alived = cm_sys_process_alived(session->cli_info.cli_pid, session->cli_info.start_time);
        if (!alived) {
            // unlock if the client goes offline
            LOG_DEBUG_INF("Process:%s is not alive, pid:%llu, start_time:%lld.", session->cli_info.process_name,
                session->cli_info.cli_pid, session->cli_info.start_time);
            cm_spin_unlock(&session->shm_lock);
            LOG_DEBUG_INF("Succeed to unlock session %u shm lock", session->id);
            continue;
        }
        LOG_DEBUG_INF("Process:%s is alive, pid:%llu, start_time:%lld.", session->cli_info.process_name,
            session->cli_info.cli_pid, session->cli_info.start_time);
        cm_sleep(CM_SLEEP_500_FIXED);
    }
    LOG_DEBUG_INF("Succeed to lock session %u shm lock", session->id);
}

void wr_server_session_unlock(wr_session_t *session)
{
    cm_spin_unlock(&session->shm_lock);
    LOG_DEBUG_INF("Succeed to unlock session %u shm lock", session->id);
    cm_spin_unlock(&session->lock);
    LOG_DEBUG_INF("Succeed to unlock session %u lock", session->id);
}

void cm_spin_lock_init(spinlock_t *lock)
{
    CM_ASSERT(lock != NULL);
    *lock = 0;  // 初始化为未锁定状态
}

// 初始化hash管理器
status_t init_session_hash_mgr(wr_session_t *session)
{
    session_hash_mgr_t *mgr = &session->hash_mgr;
    mgr->hash_count = 0;
    mgr->hash_capacity = MAX_FILE_HASH_COUNT;
    mgr->hash_items = (file_hash_info_t *)malloc(
        sizeof(file_hash_info_t) * mgr->hash_capacity);
    
    if (mgr->hash_items == NULL) {
        return CM_ERROR;
    }
    
    cm_spin_lock_init(&mgr->lock);
    return CM_SUCCESS;
}

// Add or Update Hash Information
status_t update_file_hash(wr_session_t *session, uint32_t file_handle, const uint8_t *new_hash)
{
    session_hash_mgr_t *mgr = &session->hash_mgr;
    errno_t err = 0;

    if (new_hash == NULL) {
        LOG_RUN_ERR("[hash]: invalid param, failed to update file hash.");
    }
    
    cm_spin_lock(&mgr->lock, NULL);
    
    // Search Existing Records
    for (uint32_t i = 0; i < mgr->hash_count; i++) {
        if (mgr->hash_items[i].file_handle == file_handle) {
            err = memcpy_s(mgr->hash_items[i].prev_hash, SHA256_DIGEST_LENGTH, 
                            mgr->hash_items[i].curr_hash, SHA256_DIGEST_LENGTH);
            if (err != EOK) {
                LOG_RUN_ERR("[hash]: failed to update pre_hash, error code is %d.\n", err);
                return CM_ERROR;
            }
            
            err = memcpy_s(mgr->hash_items[i].curr_hash, SHA256_DIGEST_LENGTH,
                            new_hash, SHA256_DIGEST_LENGTH);
            if (err != EOK) {
                LOG_RUN_ERR("[hash]: failed to update curr_hash, error code is %d.\n", err);
                return CM_ERROR;
            }
            mgr->hash_items[i].last_update_time = cm_current_time();
            cm_spin_unlock(&mgr->lock);
            return CM_SUCCESS;
        }
    }
    
    // Add a new record
    if (mgr->hash_count >= mgr->hash_capacity) {
        cm_spin_unlock(&mgr->lock);
        return CM_ERROR;
    }
    
    file_hash_info_t *new_item = &mgr->hash_items[mgr->hash_count];
    new_item->file_handle = file_handle;
    err = memcpy_s(new_item->curr_hash, SHA256_DIGEST_LENGTH, 
                    new_hash, SHA256_DIGEST_LENGTH);
    if (err != EOK) {
        LOG_RUN_ERR("[hash]: failed to insert hash information, error code is %d.\n", err);
        return CM_ERROR;
    }
    err = memset_s(new_item->prev_hash, SHA256_DIGEST_LENGTH, 0, SHA256_DIGEST_LENGTH);
    if (err != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }
    new_item->last_update_time = cm_current_time();
    mgr->hash_count++;
    
    cm_spin_unlock(&mgr->lock);
    return CM_SUCCESS;
}

status_t get_file_hash(wr_session_t *session, uint32_t file_handle, uint8_t *curr_hash, uint8_t *prev_hash)
{
    session_hash_mgr_t *mgr = &session->hash_mgr;
    status_t status = CM_ERROR;
    errno_t err = 0;

    if (curr_hash == NULL || prev_hash == NULL) {
        LOG_RUN_ERR("[hash]: invalid param, failed to get hash");
        return CM_ERROR;
    }
    
    cm_spin_lock(&mgr->lock, NULL);
    
    for (uint32_t i = 0; i < mgr->hash_count; i++) {
        if (mgr->hash_items[i].file_handle == file_handle) {
            err = memcpy_s(curr_hash, SHA256_DIGEST_LENGTH,
                        mgr->hash_items[i].curr_hash, SHA256_DIGEST_LENGTH);
            if (err != EOK) {
                LOG_RUN_ERR("[hash]: failed to get curr_hash, error code is %d.\n", err);
                return CM_ERROR;
            }
            err = memcpy_s(prev_hash, SHA256_DIGEST_LENGTH,
                        mgr->hash_items[i].prev_hash, SHA256_DIGEST_LENGTH);
            if (err != EOK) {
                LOG_RUN_ERR("[hash]: failed to get prev_hash, error code is %d.\n", err);
                return CM_ERROR;
            }
            status = CM_SUCCESS;
            break;
        }
    }
    
    cm_spin_unlock(&mgr->lock);
    return status;
}

status_t generate_random_sha256(unsigned char *hash)
{
    if (hash == NULL) {
        LOG_RUN_ERR("invalid param, hash is NULL");
        return WR_ERROR;
    }

    if (RAND_bytes(hash, SHA256_DIGEST_LENGTH) != 1) {
        LOG_RUN_ERR("failed to generate sha256");
        return WR_ERROR;
    }

    return WR_SUCCESS;
}

#ifdef __cplusplus
}
#endif
