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
 * gr_instance.c
 *
 *
 * IDENTIFICATION
 *    src/service/gr_instance.c
 *
 * -------------------------------------------------------------------------
 */

// #include "gr_ga.h"
// #include "gr_shm.h"
#include "cm_timer.h"
#include "cm_error.h"
#include "cm_iofence.h"
#include "gr_errno.h"
#include "gr_defs.h"
#include "gr_api.h"
#include "gr_file.h"
#include "gr_malloc.h"
#include "gr_mes.h"
#include "gr_service.h"
#include "gr_instance.h"
#include "gr_reactor.h"
#include "gr_service.h"
#include "gr_zero.h"
#include "cm_utils.h"
#include "gr_thv.h"
#ifdef ENABLE_GRTEST
#include "gr_simulation_cm.h"
#endif
#include "gr_fault_injection.h"
#include "gr_nodes_list.h"

#define GR_MAINTAIN_ENV "GR_MAINTAIN"
gr_instance_t g_gr_instance;

static const char *const g_gr_lock_file = "gr.lck";


status_t gr_lock_instance(void)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    int iret_snprintf;

    iret_snprintf = snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s",
        g_gr_instance.inst_cfg.home, g_gr_lock_file);
    GR_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY, &g_gr_instance.lock_fd) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_lock_fd(g_gr_instance.lock_fd, SPIN_SLEEP_TIME) != CM_SUCCESS) {
        cm_close_file(g_gr_instance.lock_fd);
        g_gr_instance.lock_fd = CM_INVALID_INT32;
        return CM_ERROR;
    }

    return CM_SUCCESS;
}


static status_t gr_init_thread(gr_instance_t *inst)
{
    uint32_t size = gr_get_uwression_startid();
    inst->threads = (thread_t *)cm_malloc(size * (uint32_t)sizeof(thread_t));
    if (inst->threads == NULL) {
        return CM_ERROR;
    }
    errno_t errcode =
        memset_s(inst->threads, (size * (uint32_t)sizeof(thread_t)), 0x00, (size * (uint32_t)sizeof(thread_t)));
    securec_check_ret(errcode);
    return CM_SUCCESS;
}

static status_t gr_init_inst_handle_session(gr_instance_t *inst)
{
    status_t status = gr_create_session(NULL, &inst->handle_session);
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("GR instance init create handle session fail!"));
    return CM_SUCCESS;
}

status_t gr_init_certification(gr_instance_t *inst)
{
    return ser_init_ssl(inst->lsnr.socks[0]);
}

static status_t instance_init_core(gr_instance_t *inst)
{
    status_t status = gr_init_session_pool(gr_get_max_total_session_cnt());
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_SESSION_CREATE, "GR instance failed to initialize sessions."));
    status = gr_init_thread(inst);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_SESSION_CREATE, "GR instance failed to initialize thread."));
    status = gr_startup_mes();
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_SESSION_CREATE, "GR instance failed to startup mes"));
    status = gr_create_reactors();
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("GR instance failed to start reactors!"));
    status = gr_start_lsnr(inst);
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("GR instance failed to start lsnr!"));
    status = gr_init_certification(inst);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_SESSION_CREATE, "GR instance failed to startup certification"));
    status = gr_init_inst_handle_session(inst);
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("GR instance int handle session!"));
    return CM_SUCCESS;
}

static void gr_init_maintain(gr_instance_t *inst, gr_srv_args_t gr_args)
{
    if (gr_args.is_maintain) {
        inst->is_maintain = true;
    } else {
        char *maintain_env = getenv(GR_MAINTAIN_ENV);
        inst->is_maintain = (maintain_env != NULL && cm_strcmpi(maintain_env, "TRUE") == 0);
    }

    if (inst->is_maintain) {
        LOG_RUN_INF("GR_MAINTAIN is TRUE");
    } else {
        LOG_RUN_INF("GR_MAINTAIN is FALSE");
    }
}

static status_t instance_init(gr_instance_t *inst)
{
    status_t status = gr_lock_instance();
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("Another grinstance is running"));
    status = instance_init_core(inst);
    if (status != CM_SUCCESS) {
        for (uint32_t i = 0; i < g_gr_session_ctrl.alloc_sessions; i++) {
            if (g_gr_session_ctrl.sessions[i] != NULL) {
                CM_FREE_PTR(g_gr_session_ctrl.sessions[i]);
            }
        }
        CM_FREE_PTR(g_gr_session_ctrl.sessions);
        return CM_ERROR;
    }
    LOG_RUN_INF("GR instance begin to run.");
    return CM_SUCCESS;
}

static void gr_init_cluster_proto_ver(gr_instance_t *inst)
{
    for (uint32_t i = 0; i < GR_MAX_INSTANCES; i++) {
        inst->cluster_proto_vers[i] = GR_INVALID_VERSION;
    }
}

gr_instance_status_e gr_get_instance_status(void)
{
    return g_gr_instance.status;
}

static status_t gr_save_process_pid(gr_config_t *inst_cfg)
{
#ifndef WIN32
    char file_name[CM_FILE_NAME_BUFFER_SIZE] = {0};
    char dir_name[CM_FILE_NAME_BUFFER_SIZE] = {0};
    PRTS_RETURN_IFERR(
        snprintf_s(dir_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/process", inst_cfg->home));
    if (!cm_dir_exist(dir_name)) {
        GR_RETURN_IF_ERROR(cm_create_dir(dir_name));
    }
    PRTS_RETURN_IFERR(snprintf_s(
        file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s", dir_name, "gr.process"));
    pid_t pid = getpid();
    if (strlen(file_name) == 0) {
        LOG_RUN_ERR("grserver process path not existed");
        return CM_ERROR;
    }
    FILE *fp;
    CM_RETURN_IFERR(cm_fopen(file_name, "w+", S_IRUSR | S_IWUSR, &fp));
    (void)cm_truncate_file(fp->_fileno, 0);
    (void)cm_seek_file(fp->_fileno, 0, SEEK_SET);
    int32_t size = fprintf(fp, "%d", pid);
    (void)fflush(stdout);
    if (size < 0) {
        LOG_RUN_ERR("write grserver process failed, write size is %d.", size);
        (void)fclose(fp);
        return CM_ERROR;
    }
    (void)fclose(fp);
#endif
    return CM_SUCCESS;
}

status_t gr_startup(gr_instance_t *inst, gr_srv_args_t gr_args)
{
    status_t status;
    errno_t errcode = memset_s(inst, sizeof(gr_instance_t), 0, sizeof(gr_instance_t));
    securec_check_ret(errcode);

    status = gr_init_zero_buf();
    GR_RETURN_IFERR2(status, GR_PRINT_RUN_ERROR("gr init zero buf fail.\n"));

    gr_init_cluster_proto_ver(inst);
    inst->lock_fd = CM_INVALID_INT32;
    gr_set_server_flag();
    regist_get_instance_status_proc(gr_get_instance_status);
    status = gr_set_cfg_dir(gr_args.gr_home, &inst->inst_cfg);
    GR_RETURN_IFERR2(status, GR_PRINT_RUN_ERROR("Environment variant GR_HOME not found!\n"));
    status = cm_start_timer(g_timer());
    GR_RETURN_IFERR2(status, GR_PRINT_RUN_ERROR("Aborted due to starting timer thread.\n"));
    status = gr_load_config(&inst->inst_cfg);
    GR_RETURN_IFERR2(status, GR_PRINT_RUN_ERROR("Failed to load parameters!\n"));
    status = gr_load_ser_ssl_config(&inst->inst_cfg);
    GR_RETURN_IFERR2(status, GR_PRINT_RUN_ERROR("Failed to load server parameters!\n"));
    status = gr_save_process_pid(&inst->inst_cfg);
    GR_RETURN_IFERR2(status, GR_PRINT_RUN_ERROR("Save grserver pid failed!\n"));
    gr_init_maintain(inst, gr_args);
    LOG_RUN_INF("GR instance begin to initialize.");

    status = instance_init(inst);
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("GR instance failed to initialized!"));
    // cm_set_shm_ctrl_flag(CM_SHM_CTRL_FLAG_TRUE);
    inst->abort_status = CM_FALSE;
    return CM_SUCCESS;
}

static status_t gr_handshake_core(gr_session_t *session)
{
    gr_init_packet(&session->recv_pack, CM_FALSE);
    gr_init_packet(&session->send_pack, CM_FALSE);
    session->pipe.socket_timeout = (int32_t)CM_NETWORK_IO_TIMEOUT;
    status_t status = gr_process_handshake_cmd(session, GR_CMD_HANDSHAKE);
    return status;
}

static status_t gr_handshake(gr_session_t *session)
{
    LOG_RUN_INF("[GR_CONNECT]session %u begin check protocal type.", session->id);
    /* fetch protocol type */
    status_t status = gr_diag_proto_type(session);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[GR_CONNECT]Failed to get protocol type!");
        return CM_ERROR;
    }
    status = gr_handshake_core(session);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[GR_CONNECT]Failed to process get server info!");
        return CM_ERROR;
    }
    return status;
}

static status_t gr_certificate(gr_session_t *session)
{
    session->pipe.type = CS_TYPE_SSL;
    return ser_cert_accept(&session->pipe);
}

static status_t gr_lsnr_proc(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    gr_session_t *session = NULL;
    status_t status;
    status = gr_create_session(pipe, &session);
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("[GR_CONNECT] create session failed.\n"));
    // process_handshake
    status = gr_handshake(session);
    GR_RETURN_IFERR3(status, LOG_RUN_ERR("[GR_CONNECT] handshake failed.\n"), gr_destroy_session(session));
    status = gr_certificate(session);
    GR_RETURN_IFERR3(status, LOG_RUN_ERR("[GR_CONNECT] SSL certificate failed."), gr_destroy_session(session));
    LOG_RUN_INF("[GR_CONNECT]The certification between client and server has finished.");
    status = gr_reactors_add_session(session);
    GR_RETURN_IFERR3(status,
        LOG_RUN_ERR("[GR_CONNECT]Session:%u socket:%u closed.", session->id, pipe->link.tcp.sock),
        gr_destroy_session(session));
    LOG_RUN_INF("[GR_CONNECT]The client has connected, session %u.", session->id);
    return CM_SUCCESS;
}

status_t gr_start_lsnr(gr_instance_t *inst)
{
    GR_RETURN_IFERR2(strncpy_s(inst->lsnr.host[0], 
                               GR_MAX_PATH_BUFFER_SIZE,
                               g_inst_cfg->params.listen_addr.host,
                               GR_MAX_PATH_BUFFER_SIZE),
                     LOG_RUN_ERR("gr_start_lsnr strncpy_s failed"));
    inst->lsnr.host[1][0] = '\0';
    inst->lsnr.port = g_inst_cfg->params.listen_addr.port;
    return cs_start_tcp_lsnr(&inst->lsnr, gr_lsnr_proc);
}

status_t gr_init_cm(gr_instance_t *inst)
{
    inst->cm_res.is_valid = CM_FALSE;
    inst->inst_work_status_map = 0;
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    char *value = cm_get_config_value(&inst_cfg->config, "GR_CM_SO_NAME");
    if (value == NULL || strlen(value) == 0) {
        LOG_RUN_INF("gr cm config of GR_CM_SO_NAME is empty.");
        return CM_SUCCESS;
    }

    if (strlen(value) >= GR_MAX_NAME_LEN) {
        LOG_RUN_ERR("gr cm config of GR_CM_SO_NAME is exceeds the max len %u.", GR_MAX_NAME_LEN - 1);
        return CM_ERROR;
    }
#ifdef ENABLE_GRTEST
    GR_RETURN_IF_ERROR(gr_simulation_cm_res_mgr_init(value, &inst->cm_res.mgr, NULL));
#else
    GR_RETURN_IF_ERROR(cm_res_mgr_init(value, &inst->cm_res.mgr, NULL));
#endif
    status_t status =
        (status_t)cm_res_init(&inst->cm_res.mgr, (unsigned int)inst->inst_cfg.params.inst_id, GR_CMS_RES_TYPE, NULL);
#ifdef ENABLE_GRTEST
    GR_RETURN_IFERR2(status, gr_simulation_cm_res_mgr_uninit(&inst->cm_res.mgr));
#else
    GR_RETURN_IFERR2(status, cm_res_mgr_uninit(&inst->cm_res.mgr));
#endif
    inst->cm_res.is_valid = CM_TRUE;
    return CM_SUCCESS;
}

void gr_uninit_cm(gr_instance_t *inst)
{
    if (inst->cm_res.is_valid) {
#ifdef ENABLE_GRTEST
        gr_simulation_cm_res_mgr_uninit(&inst->cm_res.mgr);
#else
        cm_res_mgr_uninit(&inst->cm_res.mgr);
#endif
        inst->cm_res.is_valid = CM_FALSE;
    }
}

void gr_free_log_ctrl()
{
}

void gr_check_peer_by_inst(gr_instance_t *inst, uint64 inst_id)
{
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    // Can't be myself
    if (inst_id == (uint64)inst_cfg->params.inst_id) {
        return;
    }

    // Not cfg the inst
    uint64 inst_mask = ((uint64)0x1 << inst_id);
    if ((inst_cfg->params.nodes_list.inst_map & inst_mask) == 0) {
        return;
    }

    uint64 cur_inst_map = gr_get_inst_work_status();
    // Has connection
    if ((cur_inst_map & inst_mask) != 0) {
        return;
    }

    gr_check_peer_inst(inst, inst_id);
}

static void gr_check_peer_by_cm(gr_instance_t *inst)
{
    cm_res_mem_ctx_t res_mem_ctx;
    if (cm_res_init_memctx(&res_mem_ctx) != CM_SUCCESS) {
        return;
    }
    cm_res_stat_ptr_t res = cm_res_get_stat(&inst->cm_res.mgr, &res_mem_ctx);
    if (res == NULL) {
        cm_res_uninit_memctx(&res_mem_ctx);
        return;
    }
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    uint64 cur_inst_map = 0;
    uint32_t instance_count = 0;
    if (cm_res_get_instance_count(&instance_count, &inst->cm_res.mgr, res) != CM_SUCCESS) {
        cm_res_free_stat(&inst->cm_res.mgr, res);
        cm_res_uninit_memctx(&res_mem_ctx);
        return;
    }
    for (uint32_t idx = 0; idx < instance_count; idx++) {
        const cm_res_inst_info_ptr_t inst_res = cm_res_get_instance_info(&inst->cm_res.mgr, res, idx);
        if (inst_res == NULL) {
            cm_res_free_stat(&inst->cm_res.mgr, res);
            cm_res_uninit_memctx(&res_mem_ctx);
            return;
        }

        int res_instance_id = cm_res_get_inst_instance_id(&inst->cm_res.mgr, inst_res);
        int is_work_member = cm_res_get_inst_is_work_member(&inst->cm_res.mgr, inst_res);
        if (is_work_member == 0) {
            LOG_RUN_INF("gr instance [%d] is not work member. May be kicked off by cm.", res_instance_id);
            continue;
        }

        uint64_t inst_mask = ((uint64)0x1 << res_instance_id);
        if ((inst_cfg->params.nodes_list.inst_map & inst_mask) == 0) {
            LOG_RUN_INF("gr instance [%d] is not in mes nodes cfg lists.", res_instance_id);
            continue;
        }

        int stat = cm_res_get_inst_stat(&inst->cm_res.mgr, inst_res);
        if (stat != CM_RES_STATUS_ONLINE) {
            LOG_RUN_INF("gr instance [%d] work stat [%d] not online.", res_instance_id, stat);
        }
        cur_inst_map |= ((uint64)0x1 << res_instance_id);
    }

    gr_check_mes_conn(cur_inst_map);
    cm_res_free_stat(&inst->cm_res.mgr, res);
    cm_res_uninit_memctx(&res_mem_ctx);
}

#ifdef ENABLE_GRTEST
static void gr_check_peer_by_simulation_cm(gr_instance_t *inst)
{
    if (g_simulation_cm.simulation) {
        char *bitmap_online = inst->cm_res.mgr.cm_get_res_stat();
        uint64 cur_inst_map = 0;
        (void)cm_str2bigint(bitmap_online, (int64 *)&cur_inst_map);
        gr_check_mes_conn(cur_inst_map);
        return;
    }
    gr_check_peer_by_cm(inst);
    return;
}
#endif

static void gr_check_peer_default()
{
    gr_check_mes_conn(GR_INVALID_ID64);
}

void gr_init_cm_res(gr_instance_t *inst)
{
    gr_cm_res *cm_res = &inst->cm_res;
    cm_spin_lock(&cm_res->init_lock, NULL);
    if (cm_res->is_init) {
        cm_spin_unlock(&cm_res->init_lock);
        return;
    }
    status_t status = gr_init_cm(inst);
    if (status == CM_SUCCESS) {
        cm_res->is_init = CM_TRUE;
    }
    cm_spin_unlock(&cm_res->init_lock);
    return;
}

#ifdef ENABLE_GRTEST
status_t gr_get_cm_res_lock_owner(gr_cm_res *cm_res, uint32_t *master_id)
{
    if (g_simulation_cm.simulation) {
        int ret = cm_res_get_lock_owner(&cm_res->mgr, GR_CM_LOCK, master_id);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    } else {
        gr_config_t *inst_cfg = gr_get_inst_cfg();
        for (int i = 0; i < GR_MAX_INSTANCES; i++) {
            if (inst_cfg->params.nodes_list.ports[i] != 0) {
                *master_id = i;
                LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "Set min id %u as master id.", i);
                break;
            }
        }
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "master_id is %u when get cm lock.", *master_id);
    }
    return CM_SUCCESS;
}
#else
status_t gr_get_cm_res_lock_owner(gr_cm_res *cm_res, uint32_t *master_id)
{
    int ret = cm_res_get_lock_owner(&cm_res->mgr, GR_CM_LOCK, master_id);
    if (ret == CM_RES_TIMEOUT) {
        LOG_RUN_ERR("Try to get lock owner failed, cm error : %d.", ret);
        return CM_ERROR;
    } else if (ret == CM_RES_SUCCESS) {
        return CM_SUCCESS;
    } else {
        *master_id = CM_INVALID_ID32;
        LOG_RUN_ERR("Try to get lock owner failed, cm error : %d.", ret);
    }
    return CM_SUCCESS;
}
#endif
// get cm lock owner, if no owner, try to become.master_id can not be GR_INVALID_ID32.
status_t gr_get_cm_lock_owner(gr_instance_t *inst, bool32 *grab_lock, bool32 try_lock, uint32_t *master_id)
{
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    *master_id = GR_INVALID_ID32;
    if (inst->is_maintain || inst->inst_cfg.params.nodes_list.inst_cnt <= 1) {
        *grab_lock = CM_TRUE;
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5,
            "[RECOVERY]Set curr_id %u to be primary when grserver is maintain or just one inst.",
            (uint32_t)inst_cfg->params.inst_id);
        *master_id = (uint32_t)inst_cfg->params.inst_id;
        return CM_SUCCESS;
    }
    gr_cm_res *cm_res = &inst->cm_res;
    if (!cm_res->is_init) {
        return CM_SUCCESS;
    }
    status_t ret = gr_get_cm_res_lock_owner(cm_res, master_id);
    GR_RETURN_IFERR2(ret, LOG_RUN_WAR("Failed to get cm lock owner, if GR is normal open ignore the log."));
    if (*master_id == GR_INVALID_ID32) {
        if (!try_lock) {
            return CM_ERROR;
        }
        if (inst->no_grab_lock) {
            LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "[RECOVERY]No need to grab lock when inst %u is set no grab lock.",
                (uint32_t)inst_cfg->params.inst_id);
            gr_set_master_id(GR_INVALID_ID32);
            return CM_ERROR;
        }
        ret = cm_res_lock(&cm_res->mgr, GR_CM_LOCK);
        *grab_lock = ((int)ret == CM_RES_SUCCESS);
        if (*grab_lock) {
            *master_id = (uint32_t)inst->inst_cfg.params.inst_id;
            LOG_RUN_INF("[RECOVERY]inst id %u succeed to get lock owner.", *master_id);
            return CM_SUCCESS;
        }
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void gr_recovery_when_primary(gr_session_t *session, gr_instance_t *inst, uint32_t curr_id, bool32 grab_lock)
{
    bool32 first_start = CM_FALSE;
    if (!grab_lock) {
        first_start = (inst->status == GR_STATUS_PREPARE);
    }
    if (first_start) {
        LOG_RUN_INF("[RECOVERY]inst %u is old main inst to do recovery.", curr_id);
    } else {
        LOG_RUN_INF("[RECOVERY]master_id is %u when get cm lock to do recovery.", curr_id);
    }

    gr_instance_status_e old_status = inst->status;
    inst->status = GR_STATUS_RECOVERY;
    CM_MFENCE;

    if (old_status == GR_STATUS_OPEN && !first_start) {
        gr_wait_session_pause(inst);
    }
    gr_wait_background_pause(inst);

    if (!first_start) {
        gr_set_session_running(inst, session->id);
    }

    // when current node is standby, and will change to primary, the status is from GR_STATUS_OPEN to
    // GR_STATUS_RECOVERY, need to set the master id after the status finish
    gr_set_master_id(curr_id);
    gr_set_server_status_flag(GR_STATUS_READWRITE);
    LOG_RUN_INF("[RECOVERY]inst %u set status flag %u when get cm lock.", curr_id, GR_STATUS_READWRITE);
    // when primary, no need to check result
    g_gr_instance.is_join_cluster = CM_TRUE;
    inst->status = GR_STATUS_OPEN;
}

void gr_recovery_when_standby(gr_session_t *session, gr_instance_t *inst, uint32_t curr_id, uint32_t master_id)
{
    uint32_t old_master_id = gr_get_master_id();
    int32_t old_status = gr_get_server_status_flag();
    if (old_master_id != master_id) {
        gr_set_master_id(master_id);
        gr_set_server_status_flag(GR_STATUS_READONLY);
        LOG_RUN_INF("[RECOVERY]inst %u set status flag %u when not get cm lock.", curr_id, GR_STATUS_READONLY);
    }
    if (!gr_check_join_cluster()) {
        gr_set_master_id(old_master_id);
        gr_set_server_status_flag(old_status);
        LOG_RUN_INF("[RECOVERY]inst %u reset status flag %d and master_id %u when join failed.", curr_id, old_status,
            old_master_id);
        return;
    }
    inst->status = GR_STATUS_OPEN;
}
/*
    1、old_master_id == master_id, just return;
    2、old_master_id != master_id, just indicates that the master has been reselected.so to judge whether recover.
*/
void gr_get_cm_lock_and_recover_inner(gr_session_t *session, gr_instance_t *inst)
{
    cm_latch_x(&g_gr_instance.switch_latch, GR_DEFAULT_SESSIONID, LATCH_STAT(LATCH_SWITCH));
    uint32_t old_master_id = gr_get_master_id();
    bool32 grab_lock = CM_FALSE;
    uint32_t master_id = GR_INVALID_ID32;
    status_t status = gr_get_cm_lock_owner(inst, &grab_lock, CM_TRUE, &master_id);
    if (status != CM_SUCCESS) {
        cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        return;
    }
    if (master_id == GR_INVALID_ID32) {
        LOG_RUN_WAR("[RECOVERY]cm is not init, just try again.");
        cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        return;
    }
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    uint32_t curr_id = (uint32_t)inst_cfg->params.inst_id;
    // master no change
    if (old_master_id == master_id) {
        // primary, no need check
        if (master_id == curr_id) {
            cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            return;
        }
        if (inst->is_join_cluster) {
            cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            return;
        }
    }
    // standby is started or masterid has been changed
    if (master_id != curr_id) {
        gr_recovery_when_standby(session, inst, curr_id, master_id);
        cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        return;
    }
    /*1、grab lock success 2、set main,other switch lock 3、restart, lock no transfer*/
    gr_set_recover_thread_id(gr_get_current_thread_id());
    gr_recovery_when_primary(session, inst, curr_id, grab_lock);
    gr_set_recover_thread_id(0);
    cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
}

#define GR_RECOVER_INTERVAL 500
#define GR_SHORT_RECOVER_INTERVAL 100
void gr_get_cm_lock_and_recover(thread_t *thread)
{
    cm_set_thread_name("recovery");
    uint32_t work_idx = gr_get_recover_task_idx();
    gr_session_t *session = gr_get_reserv_session(work_idx);
    gr_instance_t *inst = (gr_instance_t *)thread->argument;
    while (!thread->closed) {
        gr_get_cm_lock_and_recover_inner(session, inst);
        if (inst->status == GR_STATUS_PREPARE) {
            LOG_RUN_WAR("[RECOVERY]Try to sleep when in prepare status.\n");
            cm_sleep(GR_SHORT_RECOVER_INTERVAL);
        } else {
            cm_sleep(GR_RECOVER_INTERVAL);
        }
    }
}

void gr_delay_clean_proc(thread_t *thread)
{
    cm_set_thread_name("delay_clean");
    uint32_t work_idx = gr_get_delay_clean_task_idx();
    gr_session_ctrl_t *session_ctrl = gr_get_session_ctrl();
    gr_session_t *session = session_ctrl->sessions[work_idx];
    LOG_RUN_INF("Session[id=%u] is available for delay clean task.", session->id);
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    uint32_t sleep_times = 0;
    while (!thread->closed) {
        if (sleep_times < inst_cfg->params.delay_clean_interval) {
            cm_sleep(CM_SLEEP_1000_FIXED);
            sleep_times++;
            continue;
        }
        g_gr_instance.is_cleaning = CM_TRUE;
        // GR_STATUS_OPEN for control with switchover
        if (gr_need_exec_local() && gr_is_readwrite() && (g_gr_instance.status == GR_STATUS_OPEN)) {
            //gr_delay_clean_all_vg(session);
        }
        g_gr_instance.is_cleaning = CM_FALSE;
        sleep_times = 0;
    }
}

void gr_alarm_check_proc(thread_t *thread)
{
    cm_set_thread_name("alarm_check");
    uint32 sleep_times = 0;
    // for check other alarms
    uint32 alarm_counts = GR_VG_ALARM_CHECK_COUNT;
    while (!thread->closed) {
        // only master node need alarm
        if (sleep_times % GR_VG_ALARM_CHECK_COUNT == 0) {
            g_gr_instance.is_checking = CM_TRUE;
            gr_alarm_check_disk_usage();
            g_gr_instance.is_checking = CM_FALSE;
        }
        cm_sleep(CM_SLEEP_500_FIXED);
        sleep_times++;
        sleep_times = sleep_times % alarm_counts;
    }
}

static void gr_check_peer_inst_inner(gr_instance_t *inst)
{
    /**
     * During installation initialization, db_init depends on the GR server. However, the CMS is not started.
     * Therefore, cm_init cannot be invoked during the GR server startup.
     * Here, cm_init is invoked before the CM interface is invoked at first time.
     */
    if (SECUREC_UNLIKELY(!inst->cm_res.is_init)) {
        gr_init_cm_res(inst);
    }
    if (inst->cm_res.is_valid) {
#ifdef ENABLE_GRTEST
        gr_check_peer_by_simulation_cm(inst);
#else
        gr_check_peer_by_cm(inst);
#endif
        return;
    }
    gr_check_peer_default();
}

void gr_check_peer_inst(gr_instance_t *inst, uint64 inst_id)
{
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    if (inst_cfg->params.nodes_list.inst_cnt <= 1) {
        return;
    }

    uint64 inst_mask = ((uint64)0x1 << inst_id);
    cm_spin_lock(&inst->inst_work_lock, NULL);

    // after lock, check again, other thd may get the lock, and init the map before
    uint64 cur_inst_map = gr_get_inst_work_status();
    // has connection
    if (inst_id != GR_INVALID_ID64 && (cur_inst_map & inst_mask) != 0) {
        cm_spin_unlock(&inst->inst_work_lock);
        return;
    }

    gr_check_peer_inst_inner(inst);
    cm_spin_unlock(&inst->inst_work_lock);
}

uint64 gr_get_inst_work_status(void)
{
    return (uint64)cm_atomic_get((atomic_t *)&g_gr_instance.inst_work_status_map);
}

void gr_set_inst_work_status(uint64 cur_inst_map)
{
    (void)cm_atomic_set((atomic_t *)&g_gr_instance.inst_work_status_map, (int64)cur_inst_map);
}

bool32 gr_check_join_cluster()
{
    if (g_gr_instance.is_join_cluster) {
        return CM_TRUE;
    }

    if (gr_get_master_id() == g_gr_instance.inst_cfg.params.inst_id) {
        g_gr_instance.is_join_cluster = CM_TRUE;
        LOG_RUN_INF("Join cluster success by primary.");
    } else {
        // try register to new master to join
        bool32 join_succ = CM_FALSE;
        status_t status = gr_join_cluster(&join_succ);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Join cluster fail, wait next try.");
            cm_reset_error();
            return CM_FALSE;
        }
        LOG_DEBUG_INF("Join cluster result [%u].", (uint32_t)join_succ);
        if (!join_succ) {
            return CM_FALSE;
        }
        g_gr_instance.is_join_cluster = CM_TRUE;
        LOG_RUN_INF("Join cluster success by standby.");
    }

    return CM_TRUE;
}