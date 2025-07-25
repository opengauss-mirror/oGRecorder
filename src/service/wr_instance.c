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
 * wr_instance.c
 *
 *
 * IDENTIFICATION
 *    src/service/wr_instance.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_ga.h"
#include "wr_shm.h"
#include "cm_timer.h"
#include "cm_error.h"
#include "cm_iofence.h"
#include "wr_errno.h"
#include "wr_defs.h"
#include "wr_api.h"
#include "wr_file.h"
#include "wr_malloc.h"
#include "wr_mes.h"
#include "wr_service.h"
#include "wr_instance.h"
#include "wr_reactor.h"
#include "wr_service.h"
#include "wr_zero.h"
#include "cm_utils.h"
#include "wr_thv.h"
#ifdef ENABLE_WRTEST
#include "wr_simulation_cm.h"
#endif
#include "wr_fault_injection.h"
#include "wr_nodes_list.h"

#define WR_MAINTAIN_ENV "WR_MAINTAIN"
wr_instance_t g_wr_instance;

static const char *const g_wr_lock_file = "wr.lck";

static void instance_set_pool_def(ga_pool_id_e pool_id, uint32_t obj_count, uint32_t obj_size, uint32_t ex_max)
{
    ga_pool_def_t pool_def;

    CM_ASSERT(ex_max <= ((uint32_t)GA_MAX_EXTENDED_POOLS));
    pool_def.object_count = obj_count;
    pool_def.object_size = obj_size;
    pool_def.ex_max = ex_max;

    ga_set_pool_def(pool_id, &pool_def);
}

status_t wr_lock_instance(void)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    int iret_snprintf;

    iret_snprintf = snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s",
        g_wr_instance.inst_cfg.home, g_wr_lock_file);
    WR_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY, &g_wr_instance.lock_fd) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_lock_fd(g_wr_instance.lock_fd, SPIN_SLEEP_TIME) != CM_SUCCESS) {
        cm_close_file(g_wr_instance.lock_fd);
        g_wr_instance.lock_fd = CM_INVALID_INT32;
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t instance_init_ga(wr_instance_t *inst)
{
    int32_t ret;
    ga_destroy_global_area();
    instance_set_pool_def(GA_INSTANCE_POOL, 1, sizeof(wr_share_vg_item_t), WR_MAX_VOLUME_GROUP_NUM - 1);
    instance_set_pool_def(
        GA_SESSION_POOL, WR_SESSION_NUM_PER_GROUP, sizeof(wr_session_t), GA_MAX_SESSION_EXTENDED_POOLS);
    instance_set_pool_def(GA_8K_POOL, WR_MAX_MEM_BLOCK_SIZE / (WR_BLOCK_SIZE + WR_BLOCK_CTRL_SIZE),
        WR_BLOCK_SIZE + WR_BLOCK_CTRL_SIZE, GA_MAX_8K_EXTENDED_POOLS);
    instance_set_pool_def(GA_16K_POOL, WR_MAX_MEM_BLOCK_SIZE / (WR_FILE_SPACE_BLOCK_SIZE + WR_BLOCK_CTRL_SIZE),
        WR_FILE_SPACE_BLOCK_SIZE + WR_BLOCK_CTRL_SIZE, GA_MAX_EXTENDED_POOLS);
    instance_set_pool_def(GA_FS_AUX_POOL, WR_MAX_MEM_BLOCK_SIZE / (WR_FS_AUX_SIZE + WR_BLOCK_CTRL_SIZE),
        WR_FS_AUX_SIZE + WR_BLOCK_CTRL_SIZE, GA_MAX_EXTENDED_POOLS);
    instance_set_pool_def(
        GA_SEGMENT_POOL, WR_MAX_VOLUME_GROUP_NUM, WR_BUCKETS_SIZE_PER_SEGMENT, WR_MAX_SEGMENT_NUM - 1);
    ret = ga_create_global_area();
    WR_RETURN_IF_ERROR(ret);
    LOG_RUN_INF("Init GA pool and area successfully.");
    return CM_SUCCESS;
}

static status_t wr_init_thread(wr_instance_t *inst)
{
    uint32_t size = wr_get_uwression_startid();
    inst->threads = (thread_t *)cm_malloc(size * (uint32_t)sizeof(thread_t));
    if (inst->threads == NULL) {
        return CM_ERROR;
    }
    errno_t errcode =
        memset_s(inst->threads, (size * (uint32_t)sizeof(thread_t)), 0x00, (size * (uint32_t)sizeof(thread_t)));
    securec_check_ret(errcode);
    return CM_SUCCESS;
}

static status_t wr_init_inst_handle_session(wr_instance_t *inst)
{
    status_t status = wr_create_session(NULL, &inst->handle_session);
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("WR instance init create handle session fail!"));
    return CM_SUCCESS;
}

status_t wr_init_certification(wr_instance_t *inst)
{
    return ser_init_ssl(inst->lsnr.socks[0]);
}

static status_t instance_init_core(wr_instance_t *inst)
{
    status_t status = wr_init_session_pool(wr_get_max_total_session_cnt());
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_GA_INIT, "WR instance failed to initialize sessions."));
    status = wr_init_thread(inst);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_GA_INIT, "WR instance failed to initialize thread."));
    status = wr_startup_mes();
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_GA_INIT, "WR instance failed to startup mes"));
    status = wr_create_reactors();
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("WR instance failed to start reactors!"));
    status = wr_start_lsnr(inst);
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("WR instance failed to start lsnr!"));
    status = wr_init_certification(inst);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_GA_INIT, "WR instance failed to startup certification"));
    status = wr_init_inst_handle_session(inst);
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("WR instance int handle session!"));
    return CM_SUCCESS;
}

static void wr_init_maintain(wr_instance_t *inst, wr_srv_args_t wr_args)
{
    if (wr_args.is_maintain) {
        inst->is_maintain = true;
    } else {
        char *maintain_env = getenv(WR_MAINTAIN_ENV);
        inst->is_maintain = (maintain_env != NULL && cm_strcmpi(maintain_env, "TRUE") == 0);
    }

    if (inst->is_maintain) {
        LOG_RUN_INF("WR_MAINTAIN is TRUE");
    } else {
        LOG_RUN_INF("WR_MAINTAIN is FALSE");
    }
}

static status_t instance_init(wr_instance_t *inst)
{
    status_t status = wr_lock_instance();
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("Another wrinstance is running"));
    uint32_t shm_key =
        (uint32_t)(inst->inst_cfg.params.shm_key << (uint8)WR_MAX_SHM_KEY_BITS) + (uint32_t)inst->inst_cfg.params.inst_id;
    status = cm_init_shm(shm_key);
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("WR instance failed to initialize shared memory!"));
    status = instance_init_ga(inst);
    WR_RETURN_IFERR4(status, (void)del_shm_by_key(CM_SHM_CTRL_KEY), cm_destroy_shm(),
        LOG_RUN_ERR("WR instance failed to initialize ga!"));
    status = instance_init_core(inst);
    if (status != CM_SUCCESS) {
        (void)del_shm_by_key(CM_SHM_CTRL_KEY);
        ga_detach_area();
        cm_destroy_shm();
        CM_FREE_PTR(g_wr_session_ctrl.sessions);
        return CM_ERROR;
    }
    LOG_RUN_INF("WR instance begin to run.");
    return CM_SUCCESS;
}

static void wr_init_cluster_proto_ver(wr_instance_t *inst)
{
    for (uint32_t i = 0; i < WR_MAX_INSTANCES; i++) {
        inst->cluster_proto_vers[i] = WR_INVALID_VERSION;
    }
}

wr_instance_status_e wr_get_instance_status(void)
{
    return g_wr_instance.status;
}

static status_t wr_save_process_pid(wr_config_t *inst_cfg)
{
#ifndef WIN32
    char file_name[CM_FILE_NAME_BUFFER_SIZE] = {0};
    char dir_name[CM_FILE_NAME_BUFFER_SIZE] = {0};
    PRTS_RETURN_IFERR(
        snprintf_s(dir_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/process", inst_cfg->home));
    if (!cm_dir_exist(dir_name)) {
        WR_RETURN_IF_ERROR(cm_create_dir(dir_name));
    }
    PRTS_RETURN_IFERR(snprintf_s(
        file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s", dir_name, "wr.process"));
    pid_t pid = getpid();
    if (strlen(file_name) == 0) {
        LOG_RUN_ERR("wrserver process path not existed");
        return CM_ERROR;
    }
    FILE *fp;
    CM_RETURN_IFERR(cm_fopen(file_name, "w+", S_IRUSR | S_IWUSR, &fp));
    (void)cm_truncate_file(fp->_fileno, 0);
    (void)cm_seek_file(fp->_fileno, 0, SEEK_SET);
    int32_t size = fprintf(fp, "%d", pid);
    (void)fflush(stdout);
    if (size < 0) {
        LOG_RUN_ERR("write wrserver process failed, write size is %d.", size);
        (void)fclose(fp);
        return CM_ERROR;
    }
    (void)fclose(fp);
#endif
    return CM_SUCCESS;
}

status_t wr_startup(wr_instance_t *inst, wr_srv_args_t wr_args)
{
    status_t status;
    errno_t errcode = memset_s(inst, sizeof(wr_instance_t), 0, sizeof(wr_instance_t));
    securec_check_ret(errcode);

    status = wr_init_zero_buf();
    WR_RETURN_IFERR2(status, WR_PRINT_RUN_ERROR("wr init zero buf fail.\n"));

    wr_init_cluster_proto_ver(inst);
    inst->lock_fd = CM_INVALID_INT32;
    wr_set_server_flag();
    regist_get_instance_status_proc(wr_get_instance_status);
    status = wr_set_cfg_dir(wr_args.wr_home, &inst->inst_cfg);
    WR_RETURN_IFERR2(status, WR_PRINT_RUN_ERROR("Environment variant WR_HOME not found!\n"));
    status = cm_start_timer(g_timer());
    WR_RETURN_IFERR2(status, WR_PRINT_RUN_ERROR("Aborted due to starting timer thread.\n"));
    status = wr_load_config(&inst->inst_cfg);
    WR_RETURN_IFERR2(status, WR_PRINT_RUN_ERROR("Failed to load parameters!\n"));
    status = wr_load_ser_ssl_config(&inst->inst_cfg);
    WR_RETURN_IFERR2(status, WR_PRINT_RUN_ERROR("Failed to load server parameters!\n"));
    status = wr_save_process_pid(&inst->inst_cfg);
    WR_RETURN_IFERR2(status, WR_PRINT_RUN_ERROR("Save wrserver pid failed!\n"));
    wr_init_maintain(inst, wr_args);
    LOG_RUN_INF("WR instance begin to initialize.");

    status = instance_init(inst);
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("WR instance failed to initialized!"));
    cm_set_shm_ctrl_flag(CM_SHM_CTRL_FLAG_TRUE);
    inst->abort_status = CM_FALSE;
    return CM_SUCCESS;
}

static status_t wr_handshake_core(wr_session_t *session)
{
    wr_init_packet(&session->recv_pack, CM_FALSE);
    wr_init_packet(&session->send_pack, CM_FALSE);
    session->pipe.socket_timeout = (int32_t)CM_NETWORK_IO_TIMEOUT;
    status_t status = wr_process_handshake_cmd(session, WR_CMD_HANDSHAKE);
    return status;
}

static status_t wr_handshake(wr_session_t *session)
{
    LOG_RUN_INF("[WR_CONNECT]session %u begin check protocal type.", session->id);
    /* fetch protocol type */
    status_t status = wr_diag_proto_type(session);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[WR_CONNECT]Failed to get protocol type!");
        return CM_ERROR;
    }
    status = wr_handshake_core(session);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[WR_CONNECT]Failed to process get server info!");
        return CM_ERROR;
    }
    return status;
}

static status_t wr_certificate(wr_session_t *session)
{
    session->pipe.type = CS_TYPE_SSL;
    return ser_cert_accept(&session->pipe);
}

static status_t wr_lsnr_proc(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    wr_session_t *session = NULL;
    status_t status;
    status = wr_create_session(pipe, &session);
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("[WR_CONNECT] create session failed.\n"));
    // process_handshake
    status = wr_handshake(session);
    WR_RETURN_IFERR3(status, LOG_RUN_ERR("[WR_CONNECT] handshake failed.\n"), wr_destroy_session(session));
    status = wr_certificate(session);
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("[WR_CONNECT]SSL certificate failed."));
    LOG_RUN_INF("[WR_CONNECT]The certification between client and server has finished.");
    status = wr_reactors_add_session(session);
    WR_RETURN_IFERR3(status,
        LOG_RUN_ERR("[WR_CONNECT]Session:%u socket:%u closed.", session->id, pipe->link.uds.sock),
        wr_destroy_session(session));
    LOG_RUN_INF("[WR_CONNECT]The client has connected, session %u.", session->id);
    return CM_SUCCESS;
}

status_t wr_start_lsnr(wr_instance_t *inst)
{
    WR_RETURN_IFERR2(strncpy_s(inst->lsnr.host[0], 
                               WR_MAX_PATH_BUFFER_SIZE,
                               g_inst_cfg->params.listen_addr.host,
                               WR_MAX_PATH_BUFFER_SIZE),
                     LOG_RUN_ERR("wr_start_lsnr strncpy_s failed"));
    inst->lsnr.host[1][0] = '\0';
    inst->lsnr.port = g_inst_cfg->params.listen_addr.port;
    // return cs_start_uds_lsnr(&inst->lsnr, wr_lsnr_proc);
    return cs_start_tcp_lsnr(&inst->lsnr, wr_lsnr_proc);
}

status_t wr_init_cm(wr_instance_t *inst)
{
    inst->cm_res.is_valid = CM_FALSE;
    inst->inst_work_status_map = 0;
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    char *value = cm_get_config_value(&inst_cfg->config, "WR_CM_SO_NAME");
    if (value == NULL || strlen(value) == 0) {
        LOG_RUN_INF("wr cm config of WR_CM_SO_NAME is empty.");
        return CM_SUCCESS;
    }

    if (strlen(value) >= WR_MAX_NAME_LEN) {
        LOG_RUN_ERR("wr cm config of WR_CM_SO_NAME is exceeds the max len %u.", WR_MAX_NAME_LEN - 1);
        return CM_ERROR;
    }
#ifdef ENABLE_WRTEST
    WR_RETURN_IF_ERROR(wr_simulation_cm_res_mgr_init(value, &inst->cm_res.mgr, NULL));
#else
    WR_RETURN_IF_ERROR(cm_res_mgr_init(value, &inst->cm_res.mgr, NULL));
#endif
    status_t status =
        (status_t)cm_res_init(&inst->cm_res.mgr, (unsigned int)inst->inst_cfg.params.inst_id, WR_CMS_RES_TYPE, NULL);
#ifdef ENABLE_WRTEST
    WR_RETURN_IFERR2(status, wr_simulation_cm_res_mgr_uninit(&inst->cm_res.mgr));
#else
    WR_RETURN_IFERR2(status, cm_res_mgr_uninit(&inst->cm_res.mgr));
#endif
    inst->cm_res.is_valid = CM_TRUE;
    return CM_SUCCESS;
}

void wr_uninit_cm(wr_instance_t *inst)
{
    if (inst->cm_res.is_valid) {
#ifdef ENABLE_WRTEST
        wr_simulation_cm_res_mgr_uninit(&inst->cm_res.mgr);
#else
        cm_res_mgr_uninit(&inst->cm_res.mgr);
#endif
        inst->cm_res.is_valid = CM_FALSE;
    }
}

void wr_free_log_ctrl()
{
    if (g_vgs_info == NULL) {
        return;
    }
    for (uint32_t i = 0; i < g_vgs_info->group_num; i++) {
        wr_vg_info_item_t *vg_item = &g_vgs_info->volume_group[i];
        if (vg_item != NULL && vg_item->log_file_ctrl.log_buf != NULL) {
            WR_FREE_POINT(vg_item->log_file_ctrl.log_buf);
        }
    }
}

void wr_check_peer_by_inst(wr_instance_t *inst, uint64 inst_id)
{
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    // Can't be myself
    if (inst_id == (uint64)inst_cfg->params.inst_id) {
        return;
    }

    // Not cfg the inst
    uint64 inst_mask = ((uint64)0x1 << inst_id);
    if ((inst_cfg->params.nodes_list.inst_map & inst_mask) == 0) {
        return;
    }

    uint64 cur_inst_map = wr_get_inst_work_status();
    // Has connection
    if ((cur_inst_map & inst_mask) != 0) {
        return;
    }

    wr_check_peer_inst(inst, inst_id);
}

static void wr_check_peer_by_cm(wr_instance_t *inst)
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
    wr_config_t *inst_cfg = wr_get_inst_cfg();
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
            LOG_RUN_INF("wr instance [%d] is not work member. May be kicked off by cm.", res_instance_id);
            continue;
        }

        uint64_t inst_mask = ((uint64)0x1 << res_instance_id);
        if ((inst_cfg->params.nodes_list.inst_map & inst_mask) == 0) {
            LOG_RUN_INF("wr instance [%d] is not in mes nodes cfg lists.", res_instance_id);
            continue;
        }

        int stat = cm_res_get_inst_stat(&inst->cm_res.mgr, inst_res);
        if (stat != CM_RES_STATUS_ONLINE) {
            LOG_RUN_INF("wr instance [%d] work stat [%d] not online.", res_instance_id, stat);
        }
        cur_inst_map |= ((uint64)0x1 << res_instance_id);
    }

    wr_check_mes_conn(cur_inst_map);
    cm_res_free_stat(&inst->cm_res.mgr, res);
    cm_res_uninit_memctx(&res_mem_ctx);
}

#ifdef ENABLE_WRTEST
static void wr_check_peer_by_simulation_cm(wr_instance_t *inst)
{
    if (g_simulation_cm.simulation) {
        char *bitmap_online = inst->cm_res.mgr.cm_get_res_stat();
        uint64 cur_inst_map = 0;
        (void)cm_str2bigint(bitmap_online, (int64 *)&cur_inst_map);
        wr_check_mes_conn(cur_inst_map);
        return;
    }
    wr_check_peer_by_cm(inst);
    return;
}
#endif

static void wr_check_peer_default()
{
    wr_check_mes_conn(WR_INVALID_ID64);
}

void wr_init_cm_res(wr_instance_t *inst)
{
    wr_cm_res *cm_res = &inst->cm_res;
    cm_spin_lock(&cm_res->init_lock, NULL);
    if (cm_res->is_init) {
        cm_spin_unlock(&cm_res->init_lock);
        return;
    }
    status_t status = wr_init_cm(inst);
    if (status == CM_SUCCESS) {
        cm_res->is_init = CM_TRUE;
    }
    cm_spin_unlock(&cm_res->init_lock);
    return;
}

#ifdef ENABLE_WRTEST
status_t wr_get_cm_res_lock_owner(wr_cm_res *cm_res, uint32_t *master_id)
{
    if (g_simulation_cm.simulation) {
        int ret = cm_res_get_lock_owner(&cm_res->mgr, WR_CM_LOCK, master_id);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    } else {
        wr_config_t *inst_cfg = wr_get_inst_cfg();
        for (int i = 0; i < WR_MAX_INSTANCES; i++) {
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
status_t wr_get_cm_res_lock_owner(wr_cm_res *cm_res, uint32_t *master_id)
{
    int ret = cm_res_get_lock_owner(&cm_res->mgr, WR_CM_LOCK, master_id);
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
// get cm lock owner, if no owner, try to become.master_id can not be WR_INVALID_ID32.
status_t wr_get_cm_lock_owner(wr_instance_t *inst, bool32 *grab_lock, bool32 try_lock, uint32_t *master_id)
{
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    *master_id = WR_INVALID_ID32;
    if (inst->is_maintain || inst->inst_cfg.params.nodes_list.inst_cnt <= 1) {
        *grab_lock = CM_TRUE;
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5,
            "[RECOVERY]Set curr_id %u to be primary when wrserver is maintain or just one inst.",
            (uint32_t)inst_cfg->params.inst_id);
        *master_id = (uint32_t)inst_cfg->params.inst_id;
        return CM_SUCCESS;
    }
    wr_cm_res *cm_res = &inst->cm_res;
    if (!cm_res->is_init) {
        return CM_SUCCESS;
    }
    status_t ret = wr_get_cm_res_lock_owner(cm_res, master_id);
    WR_RETURN_IFERR2(ret, LOG_RUN_WAR("Failed to get cm lock owner, if WR is normal open ignore the log."));
    if (*master_id == WR_INVALID_ID32) {
        if (!try_lock) {
            return CM_ERROR;
        }
        if (inst->no_grab_lock) {
            LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "[RECOVERY]No need to grab lock when inst %u is set no grab lock.",
                (uint32_t)inst_cfg->params.inst_id);
            wr_set_master_id(WR_INVALID_ID32);
            return CM_ERROR;
        }
        ret = cm_res_lock(&cm_res->mgr, WR_CM_LOCK);
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

void wr_recovery_when_primary(wr_session_t *session, wr_instance_t *inst, uint32_t curr_id, bool32 grab_lock)
{
    bool32 first_start = CM_FALSE;
    if (!grab_lock) {
        first_start = (inst->status == WR_STATUS_PREPARE);
    }
    if (first_start) {
        LOG_RUN_INF("[RECOVERY]inst %u is old main inst to do recovery.", curr_id);
    } else {
        LOG_RUN_INF("[RECOVERY]master_id is %u when get cm lock to do recovery.", curr_id);
    }

    wr_instance_status_e old_status = inst->status;
    inst->status = WR_STATUS_RECOVERY;
    CM_MFENCE;

    if (old_status == WR_STATUS_OPEN && !first_start) {
        wr_wait_session_pause(inst);
    }
    wr_wait_background_pause(inst);

    if (!first_start) {
        wr_set_session_running(inst, session->id);
    }

    // when current node is standby, and will change to primary, the status is from WR_STATUS_OPEN to
    // WR_STATUS_RECOVERY, need to set the master id after the status finish
    wr_set_master_id(curr_id);
    wr_set_server_status_flag(WR_STATUS_READWRITE);
    LOG_RUN_INF("[RECOVERY]inst %u set status flag %u when get cm lock.", curr_id, WR_STATUS_READWRITE);
    // when primary, no need to check result
    g_wr_instance.is_join_cluster = CM_TRUE;
    inst->status = WR_STATUS_OPEN;
}

void wr_recovery_when_standby(wr_session_t *session, wr_instance_t *inst, uint32_t curr_id, uint32_t master_id)
{
    uint32_t old_master_id = wr_get_master_id();
    int32_t old_status = wr_get_server_status_flag();
    if (old_master_id != master_id) {
        wr_set_master_id(master_id);
        wr_set_server_status_flag(WR_STATUS_READONLY);
        LOG_RUN_INF("[RECOVERY]inst %u set status flag %u when not get cm lock.", curr_id, WR_STATUS_READONLY);
    }
    if (!wr_check_join_cluster()) {
        wr_set_master_id(old_master_id);
        wr_set_server_status_flag(old_status);
        LOG_RUN_INF("[RECOVERY]inst %u reset status flag %d and master_id %u when join failed.", curr_id, old_status,
            old_master_id);
        return;
    }
    inst->status = WR_STATUS_OPEN;
}
/*
    1、old_master_id == master_id, just return;
    2、old_master_id != master_id, just indicates that the master has been reselected.so to judge whether recover.
*/
void wr_get_cm_lock_and_recover_inner(wr_session_t *session, wr_instance_t *inst)
{
    cm_latch_x(&g_wr_instance.switch_latch, WR_DEFAULT_SESSIONID, LATCH_STAT(LATCH_SWITCH));
    uint32_t old_master_id = wr_get_master_id();
    bool32 grab_lock = CM_FALSE;
    uint32_t master_id = WR_INVALID_ID32;
    status_t status = wr_get_cm_lock_owner(inst, &grab_lock, CM_TRUE, &master_id);
    if (status != CM_SUCCESS) {
        cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        return;
    }
    if (master_id == WR_INVALID_ID32) {
        LOG_RUN_WAR("[RECOVERY]cm is not init, just try again.");
        cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        return;
    }
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32_t curr_id = (uint32_t)inst_cfg->params.inst_id;
    // master no change
    if (old_master_id == master_id) {
        // primary, no need check
        if (master_id == curr_id) {
            cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            return;
        }
        if (inst->is_join_cluster) {
            cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            return;
        }
    }
    // standby is started or masterid has been changed
    if (master_id != curr_id) {
        wr_recovery_when_standby(session, inst, curr_id, master_id);
        cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        return;
    }
    /*1、grab lock success 2、set main,other switch lock 3、restart, lock no transfer*/
    wr_set_recover_thread_id(wr_get_current_thread_id());
    wr_recovery_when_primary(session, inst, curr_id, grab_lock);
    wr_set_recover_thread_id(0);
    cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
}

#define WR_RECOVER_INTERVAL 500
#define WR_SHORT_RECOVER_INTERVAL 100
void wr_get_cm_lock_and_recover(thread_t *thread)
{
    cm_set_thread_name("recovery");
    uint32_t work_idx = wr_get_recover_task_idx();
    wr_session_t *session = wr_get_reserv_session(work_idx);
    wr_instance_t *inst = (wr_instance_t *)thread->argument;
    while (!thread->closed) {
        wr_get_cm_lock_and_recover_inner(session, inst);
        if (inst->status == WR_STATUS_PREPARE) {
            LOG_RUN_WAR("[RECOVERY]Try to sleep when in prepare status.\n");
            cm_sleep(WR_SHORT_RECOVER_INTERVAL);
        } else {
            cm_sleep(WR_RECOVER_INTERVAL);
        }
    }
}

void wr_delay_clean_proc(thread_t *thread)
{
    cm_set_thread_name("delay_clean");
    uint32_t work_idx = wr_get_delay_clean_task_idx();
    wr_session_ctrl_t *session_ctrl = wr_get_session_ctrl();
    wr_session_t *session = session_ctrl->sessions[work_idx];
    LOG_RUN_INF("Session[id=%u] is available for delay clean task.", session->id);
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32_t sleep_times = 0;
    while (!thread->closed) {
        if (sleep_times < inst_cfg->params.delay_clean_interval) {
            cm_sleep(CM_SLEEP_1000_FIXED);
            sleep_times++;
            continue;
        }
        g_wr_instance.is_cleaning = CM_TRUE;
        // WR_STATUS_OPEN for control with switchover
        if (wr_need_exec_local() && wr_is_readwrite() && (g_wr_instance.status == WR_STATUS_OPEN)) {
            //wr_delay_clean_all_vg(session);
        }
        g_wr_instance.is_cleaning = CM_FALSE;
        sleep_times = 0;
    }
}

void wr_alarm_check_proc(thread_t *thread)
{
    cm_set_thread_name("alarm_check");
    uint32 sleep_times = 0;
    // for check other alarms
    uint32 alarm_counts = WR_VG_ALARM_CHECK_COUNT;
    while (!thread->closed) {
        // only master node need alarm
        if (sleep_times % WR_VG_ALARM_CHECK_COUNT == 0) {
            g_wr_instance.is_checking = CM_TRUE;
            wr_alarm_check_disk_usage();
            g_wr_instance.is_checking = CM_FALSE;
        }
        cm_sleep(CM_SLEEP_500_FIXED);
        sleep_times++;
        sleep_times = sleep_times % alarm_counts;
    }
}

static void wr_check_peer_inst_inner(wr_instance_t *inst)
{
    /**
     * During installation initialization, db_init depends on the WR server. However, the CMS is not started.
     * Therefore, cm_init cannot be invoked during the WR server startup.
     * Here, cm_init is invoked before the CM interface is invoked at first time.
     */
    if (SECUREC_UNLIKELY(!inst->cm_res.is_init)) {
        wr_init_cm_res(inst);
    }
    if (inst->cm_res.is_valid) {
#ifdef ENABLE_WRTEST
        wr_check_peer_by_simulation_cm(inst);
#else
        wr_check_peer_by_cm(inst);
#endif
        return;
    }
    wr_check_peer_default();
}

void wr_check_peer_inst(wr_instance_t *inst, uint64 inst_id)
{
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    if (inst_cfg->params.nodes_list.inst_cnt <= 1) {
        return;
    }

    uint64 inst_mask = ((uint64)0x1 << inst_id);
    cm_spin_lock(&inst->inst_work_lock, NULL);

    // after lock, check again, other thd may get the lock, and init the map before
    uint64 cur_inst_map = wr_get_inst_work_status();
    // has connection
    if (inst_id != WR_INVALID_ID64 && (cur_inst_map & inst_mask) != 0) {
        cm_spin_unlock(&inst->inst_work_lock);
        return;
    }

    wr_check_peer_inst_inner(inst);
    cm_spin_unlock(&inst->inst_work_lock);
}

uint64 wr_get_inst_work_status(void)
{
    return (uint64)cm_atomic_get((atomic_t *)&g_wr_instance.inst_work_status_map);
}

void wr_set_inst_work_status(uint64 cur_inst_map)
{
    (void)cm_atomic_set((atomic_t *)&g_wr_instance.inst_work_status_map, (int64)cur_inst_map);
}

bool32 wr_check_join_cluster()
{
    if (g_wr_instance.is_join_cluster) {
        return CM_TRUE;
    }

    if (wr_get_master_id() == g_wr_instance.inst_cfg.params.inst_id) {
        g_wr_instance.is_join_cluster = CM_TRUE;
        LOG_RUN_INF("Join cluster success by primary.");
    } else {
        // try register to new master to join
        bool32 join_succ = CM_FALSE;
        status_t status = wr_join_cluster(&join_succ);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Join cluster fail, wait next try.");
            cm_reset_error();
            return CM_FALSE;
        }
        LOG_DEBUG_INF("Join cluster result [%u].", (uint32_t)join_succ);
        if (!join_succ) {
            return CM_FALSE;
        }
        g_wr_instance.is_join_cluster = CM_TRUE;
        LOG_RUN_INF("Join cluster success by standby.");
    }

    return CM_TRUE;
}