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
 * gr_mes.c
 *
 *
 * IDENTIFICATION
 *    src/service/gr_mes.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_types.h"
#include "cm_error.h"
#include "gr_malloc.h"
#include "gr_session.h"
#include "gr_file.h"
#include "gr_service.h"
#include "../params/gr_param_sync.h"
#include "gr_instance.h"
#include "gr_api.h"
#include "gr_mes.h"
#include "gr_syn_meta.h"
#include "gr_thv.h"
#include "gr_fault_injection.h"
#include "gr_param_verify.h"

void gr_proc_broadcast_req(gr_session_t *session, mes_msg_t *msg);
void gr_proc_syb2active_req(gr_session_t *session, mes_msg_t *msg);
void gr_proc_loaddisk_req(gr_session_t *session, mes_msg_t *msg);
void gr_proc_join_cluster_req(gr_session_t *session, mes_msg_t *msg);
void gr_proc_refresh_ft_by_primary_req(gr_session_t *session, mes_msg_t *msg);

void gr_proc_normal_ack(gr_session_t *session, mes_msg_t *msg)
{
    gr_message_head_t *gr_head = (gr_message_head_t *)msg->buffer;
    LOG_DEBUG_INF("[MES] Receive ack(%u),src inst(%u), dst inst(%u).", (uint32_t)(gr_head->gr_cmd),
        (uint32_t)(gr_head->src_inst), (uint32_t)(gr_head->dst_inst));
}

gr_processor_t g_gr_processors[GR_CMD_CEIL] = {
    [GR_CMD_REQ_BROADCAST] = {gr_proc_broadcast_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE, "gr broadcast"},
    [GR_CMD_ACK_BROADCAST_WITH_MSG] = {gr_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE,
        "gr broadcast ack with data"},
    [GR_CMD_REQ_SYB2ACTIVE] = {gr_proc_syb2active_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE,
        "gr standby to active req"},
    [GR_CMD_ACK_SYB2ACTIVE] = {gr_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE, "gr active to standby ack"},
    [GR_CMD_REQ_JOIN_CLUSTER] = {gr_proc_join_cluster_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE,
        "gr standby join in cluster to active req"},
    [GR_CMD_ACK_JOIN_CLUSTER] = {gr_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE,
        "gr active proc join in cluster to standby ack"},
};

static inline mes_priority_t gr_get_cmd_prio_id(gr_mes_command_t cmd)
{
    return g_gr_processors[cmd].prio_id;
}

typedef void (*gr_remote_ack_proc)(gr_session_t *session, gr_remote_exec_succ_ack_t *remote_ack);
typedef struct st_gr_remote_ack_hdl {
    gr_remote_ack_proc proc;
} gr_remote_ack_hdl_t;
void gr_process_remote_ack_for_get_ftid_by_path(gr_session_t *session, gr_remote_exec_succ_ack_t *remote_ack)
{
}
static gr_remote_ack_hdl_t g_gr_remote_ack_handle[GR_CMD_TYPE_OFFSET(GR_CMD_END)] = {
    [GR_CMD_TYPE_OFFSET(GR_CMD_GET_FTID_BY_PATH)] = {gr_process_remote_ack_for_get_ftid_by_path},
};

static inline gr_remote_ack_hdl_t *gr_get_remote_ack_handle(int32_t cmd)
{
    if (cmd >= GR_CMD_BEGIN && cmd < GR_CMD_END) {
        return &g_gr_remote_ack_handle[GR_CMD_TYPE_OFFSET(cmd)];
    }
    return NULL;
}

static void gr_init_mes_head(gr_message_head_t *head, uint32_t cmd, uint32_t flags, uint16 src_inst, uint16 dst_inst,
    uint32_t size, uint32_t version, ruid_type ruid)
{
    (void)memset_s(head, GR_MES_MSG_HEAD_SIZE, 0, GR_MES_MSG_HEAD_SIZE);
    head->sw_proto_ver = GR_PROTO_VERSION;
    head->msg_proto_ver = version;
    head->size = size;
    head->gr_cmd = cmd;
    head->ruid = ruid;
    head->src_inst = src_inst;
    head->dst_inst = dst_inst;
    head->flags = flags | gr_get_cmd_prio_id(cmd);
}

static gr_bcast_ack_cmd_t gr_get_bcast_ack_cmd(gr_bcast_req_cmd_t bcast_op)
{
    switch (bcast_op) {
        case BCAST_REQ_DEL_DIR_FILE:
            return BCAST_ACK_DEL_FILE;
        case BCAST_REQ_INVALIDATE_META:
            return BCAST_ACK_INVALIDATE_META;
        case BCAST_REQ_META_SYN:
            return BCAST_ACK_META_SYN;
        case BCAST_REQ_PARAM_SYNC:
            return BCAST_ACK_PARAM_SYNC;
        default:
            LOG_RUN_ERR("Invalid broadcast request type");
            break;
    }
    return BCAST_ACK_END;
}
// warning: if add new broadcast req, please consider the impact of expired broadcast messages on the standby server
static void gr_proc_broadcast_req_inner(gr_session_t *session, gr_notify_req_msg_t *req)
{
    status_t status = CM_ERROR;
    bool32 cmd_ack = CM_FALSE;
    gr_notify_req_msg_ex_t *req_ex = NULL;
    switch (req->type) {
        case BCAST_REQ_DEL_DIR_FILE:
            status = gr_check_open_file_remote(session, req->vg_name, req->ftid, &cmd_ack);
            break;
        case BCAST_REQ_INVALIDATE_META:
            req_ex = (gr_notify_req_msg_ex_t *)req;
            status = gr_invalidate_meta_remote(
                session, (gr_invalidate_meta_msg_t *)req_ex->data, req_ex->data_size, &cmd_ack);
            break;
        case BCAST_REQ_META_SYN:
            req_ex = (gr_notify_req_msg_ex_t *)req;
            status = gr_meta_syn_remote(session, (gr_meta_syn_t *)req_ex->data, req_ex->data_size, &cmd_ack);
            return;
        case BCAST_REQ_PARAM_SYNC:
            /*
             * Handle parameter synchronization broadcast request.
             * On standby nodes, fetch the latest config from WORM and update in-memory parameters.
             */
            LOG_RUN_INF("Processing parameter sync broadcast request.");
            gr_config_t *inst_cfg = gr_get_g_inst_cfg();
            if (inst_cfg == NULL) {
                LOG_RUN_ERR("Failed to get instance config for parameter sync.");
                status = CM_ERROR;
                cmd_ack = CM_TRUE;
                break;
            }
            uint32_t current_inst_id = (uint32_t)inst_cfg->params.inst_id;
            LOG_RUN_INF("Current standby node (ID: %u) writing WORM file to local configuration.", current_inst_id);

            // Write latest config from WORM storage to local config file
            status = gr_standby_node_worm_write(inst_cfg);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Standby %u failed to sync config from WORM on broadcast.", current_inst_id);
                break;
            }
            LOG_RUN_INF("Standby %u synced config from WORM on broadcast.", current_inst_id);
            // Align the in-memory config with the updated local config file
            status = gr_apply_cfg_to_memory(inst_cfg, CM_TRUE, CM_TRUE);
            if (status == CM_SUCCESS) {
                LOG_RUN_INF("Standby %u applied sync parameters to memory from local file.", current_inst_id);
            } else {
                LOG_RUN_ERR("Standby %u failed to apply sync parameters to memory from local file.", current_inst_id);
            }
            // Always send ACK for parameter sync broadcast for easier master-side aggregation
            cmd_ack = CM_TRUE;
            break;
        default:
            LOG_RUN_ERR("invalid broadcast req type");
            return;
    }
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    gr_params_t *param = &inst_cfg->params;
    gr_message_head_t *req_head = &req->gr_head;
    uint16 dst_inst = req_head->src_inst;
    uint16 src_inst = (uint16)param->inst_id;
    uint32_t version = req_head->msg_proto_ver;
    ruid_type ruid = req_head->ruid;
    gr_notify_ack_msg_t ack_check;
    gr_init_mes_head(&ack_check.gr_head, GR_CMD_ACK_BROADCAST_WITH_MSG, 0, src_inst, dst_inst,
        sizeof(gr_notify_ack_msg_t), version, ruid);
    ack_check.type = gr_get_bcast_ack_cmd(req->type);
    ack_check.result = status;
    ack_check.cmd_ack = cmd_ack;
    int ret =
        mes_send_response(dst_inst, ack_check.gr_head.flags, ruid, (char *)&ack_check, sizeof(gr_notify_ack_msg_t));
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[MES] send message failed, src inst(%hhu), dst inst(%hhu) ret(%d) ", src_inst, dst_inst, ret);
        return;
    }
    GR_LOG_DEBUG_OP("[MES] Succeed to send message, notify %llu  result: %u. cmd=%u, src_inst=%hhu, dst_inst=%hhu.",
        req->ftid, cmd_ack, ack_check.gr_head.gr_cmd, ack_check.gr_head.src_inst, ack_check.gr_head.dst_inst);
}

int32_t gr_process_broadcast_ack(gr_notify_ack_msg_t *ack, gr_recv_msg_t *recv_msg_output)
{
    int32_t ret = ERR_GR_MES_ILL;
    switch (ack->type) {
        case BCAST_ACK_DEL_FILE:
        case BCAST_ACK_INVALIDATE_META:
        case BCAST_ACK_META_SYN:
        case BCAST_ACK_PARAM_SYNC:
            ret = ack->result;
            // recv_msg_output->cmd_ack init-ed with the deault, if some node not the same with the default, let's cover
            // the default value
            if (ret == CM_SUCCESS && recv_msg_output->default_ack != ack->cmd_ack) {
                recv_msg_output->cmd_ack = ack->cmd_ack;
            }
            break;
        default:
            LOG_RUN_ERR("invalid broadcast ack type");
            break;
    }
    return ret;
}

static void gr_ack_version_not_match(gr_session_t *session, gr_message_head_t *req_head, uint32_t version)
{
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    gr_params_t *param = &inst_cfg->params;
    uint16 dst_inst = req_head->src_inst;
    uint16 src_inst = (uint16)param->inst_id;
    ruid_type ruid = req_head->ruid;
    gr_message_head_t ack_head;
    uint32_t cmd = (req_head->gr_cmd == GR_CMD_REQ_BROADCAST) ? GR_CMD_ACK_BROADCAST_WITH_MSG : GR_CMD_ACK_SYB2ACTIVE;
    gr_init_mes_head(&ack_head, cmd, 0, src_inst, dst_inst, GR_MES_MSG_HEAD_SIZE, version, ruid);
    ack_head.result = ERR_GR_VERSION_NOT_MATCH;
    int ret = mes_send_response(dst_inst, ack_head.flags, ruid, (char *)&ack_head, GR_MES_MSG_HEAD_SIZE);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR(
            "send version not match message failed, src inst(%hhu), dst inst(%hhu) ret(%d)", src_inst, dst_inst, ret);
        return;
    }
    LOG_RUN_INF("send version not match message succeed, src inst(%hhu), dst inst(%hhu), ack msg version (%hhu)",
        src_inst, dst_inst, version);
}

void gr_proc_broadcast_req(gr_session_t *session, mes_msg_t *msg)
{
    if (gr_need_exec_local()) {
        LOG_RUN_INF("No need to solve broadcast msg when the current node is master.");
        return;
    }
    if (msg->size < OFFSET_OF(gr_notify_req_msg_t, type)) {
        LOG_RUN_ERR("invalid message req size");
        return;
    }
    gr_notify_req_msg_t *req = (gr_notify_req_msg_t *)msg->buffer;
    LOG_DEBUG_INF("[MES] Try proc broadcast req, head cmd is %u, req cmd is %u.", req->gr_head.gr_cmd, req->type);
    gr_proc_broadcast_req_inner(session, req);
    return;
}

static void gr_set_cluster_proto_vers(uint8 inst_id, uint32_t version)
{
    if (inst_id >= GR_MAX_INSTANCES) {
        LOG_RUN_ERR("Invalid request inst_id:%hhu, version is %u.", inst_id, version);
        return;
    }
    bool32 set_flag = CM_FALSE;
    do {
        uint32_t cur_version = (uint32_t)cm_atomic32_get((atomic32_t *)&g_gr_instance.cluster_proto_vers[inst_id]);
        if (cur_version == version) {
            break;
        }
        set_flag = cm_atomic32_cas(
            (atomic32_t *)&g_gr_instance.cluster_proto_vers[inst_id], (int32_t)cur_version, (int32_t)version);
    } while (!set_flag);
}

static int gr_handle_broadcast_msg(mes_msg_list_t *responses, gr_recv_msg_t *recv_msg_output)
{
    int ret;
    for (uint32_t i = 0; i < responses->count; i++) {
        mes_msg_t *msg = &responses->messages[i];
        gr_message_head_t *ack_head = (gr_message_head_t *)msg->buffer;
        uint32_t src_inst = responses->messages[i].src_inst;
        gr_set_cluster_proto_vers((uint8)src_inst, ack_head->sw_proto_ver);
        if (ack_head->result == ERR_GR_VERSION_NOT_MATCH) {
            recv_msg_output->version_not_match_inst |= ((uint64)0x1 << src_inst);
            continue;
        }
        if (ack_head->size < sizeof(gr_notify_ack_msg_t)) {
            GR_THROW_ERROR(ERR_GR_MES_ILL, "msg len is invalid");
            return ERR_GR_MES_ILL;
        }
        gr_notify_ack_msg_t *ack = (gr_notify_ack_msg_t *)ack_head;
        ret = gr_process_broadcast_ack(ack, recv_msg_output);
        GR_RETURN_IFERR2(ret, GR_THROW_ERROR(ERR_GR_FILE_OPENING_REMOTE, ack_head->src_inst, ack_head->gr_cmd));
    }
    return GR_SUCCESS;
}

static void gr_release_broadcast_msg(mes_msg_list_t *responses)
{
    for (uint32_t i = 0; i < responses->count; i++) {
        mes_release_msg(&responses->messages[i]);
    }
}

static int gr_handle_recv_broadcast_msg(
    ruid_type ruid, uint32_t timeout, uint64 *succ_ack_inst, gr_recv_msg_t *recv_msg_output)
{
    mes_msg_list_t responses;
    int ret = mes_broadcast_get_response(ruid, &responses, timeout);
    if (ret != GR_SUCCESS) {
        LOG_DEBUG_INF("[MES] Try broadcast get response failed, ret is %d, ruid is %llu.", ret, ruid);
        return ret;
    }
    ret = gr_handle_broadcast_msg(&responses, recv_msg_output);
    if (ret != GR_SUCCESS) {
        gr_release_broadcast_msg(&responses);
        LOG_DEBUG_INF("[MES] Try broadcast get response failed, ret is %d, ruid is %llu.", ret, ruid);
        return ret;
    }
    // do not care ret, just check get ack msg
    for (uint32_t i = 0; i < responses.count; i++) {
        uint32_t src_inst = responses.messages[i].src_inst;
        *succ_ack_inst |= ((uint64)0x1 << src_inst);
    }
    *succ_ack_inst = *succ_ack_inst & (~recv_msg_output->version_not_match_inst);
    gr_release_broadcast_msg(&responses);
    return ret;
}

static void gr_handle_discard_recv_broadcast_msg(ruid_type ruid)
{
    mes_msg_list_t responses;
    int ret = mes_broadcast_get_response(ruid, &responses, 0);
    if (ret == CM_SUCCESS) {
        gr_release_broadcast_msg(&responses);
    }
}

uint32_t gr_get_broadcast_proto_ver(uint64 succ_inst)
{
    uint64 inst_mask;
    uint64 cur_work_inst_map = gr_get_inst_work_status();
    uint64 need_send_inst = (~succ_inst & cur_work_inst_map);
    uint32_t inst_proto_ver;
    uint32_t broadcast_proto_vers = GR_PROTO_VERSION;
    for (uint32_t i = 0; i < GR_MAX_INSTANCES; i++) {
        inst_mask = ((uint64)0x1 << i);
        if ((need_send_inst & inst_mask) == 0) {
            continue;
        }
        inst_proto_ver = (uint32_t)cm_atomic32_get((atomic32_t *)&g_gr_instance.cluster_proto_vers[i]);
        if (inst_proto_ver == GR_INVALID_VERSION) {
            continue;
        }
        broadcast_proto_vers = MIN(broadcast_proto_vers, inst_proto_ver);
    }
    return broadcast_proto_vers;
}

void gr_get_valid_inst(uint64 valid_inst, uint32_t *arr, uint32_t count)
{
    uint32_t i = 0;
    for (uint32_t j = 0; j < GR_MAX_INSTANCES; j++) {
        if (GR_IS_INST_SEND(valid_inst, j)) {
            arr[i] = j;
            i++;
        }
    }
}

#define GR_BROADCAST_MSG_TRY_MAX 5
#define GR_BROADCAST_MSG_TRY_SLEEP_TIME 200
static status_t gr_broadcast_msg_with_try(gr_message_head_t *gr_head, gr_recv_msg_t *recv_msg, unsigned int timeout)
{
    int32_t ret = GR_SUCCESS;

    gr_config_t *inst_cfg = gr_get_inst_cfg();
    gr_params_t *param = &inst_cfg->params;
    uint64 succ_req_inst = 0;
    uint64 succ_ack_inst = 0;
    uint32_t i = 0;
    // init last send err with all
    uint64 cur_work_inst_map = gr_get_inst_work_status();
    uint64 snd_err_inst_map = (~recv_msg->succ_inst & cur_work_inst_map);
    uint64 last_inst_inst_map = 0;
    uint64 new_added_inst_map = 0;
    uint64 valid_inst = 0;
    uint64 valid_inst_mask = 0;
    do {
        // only send the last-send-failed and new added
        cm_reset_error();
        valid_inst_mask = ((cur_work_inst_map & snd_err_inst_map) | new_added_inst_map);
        valid_inst = (param->nodes_list.inst_map) & (~((uint64)0x1 << (uint64)(param->inst_id))) & valid_inst_mask;
        valid_inst = (~recv_msg->version_not_match_inst & valid_inst);
        if (valid_inst == 0) {
            if (recv_msg->version_not_match_inst != 0) {
                recv_msg->version_not_match_inst = 0;
                return ERR_GR_VERSION_NOT_MATCH;
            }
            LOG_DEBUG_INF("[MES] No inst need to broadcast.");
            return CM_SUCCESS;
        }
        LOG_DEBUG_INF("[MES] Try broadcast num is %u, head cmd is %u.", i, gr_head->gr_cmd);
        uint32_t count = cm_bitmap64_count(valid_inst);
        uint32_t valid_inst_arr[GR_MAX_INSTANCES] = {0};
        gr_get_valid_inst(valid_inst, valid_inst_arr, count);
        (void)mes_broadcast_request_sp(
            (inst_type *)valid_inst_arr, count, gr_head->flags, &gr_head->ruid, (char *)gr_head, gr_head->size);
        succ_req_inst = valid_inst;
        if (!recv_msg->ignore_ack) {
            ret = gr_handle_recv_broadcast_msg(gr_head->ruid, timeout, &succ_ack_inst, recv_msg);
        } else {
            gr_handle_discard_recv_broadcast_msg(gr_head->ruid);
            ret = CM_SUCCESS;
            succ_ack_inst = succ_req_inst;
        }

        uint64 succ_inst = valid_inst & succ_ack_inst;
        LOG_DEBUG_INF(
            "[MES] Try broadcast num is %u, valid_inst is %llu, succ_inst is %llu.", i, valid_inst, succ_inst);
        if (succ_inst != 0) {
            recv_msg->succ_inst = recv_msg->succ_inst | succ_inst;
        }
        if (ret == CM_SUCCESS && succ_req_inst == succ_ack_inst) {
            if (recv_msg->version_not_match_inst != 0) {
                recv_msg->version_not_match_inst = 0;
                return ERR_GR_VERSION_NOT_MATCH;
            }
            return ret;
        }
        // ready for next try only new added and (send req failed or recv ack  failed)
        snd_err_inst_map = valid_inst_mask & (~(succ_req_inst & succ_ack_inst));
        last_inst_inst_map = cur_work_inst_map;
        cur_work_inst_map = gr_get_inst_work_status();
        new_added_inst_map = (~last_inst_inst_map & cur_work_inst_map);
        cm_sleep(GR_BROADCAST_MSG_TRY_SLEEP_TIME);
        i++;
    } while (i < GR_BROADCAST_MSG_TRY_MAX);
    cm_reset_error();
    GR_THROW_ERROR(ERR_GR_MES_ILL, "Failed to broadcast msg with try.");
    LOG_RUN_ERR("[GR] THROW UP ERROR WHEN BROADCAST FAILED, errcode:%d", cm_get_error_code());
    return CM_ERROR;
}

static status_t gr_broadcast_msg(char *req_buf, uint32_t size, gr_recv_msg_t *recv_msg, unsigned int timeout)
{
    return gr_broadcast_msg_with_try((gr_message_head_t *)req_buf, recv_msg, timeout);
}

static bool32 gr_check_srv_status(mes_msg_t *msg)
{
    gr_message_head_t *gr_head = (gr_message_head_t *)(msg->buffer);
    if (g_gr_instance.status != GR_STATUS_OPEN && gr_head->gr_cmd != GR_CMD_ACK_JOIN_CLUSTER) {
        LOG_DEBUG_INF("[MES] Could not exec remote req for the grserver is not open or msg not join cluster, src "
                      "node:%u, wait try again.",
            (uint32_t)(gr_head->src_inst));
        return CM_FALSE;
    }
    return CM_TRUE;
}

static status_t gr_prepare_ack_msg(
    gr_session_t *session, status_t ret, char **ack_buf, uint32_t *ack_size, uint32_t version)
{
    int32_t code;
    const char *message = NULL;
    gr_packet_t *send_pack = &session->send_pack;

    if (ret != CM_SUCCESS) {
        gr_init_set(send_pack, version);
        *ack_buf = GR_WRITE_ADDR(send_pack);
        cm_get_error(&code, &message);
        CM_RETURN_IFERR(gr_put_int32(send_pack, code));
        CM_RETURN_IFERR(gr_put_str(send_pack, message));
    } else {
        *ack_buf = send_pack->buf + sizeof(gr_packet_head_t);
    }
    *ack_size = send_pack->head->size - sizeof(gr_packet_head_t);
    return CM_SUCCESS;
}

static status_t gr_process_remote_req_prepare(gr_session_t *session, mes_msg_t *msg, gr_processor_t *processor)
{
    gr_message_head_t *gr_head = (gr_message_head_t *)msg->buffer;
    // ready the ack connection
    gr_check_peer_by_inst(&g_gr_instance, gr_head->src_inst);
    if (gr_head->gr_cmd != GR_CMD_REQ_BROADCAST &&
        (!gr_need_exec_local() || get_instance_status_proc() != GR_STATUS_OPEN)) {
        LOG_RUN_ERR("Proc msg cmd:%u from remote node:%u fail, can NOT exec here.", (uint32_t)gr_head->gr_cmd,
            gr_head->src_inst);
        return CM_ERROR;
    }

    if (gr_check_srv_status(msg) != CM_TRUE) {
        LOG_RUN_WAR("Proc msg cmd:%u from remote node:%u fail, local status %u not open, wait try again.",
            (uint32_t)gr_head->gr_cmd, gr_head->src_inst, g_gr_instance.status);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t gr_process_remote_ack_prepare(gr_session_t *session, mes_msg_t *msg, gr_processor_t *processor)
{
    if (gr_check_srv_status(msg) != CM_TRUE) {
        gr_message_head_t *gr_head = (gr_message_head_t *)msg->buffer;
        LOG_RUN_WAR("Proc msg cmd:%u from remote node:%u fail, local status %u not open, wait try again.",
            (uint32_t)gr_head->gr_cmd, gr_head->src_inst, g_gr_instance.status);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void gr_process_message(uint32_t work_idx, ruid_type ruid, mes_msg_t *msg)
{
    cm_reset_error();

    DDES_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(
        GR_FI_MES_PROC_ENTER, cm_sleep(ddes_fi_get_entry_value(DDES_FI_TYPE_CUSTOM_FAULT)));

    gr_config_t *inst_cfg = gr_get_inst_cfg();
    uint32_t mes_sess_cnt = inst_cfg->params.channel_num + inst_cfg->params.work_thread_cnt;
    if (work_idx >= mes_sess_cnt) {
        cm_panic(0);
    }
    if (msg->size < GR_MES_MSG_HEAD_SIZE) {
        LOG_RUN_ERR("invalid message req size.");
        return;
    }
    gr_message_head_t *gr_head = (gr_message_head_t *)msg->buffer;
    LOG_DEBUG_INF("[MES] Proc msg cmd:%u, src node:%u, dst node:%u begin.", (uint32_t)(gr_head->gr_cmd),
        (uint32_t)(gr_head->src_inst), (uint32_t)(gr_head->dst_inst));

    gr_session_ctrl_t *session_ctrl = gr_get_session_ctrl();
    gr_session_t *session = session_ctrl->sessions[work_idx];
    status_t ret;
    if (gr_head->size < GR_MES_MSG_HEAD_SIZE) {
        LOG_RUN_ERR("Invalid message size");
        return;
    }
    gr_set_cluster_proto_vers((uint8)gr_head->src_inst, gr_head->sw_proto_ver);
    if (gr_head->msg_proto_ver > GR_PROTO_VERSION) {
        uint32_t curr_proto_ver = MIN(gr_head->sw_proto_ver, GR_PROTO_VERSION);
        gr_ack_version_not_match(session, gr_head, curr_proto_ver);
        return;
    }
    if (gr_head->gr_cmd >= GR_CMD_CEIL) {
        LOG_RUN_ERR("Invalid request received,cmd is %u.", (uint8)gr_head->gr_cmd);
        return;
    }
    gr_init_packet(&session->recv_pack, CM_FALSE);
    gr_init_packet(&session->send_pack, CM_FALSE);
    gr_init_set(&session->send_pack, gr_head->msg_proto_ver);
    session->proto_version = gr_head->msg_proto_ver;
    LOG_DEBUG_INF(
        "[MES] gr process message, cmd is %u, proto_version is %u.", gr_head->gr_cmd, gr_head->msg_proto_ver);
    gr_processor_t *processor = &g_gr_processors[gr_head->gr_cmd];
    const char *error_message = NULL;
    int32_t error_code;
    // from here, the proc need to give the ack and release message buf
    while (CM_TRUE) {
        cm_latch_s(&g_gr_instance.switch_latch, GR_DEFAULT_SESSIONID, CM_FALSE, LATCH_STAT(LATCH_SWITCH));
        if (processor->is_req) {
            ret = gr_process_remote_req_prepare(session, msg, processor);
        } else {
            ret = gr_process_remote_ack_prepare(session, msg, processor);
        }
        if (ret != CM_SUCCESS) {
            cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            return;
        }
        processor->proc(session, msg);
        cm_get_error(&error_code, &error_message);
        if (error_code != CM_SUCCESS) {
            cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            LOG_RUN_INF("Error processing message, code: %d", error_code);
            cm_reset_error();
            continue;
        }
        cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        break;
    }
    LOG_DEBUG_INF("[MES] Proc msg cmd:%u, src node:%u, dst node:%u end.", (uint32_t)(gr_head->gr_cmd),
        (uint32_t)(gr_head->src_inst), (uint32_t)(gr_head->dst_inst));
}

// add function
static status_t gr_register_proc(void)
{
    mes_register_proc_func(gr_process_message);
    return CM_SUCCESS;
}

#define GR_MES_PRIO_CNT 2
static status_t gr_set_mes_message_pool(unsigned long long recv_msg_buf_size, mes_profile_t *profile)
{
    LOG_DEBUG_INF("mes message pool size:%llu", recv_msg_buf_size);
    int ret = CM_SUCCESS;
    mes_msg_pool_attr_t *mpa = &profile->msg_pool_attr;
    mpa->total_size = recv_msg_buf_size;
    mpa->enable_inst_dimension = CM_FALSE;
    mpa->buf_pool_count = GR_MSG_BUFFER_NO_CEIL;

    mpa->buf_pool_attr[GR_MSG_BUFFER_NO_0].buf_size = GR_FIRST_BUFFER_LENGTH;
    mpa->buf_pool_attr[GR_MSG_BUFFER_NO_1].buf_size = GR_SECOND_BUFFER_LENGTH;
    mpa->buf_pool_attr[GR_MSG_BUFFER_NO_2].buf_size = GR_THIRD_BUFFER_LENGTH;
    mpa->buf_pool_attr[GR_MSG_BUFFER_NO_3].buf_size = GR_FOURTH_BUFFER_LENGTH;

    mes_msg_buffer_pool_attr_t *buf_pool_attr;
    buf_pool_attr = &mpa->buf_pool_attr[GR_MSG_BUFFER_NO_3];
    buf_pool_attr->shared_pool_attr.queue_num = GR_MSG_FOURTH_BUFFER_QUEUE_NUM;
    for (uint32_t prio = 0; prio < profile->priority_cnt; prio++) {
        buf_pool_attr->priority_pool_attr[prio].queue_num = GR_MSG_FOURTH_BUFFER_QUEUE_NUM;
    }

    for (uint8 buf_pool_no = 0; buf_pool_no < mpa->buf_pool_count; buf_pool_no++) {
        buf_pool_attr = &mpa->buf_pool_attr[buf_pool_no];
        buf_pool_attr->shared_pool_attr.queue_num = GR_MSG_BUFFER_QUEUE_NUM;
        for (uint32_t prio = 0; prio < profile->priority_cnt; prio++) {
            buf_pool_attr->priority_pool_attr[prio].queue_num = GR_MSG_BUFFER_QUEUE_NUM;
        }
    }

    for (uint32_t prio = 0; prio < profile->priority_cnt; prio++) {
        mpa->max_buf_size[prio] = mpa->buf_pool_attr[GR_MSG_BUFFER_NO_3].buf_size;
    }

    mes_msg_pool_minimum_info_t minimum_info ={0};
    ret = mes_get_message_pool_minimum_info(profile, CM_FALSE, &minimum_info);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[GR] set mes message pool, get message pool minimum info failed");
        return ret;
    }
    // want fourth buf_pool smallest
    double fourth_ratio = ((double)(minimum_info.buf_pool_minimum_size[GR_MSG_BUFFER_NO_3]) /
                              (mpa->total_size - minimum_info.metadata_size)) +
                          DBL_EPSILON;
    mpa->buf_pool_attr[GR_MSG_BUFFER_NO_3].proportion = fourth_ratio;

    double left_ratio = 1 - fourth_ratio;
    mpa->buf_pool_attr[GR_MSG_BUFFER_NO_0].proportion = GR_FIRST_BUFFER_RATIO * left_ratio;
    mpa->buf_pool_attr[GR_MSG_BUFFER_NO_1].proportion = GR_SECOND_BUFFER_RATIO * left_ratio;
    mpa->buf_pool_attr[GR_MSG_BUFFER_NO_2].proportion =
        1 - (mpa->buf_pool_attr[GR_MSG_BUFFER_NO_0].proportion + mpa->buf_pool_attr[GR_MSG_BUFFER_NO_1].proportion +
                mpa->buf_pool_attr[GR_MSG_BUFFER_NO_3].proportion);
    return CM_SUCCESS;
}

static void gr_set_group_task_num(gr_config_t *gr_profile, mes_profile_t *mes_profile)
{
    uint32_t work_thread_cnt_load_meta =
        (uint32_t)(gr_profile->params.work_thread_cnt * GR_WORK_THREAD_LOAD_DATA_PERCENT);
    if (work_thread_cnt_load_meta == 0) {
        work_thread_cnt_load_meta = 1;
    }
    uint32_t work_thread_cnt_comm = (gr_profile->params.work_thread_cnt - work_thread_cnt_load_meta);
    mes_profile->send_directly = CM_TRUE;
    mes_profile->send_task_count[MES_PRIORITY_ZERO] = 0;
    mes_profile->work_task_count[MES_PRIORITY_ZERO] = work_thread_cnt_load_meta;
    mes_profile->recv_task_count[MES_PRIORITY_ZERO] =
        MAX(1, (uint32_t)(work_thread_cnt_load_meta * GR_RECV_WORK_THREAD_RATIO));

    mes_profile->send_task_count[MES_PRIORITY_ONE] = 0;
    mes_profile->work_task_count[MES_PRIORITY_ONE] = work_thread_cnt_comm;
    mes_profile->recv_task_count[MES_PRIORITY_ONE] =
        MAX(1, (uint32_t)(work_thread_cnt_comm * GR_RECV_WORK_THREAD_RATIO));
}

static status_t gr_set_mes_profile(mes_profile_t *profile)
{
    errno_t errcode = memset_sp(profile, sizeof(mes_profile_t), 0, sizeof(mes_profile_t));
    securec_check_ret(errcode);

    gr_config_t *inst_cfg = gr_get_inst_cfg();
    profile->inst_id = (uint32_t)inst_cfg->params.inst_id;
    profile->pipe_type = (mes_pipe_type_t)inst_cfg->params.pipe_type;
    profile->channel_cnt = inst_cfg->params.channel_num;
    profile->conn_created_during_init = 0;
    profile->mes_elapsed_switch = inst_cfg->params.elapsed_switch;
    profile->mes_with_ip = inst_cfg->params.mes_with_ip;
    profile->ip_white_list_on = inst_cfg->params.ip_white_list_on;
    profile->inst_cnt = inst_cfg->params.nodes_list.inst_cnt;
    uint32_t inst_cnt = 0;
    for (uint32_t i = 0; i < GR_MAX_INSTANCES; i++) {
        uint64_t inst_mask = ((uint64)0x1 << i);
        if ((inst_cfg->params.nodes_list.inst_map & inst_mask) == 0) {
            continue;
        }
        errcode = strncpy_s(profile->inst_net_addr[inst_cnt].ip, CM_MAX_IP_LEN, inst_cfg->params.nodes_list.nodes[i],
            strlen(inst_cfg->params.nodes_list.nodes[i]));
        if (errcode != EOK) {
            GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_SYSTEM_CALL, (errcode)));
        }
        profile->inst_net_addr[inst_cnt].port = inst_cfg->params.nodes_list.ports[i];
        profile->inst_net_addr[inst_cnt].need_connect = CM_TRUE;
        profile->inst_net_addr[inst_cnt].inst_id = i;
        inst_cnt++;
        if (inst_cnt == inst_cfg->params.nodes_list.inst_cnt) {
            break;
        }
    }
    profile->priority_cnt = GR_MES_PRIO_CNT;
    profile->frag_size = GR_FOURTH_BUFFER_LENGTH;
    profile->max_wait_time = inst_cfg->params.mes_wait_timeout;
    profile->connect_timeout = (int)CM_CONNECT_TIMEOUT;
    profile->socket_timeout = (int)CM_NETWORK_IO_TIMEOUT;

    gr_set_group_task_num(inst_cfg, profile);
    status_t status = gr_set_mes_message_pool(inst_cfg->params.mes_pool_size, profile);
    if (status != CM_SUCCESS) {
        return status;
    }
    profile->tpool_attr.enable_threadpool = CM_FALSE;
    return CM_SUCCESS;
}

static status_t gr_create_mes_session(void)
{
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    uint32_t mes_sess_cnt = inst_cfg->params.channel_num + inst_cfg->params.work_thread_cnt;
    gr_session_ctrl_t *session_ctrl = gr_get_session_ctrl();
    cm_spin_lock(&session_ctrl->lock, NULL);
    if (session_ctrl->used_count > 0) {
        GR_RETURN_IFERR3(CM_ERROR,
            LOG_RUN_ERR("gr_create_mes_session failed, mes must occupy first %u sessions.", mes_sess_cnt),
            cm_spin_unlock(&session_ctrl->lock));
    }
    
    for (uint32_t i = 0; i < mes_sess_cnt; i++) {
        gr_session_t *session = session_ctrl->sessions[i];
        session->is_direct = CM_TRUE;
        session->is_closed = CM_FALSE;
        session->is_used = CM_FALSE;
    }
    session_ctrl->used_count = mes_sess_cnt;
    cm_spin_unlock(&session_ctrl->lock);
    return CM_SUCCESS;
}

status_t gr_startup_mes(void)
{
    if (g_gr_instance.is_maintain) {
        return CM_SUCCESS;
    }
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    if (inst_cfg->params.nodes_list.inst_cnt <= 1) {
        return CM_SUCCESS;
    }

    status_t status = gr_register_proc();
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("gr_register_proc failed."));

    mes_profile_t profile;
    status = gr_set_mes_profile(&profile);
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("gr_set_mes_profile failed."));

    status = gr_create_mes_session();
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("gr_set_mes_profile failed."));
    /*
    regist_invalidate_other_nodes_proc();
    regist_broadcast_check_file_open_proc();
    regist_meta_syn2other_nodes_proc();
    */
    return mes_init(&profile);
}

void gr_stop_mes(void)
{
    if (g_gr_instance.is_maintain) {
        return;
    }
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    if (g_inst_cfg != NULL && inst_cfg->params.nodes_list.inst_cnt <= 1) {
        return;
    }
    mes_uninit();
}

status_t gr_notify_sync(char *buffer, uint32_t size, gr_recv_msg_t *recv_msg)
{
    CM_ASSERT(buffer != NULL);
    CM_ASSERT(size < SIZE_K(1));
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    uint32_t timeout = inst_cfg->params.mes_wait_timeout;
    status_t status = gr_broadcast_msg(buffer, size, recv_msg, timeout);
    return status;
}

status_t gr_notify_sync_ex(char *buffer, uint32_t size, gr_recv_msg_t *recv_msg)
{
    CM_ASSERT(buffer != NULL);
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    uint32_t timeout = inst_cfg->params.mes_wait_timeout;
    status_t status = gr_broadcast_msg(buffer, size, recv_msg, timeout);
    return status;
}

static void gr_check_inst_conn(uint32_t id, uint64 old_inst_stat, uint64 cur_inst_stat)
{
    if (old_inst_stat == cur_inst_stat) {
        return;
    }
    if (old_inst_stat == 0) {
        (void)mes_connect_instance(id);
    } else {
        (void)mes_disconnect_instance(id);
    }
}

void gr_check_mes_conn(uint64 cur_inst_map)
{
    gr_config_t *inst_cfg = gr_get_inst_cfg();

    uint64 old_inst_map = gr_get_inst_work_status();
    if (old_inst_map == cur_inst_map) {
        return;
    }
    gr_set_inst_work_status(cur_inst_map);
    uint32_t inst_cnt = 0;
    for (uint32_t id = 0; id < GR_MAX_INSTANCES; id++) {
        if (id == inst_cfg->params.inst_id) {
            continue;
        }
        uint64_t inst_mask = ((uint64)0x1 << id);
        if ((inst_cfg->params.nodes_list.inst_map & inst_mask) == 0) {
            continue;
        }
        gr_check_inst_conn(id, (old_inst_map & inst_mask), (cur_inst_map & inst_mask));
        inst_cnt++;
        if (inst_cnt == inst_cfg->params.nodes_list.inst_cnt) {
            break;
        }
    }
}

static uint32_t gr_get_remote_proto_ver(uint32_t remoteid)
{
    if (remoteid >= GR_MAX_INSTANCES) {
        LOG_RUN_ERR("Invalid remote id:%u.", remoteid);
        return GR_PROTO_VERSION;
    }
    uint32_t remote_proto_ver = (uint32_t)cm_atomic32_get((atomic32_t *)&g_gr_instance.cluster_proto_vers[remoteid]);
    if (remote_proto_ver == GR_INVALID_VERSION) {
        return GR_PROTO_VERSION;
    }
    remote_proto_ver = MIN(remote_proto_ver, GR_PROTO_VERSION);
    return remote_proto_ver;
}

static int gr_get_mes_response(ruid_type ruid, mes_msg_t *response, int timeout_ms)
{
    int ret = mes_get_response(ruid, response, timeout_ms);
    if (ret == CM_SUCCESS) {
        gr_message_head_t *ack_head = (gr_message_head_t *)response->buffer;
        if (ack_head->size < GR_MES_MSG_HEAD_SIZE) {
            LOG_RUN_ERR("Invalid message size");
            GR_THROW_ERROR(ERR_GR_MES_ILL, "msg len is invalid");
            mes_release_msg(response);
            return ERR_GR_MES_ILL;
        }
        gr_set_cluster_proto_vers((uint8)ack_head->src_inst, ack_head->sw_proto_ver);
    }
    return ret;
}

status_t gr_exec_sync(gr_session_t *session, uint32_t remoteid, uint32_t currtid, status_t *remote_result)
{
    status_t ret = CM_ERROR;
    gr_message_head_t gr_head;
    mes_msg_t msg;
    gr_message_head_t *ack_head = NULL;
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    uint32_t timeout = inst_cfg->params.mes_wait_timeout;
    uint32_t new_proto_ver = gr_get_version(&session->recv_pack);
    do {
        uint32_t buf_size = GR_MES_MSG_HEAD_SIZE + session->recv_pack.head->size;
        // 1.init mes head, gr head, wrbody
        gr_init_mes_head(
            &gr_head, GR_CMD_REQ_SYB2ACTIVE, 0, (uint16)currtid, (uint16)remoteid, buf_size, new_proto_ver, 0);
        // 2. send request to remote
        ret = mes_send_request_x(gr_head.dst_inst, gr_head.flags, &gr_head.ruid, 2, &gr_head, GR_MES_MSG_HEAD_SIZE,
            session->recv_pack.buf, session->recv_pack.head->size);
        char *err_msg = "The gr server fails to send messages to the remote node";
        GR_RETURN_IFERR2(ret, LOG_RUN_ERR("%s, src node(%u), dst node(%u).", err_msg, currtid, remoteid));
        // 3. receive msg from remote
        ret = gr_get_mes_response(gr_head.ruid, &msg, timeout);
        GR_RETURN_IFERR2(
            ret, LOG_RUN_ERR("gr server receive msg from remote failed, src node:%u, dst node:%u, cmd:%u.", currtid,
                     remoteid, session->recv_pack.head->cmd));
        // 4. attach remote execution result
        ack_head = (gr_message_head_t *)msg.buffer;
        if (ack_head->result == ERR_GR_VERSION_NOT_MATCH) {
            session->client_version = gr_get_client_version(&session->recv_pack);
            new_proto_ver = MIN(ack_head->sw_proto_ver, GR_PROTO_VERSION);
            new_proto_ver = MIN(new_proto_ver, session->client_version);
            session->proto_version = new_proto_ver;
            if (session->proto_version != gr_get_version(&session->recv_pack)) {
                LOG_RUN_INF("[CHECK_PROTO]The client protocol version need be changed, old protocol version is %u, new "
                            "protocol version is %u",
                    gr_get_version(&session->recv_pack), session->proto_version);
                GR_THROW_ERROR(
                    ERR_GR_VERSION_NOT_MATCH, gr_get_version(&session->recv_pack), session->proto_version);
                *remote_result = ERR_GR_VERSION_NOT_MATCH;
                mes_release_msg(&msg);
                return ret;
            } else {
                gr_head.msg_proto_ver = new_proto_ver;
                // if msg version has changed, please motify your change
                mes_release_msg(&msg);
                continue;
            }
        } else {
            break;
        }
    } while (CM_TRUE);
    // errcode|errmsg
    // data
    *remote_result = ack_head->result;
    uint32_t body_size = ack_head->size - GR_MES_MSG_HEAD_SIZE;
    if (*remote_result != CM_SUCCESS) {
        if (ack_head->size < sizeof(gr_remote_exec_fail_ack_t)) {
            GR_RETURN_IFERR3(CM_ERROR, GR_THROW_ERROR(ERR_GR_MES_ILL, "msg len is invalid"), mes_release_msg(&msg));
        }
        gr_remote_exec_fail_ack_t *fail_ack = (gr_remote_exec_fail_ack_t *)msg.buffer;
        GR_THROW_ERROR(ERR_GR_PROCESS_REMOTE, fail_ack->err_code, fail_ack->err_msg);
    } else if (body_size > 0) {
        gr_remote_exec_succ_ack_t *succ_ack = (gr_remote_exec_succ_ack_t *)msg.buffer;
        LOG_DEBUG_INF("[MES] gr server receive msg from remote node, cmd:%u, ack to cli data size:%u.",
            session->recv_pack.head->cmd, body_size);
        gr_remote_ack_hdl_t *handle = gr_get_remote_ack_handle(session->recv_pack.head->cmd);
        if (handle != NULL) {
            handle->proc(session, succ_ack);
        }
        // do not parse the format
        ret = gr_put_data(&session->send_pack, succ_ack->body_buf, body_size);
    }
    mes_release_msg(&msg);
    return ret;
}

status_t gr_exec_on_remote(uint8 cmd, char *req, int32_t req_size, char *ack, int ack_size, status_t *remote_result)
{
    status_t ret = CM_ERROR;
    gr_message_head_t *gr_head = (gr_message_head_t *)req;
    gr_message_head_t *ack_head = NULL;
    gr_session_t *session = NULL;
    uint32_t remoteid = GR_INVALID_ID32;
    uint32_t currid = GR_INVALID_ID32;
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    uint32_t timeout = inst_cfg->params.mes_wait_timeout;
    mes_msg_t msg;
    if (gr_create_session(NULL, &session) != CM_SUCCESS) {
        LOG_RUN_ERR("Exec cmd:%u on remote node create session fail.", (uint32_t)cmd);
        return CM_ERROR;
    }

    GR_RETURN_IF_ERROR(gr_get_exec_nodeid(session, &currid, &remoteid));

    LOG_DEBUG_INF("[MES] Exec cmd:%u on remote node:%u begin.", (uint32_t)cmd, remoteid);
    do {
        uint32_t proto_ver = gr_get_remote_proto_ver(remoteid);
        // 1. init msg head
        gr_init_mes_head(gr_head, cmd, 0, (uint16)currid, (uint16)remoteid, req_size, proto_ver, 0);
        // 2. send request to remote
        ret = mes_send_request(remoteid, gr_head->flags, &gr_head->ruid, req, gr_head->size);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Exec cmd:%u on remote node:%u send msg fail.", (uint32_t)cmd, remoteid);
            gr_destroy_session(session);
            return ERR_GR_MES_ILL;
        }
        // 3. receive msg from remote
        ret = gr_get_mes_response(gr_head->ruid, &msg, timeout);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Exec cmd:%u on remote node:%u  recv msg fail.", (uint32_t)cmd, remoteid);
            gr_destroy_session(session);
            return ERR_GR_MES_ILL;
        }
        ack_head = (gr_message_head_t *)msg.buffer;
        if (ack_head->result == ERR_GR_VERSION_NOT_MATCH) {
            // if msg version has changed, please motify your change
            mes_release_msg(&msg);
            continue;
        }
        break;
    } while (CM_TRUE);
    // 4. attach remote execution result
    *remote_result = ack_head->result;
    LOG_DEBUG_INF("[MES] gr server receive msg from remote node, cmd:%u, ack to cli data size:%hu, remote_result:%u.",
        ack_head->gr_cmd, ack_head->size, (uint32_t)*remote_result);
    if (*remote_result != CM_SUCCESS) {
        if (ack_head->size < sizeof(gr_remote_exec_fail_ack_t)) {
            GR_THROW_ERROR(ERR_GR_MES_ILL, "msg len is invalid");
            GR_RETURN_IFERR3(CM_ERROR, gr_destroy_session(session), mes_release_msg(&msg));
        }
        gr_remote_exec_fail_ack_t *fail_ack = (gr_remote_exec_fail_ack_t *)msg.buffer;
        GR_THROW_ERROR(ERR_GR_PROCESS_REMOTE, fail_ack->err_code, fail_ack->err_msg);
    } else {
        if (ack_head->size != ack_size) {
            GR_THROW_ERROR(ERR_GR_MES_ILL, "msg len is invalid");
            GR_RETURN_IFERR3(CM_ERROR, gr_destroy_session(session), mes_release_msg(&msg));
        }
        errno_t err = memcpy_s(ack, (size_t)ack_size, msg.buffer, (size_t)ack_head->size);
        if (err != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
            ret = CM_ERROR;
        }
    }

    mes_release_msg(&msg);
    gr_destroy_session(session);
    LOG_DEBUG_INF("[MES] Exec cmd:%u on remote node:%u end.", (uint32_t)cmd, remoteid);
    return ret;
}

void gr_proc_syb2active_req(gr_session_t *session, mes_msg_t *msg)
{
    gr_message_head_t req_head = *(gr_message_head_t *)(msg->buffer);
    uint32_t size = req_head.size - GR_MES_MSG_HEAD_SIZE;
    uint16 srcid = req_head.src_inst;
    uint16 dstid = req_head.dst_inst;
    ruid_type ruid = req_head.ruid;
    if (size > GR_MAX_PACKET_SIZE) {
        LOG_RUN_ERR(
            "The gr server receive msg from remote failed, src node:%u, dst node:%u, size is %u.", srcid, dstid, size);
        return;
    }
    LOG_DEBUG_INF("[MES] The gr server receive messages from remote node, src node:%u, dst node:%u.", srcid, dstid);
    errno_t errcode = memcpy_s(session->recv_pack.buf, size, msg->buffer + GR_MES_MSG_HEAD_SIZE, size);
    if (errcode != EOK) {
        LOG_RUN_ERR("The gr server memcpy msg failed, src node:%u, dst node:%u.", srcid, dstid);
        return;
    }
    status_t ret = gr_proc_standby_req(session);
    char *body_buf = NULL;
    uint32_t body_size = 0;
    status_t status = gr_prepare_ack_msg(session, ret, &body_buf, &body_size, req_head.msg_proto_ver);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("The gr server prepare ack msg failed, src node:%u, dst node:%u.", srcid, dstid);
        return;
    }
    LOG_DEBUG_INF(
        "[MES] The gr server send messages to the remote node, src node:%u, dst node:%u, cmd:%u,ack size:%u.", srcid,
        dstid, session->send_pack.head->cmd, body_size);
    gr_message_head_t ack;
    gr_init_mes_head(
        &ack, GR_CMD_ACK_SYB2ACTIVE, 0, dstid, srcid, body_size + GR_MES_MSG_HEAD_SIZE, req_head.msg_proto_ver, ruid);
    ack.result = ret;
    ret = mes_send_response_x(ack.dst_inst, ack.flags, ack.ruid, 2, &ack, GR_MES_MSG_HEAD_SIZE, body_buf, body_size);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("The gr server fails to send messages to the remote node, src node:%u, dst node:%u.",
            (uint32_t)(ack.src_inst), (uint32_t)(ack.dst_inst));
        return;
    }
    LOG_DEBUG_INF("[MES] The gr server send messages to the remote node success, src node:%u, dst node:%u.",
        (uint32_t)(ack.src_inst), (uint32_t)(ack.dst_inst));
}

status_t gr_join_cluster(bool32 *join_succ)
{
    *join_succ = CM_FALSE;

    LOG_DEBUG_INF("[MES] Try join cluster begin.");

    gr_join_cluster_req_t req;
    gr_config_t *cfg = gr_get_inst_cfg();
    req.reg_id = (uint32_t)(cfg->params.inst_id);

    status_t remote_result;
    gr_join_cluster_ack_t ack;
    status_t ret = gr_exec_on_remote(GR_CMD_REQ_JOIN_CLUSTER, (char *)&req, sizeof(gr_join_cluster_req_t),
        (char *)&ack, sizeof(gr_join_cluster_ack_t), &remote_result);
    if (ret != CM_SUCCESS || remote_result != CM_SUCCESS) {
        LOG_RUN_ERR("Try join cluster exec fail.");
        return CM_ERROR;
    }
    if (ack.is_reg) {
        *join_succ = CM_TRUE;
    }

    LOG_DEBUG_INF("[MES] Try join cluster exec result:%u.", (uint32_t)*join_succ);
    return CM_SUCCESS;
}

void gr_proc_join_cluster_req(gr_session_t *session, mes_msg_t *msg)
{
    gr_message_head_t *req_head = (gr_message_head_t *)msg->buffer;
    if (req_head->size != sizeof(gr_join_cluster_req_t)) {
        LOG_RUN_ERR("Proc join cluster from remote node:%u check req msg fail.", (uint32_t)(req_head->src_inst));
        return;
    }

    gr_join_cluster_req_t *req = (gr_join_cluster_req_t *)msg->buffer;
    uint16 dst_inst = req_head->src_inst;
    uint16 src_inst = req_head->dst_inst;
    uint32_t version = req_head->msg_proto_ver;
    ruid_type ruid = req_head->ruid;
    // please solve with your proto_ver
    LOG_DEBUG_INF(
        "[MES] Proc join cluster from remote node:%u reg node:%u begin.", (uint32_t)(req_head->src_inst), req->reg_id);

    // only in the work_status map can join the cluster

    gr_join_cluster_ack_t ack;
    gr_init_mes_head(
        &ack.ack_head, GR_CMD_ACK_JOIN_CLUSTER, 0, src_inst, dst_inst, sizeof(gr_join_cluster_ack_t), version, ruid);
    ack.is_reg = CM_FALSE;
    ack.ack_head.result = CM_SUCCESS;
    uint64 work_status = gr_get_inst_work_status();
    uint64 inst_mask = ((uint64)0x1 << req->reg_id);
    if (work_status & inst_mask) {
        ack.is_reg = CM_TRUE;
    }

    LOG_DEBUG_INF("[MES] Proc join cluster from remote node:%u, reg node:%u, is_reg:%u.", (uint32_t)(req_head->src_inst),
        req->reg_id, (uint32_t)ack.is_reg);
    int send_ret = mes_send_response(dst_inst, ack.ack_head.flags, ruid, (char *)&ack, ack.ack_head.size);
    if (send_ret != CM_SUCCESS) {
        LOG_RUN_ERR("Proc join cluster from remote node:%u, reg node:%u send ack fail.", (uint32_t)dst_inst, req->reg_id);
        return;
    }

    LOG_DEBUG_INF("[MES] Proc join cluster from remote node:%u, reg node:%u send ack size:%u end.", (uint32_t)dst_inst,
        req->reg_id, ack.ack_head.size);
}
