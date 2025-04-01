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
 * wr_mes.c
 *
 *
 * IDENTIFICATION
 *    src/service/wr_mes.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_types.h"
#include "cm_error.h"
#include "wr_malloc.h"
#include "wr_session.h"
#include "wr_file.h"
#include "wr_service.h"
#include "wr_instance.h"
#include "wr_api.h"
#include "wr_mes.h"
#include "wr_syn_meta.h"
#include "wr_thv.h"
#include "wr_fault_injection.h"
#include "wr_param_verify.h"

#ifndef WIN32
static __thread char *g_thv_read_buf = NULL;
#else
__declspec(thread) char *g_thv_read_buf = NULL;
#endif

void wr_proc_broadcast_req(wr_session_t *session, mes_msg_t *msg);
void wr_proc_syb2active_req(wr_session_t *session, mes_msg_t *msg);
void wr_proc_loaddisk_req(wr_session_t *session, mes_msg_t *msg);
void wr_proc_join_cluster_req(wr_session_t *session, mes_msg_t *msg);
void wr_proc_refresh_ft_by_primary_req(wr_session_t *session, mes_msg_t *msg);

void wr_proc_normal_ack(wr_session_t *session, mes_msg_t *msg)
{
    wr_message_head_t *wr_head = (wr_message_head_t *)msg->buffer;
    LOG_DEBUG_INF("[MES] Receive ack(%u),src inst(%u), dst inst(%u).", (uint32)(wr_head->wr_cmd),
        (uint32)(wr_head->src_inst), (uint32)(wr_head->dst_inst));
}

wr_processor_t g_wr_processors[WR_CMD_CEIL] = {
    [WR_CMD_REQ_BROADCAST] = {wr_proc_broadcast_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE, "wr broadcast"},
    [WR_CMD_ACK_BROADCAST_WITH_MSG] = {wr_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE,
        "wr broadcast ack with data"},
    [WR_CMD_REQ_SYB2ACTIVE] = {wr_proc_syb2active_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE,
        "wr standby to active req"},
    [WR_CMD_ACK_SYB2ACTIVE] = {wr_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE, "wr active to standby ack"},
    [WR_CMD_REQ_JOIN_CLUSTER] = {wr_proc_join_cluster_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE,
        "wr standby join in cluster to active req"},
    [WR_CMD_ACK_JOIN_CLUSTER] = {wr_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE,
        "wr active proc join in cluster to standby ack"},
};

static inline mes_priority_t wr_get_cmd_prio_id(wr_mes_command_t cmd)
{
    return g_wr_processors[cmd].prio_id;
}

typedef void (*wr_remote_ack_proc)(wr_session_t *session, wr_remote_exec_succ_ack_t *remote_ack);
typedef struct st_wr_remote_ack_hdl {
    wr_remote_ack_proc proc;
} wr_remote_ack_hdl_t;
void wr_process_remote_ack_for_get_ftid_by_path(wr_session_t *session, wr_remote_exec_succ_ack_t *remote_ack)
{
    wr_find_node_t *ft_node = (wr_find_node_t *)(remote_ack->body_buf + sizeof(uint32));
    wr_vg_info_item_t *vg_item = wr_find_vg_item(ft_node->vg_name);
    (void)wr_get_ft_node_by_ftid(session, vg_item, ft_node->ftid, CM_TRUE, CM_FALSE);
}
static wr_remote_ack_hdl_t g_wr_remote_ack_handle[WR_CMD_TYPE_OFFSET(WR_CMD_END)] = {
    [WR_CMD_TYPE_OFFSET(WR_CMD_GET_FTID_BY_PATH)] = {wr_process_remote_ack_for_get_ftid_by_path},
};

static inline wr_remote_ack_hdl_t *wr_get_remote_ack_handle(int32 cmd)
{
    if (cmd >= WR_CMD_BEGIN && cmd < WR_CMD_END) {
        return &g_wr_remote_ack_handle[WR_CMD_TYPE_OFFSET(cmd)];
    }
    return NULL;
}

static void wr_init_mes_head(wr_message_head_t *head, uint32 cmd, uint32 flags, uint16 src_inst, uint16 dst_inst,
    uint32 size, uint32 version, ruid_type ruid)
{
    (void)memset_s(head, WR_MES_MSG_HEAD_SIZE, 0, WR_MES_MSG_HEAD_SIZE);
    head->sw_proto_ver = WR_PROTO_VERSION;
    head->msg_proto_ver = version;
    head->size = size;
    head->wr_cmd = cmd;
    head->ruid = ruid;
    head->src_inst = src_inst;
    head->dst_inst = dst_inst;
    head->flags = flags | wr_get_cmd_prio_id(cmd);
}

static wr_bcast_ack_cmd_t wr_get_bcast_ack_cmd(wr_bcast_req_cmd_t bcast_op)
{
    switch (bcast_op) {
        case BCAST_REQ_DEL_DIR_FILE:
            return BCAST_ACK_DEL_FILE;
        case BCAST_REQ_INVALIDATE_META:
            return BCAST_ACK_INVALIDATE_META;
        case BCAST_REQ_META_SYN:
            return BCAST_ACK_META_SYN;
        default:
            LOG_RUN_ERR("Invalid broadcast request type");
            break;
    }
    return BCAST_ACK_END;
}
// warning: if add new broadcast req, please consider the impact of expired broadcast messages on the standby server
static void wr_proc_broadcast_req_inner(wr_session_t *session, wr_notify_req_msg_t *req)
{
    status_t status = CM_ERROR;
    bool32 cmd_ack = CM_FALSE;
    wr_notify_req_msg_ex_t *req_ex = NULL;
    switch (req->type) {
        case BCAST_REQ_DEL_DIR_FILE:
            status = wr_check_open_file_remote(session, req->vg_name, req->ftid, &cmd_ack);
            break;
        case BCAST_REQ_INVALIDATE_META:
            req_ex = (wr_notify_req_msg_ex_t *)req;
            status = wr_invalidate_meta_remote(
                session, (wr_invalidate_meta_msg_t *)req_ex->data, req_ex->data_size, &cmd_ack);
            break;
        case BCAST_REQ_META_SYN:
            req_ex = (wr_notify_req_msg_ex_t *)req;
            status = wr_meta_syn_remote(session, (wr_meta_syn_t *)req_ex->data, req_ex->data_size, &cmd_ack);
            return;
        default:
            LOG_RUN_ERR("invalid broadcast req type");
            return;
    }
    if (cm_get_error_code() == ERR_WR_SHM_LOCK_TIMEOUT) {
        LOG_RUN_ERR("broadcast is breaked by shm lock timeout.");
        return;
    }
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    wr_params_t *param = &inst_cfg->params;
    wr_message_head_t *req_head = &req->wr_head;
    uint16 dst_inst = req_head->src_inst;
    uint16 src_inst = (uint16)param->inst_id;
    uint32 version = req_head->msg_proto_ver;
    ruid_type ruid = req_head->ruid;
    wr_notify_ack_msg_t ack_check;
    wr_init_mes_head(&ack_check.wr_head, WR_CMD_ACK_BROADCAST_WITH_MSG, 0, src_inst, dst_inst,
        sizeof(wr_notify_ack_msg_t), version, ruid);
    ack_check.type = wr_get_bcast_ack_cmd(req->type);
    ack_check.result = status;
    ack_check.cmd_ack = cmd_ack;
    int ret =
        mes_send_response(dst_inst, ack_check.wr_head.flags, ruid, (char *)&ack_check, sizeof(wr_notify_ack_msg_t));
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MES] send message failed, src inst(%hhu), dst inst(%hhu) ret(%d) ", src_inst, dst_inst, ret);
        return;
    }
    WR_LOG_DEBUG_OP("[MES] Succeed to send message, notify %llu  result: %u. cmd=%u, src_inst=%hhu, dst_inst=%hhu.",
        req->ftid, cmd_ack, ack_check.wr_head.wr_cmd, ack_check.wr_head.src_inst, ack_check.wr_head.dst_inst);
}

int32 wr_process_broadcast_ack(wr_notify_ack_msg_t *ack, wr_recv_msg_t *recv_msg_output)
{
    int32 ret = ERR_WR_MES_ILL;
    switch (ack->type) {
        case BCAST_ACK_DEL_FILE:
        case BCAST_ACK_INVALIDATE_META:
        case BCAST_ACK_META_SYN:
            ret = ack->result;
            // recv_msg_output->cmd_ack init-ed with the deault, if some node not the same with the default, let's cover
            // the default value
            if (ret == CM_SUCCESS && recv_msg_output->default_ack != ack->cmd_ack) {
                recv_msg_output->cmd_ack = ack->cmd_ack;
            }
            break;
        default:
            LOG_DEBUG_ERR("invalid broadcast ack type");
            break;
    }
    return ret;
}

static void wr_ack_version_not_match(wr_session_t *session, wr_message_head_t *req_head, uint32 version)
{
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    wr_params_t *param = &inst_cfg->params;
    uint16 dst_inst = req_head->src_inst;
    uint16 src_inst = (uint16)param->inst_id;
    ruid_type ruid = req_head->ruid;
    wr_message_head_t ack_head;
    uint32 cmd = (req_head->wr_cmd == WR_CMD_REQ_BROADCAST) ? WR_CMD_ACK_BROADCAST_WITH_MSG : WR_CMD_ACK_SYB2ACTIVE;
    wr_init_mes_head(&ack_head, cmd, 0, src_inst, dst_inst, WR_MES_MSG_HEAD_SIZE, version, ruid);
    ack_head.result = ERR_WR_VERSION_NOT_MATCH;
    int ret = mes_send_response(dst_inst, ack_head.flags, ruid, (char *)&ack_head, WR_MES_MSG_HEAD_SIZE);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR(
            "send version not match message failed, src inst(%hhu), dst inst(%hhu) ret(%d)", src_inst, dst_inst, ret);
        return;
    }
    LOG_RUN_INF("send version not match message succeed, src inst(%hhu), dst inst(%hhu), ack msg version (%hhu)",
        src_inst, dst_inst, version);
}

void wr_proc_broadcast_req(wr_session_t *session, mes_msg_t *msg)
{
    if (wr_need_exec_local()) {
        LOG_RUN_INF("No need to solve broadcast msg when the current node is master.");
        return;
    }
    if (msg->size < OFFSET_OF(wr_notify_req_msg_t, type)) {
        LOG_DEBUG_ERR("invalid message req size");
        return;
    }
    wr_notify_req_msg_t *req = (wr_notify_req_msg_t *)msg->buffer;
    LOG_DEBUG_INF("[MES] Try proc broadcast req, head cmd is %u, req cmd is %u.", req->wr_head.wr_cmd, req->type);
    wr_proc_broadcast_req_inner(session, req);
    return;
}

static void wr_set_cluster_proto_vers(uint8 inst_id, uint32 version)
{
    if (inst_id >= WR_MAX_INSTANCES) {
        LOG_DEBUG_ERR("Invalid request inst_id:%hhu, version is %u.", inst_id, version);
        return;
    }
    bool32 set_flag = CM_FALSE;
    do {
        uint32 cur_version = (uint32)cm_atomic32_get((atomic32_t *)&g_wr_instance.cluster_proto_vers[inst_id]);
        if (cur_version == version) {
            break;
        }
        set_flag = cm_atomic32_cas(
            (atomic32_t *)&g_wr_instance.cluster_proto_vers[inst_id], (int32)cur_version, (int32)version);
    } while (!set_flag);
}

static int wr_handle_broadcast_msg(mes_msg_list_t *responses, wr_recv_msg_t *recv_msg_output)
{
    int ret;
    wr_message_head_t *ack_head;
    uint32 src_inst;
    for (uint32 i = 0; i < responses->count; i++) {
        mes_msg_t *msg = &responses->messages[i];
        ack_head = (wr_message_head_t *)msg->buffer;
        src_inst = responses->messages[i].src_inst;
        wr_set_cluster_proto_vers((uint8)src_inst, ack_head->sw_proto_ver);
        if (ack_head->result == ERR_WR_VERSION_NOT_MATCH) {
            recv_msg_output->version_not_match_inst |= ((uint64)0x1 << src_inst);
            continue;
        }
        if (ack_head->size < sizeof(wr_notify_ack_msg_t)) {
            WR_THROW_ERROR(ERR_WR_MES_ILL, "msg len is invalid");
            return ERR_WR_MES_ILL;
        }
        wr_notify_ack_msg_t *ack = (wr_notify_ack_msg_t *)ack_head;
        ret = wr_process_broadcast_ack(ack, recv_msg_output);
        WR_RETURN_IFERR2(ret, WR_THROW_ERROR(ERR_WR_FILE_OPENING_REMOTE, ack_head->src_inst, ack_head->wr_cmd));
    }
    return WR_SUCCESS;
}

static void wr_release_broadcast_msg(mes_msg_list_t *responses)
{
    for (uint32 i = 0; i < responses->count; i++) {
        mes_release_msg(&responses->messages[i]);
    }
}

static int wr_handle_recv_broadcast_msg(
    ruid_type ruid, uint32 timeout, uint64 *succ_ack_inst, wr_recv_msg_t *recv_msg_output)
{
    mes_msg_list_t responses;
    int ret = mes_broadcast_get_response(ruid, &responses, timeout);
    if (ret != WR_SUCCESS) {
        LOG_DEBUG_INF("[MES] Try broadcast get response failed, ret is %d, ruid is %llu.", ret, ruid);
        return ret;
    }
    ret = wr_handle_broadcast_msg(&responses, recv_msg_output);
    if (ret != WR_SUCCESS) {
        wr_release_broadcast_msg(&responses);
        LOG_DEBUG_INF("[MES] Try broadcast get response failed, ret is %d, ruid is %llu.", ret, ruid);
        return ret;
    }
    // do not care ret, just check get ack msg
    for (uint32 i = 0; i < responses.count; i++) {
        uint32 src_inst = responses.messages[i].src_inst;
        *succ_ack_inst |= ((uint64)0x1 << src_inst);
    }
    *succ_ack_inst = *succ_ack_inst & (~recv_msg_output->version_not_match_inst);
    wr_release_broadcast_msg(&responses);
    return ret;
}

static void wr_handle_discard_recv_broadcast_msg(ruid_type ruid)
{
    mes_msg_list_t responses;
    int ret = mes_broadcast_get_response(ruid, &responses, 0);
    if (ret == CM_SUCCESS) {
        wr_release_broadcast_msg(&responses);
    }
}

uint32 wr_get_broadcast_proto_ver(uint64 succ_inst)
{
    uint64 inst_mask;
    uint64 cur_work_inst_map = wr_get_inst_work_status();
    uint64 need_send_inst = (~succ_inst & cur_work_inst_map);
    uint32 inst_proto_ver;
    uint32 broadcast_proto_vers = WR_PROTO_VERSION;
    for (uint32 i = 0; i < WR_MAX_INSTANCES; i++) {
        inst_mask = ((uint64)0x1 << i);
        if ((need_send_inst & inst_mask) == 0) {
            continue;
        }
        inst_proto_ver = (uint32)cm_atomic32_get((atomic32_t *)&g_wr_instance.cluster_proto_vers[i]);
        if (inst_proto_ver == WR_INVALID_VERSION) {
            continue;
        }
        broadcast_proto_vers = MIN(broadcast_proto_vers, inst_proto_ver);
    }
    return broadcast_proto_vers;
}

void wr_get_valid_inst(uint64 valid_inst, uint32 *arr, uint32 count)
{
    uint32 i = 0;
    for (uint32 j = 0; j < WR_MAX_INSTANCES; j++) {
        if (WR_IS_INST_SEND(valid_inst, j)) {
            arr[i] = j;
            i++;
        }
    }
}

#define WR_BROADCAST_MSG_TRY_MAX 5
#define WR_BROADCAST_MSG_TRY_SLEEP_TIME 200
static status_t wr_broadcast_msg_with_try(wr_message_head_t *wr_head, wr_recv_msg_t *recv_msg, unsigned int timeout)
{
    int32 ret = WR_SUCCESS;

    wr_config_t *inst_cfg = wr_get_inst_cfg();
    wr_params_t *param = &inst_cfg->params;
    uint64 succ_req_inst = 0;
    uint64 succ_ack_inst = 0;
    uint32 i = 0;
    // init last send err with all
    uint64 cur_work_inst_map = wr_get_inst_work_status();
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
                return ERR_WR_VERSION_NOT_MATCH;
            }
            LOG_DEBUG_INF("[MES] No inst need to broadcast.");
            return CM_SUCCESS;
        }
        LOG_DEBUG_INF("[MES] Try broadcast num is %u, head cmd is %u.", i, wr_head->wr_cmd);
        uint32 count = cm_bitmap64_count(valid_inst);
        uint32 valid_inst_arr[WR_MAX_INSTANCES] = {0};
        wr_get_valid_inst(valid_inst, valid_inst_arr, count);
        (void)mes_broadcast_request_sp(
            (inst_type *)valid_inst_arr, count, wr_head->flags, &wr_head->ruid, (char *)wr_head, wr_head->size);
        succ_req_inst = valid_inst;
        if (!recv_msg->ignore_ack) {
            ret = wr_handle_recv_broadcast_msg(wr_head->ruid, timeout, &succ_ack_inst, recv_msg);
        } else {
            wr_handle_discard_recv_broadcast_msg(wr_head->ruid);
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
                return ERR_WR_VERSION_NOT_MATCH;
            }
            return ret;
        }
        // ready for next try only new added and (send req failed or recv ack  failed)
        snd_err_inst_map = valid_inst_mask & (~(succ_req_inst & succ_ack_inst));
        last_inst_inst_map = cur_work_inst_map;
        cur_work_inst_map = wr_get_inst_work_status();
        new_added_inst_map = (~last_inst_inst_map & cur_work_inst_map);
        cm_sleep(WR_BROADCAST_MSG_TRY_SLEEP_TIME);
        i++;
    } while (i < WR_BROADCAST_MSG_TRY_MAX);
    cm_reset_error();
    WR_THROW_ERROR(ERR_WR_MES_ILL, "Failed to broadcast msg with try.");
    LOG_RUN_ERR("[WR] THROW UP ERROR WHEN BROADCAST FAILED, errcode:%d", cm_get_error_code());
    return CM_ERROR;
}

static status_t wr_broadcast_msg(char *req_buf, uint32 size, wr_recv_msg_t *recv_msg, unsigned int timeout)
{
    return wr_broadcast_msg_with_try((wr_message_head_t *)req_buf, recv_msg, timeout);
}

static bool32 wr_check_srv_status(mes_msg_t *msg)
{
    wr_message_head_t *wr_head = (wr_message_head_t *)(msg->buffer);
    if (g_wr_instance.status != WR_STATUS_OPEN && wr_head->wr_cmd != WR_CMD_ACK_JOIN_CLUSTER) {
        LOG_DEBUG_INF("[MES] Could not exec remote req for the wrserver is not open or msg not join cluster, src "
                      "node:%u, wait try again.",
            (uint32)(wr_head->src_inst));
        return CM_FALSE;
    }
    return CM_TRUE;
}

static status_t wr_prepare_ack_msg(
    wr_session_t *session, status_t ret, char **ack_buf, uint32 *ack_size, uint32 version)
{
    int32 code;
    const char *message = NULL;
    wr_packet_t *send_pack = &session->send_pack;

    if (ret != CM_SUCCESS) {
        wr_init_set(send_pack, version);
        *ack_buf = WR_WRITE_ADDR(send_pack);
        cm_get_error(&code, &message);
        CM_RETURN_IFERR(wr_put_int32(send_pack, code));
        CM_RETURN_IFERR(wr_put_str(send_pack, message));
    } else {
        *ack_buf = send_pack->buf + sizeof(wr_packet_head_t);
    }
    *ack_size = send_pack->head->size - sizeof(wr_packet_head_t);
    return CM_SUCCESS;
}

void wr_proc_remote_req_err(wr_session_t *session, wr_message_head_t *req_wr_head, unsigned char cmd, int32 ret)
{
    wr_message_head_t ack;
    char *ack_buf = NULL;
    uint32 ack_size = 0;
    status_t status = wr_prepare_ack_msg(session, ret, &ack_buf, &ack_size, req_wr_head->msg_proto_ver);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The wrserver prepare ack msg failed, src node:%u, dst node:%u.", req_wr_head->src_inst,
            req_wr_head->dst_inst);
        return;
    }
    uint16 src_inst = req_wr_head->dst_inst;
    uint16 dst_inst = req_wr_head->src_inst;
    ruid_type ruid = req_wr_head->ruid;
    uint32 version = req_wr_head->msg_proto_ver;
    wr_init_mes_head(&ack, cmd, 0, src_inst, dst_inst, ack_size + WR_MES_MSG_HEAD_SIZE, version, ruid);
    ack.result = ret;
    (void)mes_send_response_x(dst_inst, ack.flags, ruid, 2, &ack, WR_MES_MSG_HEAD_SIZE, ack_buf, ack_size);
}

static status_t wr_process_remote_req_prepare(wr_session_t *session, mes_msg_t *msg, wr_processor_t *processor)
{
    wr_message_head_t *wr_head = (wr_message_head_t *)msg->buffer;
    // ready the ack connection
    wr_check_peer_by_inst(&g_wr_instance, wr_head->src_inst);
    if (wr_head->wr_cmd != WR_CMD_REQ_BROADCAST &&
        (!wr_need_exec_local() || get_instance_status_proc() != WR_STATUS_OPEN)) {
        LOG_RUN_ERR("Proc msg cmd:%u from remote node:%u fail, can NOT exec here.", (uint32)wr_head->wr_cmd,
            wr_head->src_inst);
        return CM_ERROR;
    }

    if (wr_check_srv_status(msg) != CM_TRUE) {
        LOG_RUN_WAR("Proc msg cmd:%u from remote node:%u fail, local status %u not open, wait try again.",
            (uint32)wr_head->wr_cmd, wr_head->src_inst, g_wr_instance.status);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t wr_process_remote_ack_prepare(wr_session_t *session, mes_msg_t *msg, wr_processor_t *processor)
{
    if (wr_check_srv_status(msg) != CM_TRUE) {
        wr_message_head_t *wr_head = (wr_message_head_t *)msg->buffer;
        LOG_RUN_WAR("Proc msg cmd:%u from remote node:%u fail, local status %u not open, wait try again.",
            (uint32)wr_head->wr_cmd, wr_head->src_inst, g_wr_instance.status);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void wr_process_message(uint32 work_idx, ruid_type ruid, mes_msg_t *msg)
{
    cm_reset_error();

    DDES_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(
        WR_FI_MES_PROC_ENTER, cm_sleep(ddes_fi_get_entry_value(DDES_FI_TYPE_CUSTOM_FAULT)));

    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32 mes_sess_cnt = inst_cfg->params.channel_num + inst_cfg->params.work_thread_cnt;
    if (work_idx >= mes_sess_cnt) {
        cm_panic(0);
    }
    if (msg->size < WR_MES_MSG_HEAD_SIZE) {
        LOG_DEBUG_ERR("invalid message req size.");
        return;
    }
    wr_message_head_t *wr_head = (wr_message_head_t *)msg->buffer;
    LOG_DEBUG_INF("[MES] Proc msg cmd:%u, src node:%u, dst node:%u begin.", (uint32)(wr_head->wr_cmd),
        (uint32)(wr_head->src_inst), (uint32)(wr_head->dst_inst));

    wr_session_ctrl_t *session_ctrl = wr_get_session_ctrl();
    wr_session_t *session = session_ctrl->sessions[work_idx];
    status_t ret;
    if (wr_head->size < WR_MES_MSG_HEAD_SIZE) {
        LOG_DEBUG_ERR("Invalid message size");
        return;
    }
    wr_set_cluster_proto_vers((uint8)wr_head->src_inst, wr_head->sw_proto_ver);
    if (wr_head->msg_proto_ver > WR_PROTO_VERSION) {
        uint32 curr_proto_ver = MIN(wr_head->sw_proto_ver, WR_PROTO_VERSION);
        wr_ack_version_not_match(session, wr_head, curr_proto_ver);
        return;
    }
    if (wr_head->wr_cmd >= WR_CMD_CEIL) {
        LOG_DEBUG_ERR("Invalid request received,cmd is %u.", (uint8)wr_head->wr_cmd);
        return;
    }
    wr_init_packet(&session->recv_pack, CM_FALSE);
    wr_init_packet(&session->send_pack, CM_FALSE);
    wr_init_set(&session->send_pack, wr_head->msg_proto_ver);
    session->proto_version = wr_head->msg_proto_ver;
    LOG_DEBUG_INF(
        "[MES] wr process message, cmd is %u, proto_version is %u.", wr_head->wr_cmd, wr_head->msg_proto_ver);
    wr_processor_t *processor = &g_wr_processors[wr_head->wr_cmd];
    const char *error_message = NULL;
    int32 error_code;
    // from here, the proc need to give the ack and release message buf
    while (CM_TRUE) {
        cm_latch_s(&g_wr_instance.switch_latch, WR_DEFAULT_SESSIONID, CM_FALSE, LATCH_STAT(LATCH_SWITCH));
        if (processor->is_req) {
            ret = wr_process_remote_req_prepare(session, msg, processor);
        } else {
            ret = wr_process_remote_ack_prepare(session, msg, processor);
        }
        if (ret != CM_SUCCESS) {
            cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            return;
        }
        processor->proc(session, msg);
        cm_get_error(&error_code, &error_message);
        if (error_code == ERR_WR_SHM_LOCK_TIMEOUT) {
            cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            LOG_RUN_INF("Try again if error is shm lock timeout.");
            cm_reset_error();
            continue;
        }
        cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        break;
    }
    LOG_DEBUG_INF("[MES] Proc msg cmd:%u, src node:%u, dst node:%u end.", (uint32)(wr_head->wr_cmd),
        (uint32)(wr_head->src_inst), (uint32)(wr_head->dst_inst));
}

// add function
static status_t wr_register_proc(void)
{
    mes_register_proc_func(wr_process_message);
    return CM_SUCCESS;
}

#define WR_MES_PRIO_CNT 2
static status_t wr_set_mes_message_pool(unsigned long long recv_msg_buf_size, mes_profile_t *profile)
{
    LOG_DEBUG_INF("mes message pool size:%llu", recv_msg_buf_size);
    int ret = CM_SUCCESS;
    mes_msg_pool_attr_t *mpa = &profile->msg_pool_attr;
    mpa->total_size = recv_msg_buf_size;
    mpa->enable_inst_dimension = CM_FALSE;
    mpa->buf_pool_count = WR_MSG_BUFFER_NO_CEIL;

    mpa->buf_pool_attr[WR_MSG_BUFFER_NO_0].buf_size = WR_FIRST_BUFFER_LENGTH;
    mpa->buf_pool_attr[WR_MSG_BUFFER_NO_1].buf_size = WR_SECOND_BUFFER_LENGTH;
    mpa->buf_pool_attr[WR_MSG_BUFFER_NO_2].buf_size = WR_THIRD_BUFFER_LENGTH;
    mpa->buf_pool_attr[WR_MSG_BUFFER_NO_3].buf_size = WR_FOURTH_BUFFER_LENGTH;

    mes_msg_buffer_pool_attr_t *buf_pool_attr;
    buf_pool_attr = &mpa->buf_pool_attr[WR_MSG_BUFFER_NO_3];
    buf_pool_attr->shared_pool_attr.queue_num = WR_MSG_FOURTH_BUFFER_QUEUE_NUM;
    for (uint32 prio = 0; prio < profile->priority_cnt; prio++) {
        buf_pool_attr->priority_pool_attr[prio].queue_num = WR_MSG_FOURTH_BUFFER_QUEUE_NUM;
    }

    for (uint8 buf_pool_no = 0; buf_pool_no < mpa->buf_pool_count; buf_pool_no++) {
        buf_pool_attr = &mpa->buf_pool_attr[buf_pool_no];
        buf_pool_attr->shared_pool_attr.queue_num = WR_MSG_BUFFER_QUEUE_NUM;
        for (uint32 prio = 0; prio < profile->priority_cnt; prio++) {
            buf_pool_attr->priority_pool_attr[prio].queue_num = WR_MSG_BUFFER_QUEUE_NUM;
        }
    }

    for (uint32 prio = 0; prio < profile->priority_cnt; prio++) {
        mpa->max_buf_size[prio] = mpa->buf_pool_attr[WR_MSG_BUFFER_NO_3].buf_size;
    }

    mes_msg_pool_minimum_info_t minimum_info ={0};
    ret = mes_get_message_pool_minimum_info(profile, CM_FALSE, &minimum_info);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[WR] set mes message pool, get message pool minimum info failed");
        return ret;
    }
    // want fourth buf_pool smallest
    double fourth_ratio = ((double)(minimum_info.buf_pool_minimum_size[WR_MSG_BUFFER_NO_3]) /
                              (mpa->total_size - minimum_info.metadata_size)) +
                          DBL_EPSILON;
    mpa->buf_pool_attr[WR_MSG_BUFFER_NO_3].proportion = fourth_ratio;

    double left_ratio = 1 - fourth_ratio;
    mpa->buf_pool_attr[WR_MSG_BUFFER_NO_0].proportion = WR_FIRST_BUFFER_RATIO * left_ratio;
    mpa->buf_pool_attr[WR_MSG_BUFFER_NO_1].proportion = WR_SECOND_BUFFER_RATIO * left_ratio;
    mpa->buf_pool_attr[WR_MSG_BUFFER_NO_2].proportion =
        1 - (mpa->buf_pool_attr[WR_MSG_BUFFER_NO_0].proportion + mpa->buf_pool_attr[WR_MSG_BUFFER_NO_1].proportion +
                mpa->buf_pool_attr[WR_MSG_BUFFER_NO_3].proportion);
    return CM_SUCCESS;
}

static void wr_set_group_task_num(wr_config_t *wr_profile, mes_profile_t *mes_profile)
{
    uint32 work_thread_cnt_load_meta =
        (uint32)(wr_profile->params.work_thread_cnt * WR_WORK_THREAD_LOAD_DATA_PERCENT);
    if (work_thread_cnt_load_meta == 0) {
        work_thread_cnt_load_meta = 1;
    }
    uint32 work_thread_cnt_comm = (wr_profile->params.work_thread_cnt - work_thread_cnt_load_meta);
    mes_profile->send_directly = CM_TRUE;
    mes_profile->send_task_count[MES_PRIORITY_ZERO] = 0;
    mes_profile->work_task_count[MES_PRIORITY_ZERO] = work_thread_cnt_load_meta;
    mes_profile->recv_task_count[MES_PRIORITY_ZERO] =
        MAX(1, (uint32)(work_thread_cnt_load_meta * WR_RECV_WORK_THREAD_RATIO));

    mes_profile->send_task_count[MES_PRIORITY_ONE] = 0;
    mes_profile->work_task_count[MES_PRIORITY_ONE] = work_thread_cnt_comm;
    mes_profile->recv_task_count[MES_PRIORITY_ONE] =
        MAX(1, (uint32)(work_thread_cnt_comm * WR_RECV_WORK_THREAD_RATIO));
}

static status_t wr_set_mes_profile(mes_profile_t *profile)
{
    errno_t errcode = memset_sp(profile, sizeof(mes_profile_t), 0, sizeof(mes_profile_t));
    securec_check_ret(errcode);

    wr_config_t *inst_cfg = wr_get_inst_cfg();
    profile->inst_id = (uint32)inst_cfg->params.inst_id;
    profile->pipe_type = (mes_pipe_type_t)inst_cfg->params.pipe_type;
    profile->channel_cnt = inst_cfg->params.channel_num;
    profile->conn_created_during_init = 0;
    profile->mes_elapsed_switch = inst_cfg->params.elapsed_switch;
    profile->mes_with_ip = inst_cfg->params.mes_with_ip;
    profile->ip_white_list_on = inst_cfg->params.ip_white_list_on;
    profile->inst_cnt = inst_cfg->params.nodes_list.inst_cnt;
    uint32 inst_cnt = 0;
    for (uint32 i = 0; i < WR_MAX_INSTANCES; i++) {
        uint64_t inst_mask = ((uint64)0x1 << i);
        if ((inst_cfg->params.nodes_list.inst_map & inst_mask) == 0) {
            continue;
        }
        errcode = strncpy_s(profile->inst_net_addr[inst_cnt].ip, CM_MAX_IP_LEN, inst_cfg->params.nodes_list.nodes[i],
            strlen(inst_cfg->params.nodes_list.nodes[i]));
        if (errcode != EOK) {
            WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_SYSTEM_CALL, (errcode)));
        }
        profile->inst_net_addr[inst_cnt].port = inst_cfg->params.nodes_list.ports[i];
        profile->inst_net_addr[inst_cnt].need_connect = CM_TRUE;
        profile->inst_net_addr[inst_cnt].inst_id = i;
        inst_cnt++;
        if (inst_cnt == inst_cfg->params.nodes_list.inst_cnt) {
            break;
        }
    }
    profile->priority_cnt = WR_MES_PRIO_CNT;
    profile->frag_size = WR_FOURTH_BUFFER_LENGTH;
    profile->max_wait_time = inst_cfg->params.mes_wait_timeout;
    profile->connect_timeout = (int)CM_CONNECT_TIMEOUT;
    profile->socket_timeout = (int)CM_NETWORK_IO_TIMEOUT;

    wr_set_group_task_num(inst_cfg, profile);
    status_t status = wr_set_mes_message_pool(inst_cfg->params.mes_pool_size, profile);
    if (status != CM_SUCCESS) {
        return status;
    }
    profile->tpool_attr.enable_threadpool = CM_FALSE;
    return CM_SUCCESS;
}

static status_t wr_create_mes_session(void)
{
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32 mes_sess_cnt = inst_cfg->params.channel_num + inst_cfg->params.work_thread_cnt;
    wr_session_ctrl_t *session_ctrl = wr_get_session_ctrl();
    cm_spin_lock(&session_ctrl->lock, NULL);
    if (session_ctrl->used_count > 0) {
        WR_RETURN_IFERR3(CM_ERROR,
            LOG_RUN_ERR("wr_create_mes_session failed, mes must occupy first %u sessions.", mes_sess_cnt),
            cm_spin_unlock(&session_ctrl->lock));
    }
    for (uint32 i = 0; i < mes_sess_cnt; i++) {
        wr_session_t *session = session_ctrl->sessions[i];
        session->is_direct = CM_TRUE;
        session->is_closed = CM_FALSE;
        session->is_used = CM_FALSE;
    }
    session_ctrl->used_count = mes_sess_cnt;
    cm_spin_unlock(&session_ctrl->lock);
    return CM_SUCCESS;
}

status_t wr_startup_mes(void)
{
    if (g_wr_instance.is_maintain) {
        return CM_SUCCESS;
    }
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    if (inst_cfg->params.nodes_list.inst_cnt <= 1) {
        return CM_SUCCESS;
    }

    status_t status = wr_register_proc();
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("wr_register_proc failed."));

    mes_profile_t profile;
    status = wr_set_mes_profile(&profile);
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("wr_set_mes_profile failed."));

    status = wr_create_mes_session();
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("wr_set_mes_profile failed."));

    regist_invalidate_other_nodes_proc(wr_invalidate_other_nodes);
    regist_broadcast_check_file_open_proc(wr_broadcast_check_file_open);
    regist_meta_syn2other_nodes_proc(wr_syn_data2other_nodes);
    return mes_init(&profile);
}

void wr_stop_mes(void)
{
    if (g_wr_instance.is_maintain) {
        return;
    }
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    if (g_inst_cfg != NULL && inst_cfg->params.nodes_list.inst_cnt <= 1) {
        return;
    }
    mes_uninit();
}

status_t wr_notify_sync(char *buffer, uint32 size, wr_recv_msg_t *recv_msg)
{
    CM_ASSERT(buffer != NULL);
    CM_ASSERT(size < SIZE_K(1));
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32 timeout = inst_cfg->params.mes_wait_timeout;
    status_t status = wr_broadcast_msg(buffer, size, recv_msg, timeout);
    return status;
}

status_t wr_notify_sync_ex(char *buffer, uint32 size, wr_recv_msg_t *recv_msg)
{
    CM_ASSERT(buffer != NULL);
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32 timeout = inst_cfg->params.mes_wait_timeout;
    status_t status = wr_broadcast_msg(buffer, size, recv_msg, timeout);
    return status;
}

status_t wr_notify_expect_bool_ack(wr_vg_info_item_t *vg_item, wr_bcast_req_cmd_t cmd, uint64 ftid, bool32 *cmd_ack)
{
    if (g_wr_instance.is_maintain) {
        return CM_SUCCESS;
    }
    wr_recv_msg_t recv_msg = {CM_TRUE, *cmd_ack, WR_PROTO_VERSION, 0, 0, CM_FALSE, *cmd_ack};
    recv_msg.broadcast_proto_ver = wr_get_broadcast_proto_ver(0);
    wr_notify_req_msg_t req;
    status_t ret;
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    wr_params_t *param = &inst_cfg->params;
    do {
        req.ftid = ftid;
        req.type = cmd;
        errno_t err = strncpy_s(req.vg_name, WR_MAX_NAME_LEN, vg_item->vg_name, strlen(vg_item->vg_name));
        if (err != EOK) {
            WR_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return CM_ERROR;
        }
        LOG_DEBUG_INF("[MES] notify other wr instance to do cmd %u, ftid:%llu in vg:%s.", cmd, ftid, vg_item->vg_name);
        wr_init_mes_head(&req.wr_head, WR_CMD_REQ_BROADCAST, 0, (uint16)param->inst_id, CM_INVALID_ID16,
            sizeof(wr_notify_req_msg_t), recv_msg.broadcast_proto_ver, 0);
        ret = wr_notify_sync((char *)&req, req.wr_head.size, &recv_msg);
        if (ret == ERR_WR_VERSION_NOT_MATCH) {
            uint32 new_proto_ver = wr_get_broadcast_proto_ver(recv_msg.succ_inst);
            LOG_RUN_INF("[CHECK_PROTO]broadcast msg proto version has changed, old is %hhu, new is %hhu",
                recv_msg.broadcast_proto_ver, new_proto_ver);
            recv_msg.broadcast_proto_ver = new_proto_ver;
            recv_msg.version_not_match_inst = 0;
            // if msg has been changed, need rewrite req
            continue;
        } else {
            break;
        }
    } while (CM_TRUE);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[WR]: Failed to notify other wr instance, cmd: %u, file: %llu, vg: %s, errcode:%d, "
                    "OS errno:%d, OS errmsg:%s.",
            cmd, ftid, vg_item->vg_name, cm_get_error_code(), errno, strerror(errno));
        return CM_ERROR;
    }
    *cmd_ack = recv_msg.cmd_ack;
    return ret;
}

status_t wr_notify_data_expect_bool_ack(
    wr_vg_info_item_t *vg_item, wr_bcast_req_cmd_t cmd, char *data, uint32 size, bool32 *cmd_ack)
{
    if (g_wr_instance.is_maintain) {
        return CM_SUCCESS;
    }
    wr_recv_msg_t recv_msg = {CM_TRUE, CM_TRUE, WR_PROTO_VERSION, 0, 0, CM_FALSE, CM_TRUE};
    if (cmd_ack) {
        recv_msg.cmd_ack = *cmd_ack;
        recv_msg.default_ack = *cmd_ack;
    } else {
        recv_msg.ignore_ack = CM_TRUE;
    }
    recv_msg.broadcast_proto_ver = wr_get_broadcast_proto_ver(0);
    wr_notify_req_msg_ex_t req;
    status_t status;
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    wr_params_t *param = &inst_cfg->params;
    do {
        req.type = cmd;
        errno_t err = memcpy_s(req.data, sizeof(req.data), data, size);
        if (err != EOK) {
            WR_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return CM_ERROR;
        }
        req.data_size = size;
        LOG_DEBUG_INF("notify other wr instance to do cmd %u, in vg:%s.", cmd, vg_item->vg_name);
        wr_init_mes_head(&req.wr_head, WR_CMD_REQ_BROADCAST, 0, (uint16)param->inst_id, CM_INVALID_ID16,
            (OFFSET_OF(wr_notify_req_msg_ex_t, data) + size), recv_msg.broadcast_proto_ver, 0);
        status = wr_notify_sync_ex((char *)&req, req.wr_head.size, &recv_msg);
        if (status == ERR_WR_VERSION_NOT_MATCH) {
            uint32 new_proto_ver = wr_get_broadcast_proto_ver(recv_msg.succ_inst);
            LOG_RUN_INF("[CHECK_PROTO]broadcast msg proto version has changed, old is %hhu, new is %hhu",
                recv_msg.broadcast_proto_ver, new_proto_ver);
            recv_msg.broadcast_proto_ver = new_proto_ver;
            recv_msg.version_not_match_inst = 0;
            // if msg need changed, need rewrite req
            continue;
        } else {
            break;
        }
    } while (CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[WR] Failed to notify other wr instance, cmd: %u, vg%s, errcode:%d, "
                    "OS errno:%d, OS errmsg:%s.",
            cmd, vg_item->vg_name, cm_get_error_code(), errno, strerror(errno));
        return CM_ERROR;
    }
    if (cmd_ack) {
        *cmd_ack = recv_msg.cmd_ack;
    }
    return status;
}

status_t wr_invalidate_other_nodes(
    wr_vg_info_item_t *vg_item, char *meta_info, uint32 meta_info_size, bool32 *cmd_ack)
{
    return wr_notify_data_expect_bool_ack(vg_item, BCAST_REQ_INVALIDATE_META, meta_info, meta_info_size, cmd_ack);
}

status_t wr_broadcast_check_file_open(wr_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack)
{
    return wr_notify_expect_bool_ack(vg_item, BCAST_REQ_DEL_DIR_FILE, ftid, cmd_ack);
}

status_t wr_syn_data2other_nodes(wr_vg_info_item_t *vg_item, char *meta_syn, uint32 meta_syn_size, bool32 *cmd_ack)
{
    return wr_notify_data_expect_bool_ack(vg_item, BCAST_REQ_META_SYN, meta_syn, meta_syn_size, cmd_ack);
}

static void wr_check_inst_conn(uint32_t id, uint64 old_inst_stat, uint64 cur_inst_stat)
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

void wr_check_mes_conn(uint64 cur_inst_map)
{
    wr_config_t *inst_cfg = wr_get_inst_cfg();

    uint64 old_inst_map = wr_get_inst_work_status();
    if (old_inst_map == cur_inst_map) {
        return;
    }
    wr_set_inst_work_status(cur_inst_map);
    uint32 inst_cnt = 0;
    for (uint32_t id = 0; id < WR_MAX_INSTANCES; id++) {
        if (id == inst_cfg->params.inst_id) {
            continue;
        }
        uint64_t inst_mask = ((uint64)0x1 << id);
        if ((inst_cfg->params.nodes_list.inst_map & inst_mask) == 0) {
            continue;
        }
        wr_check_inst_conn(id, (old_inst_map & inst_mask), (cur_inst_map & inst_mask));
        inst_cnt++;
        if (inst_cnt == inst_cfg->params.nodes_list.inst_cnt) {
            break;
        }
    }
}

static uint32 wr_get_remote_proto_ver(uint32 remoteid)
{
    if (remoteid >= WR_MAX_INSTANCES) {
        LOG_DEBUG_ERR("Invalid remote id:%u.", remoteid);
        return WR_PROTO_VERSION;
    }
    uint32 remote_proto_ver = (uint32)cm_atomic32_get((atomic32_t *)&g_wr_instance.cluster_proto_vers[remoteid]);
    if (remote_proto_ver == WR_INVALID_VERSION) {
        return WR_PROTO_VERSION;
    }
    remote_proto_ver = MIN(remote_proto_ver, WR_PROTO_VERSION);
    return remote_proto_ver;
}

static int wr_get_mes_response(ruid_type ruid, mes_msg_t *response, int timeout_ms)
{
    int ret = mes_get_response(ruid, response, timeout_ms);
    if (ret == CM_SUCCESS) {
        wr_message_head_t *ack_head = (wr_message_head_t *)response->buffer;
        if (ack_head->size < WR_MES_MSG_HEAD_SIZE) {
            LOG_RUN_ERR("Invalid message size");
            WR_THROW_ERROR(ERR_WR_MES_ILL, "msg len is invalid");
            mes_release_msg(response);
            return ERR_WR_MES_ILL;
        }
        wr_set_cluster_proto_vers((uint8)ack_head->src_inst, ack_head->sw_proto_ver);
    }
    return ret;
}

status_t wr_exec_sync(wr_session_t *session, uint32 remoteid, uint32 currtid, status_t *remote_result)
{
    status_t ret = CM_ERROR;
    wr_message_head_t wr_head;
    mes_msg_t msg;
    wr_message_head_t *ack_head = NULL;
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32 timeout = inst_cfg->params.mes_wait_timeout;
    uint32 new_proto_ver = wr_get_version(&session->recv_pack);
    do {
        uint32 buf_size = WR_MES_MSG_HEAD_SIZE + session->recv_pack.head->size;
        // 1.init mes head, wr head, wrbody
        wr_init_mes_head(
            &wr_head, WR_CMD_REQ_SYB2ACTIVE, 0, (uint16)currtid, (uint16)remoteid, buf_size, new_proto_ver, 0);
        // 2. send request to remote
        ret = mes_send_request_x(wr_head.dst_inst, wr_head.flags, &wr_head.ruid, 2, &wr_head, WR_MES_MSG_HEAD_SIZE,
            session->recv_pack.buf, session->recv_pack.head->size);
        char *err_msg = "The wr server fails to send messages to the remote node";
        WR_RETURN_IFERR2(ret, LOG_RUN_ERR("%s, src node(%u), dst node(%u).", err_msg, currtid, remoteid));
        // 3. receive msg from remote
        ret = wr_get_mes_response(wr_head.ruid, &msg, timeout);
        WR_RETURN_IFERR2(
            ret, LOG_RUN_ERR("wr server receive msg from remote failed, src node:%u, dst node:%u, cmd:%u.", currtid,
                     remoteid, session->recv_pack.head->cmd));
        // 4. attach remote execution result
        ack_head = (wr_message_head_t *)msg.buffer;
        if (ack_head->result == ERR_WR_VERSION_NOT_MATCH) {
            session->client_version = wr_get_client_version(&session->recv_pack);
            new_proto_ver = MIN(ack_head->sw_proto_ver, WR_PROTO_VERSION);
            new_proto_ver = MIN(new_proto_ver, session->client_version);
            session->proto_version = new_proto_ver;
            if (session->proto_version != wr_get_version(&session->recv_pack)) {
                LOG_RUN_INF("[CHECK_PROTO]The client protocol version need be changed, old protocol version is %u, new "
                            "protocol version is %u",
                    wr_get_version(&session->recv_pack), session->proto_version);
                WR_THROW_ERROR(
                    ERR_WR_VERSION_NOT_MATCH, wr_get_version(&session->recv_pack), session->proto_version);
                *remote_result = ERR_WR_VERSION_NOT_MATCH;
                mes_release_msg(&msg);
                return ret;
            } else {
                wr_head.msg_proto_ver = new_proto_ver;
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
    uint32 body_size = ack_head->size - WR_MES_MSG_HEAD_SIZE;
    if (*remote_result != CM_SUCCESS) {
        if (ack_head->size < sizeof(wr_remote_exec_fail_ack_t)) {
            WR_RETURN_IFERR3(CM_ERROR, WR_THROW_ERROR(ERR_WR_MES_ILL, "msg len is invalid"), mes_release_msg(&msg));
        }
        wr_remote_exec_fail_ack_t *fail_ack = (wr_remote_exec_fail_ack_t *)msg.buffer;
        WR_THROW_ERROR(ERR_WR_PROCESS_REMOTE, fail_ack->err_code, fail_ack->err_msg);
    } else if (body_size > 0) {
        wr_remote_exec_succ_ack_t *succ_ack = (wr_remote_exec_succ_ack_t *)msg.buffer;
        LOG_DEBUG_INF("[MES] wr server receive msg from remote node, cmd:%u, ack to cli data size:%u.",
            session->recv_pack.head->cmd, body_size);
        wr_remote_ack_hdl_t *handle = wr_get_remote_ack_handle(session->recv_pack.head->cmd);
        if (handle != NULL) {
            handle->proc(session, succ_ack);
        }
        // do not parse the format
        ret = wr_put_data(&session->send_pack, succ_ack->body_buf, body_size);
    }
    mes_release_msg(&msg);
    return ret;
}

status_t wr_exec_on_remote(uint8 cmd, char *req, int32 req_size, char *ack, int ack_size, status_t *remote_result)
{
    status_t ret = CM_ERROR;
    wr_message_head_t *wr_head = (wr_message_head_t *)req;
    wr_message_head_t *ack_head = NULL;
    wr_session_t *session = NULL;
    uint32 remoteid = WR_INVALID_ID32;
    uint32 currid = WR_INVALID_ID32;
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32 timeout = inst_cfg->params.mes_wait_timeout;
    mes_msg_t msg;
    if (wr_create_session(NULL, &session) != CM_SUCCESS) {
        LOG_RUN_ERR("Exec cmd:%u on remote node create session fail.", (uint32)cmd);
        return CM_ERROR;
    }

    WR_RETURN_IF_ERROR(wr_get_exec_nodeid(session, &currid, &remoteid));

    LOG_DEBUG_INF("[MES] Exec cmd:%u on remote node:%u begin.", (uint32)cmd, remoteid);
    do {
        uint32 proto_ver = wr_get_remote_proto_ver(remoteid);
        // 1. init msg head
        wr_init_mes_head(wr_head, cmd, 0, (uint16)currid, (uint16)remoteid, req_size, proto_ver, 0);
        // 2. send request to remote
        ret = mes_send_request(remoteid, wr_head->flags, &wr_head->ruid, req, wr_head->size);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Exec cmd:%u on remote node:%u send msg fail.", (uint32)cmd, remoteid);
            wr_destroy_session(session);
            return ERR_WR_MES_ILL;
        }
        // 3. receive msg from remote
        ret = wr_get_mes_response(wr_head->ruid, &msg, timeout);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Exec cmd:%u on remote node:%u  recv msg fail.", (uint32)cmd, remoteid);
            wr_destroy_session(session);
            return ERR_WR_MES_ILL;
        }
        ack_head = (wr_message_head_t *)msg.buffer;
        if (ack_head->result == ERR_WR_VERSION_NOT_MATCH) {
            // if msg version has changed, please motify your change
            mes_release_msg(&msg);
            continue;
        }
        break;
    } while (CM_TRUE);
    // 4. attach remote execution result
    *remote_result = ack_head->result;
    LOG_DEBUG_INF("[MES] wr server receive msg from remote node, cmd:%u, ack to cli data size:%hu, remote_result:%u.",
        ack_head->wr_cmd, ack_head->size, (uint32)*remote_result);
    if (*remote_result != CM_SUCCESS) {
        if (ack_head->size < sizeof(wr_remote_exec_fail_ack_t)) {
            WR_THROW_ERROR(ERR_WR_MES_ILL, "msg len is invalid");
            WR_RETURN_IFERR3(CM_ERROR, wr_destroy_session(session), mes_release_msg(&msg));
        }
        wr_remote_exec_fail_ack_t *fail_ack = (wr_remote_exec_fail_ack_t *)msg.buffer;
        WR_THROW_ERROR(ERR_WR_PROCESS_REMOTE, fail_ack->err_code, fail_ack->err_msg);
    } else {
        if (ack_head->size != ack_size) {
            WR_THROW_ERROR(ERR_WR_MES_ILL, "msg len is invalid");
            WR_RETURN_IFERR3(CM_ERROR, wr_destroy_session(session), mes_release_msg(&msg));
        }
        errno_t err = memcpy_s(ack, (size_t)ack_size, msg.buffer, (size_t)ack_head->size);
        if (err != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
            ret = CM_ERROR;
        }
    }

    mes_release_msg(&msg);
    wr_destroy_session(session);
    LOG_DEBUG_INF("[MES] Exec cmd:%u on remote node:%u end.", (uint32)cmd, remoteid);
    return ret;
}

void wr_proc_syb2active_req(wr_session_t *session, mes_msg_t *msg)
{
    wr_message_head_t req_head = *(wr_message_head_t *)(msg->buffer);
    uint32 size = req_head.size - WR_MES_MSG_HEAD_SIZE;
    uint16 srcid = req_head.src_inst;
    uint16 dstid = req_head.dst_inst;
    ruid_type ruid = req_head.ruid;
    if (size > WR_MAX_PACKET_SIZE) {
        LOG_DEBUG_ERR(
            "The wr server receive msg from remote failed, src node:%u, dst node:%u, size is %u.", srcid, dstid, size);
        return;
    }
    LOG_DEBUG_INF("[MES] The wr server receive messages from remote node, src node:%u, dst node:%u.", srcid, dstid);
    errno_t errcode = memcpy_s(session->recv_pack.buf, size, msg->buffer + WR_MES_MSG_HEAD_SIZE, size);
    if (errcode != EOK) {
        LOG_DEBUG_ERR("The wr server memcpy msg failed, src node:%u, dst node:%u.", srcid, dstid);
        return;
    }
    status_t ret = wr_proc_standby_req(session);
    char *body_buf = NULL;
    uint32 body_size = 0;
    status_t status = wr_prepare_ack_msg(session, ret, &body_buf, &body_size, req_head.msg_proto_ver);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The wr server prepare ack msg failed, src node:%u, dst node:%u.", srcid, dstid);
        return;
    }
    LOG_DEBUG_INF(
        "[MES] The wr server send messages to the remote node, src node:%u, dst node:%u, cmd:%u,ack size:%u.", srcid,
        dstid, session->send_pack.head->cmd, body_size);
    wr_message_head_t ack;
    wr_init_mes_head(
        &ack, WR_CMD_ACK_SYB2ACTIVE, 0, dstid, srcid, body_size + WR_MES_MSG_HEAD_SIZE, req_head.msg_proto_ver, ruid);
    ack.result = ret;
    ret = mes_send_response_x(ack.dst_inst, ack.flags, ack.ruid, 2, &ack, WR_MES_MSG_HEAD_SIZE, body_buf, body_size);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("The wr server fails to send messages to the remote node, src node:%u, dst node:%u.",
            (uint32)(ack.src_inst), (uint32)(ack.dst_inst));
        return;
    }
    LOG_DEBUG_INF("[MES] The wr server send messages to the remote node success, src node:%u, dst node:%u.",
        (uint32)(ack.src_inst), (uint32)(ack.dst_inst));
}

status_t wr_send2standby(big_packets_ctrl_t *ack, const char *buf)
{
    wr_message_head_t *wr_head = &ack->wr_head;
    status_t ret = mes_send_response_x(wr_head->dst_inst, wr_head->flags, wr_head->ruid, 2, ack,
        sizeof(big_packets_ctrl_t), buf, wr_head->size - sizeof(big_packets_ctrl_t));
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("The wrserver fails to send messages to the remote node, src node:%u, dst node:%u.",
            (uint32)(wr_head->src_inst), (uint32)(wr_head->dst_inst));
        return ret;
    }

    LOG_DEBUG_INF("[MES] The wr server send messages to the remote node success, src node:%u, dst node:%u.",
        (uint32)(wr_head->src_inst), (uint32)(wr_head->dst_inst));
    return ret;
}

static status_t wr_init_readvlm_remote_params(
    wr_loaddisk_req_t *req, const char *entry, uint32 *currid, uint32 *remoteid, wr_session_t *session)
{
    errno_t errcode = memset_s(req, sizeof(wr_loaddisk_req_t), 0, sizeof(wr_loaddisk_req_t));
    securec_check_ret(errcode);
    errcode = memcpy_s(req->vg_name, WR_MAX_NAME_LEN, entry, WR_MAX_NAME_LEN);
    securec_check_ret(errcode);
    WR_RETURN_IF_ERROR(wr_get_exec_nodeid(session, currid, remoteid));
    if (*currid == *remoteid) {
        LOG_DEBUG_ERR("read from current node %u no need to send message.", *currid);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static bool32 wr_packets_verify(big_packets_ctrl_t *lastctrl, big_packets_ctrl_t *ctrl, uint32 size)
{
    if (ctrl->endflag != CM_TRUE && size != ctrl->totalsize) {
        LOG_RUN_ERR("[MES] end flag is not CM_TRUE.");
        return CM_FALSE;
    }
    if (ctrl->endflag == CM_TRUE && ctrl->cursize + ctrl->offset != ctrl->totalsize) {
        LOG_RUN_ERR("[MES]size is not true, cursize is %u, offset is %u, total size is %u.", ctrl->cursize,
            ctrl->offset, ctrl->totalsize);
        return CM_FALSE;
    }

    *lastctrl = *ctrl;
    return CM_TRUE;
}

static status_t wr_rec_msgs(ruid_type ruid, void *buf, uint32 size)
{
    mes_msg_t msg;
    big_packets_ctrl_t lastctrl;
    (void)memset_s(&lastctrl, sizeof(big_packets_ctrl_t), 0, sizeof(big_packets_ctrl_t));
    big_packets_ctrl_t *ctrl;
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32 timeout = inst_cfg->params.mes_wait_timeout;
    do {
        status_t ret = wr_get_mes_response(ruid, &msg, timeout);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("wr server receive msg from remote node failed, result:%d.", ret);
            return ret;
        }
        wr_message_head_t *ack_head = (wr_message_head_t *)msg.buffer;
        if (ack_head->result == ERR_WR_VERSION_NOT_MATCH) {
            mes_release_msg(&msg);
            return ERR_WR_VERSION_NOT_MATCH;
        }
        if (ack_head->size < sizeof(big_packets_ctrl_t)) {
            ret = CM_ERROR;
            LOG_RUN_ERR("wr load disk from remote node failed invalid size, msg len(%d) error.", ack_head->size);
            if (ack_head->size == WR_MES_MSG_HEAD_SIZE) {
                ret = ack_head->result;
            }
            mes_release_msg(&msg);
            return ret;
        }
        ctrl = (big_packets_ctrl_t *)msg.buffer;
        if (wr_packets_verify(&lastctrl, ctrl, size) == CM_FALSE) {
            mes_release_msg(&msg);
            LOG_RUN_ERR("wr server receive msg verify failed.");
            return CM_ERROR;
        }
        if (size < ctrl->offset + ctrl->cursize || ack_head->size != (sizeof(big_packets_ctrl_t) + ctrl->cursize)) {
            mes_release_msg(&msg);
            LOG_RUN_ERR("wr server receive msg size is invalid.");
            return CM_ERROR;
        }
        errno_t errcode =
            memcpy_s((char *)buf + ctrl->offset, ctrl->cursize, msg.buffer + sizeof(big_packets_ctrl_t), ctrl->cursize);
        mes_release_msg(&msg);
        securec_check_ret(errcode);
    } while (ctrl->endflag != CM_TRUE);

    return CM_SUCCESS;
}

status_t wr_join_cluster(bool32 *join_succ)
{
    *join_succ = CM_FALSE;

    LOG_DEBUG_INF("[MES] Try join cluster begin.");

    wr_join_cluster_req_t req;
    wr_config_t *cfg = wr_get_inst_cfg();
    req.reg_id = (uint32)(cfg->params.inst_id);

    status_t remote_result;
    wr_join_cluster_ack_t ack;
    status_t ret = wr_exec_on_remote(WR_CMD_REQ_JOIN_CLUSTER, (char *)&req, sizeof(wr_join_cluster_req_t),
        (char *)&ack, sizeof(wr_join_cluster_ack_t), &remote_result);
    if (ret != CM_SUCCESS || remote_result != CM_SUCCESS) {
        LOG_RUN_ERR("Try join cluster exec fail.");
        return CM_ERROR;
    }
    if (ack.is_reg) {
        *join_succ = CM_TRUE;
    }

    LOG_DEBUG_INF("[MES] Try join cluster exec result:%u.", (uint32)*join_succ);
    return CM_SUCCESS;
}

void wr_proc_join_cluster_req(wr_session_t *session, mes_msg_t *msg)
{
    wr_message_head_t *req_head = (wr_message_head_t *)msg->buffer;
    if (req_head->size != sizeof(wr_join_cluster_req_t)) {
        LOG_RUN_ERR("Proc join cluster from remote node:%u check req msg fail.", (uint32)(req_head->src_inst));
        return;
    }

    wr_join_cluster_req_t *req = (wr_join_cluster_req_t *)msg->buffer;
    uint16 dst_inst = req_head->src_inst;
    uint16 src_inst = req_head->dst_inst;
    uint32 version = req_head->msg_proto_ver;
    ruid_type ruid = req_head->ruid;
    // please solve with your proto_ver
    LOG_DEBUG_INF(
        "[MES] Proc join cluster from remote node:%u reg node:%u begin.", (uint32)(req_head->src_inst), req->reg_id);

    // only in the work_status map can join the cluster

    wr_join_cluster_ack_t ack;
    wr_init_mes_head(
        &ack.ack_head, WR_CMD_ACK_JOIN_CLUSTER, 0, src_inst, dst_inst, sizeof(wr_join_cluster_ack_t), version, ruid);
    ack.is_reg = CM_FALSE;
    ack.ack_head.result = CM_SUCCESS;
    uint64 work_status = wr_get_inst_work_status();
    uint64 inst_mask = ((uint64)0x1 << req->reg_id);
    if (work_status & inst_mask) {
        ack.is_reg = CM_TRUE;
    }

    LOG_DEBUG_INF("[MES] Proc join cluster from remote node:%u, reg node:%u, is_reg:%u.", (uint32)(req_head->src_inst),
        req->reg_id, (uint32)ack.is_reg);
    int send_ret = mes_send_response(dst_inst, ack.ack_head.flags, ruid, (char *)&ack, ack.ack_head.size);
    if (send_ret != CM_SUCCESS) {
        LOG_RUN_ERR("Proc join cluster from remote node:%u, reg node:%u send ack fail.", (uint32)dst_inst, req->reg_id);
        return;
    }

    LOG_DEBUG_INF("[MES] Proc join cluster from remote node:%u, reg node:%u send ack size:%u end.", (uint32)dst_inst,
        req->reg_id, ack.ack_head.size);
}
