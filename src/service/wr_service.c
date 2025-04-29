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
 * wr_service.c
 *
 *
 * IDENTIFICATION
 *    src/service/wr_service.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_service.h"
#include "cm_system.h"
#include "wr_instance.h"
#include "wr_io_fence.h"
#include "wr_malloc.h"
#include "wr_open_file.h"
#include "wr_filesystem.h"
#include "wr_srv_proc.h"
#include "wr_mes.h"
#include "wr_api.h"
#include "wr_thv.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline bool32 wr_need_exec_remote(bool32 exec_on_active, bool32 local_req)
{
    wr_config_t *cfg = wr_get_inst_cfg();
    uint32 master_id = wr_get_master_id();
    uint32 curr_id = (uint32)(cfg->params.inst_id);
    return ((curr_id != master_id) && (exec_on_active) && (local_req == CM_TRUE));
}

static uint32 wr_get_master_proto_ver(void)
{
    uint32 master_id = wr_get_master_id();
    if (master_id >= WR_MAX_INSTANCES) {
        return WR_PROTO_VERSION;
    }
    uint32 master_proto_ver = (uint32)cm_atomic32_get((atomic32_t *)&g_wr_instance.cluster_proto_vers[master_id]);
    if (master_proto_ver == WR_INVALID_VERSION) {
        return WR_PROTO_VERSION;
    }
    master_proto_ver = MIN(master_proto_ver, WR_PROTO_VERSION);
    return master_proto_ver;
}

status_t wr_get_exec_nodeid(wr_session_t *session, uint32 *currid, uint32 *remoteid)
{
    wr_config_t *cfg = wr_get_inst_cfg();
    *currid = (uint32)(cfg->params.inst_id);
    *remoteid = wr_get_master_id();
    while (*remoteid == WR_INVALID_ID32) {
        if (get_instance_status_proc() == WR_STATUS_RECOVERY) {
            WR_THROW_ERROR(ERR_WR_RECOVER_CAUSE_BREAK);
            LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Master id is invalid.");
            return CM_ERROR;
        }
        *remoteid = wr_get_master_id();
        cm_sleep(WR_PROCESS_GET_MASTER_ID);
    }
    LOG_DEBUG_INF("Start processing remote requests(%d), remote node(%u),current node(%u).",
        (session->recv_pack.head == NULL) ? -1 : session->recv_pack.head->cmd, *remoteid, *currid);
    return CM_SUCCESS;
}

#define WR_PROCESS_REMOTE_INTERVAL 50
static status_t wr_process_remote(wr_session_t *session)
{
    uint32 remoteid = WR_INVALID_ID32;
    uint32 currid = WR_INVALID_ID32;
    status_t ret = CM_ERROR;
    WR_RETURN_IF_ERROR(wr_get_exec_nodeid(session, &currid, &remoteid));

    LOG_DEBUG_INF("Start processing remote requests(%d), remote node(%u),current node(%u).",
        session->recv_pack.head->cmd, remoteid, currid);
    status_t remote_result = CM_ERROR;
    while (CM_TRUE) {
        if (get_instance_status_proc() == WR_STATUS_RECOVERY) {
            WR_THROW_ERROR(ERR_WR_RECOVER_CAUSE_BREAK);
            LOG_RUN_INF("Req break by recovery");
            return CM_ERROR;
        }

        ret = wr_exec_sync(session, remoteid, currid, &remote_result);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR(
                "End of processing the remote request(%d) failed, remote node(%u),current node(%u), result code(%d).",
                session->recv_pack.head->cmd, remoteid, currid, ret);
            if (session->recv_pack.head->cmd == WR_CMD_SWITCH_LOCK) {
                return ret;
            }
            cm_sleep(WR_PROCESS_REMOTE_INTERVAL);
            WR_RETURN_IF_ERROR(wr_get_exec_nodeid(session, &currid, &remoteid));
            if (currid == remoteid) {
                WR_THROW_ERROR(ERR_WR_MASTER_CHANGE);
                LOG_RUN_INF("Req break if currid is equal to remoteid, just try again.");
                return CM_ERROR;
            }
            continue;
        }
        break;
    }
    LOG_DEBUG_INF("The remote request(%d) is processed successfully, remote node(%u),current node(%u), result(%u).",
        session->recv_pack.head->cmd, remoteid, currid, remote_result);
    return remote_result;
}

status_t wr_diag_proto_type(wr_session_t *session)
{
    link_ready_ack_t ack;
    uint32 proto_code = 0;
    int32 size;
    char buffer[sizeof(version_proto_code_t)] = {0};
    version_proto_code_t version_proto_code = {0};

    status_t ret = cs_read_bytes(&session->pipe, buffer, sizeof(version_proto_code_t), &size);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("Instance recieve protocol failed, errno:%d.", errno));

    if (size == sizeof(version_proto_code_t)) {
        version_proto_code = *(version_proto_code_t*)buffer;
        proto_code = version_proto_code.proto_code;
    } else if (size == sizeof(proto_code)) {
        proto_code = *(uint32 *)buffer;
    } else {
        LOG_RUN_ERR("wr_diag_proto_type invalid size[%u].", size);
    }
    LOG_RUN_INF("wr_diag_proto_type proto_code=%u.", proto_code);

    if (proto_code != CM_PROTO_CODE) {
        LOG_RUN_ERR("Instance recieve invalid protocol:%u.", proto_code);
        return CM_ERROR;
    }

    session->proto_type = PROTO_TYPE_GS;
    ack.endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    ack.version = CS_LOCAL_VERSION;
    return cs_send_bytes(&session->pipe, (char *)&ack, sizeof(link_ready_ack_t));
}

// TODO: 后期考虑启用
static void wr_clean_open_files(wr_session_t *session)
{
    if (cm_sys_process_alived(session->cli_info.cli_pid, session->cli_info.start_time)) {
        LOG_DEBUG_INF("Process:%s is alive, pid:%llu, start_time:%lld.", session->cli_info.process_name,
            session->cli_info.cli_pid, session->cli_info.start_time);
        return;
    }

    LOG_RUN_INF("Clean open files for pid:%llu.", session->cli_info.cli_pid);
}

void wr_release_session_res(wr_session_t *session)
{
    wr_server_session_lock(session);
    wr_clean_session_latch(session, CM_FALSE);
    wr_clean_open_files(session);
    wr_destroy_session_inner(session);
    cm_spin_unlock(&session->shm_lock);
    LOG_DEBUG_INF("Succeed to unlock session %u shm lock", session->id);
    cm_spin_unlock(&session->lock);
}

status_t wr_process_single_cmd(wr_session_t **session)
{
    status_t status = wr_process_command(*session);
    if ((*session)->is_closed) {
        LOG_RUN_INF("Session:%u end to do service, thread id is %u, connect time is %llu, try to clean source.",
            (*session)->id, (*session)->cli_info.thread_id, (*session)->cli_info.connect_time);
        wr_clean_reactor_session(*session);
        *session = NULL;
    } else {
        wr_session_detach_workthread(*session);
    }
    return status;
}

static void wr_return_error(wr_session_t *session)
{
    int32 code;
    const char *message = NULL;
    wr_packet_t *send_pack = NULL;

    CM_ASSERT(session != NULL);
    send_pack = &session->send_pack;
    wr_init_set(send_pack, session->proto_version);
    send_pack->head->cmd = session->recv_pack.head->cmd;
    send_pack->head->result = (uint8)CM_ERROR;
    send_pack->head->flags = 0;
    cm_get_error(&code, &message);
    // volume open/seek/read write fail for I/O, just abort
    if (code == ERR_WR_VOLUME_SYSTEM_IO) {
        LOG_RUN_ERR("[WR] ABORT INFO: volume operate failed for I/O ERROR, errcode:%d.", code);
        cm_fync_logfile();
        wr_exit_error();
    }
    (void)wr_put_int32(send_pack, (uint32)code);
    (void)wr_put_str_with_cutoff(send_pack, message);
    status_t status = wr_write(&session->pipe, send_pack);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to reply,size:%u, cmd:%u.", send_pack->head->size, send_pack->head->cmd);
    }
    cm_reset_error();
}

static void wr_return_success(wr_session_t *session)
{
    CM_ASSERT(session != NULL);
    status_t status;
    wr_packet_t *send_pack = NULL;
    send_pack = &session->send_pack;
    send_pack->head->cmd = session->recv_pack.head->cmd;
    send_pack->head->result = (uint8)CM_SUCCESS;
    send_pack->head->flags = 0;
    wr_set_version(send_pack, session->proto_version);
    wr_set_client_version(send_pack, session->client_version);

    status = wr_write(&session->pipe, send_pack);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to reply message,size:%u, cmd:%u.", send_pack->head->size, send_pack->head->cmd);
    }
}

static status_t wr_set_audit_resource(char *resource, uint32 audit_type, const char *format, ...)
{
    if ((cm_log_param_instance()->audit_level & audit_type) == 0) {
        return CM_SUCCESS;
    }
    va_list args;
    va_start(args, format);
    int32 ret =
        vsnprintf_s(resource, (size_t)WR_MAX_AUDIT_PATH_LENGTH, (size_t)(WR_MAX_AUDIT_PATH_LENGTH - 1), format, args);
    WR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    va_end(args);
    return CM_SUCCESS;
}

static status_t wr_process_mkdir(wr_session_t *session)
{
    char *dir = NULL;

    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &dir));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY, "%s", dir));
    WR_LOG_DEBUG_OP("Begin to mkdir:%s", dir);
    status_t status = wr_make_dir(session, (const char *)dir);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to mkdir:%s", dir);
        return status;
    }
    LOG_DEBUG_ERR("Failed to mkdir:%s", dir);
    return status;
}

static status_t wr_process_rmdir(wr_session_t *session)
{
    char *dir = NULL;
    int32 recursive = 0;
    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &dir));
    WR_RETURN_IF_ERROR(wr_get_int32(&session->recv_pack, &recursive));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY, "%s", dir));
    WR_LOG_DEBUG_OP("Begin to rmdir:%s.", dir);
    status_t status = wr_filesystem_rmdir(dir);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to rmdir:%s", dir);
        return status;
    }
    LOG_DEBUG_ERR("Failed to rmdir:%s", dir);
    return status;
}

static status_t wr_process_query_file_num(wr_session_t *session)
{
    char *vfs_name = NULL;
    uint32 file_num = 0;
    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &vfs_name));
    if (wr_filesystem_query_file_num(vfs_name, &file_num) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to query file num for vfs:%s", vfs_name);
        return CM_ERROR;
    }
    (void)wr_put_int32(&session->send_pack, file_num);
    return CM_SUCCESS;
}

static status_t wr_process_create_file(wr_session_t *session)
{
    char *file_ptr = NULL;
    text_t text;
    text_t sub = CM_NULL_TEXT;
    int32 flag;

    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &file_ptr));
    WR_RETURN_IF_ERROR(wr_get_int32(&session->recv_pack, &flag));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY, "%s", file_ptr));

    cm_str2text(file_ptr, &text);
    bool32 result = cm_fetch_rtext(&text, '/', '\0', &sub);
    WR_RETURN_IF_FALSE2(
        result, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, sub.str, ", which is not a complete absolute path name."));
    if (text.len == 0) {
        WR_THROW_ERROR(ERR_WR_FILE_CREATE, "file name is null.");
        return CM_ERROR;
    }
    result = (bool32)(text.len < WR_MAX_NAME_LEN);
    WR_RETURN_IF_FALSE2(result, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, text.str, "name length should less than 64."));

    char parent_str[WR_FILE_PATH_MAX_LENGTH];
    char name_str[WR_MAX_NAME_LEN];
    WR_RETURN_IF_ERROR(cm_text2str(&sub, parent_str, sizeof(parent_str)));
    WR_RETURN_IF_ERROR(cm_text2str(&text, name_str, sizeof(name_str)));

    WR_LOG_DEBUG_OP("Begin to create file:%s in path:%s.", name_str, parent_str);
    status_t status = wr_create_file(session, (const char *)parent_str, (const char *)name_str, flag);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to create file:%s in path:%s", name_str, parent_str);
        return status;
    }
    LOG_DEBUG_ERR("Failed to create file:%s in path:%s", name_str, parent_str);
    return status;
}

static status_t wr_process_delete_file(wr_session_t *session)
{
    char *name = NULL;
    wr_init_get(&session->recv_pack);
    status_t status = wr_get_str(&session->recv_pack, &name);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("delete file get file name failed."));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY, "%s", name));
    WR_LOG_DEBUG_OP("Begin to rm file:%s", name);
    status = wr_filesystem_rm(name);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to rm file:%s", name);
        return status;
    }
    LOG_DEBUG_ERR("Failed to rm file:%s", name);
    return status;
}

static status_t wr_process_exist(wr_session_t *session)
{
    bool32 result = CM_FALSE;
    gft_item_type_t type;
    char *name = NULL;
    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &name));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_QUERY, "%s", name));
    WR_RETURN_IF_ERROR(wr_exist_item(session, (const char *)name, &result, &type));

    WR_RETURN_IF_ERROR(wr_put_int32(&session->send_pack, (uint32)result));
    WR_RETURN_IF_ERROR(wr_put_int32(&session->send_pack, (uint32)type));
    return CM_SUCCESS;
}

static status_t wr_process_open_file(wr_session_t *session)
{
    char *name = NULL;
    int32 flag;
    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &name));
    WR_RETURN_IF_ERROR(wr_get_int32(&session->recv_pack, &flag));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY, "%s", name));
    int64_t fd = 0;
    status_t status = wr_open_file(session, (const char *)name, flag, &fd);
    if (status == CM_SUCCESS) {
        WR_RETURN_IF_ERROR(wr_put_int64(&session->send_pack, fd));
    }
    return status;
}

static status_t wr_process_close_file(wr_session_t *session)
{
    int64_t fd;
    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, (int64 *)&fd));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY, "fd:%ld", fd));

    WR_LOG_DEBUG_OP("Begin to close file, fd:%ld", fd);
    WR_RETURN_IF_ERROR(wr_filesystem_close(fd));
    LOG_DEBUG_INF("Succeed to close file, fd:%ld", fd);
    return CM_SUCCESS;
}

static status_t wr_process_open_dir(wr_session_t *session)
{
    char *name = NULL;
    int32 refresh_recursive;
    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &name));
    WR_RETURN_IF_ERROR(wr_get_int32(&session->recv_pack, &refresh_recursive));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY, "%s", name));
    wr_find_node_t find_info;
    WR_LOG_DEBUG_OP("Begin to open dir:%s, is_refresh:%d", name, refresh_recursive);
    status_t status = wr_open_dir(session, (const char *)name, (bool32)refresh_recursive, &find_info);
    if (status == CM_SUCCESS) {
        WR_RETURN_IF_ERROR(wr_put_data(&session->send_pack, &find_info, sizeof(wr_find_node_t)));
        LOG_DEBUG_INF("Succeed to open dir:%s, ftid: %s", name, wr_display_metaid(find_info.ftid));
        return status;
    }
    LOG_DEBUG_ERR("Failed to open dir:%s", name);
    return status;
}

static status_t wr_process_close_dir(wr_session_t *session)
{
    uint64_t ftid;
    char *vg_name = NULL;
    uint32_t vgid;

    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, (int64 *)&ftid));
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &vg_name));
    WR_RETURN_IF_ERROR(wr_get_int32(&session->recv_pack, (int32 *)&vgid));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(
        session->audit_info.resource, WR_AUDIT_MODIFY, "vg_name:%s, ftid:%llu", vg_name, *(uint64 *)&ftid));
    WR_LOG_DEBUG_OP("Begin to close dir, ftid:%llu, vg:%s.", ftid, vg_name);
    wr_close_dir(session, vg_name, ftid);
    return CM_SUCCESS;
}

static status_t wr_process_write_file(wr_session_t *session)
{
    int64_t offset = 0;
    int64_t file_size = 0;
    int64_t handle = 0;
    char *buf = NULL;

    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &offset));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &handle));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &file_size));
    WR_RETURN_IF_ERROR(wr_get_data(&session->recv_pack, file_size, (void**)&buf));

    WR_RETURN_IF_ERROR(wr_set_audit_resource(
        session->audit_info.resource, WR_AUDIT_MODIFY, "handle:%ld, offset:%ld, size:%ld", handle, offset, file_size));

    return wr_filesystem_write(handle, offset, file_size, buf);
}

static status_t wr_process_read_file(wr_session_t *session)
{
    int64 offset;
    int64 size;
    int64 handle;

    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &offset));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &handle));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &size));

    // Allocate one extra byte for the null terminator
    char *buf = (char *)malloc(size + 1);
    if (buf == NULL) {
        LOG_DEBUG_ERR("Failed to malloc buffer for read file.");
        return CM_ERROR;
    }

    // Initialize the buffer and ensure it is null-terminated
    memset(buf, 0, size + 1);

    // Read the file content into the buffer
    WR_RETURN_IF_ERROR(wr_filesystem_pread(handle, offset, size, buf));

    // Convert the buffer to a text_t structure
    text_t data;
    cm_str2text(buf, &data);

    // Send the data
    WR_RETURN_IF_ERROR(wr_put_text(&session->send_pack, &data));

    // Free the allocated buffer
    free(buf);

    return CM_SUCCESS;
}

static status_t wr_process_extending_file(wr_session_t *session)
{
    wr_node_data_t node_data;

    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, (int64 *)&node_data.fid));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, (int64 *)&node_data.ftid));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &node_data.offset));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &node_data.size));
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &node_data.vg_name));
    WR_RETURN_IF_ERROR(wr_get_int32(&session->recv_pack, (int32 *)&node_data.vgid));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY,
        "extend vg_name:%s, fid:%llu, ftid:%llu, offset:%lld, size:%lld", node_data.vg_name, node_data.fid,
        *(uint64 *)&node_data.ftid, node_data.offset, node_data.size));

    return wr_extend(session, &node_data);
}

static status_t wr_process_fallocate_file(wr_session_t *session)
{
    wr_node_data_t node_data;

    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, (int64 *)&node_data.fid));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, (int64 *)&node_data.ftid));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &node_data.offset));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &node_data.size));
    WR_RETURN_IF_ERROR(wr_get_int32(&session->recv_pack, (int32 *)&node_data.vgid));
    WR_RETURN_IF_ERROR(wr_get_int32(&session->recv_pack, (int32 *)&node_data.mode));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY,
        "fallocate vg_id:%u, fid:%llu, ftid:%llu, offset:%lld, size:%lld, mode:%d", node_data.vgid, node_data.fid,
        *(uint64 *)&node_data.ftid, node_data.offset, node_data.size, node_data.mode));

    LOG_DEBUG_INF("fallocate vg_id:%u, fid:%llu, ftid:%llu, offset:%lld, size:%lld, mode:%d", node_data.vgid,
        node_data.fid, *(uint64 *)&node_data.ftid, node_data.offset, node_data.size, node_data.mode);

    return wr_do_fallocate(session, &node_data);
}

static status_t wr_process_truncate_file(wr_session_t *session)
{
    int64 length;
    int64 handle;
    int64 truncateType;

    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &length));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &handle));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, &truncateType));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY,
        "handle:%ld, length:%lld", handle, length));
    LOG_DEBUG_INF("Truncate file handle:%ld, length:%lld", handle, length);
    return wr_filesystem_truncate(handle, length);
}

static status_t wr_process_handshake(wr_session_t *session)
{
    wr_init_get(&session->recv_pack);
    session->client_version = wr_get_version(&session->recv_pack);
    uint32 current_proto_ver = wr_get_master_proto_ver();
    session->proto_version = MIN(session->client_version, current_proto_ver);
    wr_cli_info_t *cli_info;
    WR_RETURN_IF_ERROR(wr_get_data(&session->recv_pack, sizeof(wr_cli_info_t), (void **)&cli_info));
    errno_t errcode;
    cm_spin_lock(&session->lock, NULL);
    errcode = memcpy_s(&session->cli_info, sizeof(wr_cli_info_t), cli_info, sizeof(wr_cli_info_t));
    cm_spin_unlock(&session->lock);
    securec_check_ret(errcode);
    LOG_RUN_INF(
        "[WR_CONNECT]The client has connected, session id:%u, pid:%llu, process name:%s.st_time:%lld, objectid:%u",
        session->id, session->cli_info.cli_pid, session->cli_info.process_name, session->cli_info.start_time,
        session->objectid);
    char *server_home = wr_get_cfg_dir(ZFS_CFG);
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_QUERY, "%s", server_home));
    LOG_RUN_INF("[WR_CONNECT]Server home is %s, when get home.", server_home);
    uint32 server_pid = getpid();
    text_t data;
    cm_str2text(server_home, &data);
    data.len++;  // for keeping the '\0'
    WR_RETURN_IF_ERROR(wr_put_text(&session->send_pack, &data));
    WR_RETURN_IF_ERROR(wr_put_int32(&session->send_pack, session->objectid));
    if (session->proto_version >= WR_VERSION_2) {
        WR_RETURN_IF_ERROR(wr_put_int32(&session->send_pack, server_pid));
    }
    return CM_SUCCESS;
}

static status_t wr_process_rename(wr_session_t *session)
{
    char *src = NULL;
    char *dst = NULL;
    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &src));
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &dst));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY, "%s, %s", src, dst));
    return wr_rename_file(session, src, dst);
}

status_t wr_process_update_file_written_size(wr_session_t *session)
{
    uint64 fid;
    int64 offset;
    int64 size;
    wr_block_id_t ftid;
    uint32 vg_id;

    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, (int64 *)&fid));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, (int64 *)&ftid));
    WR_RETURN_IF_ERROR(wr_get_int32(&session->recv_pack, (int32 *)&vg_id));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, (int64 *)&offset));
    WR_RETURN_IF_ERROR(wr_get_int64(&session->recv_pack, (int64 *)&size));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY,
        "vg_id:%u, fid:%llu, ftid:%llu, offset:%lld, size:%lld", vg_id, fid, *(uint64 *)&ftid, offset, size));
    return wr_update_file_written_size(session, vg_id, offset, size, ftid, fid);
}

#define WR_SERVER_STATUS_OFFSET(i) ((uint32)(i) - (uint32)WR_STATUS_NORMAL)
static char *g_wr_instance_rdwr_type[WR_SERVER_STATUS_OFFSET(WR_SERVER_STATUS_END)] = {
    [WR_SERVER_STATUS_OFFSET(WR_STATUS_NORMAL)] = "NORMAL",
    [WR_SERVER_STATUS_OFFSET(WR_STATUS_READONLY)] = "READONLY",
    [WR_SERVER_STATUS_OFFSET(WR_STATUS_READWRITE)] = "READWRITE",
};

char *wr_get_wr_server_status(int32 server_status)
{
    if (server_status < WR_STATUS_NORMAL || server_status > WR_STATUS_READWRITE) {
        return "unknown";
    }
    return g_wr_instance_rdwr_type[WR_SERVER_STATUS_OFFSET(server_status)];
}

#define WR_INSTANCE_STATUS_OFFSET(i) ((uint32)(i) - (uint32)WR_STATUS_PREPARE)
static char *g_wr_instance_status_desc[WR_INSTANCE_STATUS_OFFSET(WR_INSTANCE_STATUS_END)] = {
    [WR_INSTANCE_STATUS_OFFSET(WR_STATUS_PREPARE)] = "prepare",
    [WR_INSTANCE_STATUS_OFFSET(WR_STATUS_RECOVERY)] = "recovery",
    [WR_INSTANCE_STATUS_OFFSET(WR_STATUS_SWITCH)] = "switch",
    [WR_INSTANCE_STATUS_OFFSET(WR_STATUS_OPEN)] = "open",
};

char *wr_get_wr_instance_status(int32 instance_status)
{
    if (instance_status < WR_STATUS_PREPARE || instance_status > WR_STATUS_OPEN) {
        return "unknown";
    }
    return g_wr_instance_status_desc[WR_INSTANCE_STATUS_OFFSET(instance_status)];
}

// get wrserver status:open, recovery or switch
static status_t wr_process_get_inst_status(wr_session_t *session)
{
    wr_server_status_t *wr_status = NULL;
    WR_RETURN_IF_ERROR(
        wr_reserv_text_buf(&session->send_pack, (uint32)sizeof(wr_server_status_t), (char **)&wr_status));

    wr_status->instance_status_id = g_wr_instance.status;
    wr_status->server_status_id = wr_get_server_status_flag();
    wr_status->local_instance_id = g_wr_instance.inst_cfg.params.inst_id;
    wr_status->master_id = wr_get_master_id();
    wr_status->is_maintain = g_wr_instance.is_maintain;
    char *wr_instance_status = wr_get_wr_instance_status(wr_status->instance_status_id);
    errno_t errcode = strcpy_s(wr_status->instance_status, WR_MAX_STATUS_LEN, wr_instance_status);
    MEMS_RETURN_IFERR(errcode);

    char *wr_server_status = wr_get_wr_server_status(wr_status->server_status_id);
    errcode = strcpy_s(wr_status->server_status, WR_MAX_STATUS_LEN, wr_server_status);
    MEMS_RETURN_IFERR(errcode);

    WR_RETURN_IF_ERROR(wr_set_audit_resource(
        session->audit_info.resource, WR_AUDIT_MODIFY, "status:%s", wr_status->instance_status));
    WR_LOG_DEBUG_OP("Server status is %s.", wr_status->instance_status);
    return CM_SUCCESS;
}
static status_t wr_process_get_time_stat(wr_session_t *session)
{
    uint64 size = sizeof(wr_stat_item_t) * WR_EVT_COUNT;
    wr_stat_item_t *time_stat = NULL;
    WR_RETURN_IF_ERROR(wr_reserv_text_buf(&session->send_pack, (uint32)size, (char **)&time_stat));

    errno_t errcode = memset_s(time_stat, (size_t)size, 0, (size_t)size);
    securec_check_ret(errcode);
    wr_session_ctrl_t *session_ctrl = wr_get_session_ctrl();
    wr_session_t *tmp_session = NULL;
    cm_spin_lock(&session_ctrl->lock, NULL);
    for (uint32 i = 0; i < session_ctrl->alloc_sessions; i++) {
        tmp_session = session_ctrl->sessions[i];
        if (tmp_session->is_used && !tmp_session->is_closed) {
            for (uint32 j = 0; j < WR_EVT_COUNT; j++) {
                int64 count = (int64)tmp_session->wr_session_stat[j].wait_count;
                int64 total_time = (int64)tmp_session->wr_session_stat[j].total_wait_time;
                int64 max_sgl_time = (int64)tmp_session->wr_session_stat[j].max_single_time;

                time_stat[j].wait_count += count;
                time_stat[j].total_wait_time += total_time;
                time_stat[j].max_single_time = (atomic_t)MAX((int64)time_stat[j].max_single_time, max_sgl_time);

                (void)cm_atomic_add(&tmp_session->wr_session_stat[j].wait_count, -count);
                (void)cm_atomic_add(&tmp_session->wr_session_stat[j].total_wait_time, -total_time);
                (void)cm_atomic_cas(&tmp_session->wr_session_stat[j].max_single_time, max_sgl_time, 0);
            }
        }
    }
    cm_spin_unlock(&session_ctrl->lock);

    return CM_SUCCESS;
}

void wr_wait_session_pause(wr_instance_t *inst)
{
    tcp_lsnr_t *lsnr = &inst->lsnr;
    LOG_DEBUG_INF("Begin to set session paused.");
    cs_pause_tcp_lsnr(lsnr);
    wr_pause_reactors();
    while (inst->active_sessions != 0) {
        cm_sleep(1);
    }
    LOG_DEBUG_INF("Succeed to pause all session.");
}

void wr_wait_background_pause(wr_instance_t *inst)
{
    LOG_DEBUG_INF("Begin to set background paused.");
    while (inst->is_cleaning || inst->is_checking) {
        cm_sleep(1);
    }
    LOG_DEBUG_INF("Succeed to pause background task.");
}

void wr_set_session_running(wr_instance_t *inst, uint32 sid)
{
    LOG_DEBUG_INF("Begin to set session running.");
    cm_latch_x(&inst->tcp_lsnr_latch, sid, NULL);
    if (inst->abort_status) {
        LOG_RUN_INF("wrserver is aborting, no need to set sessions running.");
        cm_unlatch(&inst->tcp_lsnr_latch, NULL);
        return;
    }
    tcp_lsnr_t *lsnr = &inst->lsnr;
    wr_continue_reactors();
    lsnr->status = LSNR_STATUS_RUNNING;
    cm_unlatch(&inst->tcp_lsnr_latch, NULL);
    LOG_DEBUG_INF("Succeed to run all sessions.");
}

static status_t wr_process_setcfg(wr_session_t *session)
{
    char *name = NULL;
    char *value = NULL;
    char *scope = NULL;
    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &name));
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &value));
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &scope));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY, "%s", name));

    return wr_set_cfg_param(name, value, scope);
}

static status_t wr_process_getcfg(wr_session_t *session)
{
    char *name = NULL;
    char *value = NULL;
    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_get_str(&session->recv_pack, &name));
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_QUERY, "%s", name));

    WR_RETURN_IF_ERROR(wr_get_cfg_param(name, &value));
    if (strlen(value) != 0 && cm_str_equal_ins(name, "SSL_PWD_CIPHERTEXT")) {
        WR_LOG_DEBUG_OP("Server value is ***, when get cfg.");
    } else {
        WR_LOG_DEBUG_OP("Server value is %s, when get cfg.", value);
    }
    text_t data;
    cm_str2text(value, &data);
    // SSL default value is NULL
    if (value != NULL) {
        data.len++;  // for keeping the '\0'
    }
    return wr_put_text(&session->send_pack, &data);
}

static status_t wr_process_stop_server(wr_session_t *session)
{
    wr_init_get(&session->recv_pack);
    WR_RETURN_IF_ERROR(wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY, "%u", session->id));
    g_wr_instance.abort_status = CM_TRUE;

    return CM_SUCCESS;
}

// process switch lock,just master id can do
static status_t wr_process_switch_lock_inner(wr_session_t *session, uint32 switch_id)
{
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32 curr_id = (uint32)inst_cfg->params.inst_id;
    uint32 master_id = wr_get_master_id();
    if ((uint32)switch_id == master_id) {
        LOG_RUN_INF("[SWITCH]switchid is equal to current master_id, which is %u.", master_id);
        return CM_SUCCESS;
    }
    if (master_id != curr_id) {
        LOG_RUN_ERR("[SWITCH]current id is %u, just master id %u can do switch lock.", curr_id, master_id);
        return CM_ERROR;
    }
    wr_wait_session_pause(&g_wr_instance);
    g_wr_instance.status = WR_STATUS_SWITCH;
    wr_wait_background_pause(&g_wr_instance);
#ifdef ENABLE_WRTEST
    wr_set_server_status_flag(WR_STATUS_READONLY);
    LOG_RUN_INF("[SWITCH]inst %u set status flag %u when trans lock.", curr_id, WR_STATUS_READONLY);
    wr_set_master_id((uint32)switch_id);
    wr_set_session_running(&g_wr_instance, session->id);
    g_wr_instance.status = WR_STATUS_OPEN;
#endif
    status_t ret = CM_SUCCESS;
    // trans lock
    if (g_wr_instance.cm_res.is_valid) {
        wr_set_server_status_flag(WR_STATUS_READONLY);
        LOG_RUN_INF("[SWITCH]inst %u set status flag %u when trans lock.", curr_id, WR_STATUS_READONLY);
        ret = cm_res_trans_lock(&g_wr_instance.cm_res.mgr, WR_CM_LOCK, (uint32)switch_id);
        if (ret != CM_SUCCESS) {
            wr_set_session_running(&g_wr_instance, session->id);
            wr_set_server_status_flag(WR_STATUS_READWRITE);
            LOG_RUN_INF("[SWITCH]inst %u set status flag %u when failed to trans lock.", curr_id, WR_STATUS_READWRITE);
            g_wr_instance.status = WR_STATUS_OPEN;
            LOG_RUN_ERR("[SWITCH]cm do switch lock failed from %u to %u.", curr_id, master_id);
            return ret;
        }
        wr_set_master_id((uint32)switch_id);
        wr_set_session_running(&g_wr_instance, session->id);
        g_wr_instance.status = WR_STATUS_OPEN;
    } else {
        wr_set_session_running(&g_wr_instance, session->id);
        g_wr_instance.status = WR_STATUS_OPEN;
        LOG_RUN_ERR("[SWITCH]Only with cm can switch lock.");
        return CM_ERROR;
    }
    LOG_RUN_INF(
        "[SWITCH]Old main server %u switch lock to new main server %u successfully.", curr_id, (uint32)switch_id);
    return CM_SUCCESS;
}

static status_t wr_process_switch_lock(wr_session_t *session)
{
    int32 switch_id;
    wr_init_get(&session->recv_pack);
    if (wr_get_int32(&session->recv_pack, &switch_id) != CM_SUCCESS) {
        return CM_ERROR;
    }
    cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));  // when mes process req, will latch s
    cm_latch_x(&g_wr_instance.switch_latch, session->id, LATCH_STAT(LATCH_SWITCH));
    wr_set_recover_thread_id(wr_get_current_thread_id());
    status_t ret = wr_process_switch_lock_inner(session, (uint32)switch_id);
    wr_set_recover_thread_id(0);
    // no need to unlatch, for wr_process_message will
    return ret;
}
/*
    1 curr_id == master_id, just return success;
    2 curr_id != master_id, just send message to master_id to do switch lock
    then master_id to do:
    (1) set status switch
    (2) lsnr pause
    (3) trans lock
*/
static status_t wr_process_remote_switch_lock(wr_session_t *session, uint32 curr_id, uint32 master_id)
{
    wr_instance_status_e old_status = g_wr_instance.status;
    g_wr_instance.status = WR_STATUS_SWITCH;
    uint32 current_proto_ver = wr_get_master_proto_ver();
    wr_init_set(&session->recv_pack, current_proto_ver);
    session->recv_pack.head->cmd = WR_CMD_SWITCH_LOCK;
    session->recv_pack.head->flags = 0;
    LOG_RUN_INF("[SWITCH] Try to switch lock to %u by %u.", curr_id, master_id);
    (void)wr_put_int32(&session->recv_pack, curr_id);
    status_t status = wr_process_remote(session);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[SWITCH] Failed to switch lock to %u by %u.", curr_id, master_id);
        g_wr_instance.status = old_status;
    }
    return status;
}

static status_t wr_process_set_main_inst(wr_session_t *session)
{
    status_t status = CM_ERROR;
    wr_config_t *cfg = wr_get_inst_cfg();
    uint32 curr_id = (uint32)(cfg->params.inst_id);
    uint32 master_id;
    WR_RETURN_IF_ERROR(
        wr_set_audit_resource(session->audit_info.resource, WR_AUDIT_MODIFY, "set %u as master", curr_id));
    while (CM_TRUE) {
        master_id = wr_get_master_id();
        if (master_id == curr_id) {
            session->recv_pack.head->cmd = WR_CMD_SET_MAIN_INST;
            LOG_RUN_INF("[SWITCH] Main server %u is set successfully by %u.", curr_id, master_id);
            return CM_SUCCESS;
        }
        if (get_instance_status_proc() == WR_STATUS_RECOVERY) {
            session->recv_pack.head->cmd = WR_CMD_SET_MAIN_INST;
            WR_THROW_ERROR(ERR_WR_RECOVER_CAUSE_BREAK);
            LOG_RUN_INF("[SWITCH] Set main inst break by recovery");
            return CM_ERROR;
        }
        if (!cm_latch_timed_x(
            &g_wr_instance.switch_latch, session->id, WR_PROCESS_REMOTE_INTERVAL, LATCH_STAT(LATCH_SWITCH))) {
            LOG_RUN_INF("[SWITCH] Spin switch lock timed out, just continue.");
            continue;
        }
        status = wr_process_remote_switch_lock(session, curr_id, master_id);
        if (status != CM_SUCCESS) {
            cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            if (cm_get_error_code() == ERR_WR_RECOVER_CAUSE_BREAK) {
                session->recv_pack.head->cmd = WR_CMD_SET_MAIN_INST;
                LOG_RUN_INF("[SWITCH] Try set main break because master id is invalid.");
                return CM_ERROR;
            }
            cm_sleep(WR_PROCESS_REMOTE_INTERVAL);
            continue;
        }
        break;
    }
    session->recv_pack.head->cmd = WR_CMD_SET_MAIN_INST;
    wr_set_recover_thread_id(wr_get_current_thread_id());
    g_wr_instance.status = WR_STATUS_RECOVERY;
    wr_set_master_id(curr_id);
    status = wr_refresh_meta_info(session);
    if (status != CM_SUCCESS) {
        g_wr_instance.status = WR_STATUS_OPEN;
        cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        LOG_RUN_ERR("[WR][SWITCH] ABORT INFO: wr instance %u refresh meta failed, result(%d).", curr_id, status);
        cm_fync_logfile();
        wr_exit_error();
    }
    wr_set_server_status_flag(WR_STATUS_READWRITE);
    LOG_RUN_INF("[SWITCH] inst %u set status flag %u when set main inst.", curr_id, WR_STATUS_READWRITE);
    g_wr_instance.status = WR_STATUS_OPEN;
    wr_set_recover_thread_id(0);
    LOG_RUN_INF("[SWITCH] Main server %u is set successfully by %u.", curr_id, master_id);
    cm_unlatch(&g_wr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
    return CM_SUCCESS;
}


static wr_cmd_hdl_t g_wr_cmd_handle[WR_CMD_TYPE_OFFSET(WR_CMD_END)] = {
    // modify
    [WR_CMD_TYPE_OFFSET(WR_CMD_MKDIR)] = {WR_CMD_MKDIR, wr_process_mkdir, NULL, CM_TRUE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_RMDIR)] = {WR_CMD_RMDIR, wr_process_rmdir, NULL, CM_TRUE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_QUERY_FILE_NUM)] = {WR_CMD_QUERY_FILE_NUM, wr_process_query_file_num, NULL, CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_OPEN_DIR)] = {WR_CMD_OPEN_DIR, wr_process_open_dir, NULL, CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_CLOSE_DIR)] = {WR_CMD_CLOSE_DIR, wr_process_close_dir, NULL, CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_OPEN_FILE)] = {WR_CMD_OPEN_FILE, wr_process_open_file, NULL, CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_CLOSE_FILE)] = {WR_CMD_CLOSE_FILE, wr_process_close_file, NULL, CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_CREATE_FILE)] = {WR_CMD_CREATE_FILE, wr_process_create_file, NULL, CM_TRUE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_DELETE_FILE)] = {WR_CMD_DELETE_FILE, wr_process_delete_file, NULL, CM_TRUE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_WRITE_FILE)] = {WR_CMD_WRITE_FILE, wr_process_write_file, NULL, CM_TRUE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_READ_FILE)] = {WR_CMD_READ_FILE, wr_process_read_file, NULL, CM_TRUE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_EXTEND_FILE)] = {WR_CMD_EXTEND_FILE, wr_process_extending_file, NULL, CM_TRUE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_RENAME_FILE)] = {WR_CMD_RENAME_FILE, wr_process_rename, NULL, CM_TRUE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_TRUNCATE_FILE)] = {WR_CMD_TRUNCATE_FILE, wr_process_truncate_file, NULL, CM_TRUE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_FALLOCATE_FILE)] = {WR_CMD_FALLOCATE_FILE, wr_process_fallocate_file, NULL, CM_TRUE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_STOP_SERVER)] = {WR_CMD_STOP_SERVER, wr_process_stop_server, NULL, CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_SETCFG)] = {WR_CMD_SETCFG, wr_process_setcfg, NULL, CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_SET_MAIN_INST)] = {WR_CMD_SET_MAIN_INST, wr_process_set_main_inst, NULL, CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_SWITCH_LOCK)] = {WR_CMD_SWITCH_LOCK, wr_process_switch_lock, NULL, CM_FALSE},
    // query
    [WR_CMD_TYPE_OFFSET(WR_CMD_HANDSHAKE)] = {WR_CMD_HANDSHAKE, wr_process_handshake, NULL, CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_EXIST)] = {WR_CMD_EXIST, wr_process_exist, NULL, CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_GETCFG)] = {WR_CMD_GETCFG, wr_process_getcfg, NULL, CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_GET_INST_STATUS)] = {WR_CMD_GET_INST_STATUS, wr_process_get_inst_status, NULL,
        CM_FALSE},
    [WR_CMD_TYPE_OFFSET(WR_CMD_GET_TIME_STAT)] = {WR_CMD_GET_TIME_STAT, wr_process_get_time_stat, NULL, CM_FALSE},
};

wr_cmd_hdl_t g_wr_remote_handle = {WR_CMD_EXEC_REMOTE, wr_process_remote, NULL, CM_FALSE};

static wr_cmd_hdl_t *wr_get_cmd_handle(int32 cmd)
{
    if (cmd >= WR_CMD_BEGIN && cmd < WR_CMD_END) {
        return &g_wr_cmd_handle[WR_CMD_TYPE_OFFSET(cmd)];
    }
    return NULL;
}

static status_t wr_check_proto_version(wr_session_t *session)
{
    session->client_version = wr_get_client_version(&session->recv_pack);
    uint32 current_proto_ver = wr_get_master_proto_ver();
    current_proto_ver = MIN(current_proto_ver, session->client_version);
    session->proto_version = current_proto_ver;
    if (session->proto_version != wr_get_version(&session->recv_pack)) {
        LOG_RUN_INF("[CHECK_PROTO]The client protocol version need be changed, old protocol version is %u, new "
                    "protocol version is %u.",
            wr_get_version(&session->recv_pack), session->proto_version);
        WR_THROW_ERROR(ERR_WR_VERSION_NOT_MATCH, wr_get_version(&session->recv_pack), session->proto_version);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t wr_exec_cmd(wr_session_t *session, bool32 local_req)
{
    WR_LOG_DEBUG_OP(
        "Receive command:%d, server status is %d.", session->recv_pack.head->cmd, (int32)g_wr_instance.status);
    // remote req need process for proto_version
    session->proto_version = wr_get_version(&session->recv_pack);
    wr_cmd_hdl_t *handle = wr_get_cmd_handle(session->recv_pack.head->cmd);

    if ((handle == NULL) || (handle->proc == NULL)) {
        LOG_DEBUG_ERR("the req cmd: %d is not valid.", session->recv_pack.head->cmd);
        return CM_ERROR;
    }

    status_t status;
    do {
        cm_reset_error();
        wr_inc_active_sessions(session);
        if (wr_can_cmd_type_no_open(session->recv_pack.head->cmd)) {
            status = handle->proc(session);
        } else if (!wr_need_exec_remote(handle->exec_on_active, local_req)) {
            // if cur node is standby, may reset it to recovery to do recovery
            if (g_wr_instance.status != WR_STATUS_OPEN && g_wr_instance.status != WR_STATUS_PREPARE) {
                LOG_RUN_INF("Req forbided by recovery for cmd:%u", (uint32)session->recv_pack.head->cmd);
                wr_dec_active_sessions(session);
                cm_sleep(WR_PROCESS_REMOTE_INTERVAL);
                continue;
            }
            status = handle->proc(session);
        } else {
            status = g_wr_remote_handle.proc(session);
        }
        wr_dec_active_sessions(session);
        if (status != CM_SUCCESS &&
            (cm_get_error_code() == ERR_WR_RECOVER_CAUSE_BREAK || cm_get_error_code() == ERR_WR_MASTER_CHANGE)) {
            LOG_RUN_INF("Req breaked by error %d for cmd:%u", cm_get_error_code(), session->recv_pack.head->cmd);
            cm_sleep(WR_PROCESS_REMOTE_INTERVAL);
            continue;
        }
        break;
    } while (CM_TRUE);

    session->audit_info.action = wr_get_cmd_desc(session->recv_pack.head->cmd);

    if (local_req) {
        sql_record_audit_log(session, status, session->recv_pack.head->cmd);
    }
    return status;
}

void wr_process_cmd_wait_be_open(wr_session_t *session)
{
    while (g_wr_instance.status != WR_STATUS_OPEN) {
        WR_GET_CM_LOCK_LONG_SLEEP;
        LOG_RUN_INF("The status %d of instance %lld is not open, just wait.\n", (int32)g_wr_instance.status,
            wr_get_inst_cfg()->params.inst_id);
    }
}

status_t wr_process_command(wr_session_t *session)
{
    status_t status = CM_SUCCESS;
    bool32 ready = CM_FALSE;

    cm_reset_error();
    if (cs_wait(&session->pipe, CS_WAIT_FOR_READ, WR_WAIT_TIMEOUT, &ready) != CM_SUCCESS) {
        session->is_closed = CM_TRUE;
        return CM_ERROR;
    }

    if (ready == CM_FALSE) {
        return CM_SUCCESS;
    }
    wr_init_set(&session->send_pack, session->proto_version);
    status = wr_read(&session->pipe, &session->recv_pack, CM_FALSE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to read message sent by %s.", session->cli_info.process_name);
        session->is_closed = CM_TRUE;
        return CM_ERROR;
    }
    status = wr_check_proto_version(session);
    if (status != CM_SUCCESS) {
        wr_return_error(session);
        return CM_ERROR;
    }

    if (!wr_can_cmd_type_no_open(session->recv_pack.head->cmd)) {
        wr_process_cmd_wait_be_open(session);
    }

    status = wr_exec_cmd(session, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to execute command:%d.", session->recv_pack.head->cmd);
        wr_return_error(session);
        return CM_ERROR;
    } else {
        wr_return_success(session);
    }
    return CM_SUCCESS;
}

status_t wr_proc_standby_req(wr_session_t *session)
{
    if (wr_is_readonly() == CM_TRUE && !wr_need_exec_local()) {
        wr_config_t *cfg = wr_get_inst_cfg();
        uint32 id = (uint32)(cfg->params.inst_id);
        LOG_RUN_ERR("The local node(%u) is in readonly state and cannot execute remote requests.", id);
        return CM_ERROR;
    }

    return wr_exec_cmd(session, CM_FALSE);
}

status_t wr_process_handshake_cmd(wr_session_t *session, wr_cmd_type_e cmd)
{
    status_t status = CM_ERROR;
    bool32 ready = CM_FALSE;
    do {
        cm_reset_error();
        if (cs_wait(&session->pipe, CS_WAIT_FOR_READ, session->pipe.socket_timeout, &ready) != CM_SUCCESS) {
            LOG_RUN_ERR("[WR_CONNECT]session %u wait handshake cmd %u failed.", session->id, cmd);
            return CM_ERROR;
        }
        if (ready == CM_FALSE) {
            LOG_RUN_ERR("[WR_CONNECT]session %u wait handshake cmd %u timeout.", session->id, cmd);
            return CM_ERROR;
        }
        wr_init_set(&session->send_pack, session->proto_version);
        status = wr_read(&session->pipe, &session->recv_pack, CM_FALSE);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("[WR_CONNECT]session %u read handshake cmd %u msg failed.", session->id, cmd);
            return CM_ERROR;
        }
        status = wr_check_proto_version(session);
        if (status != CM_SUCCESS) {
            wr_return_error(session);
            continue;
        }
        break;
    } while (CM_TRUE);
    if (session->recv_pack.head->cmd != cmd) {
        LOG_RUN_ERR("[WR_CONNECT]session %u wait handshake cmd %u, but get msg cmd %u.", session->id, cmd,
            session->recv_pack.head->cmd);
        return CM_ERROR;
    }
    status = wr_exec_cmd(session, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR(
            "[WR_CONNECT]Failed to execute command:%d, session %u.", session->recv_pack.head->cmd, session->id);
        wr_return_error(session);
        return CM_ERROR;
    } else {
        wr_return_success(session);
    }
    return status;
}
#ifdef __cplusplus
}
#endif
