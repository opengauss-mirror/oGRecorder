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
 * gr_service.c
 *
 *
 * IDENTIFICATION
 *    src/service/gr_service.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_service.h"
#include "cm_system.h"
#include "gr_instance.h"
#include "gr_malloc.h"
#include "gr_open_file.h"
#include "gr_filesystem.h"
#include "gr_mes.h"
#include "gr_api.h"
#include "gr_thv.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline bool32 gr_need_exec_remote(bool32 exec_on_active, bool32 local_req)
{
    gr_config_t *cfg = gr_get_inst_cfg();
    uint32_t master_id = gr_get_master_id();
    uint32_t curr_id = (uint32_t)(cfg->params.inst_id);
    return ((curr_id != master_id) && (exec_on_active) && (local_req == CM_TRUE));
}

static uint32_t gr_get_master_proto_ver(void)
{
    uint32_t master_id = gr_get_master_id();
    if (master_id >= GR_MAX_INSTANCES) {
        return GR_PROTO_VERSION;
    }
    uint32_t master_proto_ver = (uint32_t)cm_atomic32_get((atomic32_t *)&g_gr_instance.cluster_proto_vers[master_id]);
    if (master_proto_ver == GR_INVALID_VERSION) {
        return GR_PROTO_VERSION;
    }
    master_proto_ver = MIN(master_proto_ver, GR_PROTO_VERSION);
    return master_proto_ver;
}

status_t gr_get_exec_nodeid(gr_session_t *session, uint32_t *currid, uint32_t *remoteid)
{
    gr_config_t *cfg = gr_get_inst_cfg();
    *currid = (uint32_t)(cfg->params.inst_id);
    *remoteid = gr_get_master_id();
    while (*remoteid == GR_INVALID_ID32) {
        if (get_instance_status_proc() == GR_STATUS_RECOVERY) {
            GR_THROW_ERROR(ERR_GR_RECOVER_CAUSE_BREAK);
            LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Master id is invalid.");
            return CM_ERROR;
        }
        *remoteid = gr_get_master_id();
        cm_sleep(GR_PROCESS_GET_MASTER_ID);
    }
    LOG_DEBUG_INF("Start processing remote requests(%d), remote node(%u),current node(%u).",
        (session->recv_pack.head == NULL) ? -1 : session->recv_pack.head->cmd, *remoteid, *currid);
    return CM_SUCCESS;
}

#define GR_PROCESS_REMOTE_INTERVAL 50
static status_t gr_process_remote(gr_session_t *session)
{
    uint32_t remoteid = GR_INVALID_ID32;
    uint32_t currid = GR_INVALID_ID32;
    status_t ret = CM_ERROR;
    GR_RETURN_IF_ERROR(gr_get_exec_nodeid(session, &currid, &remoteid));

    LOG_DEBUG_INF("Start processing remote requests(%d), remote node(%u),current node(%u).",
        session->recv_pack.head->cmd, remoteid, currid);
    status_t remote_result = CM_ERROR;
    while (CM_TRUE) {
        if (get_instance_status_proc() == GR_STATUS_RECOVERY) {
            GR_THROW_ERROR(ERR_GR_RECOVER_CAUSE_BREAK);
            LOG_RUN_INF("Req break by recovery");
            return CM_ERROR;
        }

        ret = gr_exec_sync(session, remoteid, currid, &remote_result);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR(
                "End of processing the remote request(%d) failed, remote node(%u),current node(%u), result code(%d).",
                session->recv_pack.head->cmd, remoteid, currid, ret);
            if (session->recv_pack.head->cmd == GR_CMD_SWITCH_LOCK) {
                return ret;
            }
            cm_sleep(GR_PROCESS_REMOTE_INTERVAL);
            GR_RETURN_IF_ERROR(gr_get_exec_nodeid(session, &currid, &remoteid));
            if (currid == remoteid) {
                GR_THROW_ERROR(ERR_GR_MASTER_CHANGE);
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

status_t gr_diag_proto_type(gr_session_t *session)
{
    link_ready_ack_t ack;
    uint32_t proto_code = 0;
    int32_t size;
    char buffer[sizeof(version_proto_code_t)] = {0};
    version_proto_code_t version_proto_code = {0};

    status_t ret = cs_read_bytes(&session->pipe, buffer, sizeof(version_proto_code_t), &size);
    GR_RETURN_IFERR2(ret, LOG_RUN_ERR("Instance recieve protocol failed, errno:%d.", errno));

    if (size == sizeof(version_proto_code_t)) {
        version_proto_code = *(version_proto_code_t*)buffer;
        proto_code = version_proto_code.proto_code;
    } else if (size == sizeof(proto_code)) {
        proto_code = *(uint32_t *)buffer;
    } else {
        LOG_RUN_ERR("gr_diag_proto_type invalid size[%u].", size);
    }
    LOG_RUN_INF("gr_diag_proto_type proto_code=%u.", proto_code);

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
static void gr_clean_open_files(gr_session_t *session)
{
    if (cm_sys_process_alived(session->cli_info.cli_pid, session->cli_info.start_time)) {
        LOG_DEBUG_INF("Process:%s is alive, pid:%llu, start_time:%lld.", session->cli_info.process_name,
            session->cli_info.cli_pid, session->cli_info.start_time);
        return;
    }

    LOG_RUN_INF("Clean open files for pid:%llu.", session->cli_info.cli_pid);
}

void gr_release_session_res(gr_session_t *session)
{
    gr_server_session_lock(session);
    gr_clean_session_latch(session, CM_FALSE);
    gr_clean_open_files(session);
    gr_destroy_session_inner(session);
    cm_spin_unlock(&session->shm_lock);
    LOG_DEBUG_INF("Succeed to unlock session %u shm lock", session->id);
    cm_spin_unlock(&session->lock);
}

status_t gr_process_single_cmd(gr_session_t **session)
{
    status_t status = gr_process_command(*session);
    if ((*session)->is_closed) {
        LOG_RUN_INF("Session:%u end to do service, thread id is %u, connect time is %llu, try to clean source.",
            (*session)->id, (*session)->cli_info.thread_id, (*session)->cli_info.connect_time);
        gr_clean_reactor_session(*session);
        *session = NULL;
    } else {
        gr_session_detach_workthread(*session);
    }
    return status;
}

static void gr_return_error(gr_session_t *session)
{
    int32_t code;
    const char *message = NULL;

    CM_ASSERT(session != NULL);
    gr_packet_t *send_pack = &session->send_pack;
    gr_init_set(send_pack, session->proto_version);
    send_pack->head->cmd = session->recv_pack.head->cmd;
    send_pack->head->result = (uint8)CM_ERROR;
    send_pack->head->flags = 0;
    cm_get_error(&code, &message);
    (void)gr_put_int32(send_pack, (uint32_t)code);
    (void)gr_put_str_with_cutoff(send_pack, message);
    status_t status = gr_write(&session->pipe, send_pack);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to reply,size:%u, cmd:%u.", send_pack->head->size, send_pack->head->cmd);
    }
    cm_reset_error();
}

static void gr_return_success(gr_session_t *session)
{
    CM_ASSERT(session != NULL);
    status_t status;
    gr_packet_t *send_pack = &session->send_pack;
    send_pack->head->cmd = session->recv_pack.head->cmd;
    send_pack->head->result = (uint8)CM_SUCCESS;
    send_pack->head->flags = 0;
    gr_set_version(send_pack, session->proto_version);
    gr_set_client_version(send_pack, session->client_version);

    status = gr_write(&session->pipe, send_pack);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to reply message, size:%u, cmd:%u.", send_pack->head->size, send_pack->head->cmd);
    }
}

static status_t gr_set_audit_resource(char *resource, uint32_t audit_type, const char *format, ...)
{
    if ((cm_log_param_instance()->audit_level & audit_type) == 0) {
        return CM_SUCCESS;
    }
    va_list args;
    va_start(args, format);
    int32_t ret =
        vsnprintf_s(resource, (size_t)GR_MAX_AUDIT_PATH_LENGTH, (size_t)(GR_MAX_AUDIT_PATH_LENGTH - 1), format, args);
    GR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    va_end(args);
    return CM_SUCCESS;
}

static status_t gr_process_mkdir(gr_session_t *session)
{
#define MKDIR_MODE 0700
    char *dir = NULL;

    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &dir));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY, "%s", dir));
    GR_LOG_DEBUG_OP("Begin to mkdir:%s", dir);
    GR_RETURN_IF_ERROR(gr_check_readwrite("mkdir"));
    
    status_t status = gr_filesystem_mkdir((const char *)dir, MKDIR_MODE);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to mkdir:%s", dir);
        return status;
    }
    LOG_RUN_ERR("Failed to mkdir:%s", dir);
    return status;
}

static status_t gr_process_rmdir(gr_session_t *session)
{
    char *dir = NULL;
    int64 flag = 0;
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &dir));
    GR_RETURN_IF_ERROR(gr_get_int64(&session->recv_pack, &flag));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY, "%s", dir));
    GR_LOG_DEBUG_OP("Begin to rmdir:%s.", dir);
    GR_RETURN_IF_ERROR(gr_check_readwrite("rmdir"));
    status_t status = gr_filesystem_rmdir(dir, flag);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to rmdir:%s", dir);
        return status;
    }
    LOG_RUN_ERR("Failed to rmdir:%s", dir);
    return status;
}

static status_t gr_process_mount_vfs(gr_session_t *session)
{
    char *vfs_name = NULL;
    gr_init_get(&session->recv_pack);
    uint64_t handle;
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &vfs_name));
    
    if (gr_filesystem_opendir(vfs_name, &handle) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to mount vfs:%s", vfs_name);
        return CM_ERROR;
    }
    (void)gr_put_int64(&session->send_pack, (int64)handle);
    return CM_SUCCESS;
}

static status_t gr_process_unmount_vfs(gr_session_t *session)
{
    uint64_t handle;
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_int64(&session->recv_pack, (int64 *)&handle));
    if (gr_filesystem_closedir(handle) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to unmount vfs");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t gr_process_query_file_num(gr_session_t *session)
{
    uint64_t handle = 0;
    uint32_t file_num = 0;
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_int64(&session->recv_pack, (int64 *)&handle));
    if (gr_filesystem_query_file_num(handle, &file_num) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to query file num for vfs");
        return CM_ERROR;
    }
    (void)gr_put_int32(&session->send_pack, file_num);
    return CM_SUCCESS;
}

#define GR_MAX_FILE_NUM 100
static status_t gr_process_query_file_info(gr_session_t *session)
{
    uint32_t file_count = 0;
    bool32 is_continue = CM_FALSE;
    gr_file_item_t file_items[GR_MAX_FILE_NUM];
    uint64_t handle = 0;

    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_int32(&session->recv_pack, (int32*)&is_continue));
    GR_RETURN_IF_ERROR(gr_get_int64(&session->recv_pack, (int64*)&handle));

    if (gr_filesystem_query_file_info(handle, file_items, GR_MAX_FILE_NUM, &file_count, is_continue) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to query file info for vfs");
        return CM_ERROR;
    }

    GR_RETURN_IF_ERROR(gr_put_int32(&session->send_pack, file_count));

    for (uint32_t i = 0; i < file_count; i++) {
        GR_RETURN_IF_ERROR(gr_put_data(&session->send_pack, &file_items[i], sizeof(gr_file_item_t)));
    }
    return CM_SUCCESS;
}

static status_t gr_process_create_file(gr_session_t *session)
{
    char *file_ptr = NULL;
    text_t text;
    text_t sub = CM_NULL_TEXT;
    int32_t flag;

    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &file_ptr));
    GR_RETURN_IF_ERROR(gr_get_int32(&session->recv_pack, &flag));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY, "%s", file_ptr));
    
    cm_str2text(file_ptr, &text);
    bool32 result = cm_fetch_rtext(&text, '/', '\0', &sub);
    GR_RETURN_IF_FALSE2(
        result, GR_THROW_ERROR(ERR_GR_FILE_PATH_ILL, sub.str, ", which is not a complete absolute path name."));
    if (text.len == 0) {
        GR_THROW_ERROR(ERR_GR_FILE_CREATE, "file name is null.");
        return CM_ERROR;
    }
    result = (bool32)(text.len < GR_MAX_NAME_LEN);
    GR_RETURN_IF_FALSE2(result, GR_THROW_ERROR(ERR_GR_FILE_PATH_ILL, text.str, "name length should less than 64."));

    char parent_str[GR_FILE_PATH_MAX_LENGTH];
    char name_str[GR_MAX_NAME_LEN];
    GR_RETURN_IF_ERROR(cm_text2str(&sub, parent_str, sizeof(parent_str)));
    GR_RETURN_IF_ERROR(cm_text2str(&text, name_str, sizeof(name_str)));

    GR_LOG_DEBUG_OP("Begin to create file:%s in path:%s.", name_str, parent_str);
    GR_RETURN_IF_ERROR(gr_check_readwrite("create file"));

    char full_path[GR_FILE_PATH_MAX_LENGTH];
    sprintf_s(full_path, sizeof(full_path), "%s/%s", parent_str, name_str);
    status_t status = gr_filesystem_touch((const char *)full_path);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to create file:%s in path:%s", name_str, parent_str);
        return status;
    }

    LOG_RUN_ERR("Failed to create file:%s in path:%s", name_str, parent_str);
    return status;
}

static status_t gr_process_delete_file(gr_session_t *session)
{
    char *name = NULL;
    gr_init_get(&session->recv_pack);
    status_t status = gr_get_str(&session->recv_pack, &name);
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("delete file get file name failed."));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY, "%s", name));
    GR_LOG_DEBUG_OP("Begin to rm file:%s", name);
    GR_RETURN_IF_ERROR(gr_check_readwrite("delete file"));
    status = gr_filesystem_rm(name);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to rm file:%s", name);
        return status;
    }
    LOG_RUN_ERR("Failed to rm file:%s", name);
    return status;
}

static status_t gr_process_exist(gr_session_t *session)
{
    bool32 result = CM_FALSE;
    gft_item_type_t type;
    char *name = NULL;
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &name));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_QUERY, "%s", name));
    GR_RETURN_IF_ERROR(gr_exist_item(session, (const char *)name, &result, &type));

    GR_RETURN_IF_ERROR(gr_put_int32(&session->send_pack, (uint32_t)result));
    GR_RETURN_IF_ERROR(gr_put_int32(&session->send_pack, (uint32_t)type));
    return CM_SUCCESS;
}

static status_t gr_process_open_file(gr_session_t *session)
{
    char *name = NULL;
    int fd = 0;
    int32_t flag;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &name));
    GR_RETURN_IF_ERROR(gr_get_int32(&session->recv_pack, &flag));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY, "%s", name));
    GR_LOG_DEBUG_OP("Begin to close file, fd:%d", fd);
    GR_RETURN_IF_ERROR(gr_open_file(session, (const char *)name, flag, &fd));
    LOG_DEBUG_INF("Succeed to close file, fd:%d", fd);
    GR_RETURN_IF_ERROR(gr_put_int32(&session->send_pack, fd));

    if (generate_random_sha256(hash) != GR_SUCCESS) {
        LOG_RUN_ERR("Failed to generate random SHA256 hash\n");
        return GR_ERROR;
    }
    GR_RETURN_IF_ERROR(update_file_hash(session, fd, hash));
    GR_RETURN_IF_ERROR(gr_put_sha256(&session->send_pack, hash));
    return CM_SUCCESS;
}

static status_t gr_process_close_file(gr_session_t *session)
{
    int64 fd;
    int32 need_lock;
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_int64(&session->recv_pack, &fd));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY, "fd:%d", fd));
    GR_RETURN_IF_ERROR(gr_get_int32(&session->recv_pack, &need_lock));

    GR_LOG_DEBUG_OP("Begin to close file, fd:%lld", fd);
    GR_RETURN_IF_ERROR(gr_filesystem_close(fd, need_lock));
    LOG_DEBUG_INF("Succeed to close file, fd:%lld", fd);
    return CM_SUCCESS;
}

static status_t gr_process_write_file(gr_session_t *session)
{
    int64 offset = 0;
    int64 file_size = 0;
    int64 rel_size = 0;
    int handle = 0;
    char *buf = NULL;
    unsigned char cli_hash[SHA256_DIGEST_LENGTH];
    unsigned char data_hash[SHA256_DIGEST_LENGTH];
    unsigned char session_curr_hash[SHA256_DIGEST_LENGTH];
    unsigned char session_prev_hash[SHA256_DIGEST_LENGTH];
    unsigned char combine_hash[SHA256_DIGEST_LENGTH];

    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_int64(&session->recv_pack, &offset));
    GR_RETURN_IF_ERROR(gr_get_int32(&session->recv_pack, &handle));
    GR_RETURN_IF_ERROR(gr_get_int64(&session->recv_pack, &file_size));
    GR_RETURN_IF_ERROR(gr_get_sha256(&session->recv_pack, cli_hash));
    GR_RETURN_IF_ERROR(gr_get_data(&session->recv_pack, file_size, (void**)&buf));
    GR_RETURN_IF_ERROR(gr_check_readwrite("write file"));

    status_t status = calculate_data_hash(buf, file_size, data_hash);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to calcalate data hash.");
        return CM_ERROR;
    }

    status = get_file_hash(session, handle, session_curr_hash, session_prev_hash);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to get session hash.");
        return CM_ERROR;
    }

    status = xor_sha256_hash(data_hash, session_curr_hash, combine_hash);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to calcalate combine_hash.");
        return CM_ERROR;
    }

    status = compare_sha256(cli_hash, combine_hash);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("combine hash return failed.");
        return CM_ERROR;
    }

    
    status = gr_filesystem_pwrite(handle, offset, file_size, buf, &rel_size);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to write to handle: %d, offset: %lld, size: %lld", handle, offset, file_size);
        return CM_ERROR;
    }
    status = update_file_hash(session, handle, combine_hash);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("update hash failed.");
        return CM_ERROR;
    }

    GR_RETURN_IF_ERROR(gr_put_int64(&session->send_pack, rel_size));
    return CM_SUCCESS;
}

static status_t gr_process_read_file(gr_session_t *session)
{
    int handle = 0;
    int64 offset = 0;
    int64 size = 0;
    int64 rel_size = 0;

    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_int64(&session->recv_pack, &offset));
    GR_RETURN_IF_ERROR(gr_get_int32(&session->recv_pack, &handle));
    GR_RETURN_IF_ERROR(gr_get_int64(&session->recv_pack, &size));

    if (size <= 0) {
        LOG_RUN_ERR("Invalid read size: %lld", size);
        return CM_ERROR;
    }

    char *buf = (char *)malloc(size);
    if (buf == NULL) {
        LOG_RUN_ERR("Failed to malloc buffer for read file.");
        return CM_ERROR;
    }
    memset(buf, 0, size);

    status_t res = gr_filesystem_pread(handle, offset, size, buf, &rel_size);
    if (res == CM_ERROR) {
        free(buf);
        LOG_RUN_ERR("Failed to read from handle: %d, offset: %lld, size: %lld", handle, offset, size);
        return CM_ERROR;
    }

    text_t data = { .str = buf, .len = rel_size };
    GR_RETURN_IF_ERROR(gr_put_text(&session->send_pack, &data));

    free(buf);
    return CM_SUCCESS;
}

static status_t gr_process_truncate_file(gr_session_t *session)
{
    int handle;
    int64 length;
    int64 truncateType;

    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_int64(&session->recv_pack, &length));
    GR_RETURN_IF_ERROR(gr_get_int32(&session->recv_pack, &handle));
    GR_RETURN_IF_ERROR(gr_get_int64(&session->recv_pack, &truncateType));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY,
        "handle:%d, length:%ld", handle, length));
    LOG_DEBUG_INF("Truncate file handle:%d, length:%lld", handle, length);
    return gr_filesystem_truncate(handle, length);
}

static status_t gr_process_stat_file(gr_session_t *session)
{
    char *name = NULL;
    int64 offset;
    int64 size;
    gr_file_status_t mode;
    time_t time;
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &name));
    GR_RETURN_IF_ERROR(gr_filesystem_stat(name, &offset, &size, &mode, &time));
    gr_put_int64(&session->send_pack, offset);
    gr_put_int64(&session->send_pack, size);
    gr_put_int32(&session->send_pack, (int32_t)mode);
    char *expire_time = ctime(&time);
    gr_put_str(&session->send_pack, ctime(&time));
    LOG_DEBUG_INF(
        "Stat file name:%s, offset:%lld, size:%lld, mode:%d, expire time:%s", name, offset, size, mode, expire_time);
    return CM_SUCCESS;
}

static status_t gr_process_handshake(gr_session_t *session)
{
    gr_init_get(&session->recv_pack);
    session->client_version = gr_get_version(&session->recv_pack);
    uint32_t current_proto_ver = gr_get_master_proto_ver();
    session->proto_version = MIN(session->client_version, current_proto_ver);
    gr_cli_info_t *cli_info;
    GR_RETURN_IF_ERROR(gr_get_data(&session->recv_pack, sizeof(gr_cli_info_t), (void **)&cli_info));
    errno_t errcode;
    cm_spin_lock(&session->lock, NULL);
    errcode = memcpy_s(&session->cli_info, sizeof(gr_cli_info_t), cli_info, sizeof(gr_cli_info_t));
    cm_spin_unlock(&session->lock);
    securec_check_ret(errcode);
    LOG_RUN_INF(
        "[GR_CONNECT]The client has connected, session id:%u, pid:%llu, process name:%s.st_time:%lld, objectid:%u",
        session->id, session->cli_info.cli_pid, session->cli_info.process_name, session->cli_info.start_time,
        session->objectid);
    char *server_home = gr_get_cfg_dir(ZFS_CFG);
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_QUERY, "%s", server_home));
    LOG_RUN_INF("[GR_CONNECT]Server home is %s, when get home.", server_home);
    uint32_t server_pid = getpid();
    text_t data;
    cm_str2text(server_home, &data);
    data.len++;  // for keeping the '\0'
    GR_RETURN_IF_ERROR(gr_put_text(&session->send_pack, &data));
    GR_RETURN_IF_ERROR(gr_put_int32(&session->send_pack, session->objectid));
    if (session->proto_version >= GR_VERSION_2) {
        GR_RETURN_IF_ERROR(gr_put_int32(&session->send_pack, server_pid));
    }
    return CM_SUCCESS;
}

static status_t gr_process_rename(gr_session_t *session)
{
    char *src = NULL;
    char *dst = NULL;
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &src));
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &dst));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY, "%s, %s", src, dst));
    return CM_SUCCESS;
}

#define GR_SERVER_STATUS_OFFSET(i) ((uint32_t)(i) - (uint32_t)GR_STATUS_NORMAL)
static char *g_gr_instance_rdgr_type[GR_SERVER_STATUS_OFFSET(GR_SERVER_STATUS_END)] = {
    [GR_SERVER_STATUS_OFFSET(GR_STATUS_NORMAL)] = "NORMAL",
    [GR_SERVER_STATUS_OFFSET(GR_STATUS_READONLY)] = "READONLY",
    [GR_SERVER_STATUS_OFFSET(GR_STATUS_READWRITE)] = "READWRITE",
};

char *gr_get_gr_server_status(int32_t server_status)
{
    if (server_status < GR_STATUS_NORMAL || server_status > GR_STATUS_READWRITE) {
        return "unknown";
    }
    return g_gr_instance_rdgr_type[GR_SERVER_STATUS_OFFSET(server_status)];
}

#define GR_INSTANCE_STATUS_OFFSET(i) ((uint32_t)(i) - (uint32_t)GR_STATUS_PREPARE)
static char *g_gr_instance_status_desc[GR_INSTANCE_STATUS_OFFSET(GR_INSTANCE_STATUS_END)] = {
    [GR_INSTANCE_STATUS_OFFSET(GR_STATUS_PREPARE)] = "prepare",
    [GR_INSTANCE_STATUS_OFFSET(GR_STATUS_RECOVERY)] = "recovery",
    [GR_INSTANCE_STATUS_OFFSET(GR_STATUS_SWITCH)] = "switch",
    [GR_INSTANCE_STATUS_OFFSET(GR_STATUS_OPEN)] = "open",
};

char *gr_get_gr_instance_status(int32_t instance_status)
{
    if (instance_status < GR_STATUS_PREPARE || instance_status > GR_STATUS_OPEN) {
        return "unknown";
    }
    return g_gr_instance_status_desc[GR_INSTANCE_STATUS_OFFSET(instance_status)];
}

// get grserver status:open, recovery or switch
static status_t gr_process_get_inst_status(gr_session_t *session)
{
    gr_server_status_t *gr_status = NULL;
    GR_RETURN_IF_ERROR(
        gr_reserv_text_buf(&session->send_pack, (uint32_t)sizeof(gr_server_status_t), (char **)&gr_status));

    gr_status->instance_status_id = g_gr_instance.status;
    gr_status->server_status_id = gr_get_server_status_flag();
    gr_status->local_instance_id = g_gr_instance.inst_cfg.params.inst_id;
    gr_status->master_id = gr_get_master_id();
    gr_status->is_maintain = g_gr_instance.is_maintain;
    char *gr_instance_status = gr_get_gr_instance_status(gr_status->instance_status_id);
    errno_t errcode = strcpy_s(gr_status->instance_status, GR_MAX_STATUS_LEN, gr_instance_status);
    MEMS_RETURN_IFERR(errcode);

    char *gr_server_status = gr_get_gr_server_status(gr_status->server_status_id);
    errcode = strcpy_s(gr_status->server_status, GR_MAX_STATUS_LEN, gr_server_status);
    MEMS_RETURN_IFERR(errcode);

    GR_RETURN_IF_ERROR(gr_set_audit_resource(
        session->audit_info.resource, GR_AUDIT_MODIFY, "status:%s", gr_status->instance_status));
    GR_LOG_DEBUG_OP("Server status is %s.", gr_status->instance_status);
    return CM_SUCCESS;
}
static status_t gr_process_get_time_stat(gr_session_t *session)
{
    uint64 size = sizeof(gr_stat_item_t) * GR_EVT_COUNT;
    gr_stat_item_t *time_stat = NULL;
    GR_RETURN_IF_ERROR(gr_reserv_text_buf(&session->send_pack, (uint32_t)size, (char **)&time_stat));

    errno_t errcode = memset_s(time_stat, (size_t)size, 0, (size_t)size);
    securec_check_ret(errcode);
    gr_session_ctrl_t *session_ctrl = gr_get_session_ctrl();
    gr_session_t *tmp_session = NULL;
    cm_spin_lock(&session_ctrl->lock, NULL);
    for (uint32_t i = 0; i < session_ctrl->alloc_sessions; i++) {
        tmp_session = session_ctrl->sessions[i];
        if (tmp_session->is_used && !tmp_session->is_closed) {
            for (uint32_t j = 0; j < GR_EVT_COUNT; j++) {
                int64 count = (int64)tmp_session->gr_session_stat[j].wait_count;
                int64 total_time = (int64)tmp_session->gr_session_stat[j].total_wait_time;
                int64 max_sgl_time = (int64)tmp_session->gr_session_stat[j].max_single_time;

                time_stat[j].wait_count += count;
                time_stat[j].total_wait_time += total_time;
                time_stat[j].max_single_time = (atomic_t)MAX((int64)time_stat[j].max_single_time, max_sgl_time);

                (void)cm_atomic_add(&tmp_session->gr_session_stat[j].wait_count, -count);
                (void)cm_atomic_add(&tmp_session->gr_session_stat[j].total_wait_time, -total_time);
                (void)cm_atomic_cas(&tmp_session->gr_session_stat[j].max_single_time, max_sgl_time, 0);
            }
        }
    }
    cm_spin_unlock(&session_ctrl->lock);

    return CM_SUCCESS;
}

void gr_wait_session_pause(gr_instance_t *inst)
{
    tcp_lsnr_t *lsnr = &inst->lsnr;
    LOG_DEBUG_INF("Begin to set session paused.");
    cs_pause_tcp_lsnr(lsnr);
    gr_pause_reactors();
    while (inst->active_sessions != 0) {
        cm_sleep(1);
    }
    LOG_DEBUG_INF("Succeed to pause all session.");
}

void gr_wait_background_pause(gr_instance_t *inst)
{
    LOG_DEBUG_INF("Begin to set background paused.");
    while (inst->is_cleaning || inst->is_checking) {
        cm_sleep(1);
    }
    LOG_DEBUG_INF("Succeed to pause background task.");
}

void gr_set_session_running(gr_instance_t *inst, uint32_t sid)
{
    LOG_DEBUG_INF("Begin to set session running.");
    cm_latch_x(&inst->tcp_lsnr_latch, sid, NULL);
    if (inst->abort_status) {
        LOG_RUN_INF("grserver is aborting, no need to set sessions running.");
        cm_unlatch(&inst->tcp_lsnr_latch, NULL);
        return;
    }
    tcp_lsnr_t *lsnr = &inst->lsnr;
    gr_continue_reactors();
    lsnr->status = LSNR_STATUS_RUNNING;
    cm_unlatch(&inst->tcp_lsnr_latch, NULL);
    LOG_DEBUG_INF("Succeed to run all sessions.");
}

static status_t gr_process_setcfg(gr_session_t *session)
{
    char *name = NULL;
    char *value = NULL;
    char *scope = NULL;
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &name));
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &value));
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &scope));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY, "%s", name));

    return gr_set_cfg_param(name, value, scope);
}

static status_t gr_process_getcfg(gr_session_t *session)
{
    char *name = NULL;
    char *value = NULL;
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &name));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_QUERY, "%s", name));

    GR_RETURN_IF_ERROR(gr_get_cfg_param(name, &value));
    if (strlen(value) != 0 && cm_str_equal_ins(name, "SSL_PWD_CIPHERTEXT")) {
        GR_LOG_DEBUG_OP("Server value is ***, when get cfg.");
    } else {
        GR_LOG_DEBUG_OP("Server value is %s, when get cfg.", value);
    }
    text_t data;
    cm_str2text(value, &data);
    // SSL default value is NULL
    if (value != NULL) {
        data.len++;  // for keeping the '\0'
    }
    return gr_put_text(&session->send_pack, &data);
}

static status_t gr_process_stop_server(gr_session_t *session)
{
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY, "%u", session->id));
    g_gr_instance.abort_status = CM_TRUE;

    return CM_SUCCESS;
}

// process switch lock,just master id can do
static status_t gr_process_switch_lock_inner(gr_session_t *session, uint32_t switch_id)
{
    gr_config_t *inst_cfg = gr_get_inst_cfg();
    uint32_t curr_id = (uint32_t)inst_cfg->params.inst_id;
    uint32_t master_id = gr_get_master_id();
    if ((uint32_t)switch_id == master_id) {
        LOG_RUN_INF("[SWITCH]switchid is equal to current master_id, which is %u.", master_id);
        return CM_SUCCESS;
    }
    if (master_id != curr_id) {
        LOG_RUN_ERR("[SWITCH]current id is %u, just master id %u can do switch lock.", curr_id, master_id);
        return CM_ERROR;
    }
    gr_wait_session_pause(&g_gr_instance);
    g_gr_instance.status = GR_STATUS_SWITCH;
    gr_wait_background_pause(&g_gr_instance);
#ifdef ENABLE_GRTEST
    gr_set_server_status_flag(GR_STATUS_READONLY);
    LOG_RUN_INF("[SWITCH]inst %u set status flag %u when trans lock.", curr_id, GR_STATUS_READONLY);
    gr_set_master_id((uint32_t)switch_id);
    gr_set_session_running(&g_gr_instance, session->id);
    g_gr_instance.status = GR_STATUS_OPEN;
#endif
    status_t ret = CM_SUCCESS;
    // trans lock
    if (g_gr_instance.cm_res.is_valid) {
        gr_set_server_status_flag(GR_STATUS_READONLY);
        LOG_RUN_INF("[SWITCH]inst %u set status flag %u when trans lock.", curr_id, GR_STATUS_READONLY);
        ret = cm_res_trans_lock(&g_gr_instance.cm_res.mgr, GR_CM_LOCK, (uint32_t)switch_id);
        if (ret != CM_SUCCESS) {
            gr_set_session_running(&g_gr_instance, session->id);
            gr_set_server_status_flag(GR_STATUS_READWRITE);
            LOG_RUN_INF("[SWITCH]inst %u set status flag %u when failed to trans lock.", curr_id, GR_STATUS_READWRITE);
            g_gr_instance.status = GR_STATUS_OPEN;
            LOG_RUN_ERR("[SWITCH]cm do switch lock failed from %u to %u.", curr_id, master_id);
            return ret;
        }
        gr_set_master_id((uint32_t)switch_id);
        gr_set_session_running(&g_gr_instance, session->id);
        g_gr_instance.status = GR_STATUS_OPEN;
    } else {
        gr_set_session_running(&g_gr_instance, session->id);
        g_gr_instance.status = GR_STATUS_OPEN;
        LOG_RUN_ERR("[SWITCH]Only with cm can switch lock.");
        return CM_ERROR;
    }
    LOG_RUN_INF(
        "[SWITCH]Old main server %u switch lock to new main server %u successfully.", curr_id, (uint32_t)switch_id);
    return CM_SUCCESS;
}

static status_t gr_process_switch_lock(gr_session_t *session)
{
    int32_t switch_id;
    gr_init_get(&session->recv_pack);
    if (gr_get_int32(&session->recv_pack, &switch_id) != CM_SUCCESS) {
        return CM_ERROR;
    }
    cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));  // when mes process req, will latch s
    cm_latch_x(&g_gr_instance.switch_latch, session->id, LATCH_STAT(LATCH_SWITCH));
    gr_set_recover_thread_id(gr_get_current_thread_id());
    status_t ret = gr_process_switch_lock_inner(session, (uint32_t)switch_id);
    gr_set_recover_thread_id(0);
    // no need to unlatch, for gr_process_message will
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
static status_t gr_process_remote_switch_lock(gr_session_t *session, uint32_t curr_id, uint32_t master_id)
{
    gr_instance_status_e old_status = g_gr_instance.status;
    g_gr_instance.status = GR_STATUS_SWITCH;
    uint32_t current_proto_ver = gr_get_master_proto_ver();
    gr_init_set(&session->recv_pack, current_proto_ver);
    session->recv_pack.head->cmd = GR_CMD_SWITCH_LOCK;
    session->recv_pack.head->flags = 0;
    LOG_RUN_INF("[SWITCH] Try to switch lock to %u by %u.", curr_id, master_id);
    (void)gr_put_int32(&session->recv_pack, curr_id);
    status_t status = gr_process_remote(session);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[SWITCH] Failed to switch lock to %u by %u.", curr_id, master_id);
        g_gr_instance.status = old_status;
    }
    return status;
}

static status_t gr_process_postpone_file_time(gr_session_t *session)
{
    char *name = NULL;
    char *time = NULL;
    gr_init_get(&session->recv_pack);
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &name));
    GR_RETURN_IF_ERROR(gr_get_str(&session->recv_pack, &time));
    GR_RETURN_IF_ERROR(gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY, "%s", name));
    GR_RETURN_IF_ERROR(gr_postpone_file(session, (const char *)name, (const char *)time));
    LOG_DEBUG_INF("Succeed to extend file %s expired time", name);
    return CM_SUCCESS;
}

static status_t gr_process_reload_certs(gr_session_t *session)
{
    GR_RETURN_IF_ERROR(ser_cert_reload());
    return CM_SUCCESS;
}

static status_t gr_process_get_disk_usage(gr_session_t *session)
{
    gr_init_get(&session->recv_pack);
    gr_disk_usage_info_t info;
    gr_get_disk_usage_info(&info);
    
    GR_RETURN_IF_ERROR(gr_put_int64(&session->send_pack, (int64)info.total_bytes));
    GR_RETURN_IF_ERROR(gr_put_int64(&session->send_pack, (int64)info.used_bytes));
    GR_RETURN_IF_ERROR(gr_put_int64(&session->send_pack, (int64)info.available_bytes));
    GR_RETURN_IF_ERROR(gr_put_int64(&session->send_pack, (int64)info.usage_percent));

    LOG_DEBUG_INF("Get disk usage: total=%lu, used=%lu, avail=%lu, usage=%.2f%%",
        info.total_bytes, info.used_bytes, info.available_bytes, info.usage_percent);

    return CM_SUCCESS;
};

static status_t gr_process_set_main_inst(gr_session_t *session)
{
    status_t status = CM_ERROR;
    gr_config_t *cfg = gr_get_inst_cfg();
    uint32_t curr_id = (uint32_t)(cfg->params.inst_id);
    uint32_t master_id;
    GR_RETURN_IF_ERROR(
        gr_set_audit_resource(session->audit_info.resource, GR_AUDIT_MODIFY, "set %u as master", curr_id));
    while (CM_TRUE) {
        master_id = gr_get_master_id();
        if (master_id == curr_id) {
            session->recv_pack.head->cmd = GR_CMD_SET_MAIN_INST;
            LOG_RUN_INF("[SWITCH] Main server %u is set successfully by %u.", curr_id, master_id);
            return CM_SUCCESS;
        }
        if (get_instance_status_proc() == GR_STATUS_RECOVERY) {
            session->recv_pack.head->cmd = GR_CMD_SET_MAIN_INST;
            GR_THROW_ERROR(ERR_GR_RECOVER_CAUSE_BREAK);
            LOG_RUN_INF("[SWITCH] Set main inst break by recovery");
            return CM_ERROR;
        }
        if (!cm_latch_timed_x(
            &g_gr_instance.switch_latch, session->id, GR_PROCESS_REMOTE_INTERVAL, LATCH_STAT(LATCH_SWITCH))) {
            LOG_RUN_INF("[SWITCH] Spin switch lock timed out, just continue.");
            continue;
        }
        status = gr_process_remote_switch_lock(session, curr_id, master_id);
        if (status != CM_SUCCESS) {
            cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            if (cm_get_error_code() == ERR_GR_RECOVER_CAUSE_BREAK) {
                session->recv_pack.head->cmd = GR_CMD_SET_MAIN_INST;
                LOG_RUN_INF("[SWITCH] Try set main break because master id is invalid.");
                return CM_ERROR;
            }
            cm_sleep(GR_PROCESS_REMOTE_INTERVAL);
            continue;
        }
        break;
    }
    session->recv_pack.head->cmd = GR_CMD_SET_MAIN_INST;
    gr_set_recover_thread_id(gr_get_current_thread_id());
    g_gr_instance.status = GR_STATUS_RECOVERY;
    gr_set_master_id(curr_id);

    gr_set_server_status_flag(GR_STATUS_READWRITE);
    LOG_RUN_INF("[SWITCH] inst %u set status flag %u when set main inst.", curr_id, GR_STATUS_READWRITE);
    g_gr_instance.status = GR_STATUS_OPEN;
    gr_set_recover_thread_id(0);
    LOG_RUN_INF("[SWITCH] Main server %u is set successfully by %u.", curr_id, master_id);
    cm_unlatch(&g_gr_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
    return CM_SUCCESS;
}


static gr_cmd_hdl_t g_gr_cmd_handle[GR_CMD_TYPE_OFFSET(GR_CMD_END)] = {
    // modify
    [GR_CMD_TYPE_OFFSET(GR_CMD_MKDIR)] = {GR_CMD_MKDIR, gr_process_mkdir, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_RMDIR)] = {GR_CMD_RMDIR, gr_process_rmdir, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_MOUNT_VFS)] = {GR_CMD_MOUNT_VFS, gr_process_mount_vfs, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_UNMOUNT_VFS)] = {GR_CMD_UNMOUNT_VFS, gr_process_unmount_vfs, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_QUERY_FILE_NUM)] = {GR_CMD_QUERY_FILE_NUM, gr_process_query_file_num, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_QUERY_FILE_INFO)] = {GR_CMD_QUERY_FILE_INFO, gr_process_query_file_info, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_OPEN_FILE)] = {GR_CMD_OPEN_FILE, gr_process_open_file, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_CLOSE_FILE)] = {GR_CMD_CLOSE_FILE, gr_process_close_file, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_CREATE_FILE)] = {GR_CMD_CREATE_FILE, gr_process_create_file, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_DELETE_FILE)] = {GR_CMD_DELETE_FILE, gr_process_delete_file, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_WRITE_FILE)] = {GR_CMD_WRITE_FILE, gr_process_write_file, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_READ_FILE)] = {GR_CMD_READ_FILE, gr_process_read_file, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_RENAME_FILE)] = {GR_CMD_RENAME_FILE, gr_process_rename, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_TRUNCATE_FILE)] = {GR_CMD_TRUNCATE_FILE, gr_process_truncate_file, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_STAT_FILE)] = {GR_CMD_STAT_FILE, gr_process_stat_file, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_STOP_SERVER)] = {GR_CMD_STOP_SERVER, gr_process_stop_server, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_SETCFG)] = {GR_CMD_SETCFG, gr_process_setcfg, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_SET_MAIN_INST)] = {GR_CMD_SET_MAIN_INST, gr_process_set_main_inst, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_SWITCH_LOCK)] = {GR_CMD_SWITCH_LOCK, gr_process_switch_lock, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_POSTPONE_FILE_TIME)] = {GR_CMD_POSTPONE_FILE_TIME, gr_process_postpone_file_time, NULL,
        CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_RELOAD_CERTS)] = {GR_CMD_RELOAD_CERTS, gr_process_reload_certs, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_GET_DISK_USAGE)] = {GR_CMD_GET_DISK_USAGE, gr_process_get_disk_usage, NULL, CM_FALSE},
    // query
    [GR_CMD_TYPE_OFFSET(GR_CMD_HANDSHAKE)] = {GR_CMD_HANDSHAKE, gr_process_handshake, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_EXIST)] = {GR_CMD_EXIST, gr_process_exist, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_GETCFG)] = {GR_CMD_GETCFG, gr_process_getcfg, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_GET_INST_STATUS)] = {GR_CMD_GET_INST_STATUS, gr_process_get_inst_status, NULL, CM_FALSE},
    [GR_CMD_TYPE_OFFSET(GR_CMD_GET_TIME_STAT)] = {GR_CMD_GET_TIME_STAT, gr_process_get_time_stat, NULL, CM_FALSE},
};

gr_cmd_hdl_t g_gr_remote_handle = {GR_CMD_EXEC_REMOTE, gr_process_remote, NULL, CM_FALSE};

static gr_cmd_hdl_t *gr_get_cmd_handle(int32_t cmd)
{
    if (cmd >= GR_CMD_BEGIN && cmd < GR_CMD_END) {
        return &g_gr_cmd_handle[GR_CMD_TYPE_OFFSET(cmd)];
    }
    return NULL;
}

static status_t gr_check_proto_version(gr_session_t *session)
{
    session->client_version = gr_get_client_version(&session->recv_pack);
    uint32_t current_proto_ver = gr_get_master_proto_ver();
    current_proto_ver = MIN(current_proto_ver, session->client_version);
    session->proto_version = current_proto_ver;
    if (session->proto_version != gr_get_version(&session->recv_pack)) {
        LOG_RUN_INF("[CHECK_PROTO]The client protocol version need be changed, old protocol version is %u, new "
                    "protocol version is %u.",
            gr_get_version(&session->recv_pack), session->proto_version);
        GR_THROW_ERROR(ERR_GR_VERSION_NOT_MATCH, gr_get_version(&session->recv_pack), session->proto_version);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t gr_exec_cmd(gr_session_t *session, bool32 local_req)
{
    GR_LOG_DEBUG_OP(
        "Receive command:%d, server status is %d.", session->recv_pack.head->cmd, (int32_t)g_gr_instance.status);
    // remote req need process for proto_version
    session->proto_version = gr_get_version(&session->recv_pack);
    gr_cmd_hdl_t *handle = gr_get_cmd_handle(session->recv_pack.head->cmd);

    if ((handle == NULL) || (handle->proc == NULL)) {
        LOG_RUN_ERR("the req cmd: %d is not valid.", session->recv_pack.head->cmd);
        return CM_ERROR;
    }

    status_t status;
    do {
        cm_reset_error();
        gr_inc_active_sessions(session);
        if (gr_can_cmd_type_no_open(session->recv_pack.head->cmd)) {
            status = handle->proc(session);
        } else if (!gr_need_exec_remote(handle->exec_on_active, local_req)) {
            // if cur node is standby, may reset it to recovery to do recovery
            if (g_gr_instance.status != GR_STATUS_OPEN && g_gr_instance.status != GR_STATUS_PREPARE) {
                LOG_RUN_INF("Req forbided by recovery for cmd:%u", (uint32_t)session->recv_pack.head->cmd);
                gr_dec_active_sessions(session);
                cm_sleep(GR_PROCESS_REMOTE_INTERVAL);
                continue;
            }
            status = handle->proc(session);
        } else {
            status = g_gr_remote_handle.proc(session);
        }
        gr_dec_active_sessions(session);
        if (status != CM_SUCCESS &&
            (cm_get_error_code() == ERR_GR_RECOVER_CAUSE_BREAK || cm_get_error_code() == ERR_GR_MASTER_CHANGE)) {
            LOG_RUN_INF("Req breaked by error %d for cmd:%u", cm_get_error_code(), session->recv_pack.head->cmd);
            cm_sleep(GR_PROCESS_REMOTE_INTERVAL);
            continue;
        }
        break;
    } while (CM_TRUE);

    session->audit_info.action = gr_get_cmd_desc(session->recv_pack.head->cmd);

    if (local_req) {
        sql_record_audit_log(session, status, session->recv_pack.head->cmd);
    }
    return status;
}

void gr_process_cmd_wait_be_open(gr_session_t *session)
{
    while (g_gr_instance.status != GR_STATUS_OPEN) {
        GR_GET_CM_LOCK_LONG_SLEEP;
        LOG_RUN_INF("The status %d of instance %lld is not open, just wait.\n", (int32_t)g_gr_instance.status,
            gr_get_inst_cfg()->params.inst_id);
    }
}

status_t gr_process_command(gr_session_t *session)
{
    status_t status = CM_SUCCESS;
    bool32 ready = CM_FALSE;

    cm_reset_error();
    if (cs_wait(&session->pipe, CS_WAIT_FOR_READ, GR_WAIT_TIMEOUT, &ready) != CM_SUCCESS) {
        session->is_closed = CM_TRUE;
        return CM_ERROR;
    }

    if (ready == CM_FALSE) {
        return CM_SUCCESS;
    }
    gr_init_set(&session->send_pack, session->proto_version);
    status = gr_read(&session->pipe, &session->recv_pack, CM_FALSE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to read message sent by %s.", session->cli_info.process_name);
        session->is_closed = CM_TRUE;
        return CM_ERROR;
    }
    status = gr_check_proto_version(session);
    if (status != CM_SUCCESS) {
        gr_return_error(session);
        return CM_ERROR;
    }

    if (!gr_can_cmd_type_no_open(session->recv_pack.head->cmd)) {
        gr_process_cmd_wait_be_open(session);
    }

    status = gr_exec_cmd(session, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to execute command:%d.", session->recv_pack.head->cmd);
        gr_return_error(session);
        return CM_ERROR;
    } else {
        gr_return_success(session);
    }
    return CM_SUCCESS;
}

status_t gr_proc_standby_req(gr_session_t *session)
{
    if (gr_is_readonly() == CM_TRUE && !gr_need_exec_local()) {
        gr_config_t *cfg = gr_get_inst_cfg();
        uint32_t id = (uint32_t)(cfg->params.inst_id);
        LOG_RUN_ERR("The local node(%u) is in readonly state and cannot execute remote requests.", id);
        return CM_ERROR;
    }

    return gr_exec_cmd(session, CM_FALSE);
}

status_t gr_process_handshake_cmd(gr_session_t *session, gr_cmd_type_e cmd)
{
    status_t status = CM_ERROR;
    bool32 ready = CM_FALSE;
    do {
        cm_reset_error();
        if (cs_wait(&session->pipe, CS_WAIT_FOR_READ, session->pipe.socket_timeout, &ready) != CM_SUCCESS) {
            LOG_RUN_ERR("[GR_CONNECT]session %u wait handshake cmd %u failed.", session->id, cmd);
            return CM_ERROR;
        }
        if (ready == CM_FALSE) {
            LOG_RUN_ERR("[GR_CONNECT]session %u wait handshake cmd %u timeout.", session->id, cmd);
            return CM_ERROR;
        }
        gr_init_set(&session->send_pack, session->proto_version);
        status = gr_read(&session->pipe, &session->recv_pack, CM_FALSE);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("[GR_CONNECT]session %u read handshake cmd %u msg failed.", session->id, cmd);
            return CM_ERROR;
        }
        status = gr_check_proto_version(session);
        if (status != CM_SUCCESS) {
            gr_return_error(session);
            continue;
        }
        break;
    } while (CM_TRUE);
    if (session->recv_pack.head->cmd != cmd) {
        LOG_RUN_ERR("[GR_CONNECT]session %u wait handshake cmd %u, but get msg cmd %u.", session->id, cmd,
            session->recv_pack.head->cmd);
        return CM_ERROR;
    }
    status = gr_exec_cmd(session, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR(
            "[GR_CONNECT]Failed to execute command:%d, session %u.", session->recv_pack.head->cmd, session->id);
        gr_return_error(session);
        return CM_ERROR;
    } else {
        gr_return_success(session);
    }
    return status;
}
#ifdef __cplusplus
}
#endif
