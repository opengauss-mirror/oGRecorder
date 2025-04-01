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
 * wr_api_impl.c
 *
 *
 * IDENTIFICATION
 *    src/common_api/wr_api_impl.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_system.h"
#include "cm_date.h"
#include "wr_defs.h"
#include "wr_diskgroup.h"
#include "wr_file.h"
#include "wr_file_def.h"
#include "wr_latch.h"
#include "wr_malloc.h"
#include "wr_api_impl.h"
#include "wr_defs.h"
#include "wr_fs_aux.h"
#include "wr_thv.h"
#include "wr_stats.h"
#include "wr_cli_conn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_ACCMODE 00000003
#define WR_OPEN_MODE(flag) ((flag + 1) & WR_ACCMODE)
int32 g_wr_uds_conn_timeout = WR_UDS_CONNECT_TIMEOUT;
uint32 g_wr_server_pid = 0;

typedef struct str_files_rw_ctx {
    wr_conn_t *conn;
    wr_file_context_t *file_ctx;
    wr_env_t *env;
    int32 handle;
    int32 size;
    bool32 read;
    int64 offset;
} files_rw_ctx_t;

status_t wr_kick_host_sync(wr_conn_t *conn, int64 kick_hostid)
{
    return wr_msg_interact(conn, WR_CMD_KICKH, (void *)&kick_hostid, NULL);
}

status_t wr_apply_refresh_volume(wr_conn_t *conn, wr_file_context_t *context, auid_t auid);
status_t wr_refresh_volume_handle(wr_conn_t *conn, wr_file_context_t *context, auid_t auid);
status_t wr_reopen_volume_handle(wr_conn_t *conn, wr_file_context_t *context, auid_t auid);

status_t wr_apply_extending_file(wr_conn_t *conn, int32 handle, int64 size, int64 offset)
{
    wr_env_t *wr_env = wr_get_env();
    wr_file_run_ctx_t *file_run_ctx = &wr_env->file_run_ctx;
    if (handle >= (int32)file_run_ctx->max_open_file || handle < 0) {
        return CM_ERROR;
    }
    wr_file_context_t *context = wr_get_file_context_by_handle(file_run_ctx, handle);
    if (context->flag == WR_FILE_CONTEXT_FLAG_FREE) {
        return CM_ERROR;
    }

    LOG_DEBUG_INF("Apply extending file:%s, handle:%d, curr size:%llu, curr written_size:%llu, offset:%lld, size:%lld.",
        context->node->name, handle, context->node->size, context->node->written_size, offset, size);
    wr_extend_info_t send_info;
    send_info.fid = context->fid;
    send_info.ftid = *(uint64 *)&(context->node->id);
    send_info.offset = offset;
    send_info.size = size;
    send_info.vg_name = context->vg_name;
    send_info.vg_id = context->vgid;
    return wr_msg_interact_with_stat(conn, WR_CMD_EXTEND_FILE, (void *)&send_info, NULL);
}

status_t wr_apply_fallocate_file(wr_conn_t *conn, int32 handle, int32 mode, int64 offset, int64 size)
{
    wr_env_t *wr_env = wr_get_env();
    wr_file_run_ctx_t *file_run_ctx = &wr_env->file_run_ctx;
    if (handle >= (int32)file_run_ctx->max_open_file || handle < 0) {
        return CM_ERROR;
    }
    wr_file_context_t *context = wr_get_file_context_by_handle(file_run_ctx, handle);
    if (context->flag == WR_FILE_CONTEXT_FLAG_FREE) {
        return CM_ERROR;
    }

    LOG_DEBUG_INF(
        "Apply fallocate file:%s, handle:%d, curr size:%llu, curr written_size:%llu, mode:%d, offset:%lld, size:%lld.",
        context->node->name, handle, context->node->size, context->node->written_size, mode, offset, size);

    wr_fallocate_info_t send_info;
    send_info.fid = context->fid;
    send_info.ftid = *(uint64 *)&(context->node->id);
    send_info.offset = offset;
    send_info.size = size;
    send_info.vg_id = context->vgid;
    send_info.mode = mode;
    return wr_msg_interact(conn, WR_CMD_FALLOCATE_FILE, (void *)&send_info, NULL);
}

status_t wr_apply_refresh_file(wr_conn_t *conn, wr_file_context_t *context, int64 offset)
{
    ftid_t ftid = context->node->id;
    LOG_DEBUG_INF(
        "Apply refresh file:%s, curr size:%llu, refresh ft id:%llu, refresh entry id:%llu, refresh offset:%llu.",
        context->node->name, context->node->size, WR_ID_TO_U64(ftid), WR_ID_TO_U64(context->node->entry), offset);

    wr_refresh_file_info_t send_info;
    send_info.fid = context->fid;
    send_info.ftid = *(uint64 *)(&ftid);
    send_info.vg_name = context->vg_name;
    send_info.vg_id = context->vgid;
    send_info.offset = offset;
    return wr_msg_interact_with_stat(conn, WR_CMD_REFRESH_FILE, (void *)&send_info, NULL);
}

static status_t wr_check_apply_refresh_file(wr_conn_t *conn, wr_file_context_t *context, int64 offset)
{
    bool32 is_valid = CM_FALSE;
    do {
        WR_UNLOCK_VG_META_S(context->vg_item, conn->session);
        status_t status = wr_apply_refresh_file(conn, context, offset);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to apply refresh file:%s, fid:%llu.", context->node->name, context->fid);
            return CM_ERROR;
        }
        WR_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
        is_valid = wr_is_fs_meta_valid(context->node);
        if (is_valid) {
            break;
        }
        LOG_DEBUG_INF("The node:%s name:%s is invalid, need refresh from server again.",
            wr_display_metaid(context->node->id), context->node->name);
        cm_sleep(WR_READ_REMOTE_INTERVAL);
    } while (!is_valid);
    return CM_SUCCESS;
}

static status_t wr_check_find_fs_block(files_rw_ctx_t *rw_ctx, wr_fs_pos_desc_t *fs_pos)
{
    return CM_SUCCESS;
}

static status_t wr_check_refresh_file_by_offset(
    wr_conn_t *conn, wr_file_context_t *context, int64 offset, bool32 is_read)
{
    return CM_SUCCESS;
}

static status_t wr_check_apply_extending_file(
    wr_conn_t *conn, wr_file_context_t *context, int32 handle, int64 size, int64 offset)
{
    WR_UNLOCK_VG_META_S(context->vg_item, conn->session);
    status_t status = wr_apply_extending_file(conn, handle, size, offset);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to apply extending file, fid:%llu.", context->fid);
        return CM_ERROR;
    }
    WR_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    return wr_check_apply_refresh_file(conn, context, offset);
}

status_t wr_refresh_volume_handle(wr_conn_t *conn, wr_file_context_t *context, auid_t auid)
{
    return CM_SUCCESS;
}

status_t wr_reopen_volume_handle(wr_conn_t *conn, wr_file_context_t *context, auid_t auid)
{
    return CM_SUCCESS;
}

status_t wr_lock_vg_s(wr_vg_info_item_t *vg_item, wr_session_t *session)
{
    wr_latch_offset_t latch_offset;
    latch_offset.type = WR_LATCH_OFFSET_SHMOFFSET;
    latch_offset.offset.shm_offset = wr_get_vg_latch_shm_offset(vg_item);
    return wr_cli_lock_shm_meta_s(session, &latch_offset, vg_item->vg_latch, NULL);
}

static inline void wr_init_conn(wr_conn_t *conn)
{
    conn->flag = CM_FALSE;
    conn->cli_vg_handles = NULL;
    conn->session = NULL;
}

status_t wr_alloc_conn(wr_conn_t **conn)
{
    wr_conn_t *_conn = (wr_conn_t *)cm_malloc_align(WRAPI_BLOCK_SIZE, sizeof(wr_conn_t));
    if (_conn != NULL) {
        wr_init_conn(_conn);
        *conn = _conn;
        return CM_SUCCESS;
    }

    return CM_ERROR;
}

void wr_free_conn(wr_conn_t *conn)
{
    WR_FREE_POINT(conn);
    return;
}

/*
status_t wr_connect(const char *server_locator, wr_conn_opt_t *options, wr_conn_t *conn)
{
    if (server_locator == NULL) {
        WR_THROW_ERROR(ERR_WR_UDS_INVALID_URL, "NULL", 0);
        return CM_ERROR;
    }

    if ((conn->flag == CM_TRUE) && (conn->pipe.link.uds.closed == CM_FALSE)) {
        return CM_SUCCESS;
    }

    conn->flag = CM_FALSE;
    text_t uds = {"UDS:", 4};
    if (wr_check_url_format(server_locator, &uds) != CM_SUCCESS) {
        WR_THROW_ERROR(ERR_WR_UDS_INVALID_URL, server_locator, strlen(server_locator));
        return ERR_WR_UDS_INVALID_URL;
    }
    conn->cli_vg_handles = NULL;
    conn->pipe.options = 0;
    int32 timeout = options != NULL ? options->timeout : g_wr_uds_conn_timeout;
    conn->pipe.connect_timeout = timeout < 0 ? WR_UDS_CONNECT_TIMEOUT : timeout;
    conn->pipe.socket_timeout = WR_UDS_SOCKET_TIMEOUT;
    conn->pipe.link.uds.sock = CS_INVALID_SOCKET;
    conn->pipe.link.uds.closed = CM_TRUE;
    conn->pipe.type = CS_TYPE_DOMAIN_SCOKET;
    conn->session = NULL;
    status_t ret = cs_connect_ex(
        server_locator, &conn->pipe, NULL, (const char *)(server_locator + uds.len), (const char *)CM_NULL_TEXT.str);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("connect server failed, uds path:%s", server_locator);
        return ret;
    }
    wr_init_packet(&conn->pack, conn->pipe.options);

    conn->flag = CM_TRUE;

    return CM_SUCCESS;
}
*/
status_t wr_connect(const char *server_locator, wr_conn_opt_t *options, wr_conn_t *conn)
{
    if (server_locator == NULL) {
        WR_THROW_ERROR(ERR_WR_UDS_INVALID_URL, "NULL", 0);
        return CM_ERROR;
    }

    if ((conn->flag == CM_TRUE) && (conn->pipe.link.uds.closed == CM_FALSE)) {
        return CM_SUCCESS;
    }

    conn->flag = CM_FALSE;

    conn->cli_vg_handles = NULL;
    conn->pipe.options = 0;
    int32 timeout = options != NULL ? options->timeout : g_wr_uds_conn_timeout;
    conn->pipe.connect_timeout = timeout < 0 ? WR_UDS_CONNECT_TIMEOUT : timeout;
    conn->pipe.socket_timeout = WR_UDS_SOCKET_TIMEOUT;
    conn->pipe.link.tcp.sock = CS_INVALID_SOCKET;
    conn->pipe.link.tcp.closed = CM_FALSE;
    conn->pipe.type = CS_TYPE_TCP;
    conn->session = NULL;
    status_t ret = cs_connect(
        server_locator, &conn->pipe, NULL);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("connect server failed, uds path:%s", server_locator);
        return ret;
    }
    wr_init_packet(&conn->pack, conn->pipe.options);

    conn->flag = CM_TRUE;

    return CM_SUCCESS;
}

void wr_disconnect(wr_conn_t *conn)
{
    wr_set_thv_run_ctx_item(WR_THV_RUN_CTX_ITEM_SESSION, NULL);
    if (conn->flag == CM_TRUE) {
        cs_disconnect(&conn->pipe);
        wr_free_packet_buffer(&conn->pack);
        conn->flag = CM_FALSE;
    }

    return;
}

status_t wr_set_session_id(wr_conn_t *conn, uint32 objectid)
{
    if (objectid >= wr_get_max_total_session_cnt()) {
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "objectid error, objectid is %u, max session cnt is %u.", objectid,
            wr_get_max_total_session_cnt());
        return ERR_WR_SESSION_INVALID_ID;
    }
    conn->session = (wr_session_t *)ga_object_addr(GA_SESSION_POOL, objectid);
    if (conn->session == NULL) {
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Failed to get session, object id is %u.", objectid);
        return ERR_WR_SESSION_INVALID_ID;
    }
    LOG_DEBUG_INF("wr set session id is %u, objectid is %u.", ((wr_session_t *)conn->session)->id, objectid);
    wr_set_thv_run_ctx_item(WR_THV_RUN_CTX_ITEM_SESSION, conn->session);
    return CM_SUCCESS;
}

static status_t wr_set_server_info(wr_conn_t *conn, char *home, uint32 objectid, uint32 max_open_file)
{
    status_t status = wr_init_client(max_open_file, home);
    WR_RETURN_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "wr client init failed."), wr_disconnect(conn));

    status = wr_set_session_id(conn, objectid);
    WR_RETURN_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "wr client failed to initialize session."),
        wr_disconnect(conn));
    return CM_SUCCESS;
}

status_t wr_cli_handshake(wr_conn_t *conn, uint32 max_open_file)
{
    conn->cli_info.cli_pid = cm_sys_pid();
    conn->cli_info.thread_id = cm_get_current_thread_id();

    status_t status = cm_sys_process_start_time(conn->cli_info.cli_pid, &conn->cli_info.start_time);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Failed to get process start time pid %llu.\n", conn->cli_info.cli_pid);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("The process start time is:%lld.", conn->cli_info.start_time);
    errno_t err;
    err = strcpy_s(conn->cli_info.process_name, sizeof(conn->cli_info.process_name), cm_sys_program_name());
    if (err != EOK) {
        LOG_DEBUG_ERR("System call strcpy_s error %d.", err);
        return CM_ERROR;
    }
    conn->cli_info.connect_time = cm_clock_monotonic_now();
    wr_get_server_info_t output_info = {NULL, WR_INVALID_SESSIONID, 0};
    CM_RETURN_IFERR(wr_msg_interact(conn, WR_CMD_HANDSHAKE, (void *)&conn->cli_info, (void *)&output_info));
    if (conn->pack.head->version >= WR_VERSION_2) {
        if (g_wr_server_pid == 0) {
            g_wr_server_pid = output_info.server_pid;
        } else if (g_wr_server_pid != output_info.server_pid) {
            WR_THROW_ERROR(ERR_WR_SERVER_REBOOT);
            return ERR_WR_SERVER_REBOOT;
        }
    }
    return wr_set_server_info(conn, output_info.home, output_info.objectid, max_open_file);
}

// NOTE:just for wrcmd because not support many threads in one process.
status_t wr_connect_ex(const char *server_locator, wr_conn_opt_t *options, wr_conn_t *conn)
{
    status_t status = CM_ERROR;
    wr_env_t *wr_env = wr_get_env();
    wr_init_conn(conn);
    do {
        status = wr_connect("127.0.0.1:19225", options, conn);
        WR_BREAK_IFERR2(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "wr client connet server failed."));
        uint32 max_open_file = WR_DEFAULT_OPEN_FILES_NUM;
        conn->proto_version = WR_PROTO_VERSION;
        status = wr_cli_handshake(conn, max_open_file);
        WR_BREAK_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "wr client handshake to server failed."),
            wr_disconnect(conn));
        wr_env->conn_count++;
    } while (0);
    return status;
}

status_t wr_cli_session_lock(wr_conn_t *conn, wr_session_t *session)
{
    if (!cm_spin_timed_lock(&session->shm_lock, SESSION_LOCK_TIMEOUT)) {
        LOG_RUN_ERR("Failed to lock session %u shm lock", session->id);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("Succeed to lock session %u shm lock", session->id);
    if (session->cli_info.thread_id != conn->cli_info.thread_id ||
        session->cli_info.connect_time != conn->cli_info.connect_time) {
        WR_THROW_ERROR_EX(ERR_WR_CONNECT_FAILED,
            "session %u thread id is %u, connect_time is %llu, conn thread id is %u, connect_time is %llu", session->id,
            session->cli_info.thread_id, session->cli_info.connect_time, conn->cli_info.thread_id,
            conn->cli_info.connect_time);
        LOG_RUN_ERR("Failed to check session %u, session thread id is %u, connect_time is %llu, conn thread id is %u, "
                    "connect_time is %llu",
                    session->id, session->cli_info.thread_id, session->cli_info.connect_time, conn->cli_info.thread_id,
                    conn->cli_info.connect_time);
        cm_spin_unlock(&session->shm_lock);
        LOG_DEBUG_INF("Succeed to unlock session %u shm lock", session->id);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
void wr_disconnect_ex(wr_conn_t *conn)
{
    wr_env_t *wr_env = wr_get_env();

    wr_disconnect(conn);
    wr_latch_x(&wr_env->conn_latch);
    if (wr_env->conn_count > 0) {
        wr_env->conn_count--;
    }

    if (wr_env->conn_count == 0) {
        wr_destroy();
    }
    uint32 count = wr_env->conn_count;
    wr_unlatch(&wr_env->conn_latch);
    LOG_DEBUG_INF("Remain conn count:%u when disconnect.", count);

    return;
}

status_t wr_vfs_create_impl(wr_conn_t *conn, const char *dir_name)
{
    text_t text;
    cm_str2text((char *)dir_name, &text);
    if (text.len >= WR_MAX_NAME_LEN) {
        WR_THROW_ERROR_EX(
            ERR_WR_DIR_CREATE, "Length of dir name(%s) is too long, maximum is %u.", T2S(&text), WR_MAX_NAME_LEN);
        return CM_ERROR;
    }
    WR_RETURN_IF_ERROR(wr_check_name(dir_name));
    LOG_DEBUG_INF("wr make dir entry, dir_name:%s", dir_name);
    wr_make_dir_info_t send_info;
    send_info.name = dir_name;
    status_t status = wr_msg_interact(conn, WR_CMD_MKDIR, (void *)&send_info, NULL);
    LOG_DEBUG_INF("wr make dir leave");
    return status;
}

status_t wr_vfs_delete_impl(wr_conn_t *conn, const char *dir)
{
    WR_RETURN_IF_ERROR(wr_check_device_path(dir));
    LOG_DEBUG_INF("wr remove dir entry, dir:%s", dir);
    wr_remove_dir_info_t send_info;
    send_info.name = dir;
    send_info.recursive = CM_TRUE;
    status_t status = wr_msg_interact(conn, WR_CMD_RMDIR, (void *)&send_info, NULL);
    LOG_DEBUG_INF("wr remove dir leave");
    return status;
}

static wr_vfs_t *wr_open_dir_impl_core(wr_conn_t *conn, wr_find_node_t *find_node)
{
    wr_vg_info_item_t *vg_item = wr_find_vg_item(find_node->vg_name);
    if (vg_item == NULL) {
        LOG_RUN_ERR("Failed to find vg, %s.", find_node->vg_name);
        WR_THROW_ERROR(ERR_WR_VG_NOT_EXIST, find_node->vg_name);
        return NULL;
    }

    WR_LOCK_VG_META_S_RETURN_NULL(vg_item, conn->session);
    gft_node_t *node = wr_get_ft_node_by_ftid(conn->session, vg_item, find_node->ftid, CM_FALSE, CM_FALSE);
    if (node == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_ID, "find_node ftid", *(uint64 *)&find_node->ftid);
        WR_UNLOCK_VG_META_S(vg_item, conn->session);
        return NULL;
    }
    wr_vfs_t *dir = (wr_vfs_t *)cm_malloc(sizeof(wr_vfs_t));
    if (dir == NULL) {
        WR_UNLOCK_VG_META_S(vg_item, conn->session);
        LOG_DEBUG_ERR("Failed to malloc.");
        return NULL;
    }
    dir->cur_ftid = node->items.first;
    dir->vg_item = vg_item;
    dir->version = WR_GET_ROOT_BLOCK(vg_item->wr_ctrl)->ft_block.common.version;
    dir->pftid = node->id;
    WR_UNLOCK_VG_META_S(vg_item, conn->session);

    LOG_DEBUG_INF("wr open dir leave");
    return dir;
}

wr_vfs_t *wr_open_dir_impl(wr_conn_t *conn, const char *dir_path, bool32 refresh_recursive)
{
    if (dir_path == NULL) {
        return NULL;
    }
    LOG_DEBUG_INF("wr open dir entry, dir_path:%s", dir_path);

    wr_env_t *wr_env = wr_get_env();
    if (!wr_env->initialized) {
        return NULL;
    }

    // 1. PATH
    if (wr_check_device_path(dir_path) != CM_SUCCESS) {
        return NULL;
    }
    wr_find_node_t *find_node;
    wr_open_dir_info_t send_info;
    send_info.dir_path = dir_path;
    send_info.refresh_recursive = refresh_recursive;
    status_t status = wr_msg_interact(conn, WR_CMD_OPEN_DIR, (void *)&send_info, (void *)&find_node);
    if (status != CM_SUCCESS) {
        return NULL;
    }
    return wr_open_dir_impl_core(conn, find_node);
}

gft_node_t *wr_read_dir_impl(wr_conn_t *conn, wr_vfs_t *dir, bool32 skip_delete)
{
    return NULL;
}

status_t wr_close_dir_impl(wr_conn_t *conn, wr_vfs_t *dir)
{
    if (!dir || !dir->vg_item) {
        return CM_ERROR;
    }

    // close operation just free resource, no need check server if down.
    wr_env_t *wr_env = wr_get_env();
    CM_RETURN_IF_FALSE(wr_env->initialized);

    wr_close_dir_info_t send_info;
    send_info.pftid = *(uint64 *)&dir->pftid;
    send_info.vg_name = dir->vg_item->vg_name;
    send_info.vg_id = dir->vg_item->id;
    status_t status = wr_msg_interact(conn, WR_CMD_CLOSE_DIR, (void *)&send_info, NULL);
    WR_FREE_POINT(dir);
    return status;
}

status_t wr_create_file_impl(wr_conn_t *conn, const char *file_path, int flag)
{
    LOG_DEBUG_INF("wr create file entry, file path:%s, flag:%d", file_path, flag);
    WR_RETURN_IF_ERROR(wr_check_device_path(file_path));
    wr_create_file_info_t send_info;
    send_info.file_path = file_path;
    send_info.flag = (uint32)flag;
    status_t status = wr_msg_interact(conn, WR_CMD_CREATE_FILE, (void *)&send_info, NULL);
    LOG_DEBUG_INF("wr create file leave");
    return status;
}

status_t wr_remove_file_impl(wr_conn_t *conn, const char *file_path)
{
    LOG_DEBUG_INF("wr remove file entry, file path:%s", file_path);
    WR_RETURN_IF_ERROR(wr_check_device_path(file_path));
    status_t status = wr_msg_interact(conn, WR_CMD_DELETE_FILE, (void *)file_path, NULL);
    LOG_DEBUG_INF("wr remove file leave");
    return status;
}

status_t wr_find_vg_by_file_path(const char *path, wr_vg_info_item_t **vg_item)
{
    wr_env_t *wr_env = wr_get_env();
    if (!wr_env->initialized) {
        WR_THROW_ERROR(ERR_WR_ENV_NOT_INITIALIZED);
        return CM_ERROR;
    }

    uint32_t beg_pos = 0;
    char vg_name[WR_MAX_NAME_LEN];
    status_t status = wr_get_name_from_path(path, &beg_pos, vg_name);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to get name from path:%s, status:%d.", path, status));

    *vg_item = wr_find_vg_item(vg_name);
    if (*vg_item == NULL) {
        LOG_DEBUG_ERR("Failed to find VG:%s.", vg_name);
        WR_THROW_ERROR(ERR_WR_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t wr_get_ftid_by_path_on_server(wr_conn_t *conn, const char *path, ftid_t *ftid, char *vg_name)
{
    LOG_DEBUG_INF("begin to get ftid by path: %s", path);
    text_t extra_info = CM_NULL_TEXT;
    WR_RETURN_IF_ERROR(wr_msg_interact(conn, WR_CMD_GET_FTID_BY_PATH, (void *)path, (void *)&extra_info));

    if (extra_info.len != sizeof(wr_find_node_t)) {
        WR_THROW_ERROR(ERR_WR_CLI_EXEC_FAIL, wr_get_cmd_desc(WR_CMD_GET_FTID_BY_PATH), "get result length error");
        LOG_DEBUG_ERR("get result length error.");
        return CM_ERROR;
    }
    wr_find_node_t find_node = *(wr_find_node_t *)extra_info.str;
    *ftid = find_node.ftid;
    errno_t err = strncpy_sp(vg_name, WR_MAX_NAME_LEN, find_node.vg_name, WR_MAX_NAME_LEN);
    if (err != EOK) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("wr get node ftid: %s, vg: %s by path: %s", wr_display_metaid(*ftid), vg_name, path);
    return CM_SUCCESS;
}

gft_node_t *wr_get_node_by_path_impl(wr_conn_t *conn, const char *path)
{
    ftid_t ftid;
    if (wr_check_device_path(path) != CM_SUCCESS) {
        return NULL;
    }
    char vg_name[WR_MAX_NAME_LEN];
    if (wr_get_ftid_by_path_on_server(conn, path, &ftid, (char *)vg_name) != CM_SUCCESS) {
        return NULL;
    }
    wr_vg_info_item_t *vg_item = wr_find_vg_item(vg_name);
    if (vg_item == NULL) {
        LOG_DEBUG_ERR("Failed to find vg,vg name %s.", vg_name);
        WR_THROW_ERROR(ERR_WR_VG_NOT_EXIST, vg_name);
        return NULL;
    }

    WR_LOCK_VG_META_S_RETURN_NULL(vg_item, conn->session);
    gft_node_t *node = wr_get_ft_node_by_ftid(conn->session, vg_item, ftid, CM_FALSE, CM_FALSE);
    WR_UNLOCK_VG_META_S(vg_item, conn->session);
    return node;
}

status_t wr_init_file_context(
    wr_file_context_t *context, gft_node_t *out_node, wr_vg_info_item_t *vg_item, wr_file_mode_e mode)
{
    context->flag = WR_FILE_CONTEXT_FLAG_USED;
    context->offset = 0;
    context->next = WR_INVALID_ID32;
    context->node = out_node;
    context->vg_item = vg_item;
    context->vgid = vg_item->id;
    context->fid = out_node->fid;
    context->vol_offset = 0;
    context->tid = cm_get_current_thread_id();
    if (strcpy_s(context->vg_name, WR_MAX_NAME_LEN, vg_item->vg_name) != EOK) {
        return CM_ERROR;
    }
    context->mode = mode;
    return CM_SUCCESS;
}

/*  
1 after extend success, will generate new linked list
context[file_run_ctx->files->group_num - 1] [0]->context[file_run_ctx->files->group_num - 1] 
[1]->...->context[file_run_ctx->files->group_num - 1] [WR_FILE_CONTEXT_PER_GROUP - 1]
2 insert new linked list head into the old linked list
*/
status_t wr_extend_files_context(wr_file_run_ctx_t *file_run_ctx)
{
    if (file_run_ctx->files.group_num == WR_MAX_FILE_CONTEXT_GROUP_NUM) {
        WR_THROW_ERROR(ERR_INVALID_VALUE, "file group num", file_run_ctx->files.group_num);
        LOG_RUN_ERR_INHIBIT(
            LOG_INHIBIT_LEVEL1, "file context group exceeds upper limit %d", WR_MAX_FILE_CONTEXT_GROUP_NUM);
        return CM_ERROR;
    }
    uint32 context_size = WR_FILE_CONTEXT_PER_GROUP * (uint32)sizeof(wr_file_context_t);
    uint32 i = file_run_ctx->files.group_num;
    file_run_ctx->files.files_group[i] = (wr_file_context_t *)cm_malloc(context_size);
    if (file_run_ctx->files.files_group[i] == NULL) {
        WR_THROW_ERROR(ERR_ALLOC_MEMORY, context_size, "wr extend files context");
        return CM_ERROR;
    }
    errno_t rc = memset_s(file_run_ctx->files.files_group[i], context_size, 0, context_size);
    if (rc != EOK) {
        WR_FREE_POINT(file_run_ctx->files.files_group[i]);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return CM_ERROR;
    }
    file_run_ctx->files.group_num++;
    wr_file_context_t *context = NULL;
    for (uint32 j = 0; j < WR_FILE_CONTEXT_PER_GROUP; j++) {
        context = &file_run_ctx->files.files_group[i][j];
        context->id = i * WR_FILE_CONTEXT_PER_GROUP + j;
        if (j == WR_FILE_CONTEXT_PER_GROUP - 1) {
            context->next = CM_INVALID_ID32;
        } else {
            context->next = context->id + 1;
        }
    }
    file_run_ctx->file_free_first = (&file_run_ctx->files.files_group[file_run_ctx->files.group_num - 1][0])->id;
    LOG_RUN_INF("Succeed to extend alloc open files, group num is %u, file free first is %u.",
        file_run_ctx->files.group_num, file_run_ctx->file_free_first);
    return CM_SUCCESS;
}

status_t wr_open_file_inner(wr_vg_info_item_t *vg_item, gft_node_t *ft_node, wr_file_mode_e mode, int *handle)
{
    wr_env_t *wr_env = wr_get_env();
    wr_latch_x(&wr_env->latch);
    wr_file_run_ctx_t *file_run_ctx = &wr_env->file_run_ctx;
    if (file_run_ctx->has_opened_files >= file_run_ctx->max_open_file) {
        wr_unlatch(&wr_env->latch);
        LOG_RUN_ERR("The opened files %u has exceeded the max open file number %u.", file_run_ctx->has_opened_files,
            file_run_ctx->max_open_file);
        return CM_ERROR;
    }

    if (file_run_ctx->file_free_first == WR_INVALID_ID32) {
        status_t status = wr_extend_files_context(file_run_ctx);
        if (status != CM_SUCCESS) {
            wr_unlatch(&wr_env->latch);
            LOG_RUN_ERR("Failed to extend files context.");
            return CM_ERROR;
        }
    }
    *handle = (int)file_run_ctx->file_free_first;
    wr_file_context_t *context = wr_get_file_context_by_handle(file_run_ctx, *handle);
    uint32 next = context->next;
    status_t ret = wr_init_file_context(context, ft_node, vg_item, mode);
    WR_RETURN_IFERR2(ret, wr_unlatch(&wr_env->latch));
    file_run_ctx->file_free_first = next;
    file_run_ctx->has_opened_files++;
    wr_unlatch(&wr_env->latch);
    return CM_SUCCESS;
}

status_t wr_open_file_on_server(wr_conn_t *conn, const char *file_path, int flag, wr_find_node_t **find_node)
{
    wr_open_file_info_t send_info;
    send_info.file_path = file_path;
    send_info.flag = flag;
    return wr_msg_interact(conn, WR_CMD_OPEN_FILE, (void *)&send_info, (void *)find_node);
}

status_t wr_open_file_impl(wr_conn_t *conn, const char *file_path, int flag, int *handle)
{
    status_t status = CM_ERROR;
    gft_node_t *ft_node = NULL;
    wr_find_node_t *find_node = NULL;
    LOG_DEBUG_INF("wr begin to open file, file path:%s, flag:%d", file_path, flag);
    WR_RETURN_IF_ERROR(wr_check_device_path(file_path));
    WR_RETURN_IF_ERROR(wr_open_file_on_server(conn, file_path, flag, &find_node));
    wr_vg_info_item_t *vg_item = wr_find_vg_item(find_node->vg_name);
    if (vg_item == NULL) {
        LOG_RUN_ERR("Failed to find vg, vg name %s.", find_node->vg_name);
        WR_THROW_ERROR(ERR_WR_VG_NOT_EXIST, find_node->vg_name);
        return CM_ERROR;
    }
    WR_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session);
    do {
        ft_node = wr_get_ft_node_by_ftid(conn->session, vg_item, find_node->ftid, CM_FALSE, CM_FALSE);
        if (ft_node == NULL) {
            WR_THROW_ERROR(ERR_WR_INVALID_ID, "find_node ftid", *(uint64 *)&find_node->ftid);
            status = CM_ERROR;
            break;
        }
        status = wr_open_file_inner(vg_item, ft_node, WR_OPEN_MODE(flag), handle);
    } while (0);
    WR_UNLOCK_VG_META_S(vg_item, conn->session);

    if (status != CM_SUCCESS) {
        // Try to close the handle opened on the server to avoid resource leakage.
        // But here in theory it shouldn't depend on ft_node not being NULL
        if (ft_node != NULL) {
            (void)wr_close_file_on_server(conn, vg_item, ft_node->fid, ft_node->id);
        }
        return status;
    }
    LOG_DEBUG_INF("wr open file successfully, file_path:%s, flag:%d, handle:%d, fsize:%llu, fwritten_size:%llu",
        file_path, flag, *handle, ft_node->size, ft_node->written_size);
    return CM_SUCCESS;
}

status_t wr_latch_context_by_handle(
    wr_conn_t *conn, int32 handle, wr_file_context_t **context, wr_latch_mode_e latch_mode)
{
    wr_env_t *wr_env = wr_get_env();
    if (!wr_env->initialized) {
        WR_THROW_ERROR(ERR_WR_ENV_NOT_INITIALIZED);
        LOG_DEBUG_ERR("wr env not initialized.");
        return CM_ERROR;
    }
    wr_file_run_ctx_t *file_run_ctx = &wr_env->file_run_ctx;
    if (handle >= (int32)file_run_ctx->max_open_file || handle < 0) {
        WR_THROW_ERROR(
            ERR_WR_INVALID_PARAM, "value of handle must be a positive integer and less than max_open_file.");
        LOG_DEBUG_ERR("File handle is invalid:%d.", handle);
        return CM_ERROR;
    }

    wr_file_context_t *file_cxt = wr_get_file_context_by_handle(file_run_ctx, handle);
    wr_latch(&file_cxt->latch, latch_mode, ((wr_session_t *)conn->session)->id);
    if (file_cxt->flag == WR_FILE_CONTEXT_FLAG_FREE) {
        wr_unlatch(&file_cxt->latch);
        LOG_DEBUG_ERR("Failed to r/w, file is closed, handle:%d, context id:%u.", handle, file_cxt->id);
        return CM_ERROR;
    }

    WR_ASSERT_LOG(handle == (int32)file_cxt->id, "handle %d not equal to file id %u", handle, file_cxt->id);

    if (file_cxt->node == NULL) {
        wr_unlatch(&file_cxt->latch);
        LOG_DEBUG_ERR("file node is null, handle:%d, context id:%u.", handle, file_cxt->id);
        return CM_ERROR;
    }

    *context = file_cxt;
    return CM_SUCCESS;
}

status_t wr_close_file_impl(wr_conn_t *conn, int handle)
{
    char *fname = NULL;

    LOG_DEBUG_INF("wr close file entry, handle:%d", handle);

    wr_file_context_t *context = NULL;
    WR_RETURN_IF_ERROR(wr_latch_context_by_handle(conn, handle, &context, LATCH_MODE_EXCLUSIVE));
    fname = context->node->name;

    status_t ret = wr_close_file_on_server(conn, context->vg_item, context->fid, context->node->id);
    if (ret != CM_SUCCESS) {
        wr_unlatch(&context->latch);
        LOG_DEBUG_INF("Failed to fclose, handle:%d, fname:%s, fid:%llu.", handle, fname, context->fid);
        return ret;
    }
    context->flag = WR_FILE_CONTEXT_FLAG_FREE;
    context->offset = 0;
    context->node = NULL;
    context->tid = 0;
    wr_unlatch(&context->latch);
    LOG_DEBUG_INF("Success to fclose, handle:%d, fname:%s, fid:%llu.", handle, fname, context->fid);

    /* release file context to freelist */
    wr_env_t *wr_env = wr_get_env();
    wr_latch_x(&wr_env->latch);
    wr_file_run_ctx_t *file_run_ctx = &wr_env->file_run_ctx;
    context->next = file_run_ctx->file_free_first;
    file_run_ctx->file_free_first = context->id;
    file_run_ctx->has_opened_files--;
    wr_unlatch(&wr_env->latch);
    return CM_SUCCESS;
}

status_t wr_exist_impl(wr_conn_t *conn, const char *path, bool32 *result, gft_item_type_t *type)
{
    LOG_DEBUG_INF("wr exits file entry, name:%s", path);
    WR_RETURN_IF_ERROR(wr_check_device_path(path));
    wr_exist_recv_info_t recv_info;
    WR_RETURN_IF_ERROR(wr_msg_interact(conn, WR_CMD_EXIST, (void *)path, (void *)&recv_info));
    *result = (bool32)recv_info.result;
    *type = (gft_item_type_t)recv_info.type;
    LOG_DEBUG_INF("wr exits file or dir leave, name:%s, result:%d, type:%u", path, *result, *type);
    return CM_SUCCESS;
}

static status_t wr_validate_seek_origin(int origin, int64 offset, wr_file_context_t *context, int64 *new_offset)
{
    if (origin == SEEK_SET) {
        if (offset > (int64)WR_MAX_FILE_SIZE) {
            LOG_DEBUG_ERR("Invalid parameter offset:%lld, context offset:%lld.", offset, context->offset);
            return CM_ERROR;
        }
        *new_offset = offset;
    } else if (origin == SEEK_CUR) {
        if (offset > (int64)WR_MAX_FILE_SIZE || context->offset > (int64)WR_MAX_FILE_SIZE ||
            offset + context->offset > (int64)WR_MAX_FILE_SIZE) {
            LOG_DEBUG_ERR("Invalid parameter offset:%lld, context offset:%lld.", offset, context->offset);
            return CM_ERROR;
        }
        *new_offset = context->offset + offset;
    } else if (origin == SEEK_END || origin == WR_SEEK_MAXWR) {  // for get alloced size, or actual used size
        if (offset > 0) {
            LOG_DEBUG_ERR("Invalid parameter offset:%lld, context offset:%lld.", offset, context->offset);
            return CM_ERROR;
        }
    } else {
        LOG_DEBUG_ERR("Invalid parameter origin:%d, when seek file.", origin);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int64 wr_seek_file_impl_core(wr_rw_param_t *param, int64 offset, int origin)
{
    status_t status;
    int64 new_offset = 0;
    int64 size;
    bool32 need_refresh = ((origin == SEEK_END) || (origin == WR_SEEK_MAXWR));

    wr_conn_t *conn = param->conn;
    int handle = param->handle;
    wr_file_context_t *context = param->context;

    CM_ASSERT(handle == (int32)context->id);

    if (wr_validate_seek_origin(origin, offset, context, &new_offset) != CM_SUCCESS) {
        WR_UNLOCK_VG_META_S(context->vg_item, conn->session);
        return CM_ERROR;
    }

    size = cm_atomic_get(&context->node->size);
    if (!wr_is_fs_meta_valid(context->node) || new_offset > size || need_refresh) {
        status = wr_check_apply_refresh_file(conn, context, 0);
        WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to apply refresh file,fid:%llu.", context->fid));
        size = cm_atomic_get(&context->node->size);

        if (offset > size && param->is_read) {
            LOG_DEBUG_ERR("Invalid parameter offset is greater than size, offset:%lld, new_offset:%lld,"
                          " file size:%llu, vgid:%u, fid:%llu, node fid:%llu, need_refresh:%d.",
                offset, new_offset, context->node->size, context->vg_item->id, context->fid, context->node->fid,
                need_refresh);
            WR_THROW_ERROR(ERR_WR_FILE_SEEK, context->vg_item->id, context->fid, offset, context->node->size);
            WR_UNLOCK_VG_META_S(context->vg_item, conn->session);
            return CM_ERROR;
        }
        LOG_DEBUG_INF("Apply to refresh file, offset:%lld, size:%lld, need_refresh:%d.", offset, size, need_refresh);
        if (origin == SEEK_END) {
            new_offset = (int64)context->node->written_size + offset;
        } else if (origin == WR_SEEK_MAXWR) {
            new_offset = (int64)context->node->written_size;
        }
    }
    if (new_offset < 0) {
        WR_THROW_ERROR(ERR_WR_FILE_SEEK, context->vg_item->id, context->fid, offset, context->node->size);
        WR_UNLOCK_VG_META_S(context->vg_item, conn->session);
        return CM_ERROR;
    }
    if (new_offset == 0) {
        context->vol_offset = 0;
    }
    context->offset = new_offset;
    LOG_DEBUG_INF("Success to seek(origin:%d) file:%s, offset:%lld, fsize:%llu, written_size:%llu.", origin,
        context->node->name, new_offset, context->node->size, context->node->written_size);
    return new_offset;
}

void wr_init_rw_param(
    wr_rw_param_t *param, wr_conn_t *conn, int handle, wr_file_context_t *ctx, int64 offset, bool32 atomic)
{
    param->conn = conn;
    param->handle = handle;
    param->wr_env = wr_get_env();
    param->context = ctx;
    param->offset = offset;
    param->atom_oper = atomic;
    param->is_read = WR_FALSE;
}

static int64 wr_seek_file_prepare(
    wr_conn_t *conn, wr_file_context_t *context, wr_rw_param_t *param, int64 offset, int origin)
{
    WR_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    int64 ret = wr_seek_file_impl_core(param, offset, origin);
    if (ret == CM_ERROR) {
        return CM_ERROR;
    }
    WR_UNLOCK_VG_META_S(context->vg_item, conn->session);
    return ret;
}

int64 wr_seek_file_impl(wr_conn_t *conn, int handle, int64 offset, int origin)
{
    LOG_DEBUG_INF("wr seek file entry, handle:%d, offset:%lld, origin:%d", handle, offset, origin);

    wr_file_context_t *context = NULL;
    WR_RETURN_IF_ERROR(wr_latch_context_by_handle(conn, handle, &context, LATCH_MODE_EXCLUSIVE));

    wr_rw_param_t param;
    wr_init_rw_param(&param, conn, handle, context, context->offset, WR_FALSE);
    int64 new_offset = wr_seek_file_prepare(conn, context, &param, offset, origin);
    wr_unlatch(&context->latch);

    LOG_DEBUG_INF("wr seek file leave, new_offset:%lld", new_offset);
    return new_offset;
}

static status_t wr_check_ready_fs_block(files_rw_ctx_t *rw_ctx, wr_fs_pos_desc_t *fs_pos)
{
    return CM_SUCCESS;
}

status_t wr_read_write_file_core(wr_rw_param_t *param, void *buf, int32 size, int32 *read_size)
{
    status_t status = CM_SUCCESS;
    return status;
}

status_t wr_read_write_file(wr_conn_t *conn, int32 handle, void *buf, int32 size, int32 *read_size, bool32 is_read)
{
    status_t status;
    wr_file_context_t *context = NULL;
    wr_rw_param_t param;

    if (size < 0) {
        LOG_DEBUG_ERR("File size is invalid: %d.", size);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("wr read write file entry, handle:%d, is_read:%u", handle, is_read);

    WR_RETURN_IF_ERROR(wr_latch_context_by_handle(conn, handle, &context, LATCH_MODE_EXCLUSIVE));
    bool mode_match = is_read ? (context->mode & WR_FILE_MODE_READ) : (context->mode & WR_FILE_MODE_WRITE);
    if (!mode_match) {
        wr_unlatch(&context->latch);
        WR_THROW_ERROR(ERR_WR_FILE_RDWR_INSUFF_PER, is_read ? "read" : "write", context->mode);
        return CM_ERROR;
    }
    wr_init_rw_param(&param, conn, handle, context, context->offset, WR_FALSE);
    param.is_read = is_read;
    status = wr_read_write_file_core(&param, buf, size, read_size);
    wr_unlatch(&context->latch);
    LOG_DEBUG_INF("wr read write file leave");

    return status;
}

status_t wr_write_file_impl(wr_conn_t *conn, int handle, const void *buf, int size)
{
    return wr_read_write_file(conn, handle, (void *)buf, size, NULL, WR_FALSE);
}

status_t wr_read_file_impl(wr_conn_t *conn, int handle, void *buf, int size, int *read_size)
{
    if (read_size == NULL) {
        return CM_ERROR;
    }

    return wr_read_write_file(conn, handle, buf, size, read_size, WR_TRUE);
}

static status_t wr_pwrite_file_prepare(wr_conn_t *conn, wr_file_context_t *context, long long offset)
{
    return CM_SUCCESS;
}

status_t wr_pwrite_file_impl(wr_conn_t *conn, int handle, const void *buf, int size, long long offset)
{
    status_t status;
    wr_file_context_t *context = NULL;
    wr_rw_param_t param;

    CM_RETURN_IFERR(wr_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));
    LOG_DEBUG_INF("wr pwrite file %s, handle:%d, offset:%lld, size:%d", context->node->name, handle, offset, size);
    if (!(context->mode & WR_FILE_MODE_WRITE)) {
        wr_unlatch(&context->latch);
        WR_THROW_ERROR(ERR_WR_FILE_RDWR_INSUFF_PER, "pwrite", context->mode);
        return CM_ERROR;
    }

    wr_init_rw_param(&param, conn, handle, context, offset, WR_TRUE);
    param.is_read = WR_FALSE;
    wr_set_conn_wait_event(conn, WR_PWRITE_SYN_META);
    if (wr_pwrite_file_prepare(conn, context, offset) != CM_SUCCESS) {
        wr_unset_conn_wait_event(conn);
        wr_unlatch(&context->latch);
        return CM_ERROR;
    }
    status = wr_read_write_file_core(&param, (void *)buf, size, NULL);
    wr_unset_conn_wait_event(conn);
    wr_unlatch(&context->latch);
    LOG_DEBUG_INF("wr pwrite file leave, result: %d", status);

    return status;
}

static status_t wr_pread_file_prepare(
    wr_conn_t *conn, wr_file_context_t *context, int size, long long offset, bool32 *read_end)
{
    *read_end = CM_FALSE;
    WR_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    status_t status = wr_check_refresh_file_by_offset(conn, context, offset, CM_TRUE);
    if (status != CM_SUCCESS) {
        return status;
    }
    if ((uint64)offset == context->node->size || size == 0) {
        *read_end = CM_TRUE;
    }
    WR_UNLOCK_VG_META_S(context->vg_item, conn->session);
    return CM_SUCCESS;
}

status_t wr_pread_file_impl(wr_conn_t *conn, int handle, void *buf, int size, long long offset, int *read_size)
{
    status_t status;
    wr_file_context_t *context = NULL;
    wr_rw_param_t param;

    CM_RETURN_IFERR(wr_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));
    LOG_DEBUG_INF(
        "wr pread file entry, name:%s, handle:%d, offset:%lld, size:%d", context->node->name, handle, offset, size);
    if (!(context->mode & WR_FILE_MODE_READ)) {
        wr_unlatch(&context->latch);
        WR_THROW_ERROR(ERR_WR_FILE_RDWR_INSUFF_PER, "pread", context->mode);
        return CM_ERROR;
    }

    wr_init_rw_param(&param, conn, handle, context, offset, WR_TRUE);
    param.is_read = WR_TRUE;
    wr_set_conn_wait_event(conn, WR_PREAD_SYN_META);
    do {
        bool32 read_end = CM_FALSE;
        status = wr_pread_file_prepare(conn, context, size, offset, &read_end);
        WR_BREAK_IF_ERROR(status);
        if (read_end) {
            *read_size = 0;
            break;
        }
        status = wr_read_write_file_core(&param, buf, size, read_size);
    } while (0);
    wr_unset_conn_wait_event(conn);
    wr_unlatch(&context->latch);
    LOG_DEBUG_INF("wr pread file leave, result: %d", status);
    return status;
}

status_t wr_fallocate_impl(wr_conn_t *conn, int handle, int mode, long long int offset, long long int length)
{
    status_t status;
    wr_file_context_t *context = NULL;

    if (mode < 0) {
        LOG_DEBUG_ERR("File mode is invalid:%d.", mode);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "mode must be a positive integer");
        return CM_ERROR;
    }

    if (offset > (int64)WR_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Offset is invalid:%lld.", offset);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "offset must less than WR_MAX_FILE_SIZE");
        return CM_ERROR;
    }

    if (length < 0) {
        LOG_DEBUG_ERR("File length is invalid:%lld.", length);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "length must be a positive integer");
        return CM_ERROR;
    }

    if (length > (int64)WR_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("File length is invalid:%lld.", length);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "length must less than WR_MAX_FILE_SIZE");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(wr_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));
    LOG_DEBUG_INF("wr fallocate file, name:%s, handle:%d, mode:%d, offset:%lld, length:%lld", context->node->name,
        handle, mode, offset, length);
    if (!(context->mode & WR_FILE_MODE_WRITE)) {
        wr_unlatch(&context->latch);
        WR_THROW_ERROR(ERR_WR_FILE_RDWR_INSUFF_PER, "fallocate", context->mode);
        return CM_ERROR;
    }

    status = wr_apply_fallocate_file(conn, handle, mode, offset, length);
    wr_unlatch(&context->latch);

    LOG_DEBUG_INF("wr fallocate file leave, result: %d", status);
    return status;
}

status_t wr_rename_file_impl(wr_conn_t *conn, const char *src, const char *dst)
{
    WR_RETURN_IFERR2(wr_check_device_path(src), LOG_DEBUG_ERR("old name path is invalid."));
    WR_RETURN_IFERR2(wr_check_device_path(dst), LOG_DEBUG_ERR("new name path is invalid."));
    LOG_DEBUG_INF("Rename file, old name path: %s, new name path: %s", src, dst);
    wr_rename_file_info_t send_info;
    send_info.src = src;
    send_info.dst = dst;
    WR_RETURN_IF_ERROR(wr_msg_interact(conn, WR_CMD_RENAME_FILE, (void *)&send_info, NULL));
    return CM_SUCCESS;
}

status_t wr_truncate_impl(wr_conn_t *conn, int handle, long long int length)
{
    if (length < 0) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "length must be a positive integer");
        LOG_DEBUG_ERR("File length is invalid:%lld.", length);
        return CM_ERROR;
    }

    if (length > (int64)WR_MAX_FILE_SIZE) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "length must less than WR_MAX_FILE_SIZE");
        LOG_DEBUG_ERR("File length is invalid:%lld.", length);
        return CM_ERROR;
    }

    wr_file_context_t *context = NULL;
    WR_RETURN_IF_ERROR(wr_latch_context_by_handle(conn, handle, &context, LATCH_MODE_EXCLUSIVE));

    LOG_DEBUG_INF("Truncating file via handle(%d), file name: %s, node size: %lld, length: %lld.", handle,
        context->node->name, context->node->size, length);

    wr_truncate_file_info_t send_info;
    send_info.fid = context->fid;
    send_info.ftid = *(uint64 *)&(context->node->id);
    send_info.length = (uint64)length;
    send_info.vg_name = context->vg_name;
    send_info.vg_id = context->vgid;
    status_t status = wr_msg_interact(conn, WR_CMD_TRUNCATE_FILE, (void *)&send_info, NULL);
    wr_unlatch(&context->latch);
    return status;
}

void wr_heartbeat_entry(thread_t *thread)
{
    return;
}

static status_t wr_init_err_proc(
    wr_env_t *wr_env, bool32 detach, bool32 destroy, const char *errmsg, status_t errcode)
{
    if (detach == CM_TRUE) {
        ga_detach_area();
    }

    if (destroy == CM_TRUE) {
        cm_destroy_shm();
    }
    WR_FREE_POINT(wr_env->file_run_ctx.files.files_group[0]);
    wr_unlatch(&wr_env->latch);

    if (errmsg != NULL) {
        LOG_DEBUG_ERR("init error: %s", errmsg);
    }

    return errcode;
}

static status_t wr_init_shm(wr_env_t *wr_env, char *home)
{
    status_t status = wr_set_cfg_dir(home, &wr_env->inst_cfg);
    if (status != CM_SUCCESS) {
        return wr_init_err_proc(wr_env, CM_FALSE, CM_FALSE, "Environment variant WR_HOME not found", status);
    }

    status = wr_load_config(&wr_env->inst_cfg);
    if (status != CM_SUCCESS) {
        return wr_init_err_proc(wr_env, CM_FALSE, CM_FALSE, "load config failed", status);
    }

    uint32 shm_key = (uint32)(wr_env->inst_cfg.params.shm_key << (uint8)WR_MAX_SHM_KEY_BITS) +
                     (uint32)wr_env->inst_cfg.params.inst_id;
    status = cm_init_shm(shm_key);
    if (status != CM_SUCCESS) {
        return wr_init_err_proc(wr_env, CM_FALSE, CM_FALSE, "Failed to init shared memory", status);
    }

    status = ga_attach_area(CM_SHM_ATTACH_RW);
    if (status != CM_SUCCESS) {
        return wr_init_err_proc(wr_env, CM_FALSE, CM_TRUE, "Failed to attach shared area", status);
    }
    return CM_SUCCESS;
}

static status_t wr_init_files(wr_env_t *wr_env, uint32 max_open_files)
{
    wr_file_run_ctx_t *file_run_ctx = &wr_env->file_run_ctx;
    file_run_ctx->max_open_file = max_open_files;
    errno_t rc = memset_s(&file_run_ctx->files, sizeof(wr_file_context_group_t), 0, sizeof(wr_file_context_group_t));
    if (rc != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return wr_init_err_proc(wr_env, CM_TRUE, CM_TRUE, "memory init failed", CM_ERROR);
    }
    status_t status = wr_extend_files_context(file_run_ctx);
    if (status != CM_SUCCESS) {
        return wr_init_err_proc(wr_env, CM_TRUE, CM_TRUE, "extend file context failed", status);
    }
    return status;
}

status_t wr_init_client(uint32 max_open_files, char *home)
{
    WR_STATIC_ASSERT(WR_BLOCK_SIZE / sizeof(gft_node_t) <= (1 << WR_MAX_BIT_NUM_ITEM));
    WR_STATIC_ASSERT(sizeof(wr_root_ft_block_t) == 256);

    if (max_open_files > WR_MAX_OPEN_FILES) {
        WR_THROW_ERROR(ERR_INVALID_VALUE, "max_open_files", max_open_files);
        return CM_ERROR;
    }

    wr_env_t *wr_env = wr_get_env();
    if (wr_env->initialized) {
        return CM_SUCCESS;
    }

    wr_latch_x(&wr_env->latch);
    if (wr_env->initialized) {
#ifdef ENABLE_WRTEST
        if (wr_env->inittor_pid == getpid()) {
#endif
            return wr_init_err_proc(wr_env, CM_FALSE, CM_FALSE, NULL, CM_SUCCESS);
#ifdef ENABLE_WRTEST
        } else {
            LOG_RUN_INF("wr client need re-initalization wr env, last init pid:%llu.", (uint64)wr_env->inittor_pid);
            (void)wr_init_err_proc(wr_env, CM_TRUE, CM_TRUE, "need reinit by a new process", CM_SUCCESS);

            wr_env->initialized = CM_FALSE;
            wr_env->inittor_pid = 0;
        }
#endif
    }
    CM_RETURN_IFERR(wr_init_shm(wr_env, home));
    CM_RETURN_IFERR(wr_init_files(wr_env, max_open_files));

    status_t status = cm_create_thread(wr_heartbeat_entry, SIZE_K(512), NULL, &wr_env->thread_heartbeat);
    if (status != CM_SUCCESS) {
        return wr_init_err_proc(wr_env, CM_TRUE, CM_TRUE, "WR failed to create heartbeat thread", status);
    }

#ifdef ENABLE_WRTEST
    wr_env->inittor_pid = getpid();
#endif

    wr_env->initialized = CM_TRUE;
    wr_unlatch(&wr_env->latch);

    return CM_SUCCESS;
}

void wr_destroy(void)
{
    wr_env_t *wr_env = wr_get_env();
    wr_latch_x(&wr_env->latch);
    if (!wr_env->initialized) {
        wr_unlatch(&wr_env->latch);
        return;
    }

    cm_close_thread_nowait(&wr_env->thread_heartbeat);
    wr_file_run_ctx_t *file_run_ctx = &wr_env->file_run_ctx;
    for (uint32 i = 0; i < file_run_ctx->files.group_num; i++) {
        WR_FREE_POINT(file_run_ctx->files.files_group[i]);
    }
    ga_detach_area();
    wr_env->initialized = 0;
    wr_unlatch(&wr_env->latch);
}

status_t wr_get_fname_impl(int handle, char *fname, int fname_size)
{
    wr_env_t *wr_env = wr_get_env();
    if (!wr_env->initialized) {
        WR_THROW_ERROR(ERR_WR_ENV_NOT_INITIALIZED);
        return CM_ERROR;
    }
    wr_file_run_ctx_t *file_run_ctx = &wr_env->file_run_ctx;
    if (handle < 0 || (uint32)handle >= file_run_ctx->max_open_file) {
        WR_THROW_ERROR(
            ERR_WR_INVALID_PARAM, "value of handle must be a positive integer and less than max_open_file.");
        return CM_ERROR;
    }
    if (fname_size < 0) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "value of fname_size is a positive number.");
        return CM_ERROR;
    }
    wr_file_context_t *context = wr_get_file_context_by_handle(file_run_ctx, handle);
    WR_RETURN_IF_NULL(context->node);
    int len = (fname_size > WR_MAX_NAME_LEN) ? WR_MAX_NAME_LEN : fname_size;
    errno_t errcode = strcpy_s(fname, (size_t)len, context->node->name);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "value of fname_size is not large enough.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_setcfg_impl(wr_conn_t *conn, const char *name, const char *value, const char *scope)
{
    WR_RETURN_IF_ERROR(wr_check_name(name));
    wr_setcfg_info_t send_info;
    send_info.name = name;
    send_info.value = value;
    send_info.scope = scope;
    status_t status = wr_msg_interact(conn, WR_CMD_SETCFG, (void *)&send_info, NULL);
    LOG_DEBUG_INF("wr set cfg leave");
    return status;
}

status_t wr_getcfg_impl(wr_conn_t *conn, const char *name, char *out_str, size_t str_len)
{
    WR_RETURN_IF_ERROR(wr_check_name(name));
    text_t extra_info = CM_NULL_TEXT;
    WR_RETURN_IF_ERROR(wr_msg_interact(conn, WR_CMD_GETCFG, (void *)name, (void *)&extra_info));
    if (extra_info.len == 0) {
        LOG_DEBUG_INF("Client get cfg is NULL.");
        return CM_SUCCESS;
    }

    errno_t err = strncpy_s(out_str, str_len, extra_info.str, extra_info.len);
    if (SECUREC_UNLIKELY(err != EOK)) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "value of str_len is not large enough when getcfg.");
        return CM_ERROR;
    }
    if (strlen(out_str) != 0 && cm_str_equal_ins(name, "SSL_PWD_CIPHERTEXT")) {
        LOG_DEBUG_INF("Client get cfg is ***.");
    } else {
        LOG_DEBUG_INF("Client get cfg is %s.", (strlen(out_str) == 0) ? NULL : out_str);
    }
    return CM_SUCCESS;
}

void wr_get_api_volume_error(void)
{
    int32 code = cm_get_error_code();
    // volume open/seek/read write fail for I/O, just exit
    if (code == ERR_WR_VOLUME_SYSTEM_IO) {
        LOG_RUN_ERR("[WR API] ABORT INFO : volume operate failed for I/O ERROR, errcode:%d.", code);
        cm_fync_logfile();
        wr_exit(1);
    }
    return;
}

status_t wr_get_inst_status_on_server(wr_conn_t *conn, wr_server_status_t *wr_status)
{
    if (wr_status == NULL) {
        WR_THROW_ERROR_EX(ERR_WR_INVALID_PARAM, "wr_dir_item_t");
        return CM_ERROR;
    }
    text_t extra_info = CM_NULL_TEXT;
    WR_RETURN_IF_ERROR(wr_msg_interact(conn, WR_CMD_GET_INST_STATUS, NULL, (void *)&extra_info));
    *wr_status = *(wr_server_status_t *)extra_info.str;
    return CM_SUCCESS;
}

status_t wr_get_time_stat_on_server(wr_conn_t *conn, wr_stat_item_t *time_stat, uint64 size)
{
    text_t stat_info = CM_NULL_TEXT;
    WR_RETURN_IF_ERROR(wr_msg_interact(conn, WR_CMD_GET_TIME_STAT, NULL, (void *)&stat_info));
    for (uint64 i = 0; i < WR_EVT_COUNT; i++) {
        time_stat[i] = *(wr_stat_item_t *)(stat_info.str + i * (uint64)sizeof(wr_stat_item_t));
    }
    return CM_SUCCESS;
}

status_t wr_set_main_inst_on_server(wr_conn_t *conn)
{
    return wr_msg_interact(conn, WR_CMD_SET_MAIN_INST, NULL, NULL);
}

status_t wr_close_file_on_server(wr_conn_t *conn, wr_vg_info_item_t *vg_item, uint64 fid, ftid_t ftid)
{
    wr_close_file_info_t send_info;
    send_info.fid = fid;
    send_info.vg_name = vg_item->vg_name;
    send_info.vg_id = vg_item->id;
    send_info.ftid = *(uint64 *)&ftid;
    return wr_msg_interact(conn, WR_CMD_CLOSE_FILE, (void *)&send_info, NULL);
}

status_t wr_stop_server_impl(wr_conn_t *conn)
{
    return wr_msg_interact(conn, WR_CMD_STOP_SERVER, NULL, NULL);
}

status_t wr_set_stat_info(wr_stat_info_t item, gft_node_t *node)
{
    item->type = (wr_item_type_t)node->type;
    item->size = node->size;
    item->written_size = node->written_size;
    item->create_time = node->create_time;
    item->update_time = node->update_time;
    int32 errcode = memcpy_s(item->name, WR_MAX_NAME_LEN, node->name, WR_MAX_NAME_LEN);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return WR_ERROR;
    }
    return WR_SUCCESS;
}

status_t wr_fstat_impl(wr_conn_t *conn, int handle, wr_stat_info_t item)
{
    wr_file_context_t *context = NULL;
    WR_RETURN_IF_ERROR(wr_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));
    status_t ret = wr_set_stat_info(item, context->node);
    wr_unlatch(&context->latch);
    return ret;
}

status_t wr_aio_check_need_updt_fs_aux(wr_rw_param_t *param, int32 size, bool32 *need_update)
{
    wr_conn_t *conn = param->conn;
    wr_file_context_t *context = param->context;
    long long offset = param->offset;

    *need_update = CM_FALSE;
    if (context->node->min_inited_size >= (uint64)(offset + size)) {
        return CM_SUCCESS;
    }

    uint64 au_size = wr_get_vg_au_size(context->vg_item->wr_ctrl);

    wr_fs_pos_desc_t fs_pos = {0};
    files_rw_ctx_t rw_ctx;
    rw_ctx.conn = conn;
    rw_ctx.env = param->wr_env;
    rw_ctx.file_ctx = context;
    rw_ctx.handle = param->handle;
    rw_ctx.read = CM_TRUE;  // should NOT apply extend for aio post

    int64 top_size = (context->node->size > (param->offset + size)) ? (offset + size) : context->node->size;
    int64 left_size = size;
    int64 cur_size = 0;

    do {
        int64 align_size = (int64)CM_CALC_ALIGN((uint64)(offset + 1), au_size);
        if (offset + left_size > align_size) {
            cur_size = align_size - offset;
        } else {
            cur_size = left_size;
        }

        rw_ctx.offset = offset;
        rw_ctx.size = (int32)cur_size;

        status_t status = wr_check_ready_fs_block(&rw_ctx, &fs_pos);
        WR_RETURN_IF_ERROR(status);
        if (!fs_pos.is_valid) {
            LOG_RUN_ERR("Fail to find fs block for file:%s, fid:%llu, fti:%llu, cur offset:%llu, size:%lld,"
                        "written_size:%llu, file size:%llu.",
                context->node->name, context->node->fid, WR_ID_TO_U64(context->node->id), offset, cur_size,
                context->node->written_size, (uint64)context->node->size);
            return CM_ERROR;
        }

        offset += cur_size;
        left_size -= cur_size;
    } while (offset < top_size);

    return CM_SUCCESS;
}

status_t wr_aio_post_pwrite_file_impl(wr_conn_t *conn, int handle, long long offset, int size)
{
    return CM_SUCCESS;
}

static status_t wr_get_phy_size_prepare(wr_conn_t *conn, wr_file_context_t *context, long long *size)
{
    *size = 0;
    WR_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    status_t status = wr_check_apply_refresh_file(conn, context, 0);
    if (status != CM_SUCCESS) {
        return status;
    }
    *size = cm_atomic_get(&context->node->size);
    WR_UNLOCK_VG_META_S(context->vg_item, conn->session);
    return CM_SUCCESS;
}

status_t wr_get_phy_size_impl(wr_conn_t *conn, int handle, long long *size)
{
    wr_file_context_t *context = NULL;
    WR_RETURN_IF_ERROR(wr_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));

    status_t status = wr_get_phy_size_prepare(conn, context, size);
    if (status != WR_SUCCESS) {
        LOG_DEBUG_ERR("Failed to apply refresh file,fid:%llu.", context->fid);
        wr_unlatch(&context->latch);
        return WR_ERROR;
    }
    *size = context->node->size;
    wr_unlatch(&context->latch);
    return status;
}

static status_t wr_encode_setcfg(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_setcfg_info_t *info = (wr_setcfg_info_t *)send_info;
    CM_RETURN_IFERR(wr_put_str(pack, info->name));
    CM_RETURN_IFERR(wr_put_str(pack, info->value));
    CM_RETURN_IFERR(wr_put_str(pack, info->scope));
    return CM_SUCCESS;
}

static status_t wr_encode_handshake(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    CM_RETURN_IFERR(wr_put_data(pack, send_info, sizeof(wr_cli_info_t)));
    return CM_SUCCESS;
}

static status_t wr_decode_handshake(wr_packet_t *ack_pack, void *ack)
{
    text_t ack_info = CM_NULL_TEXT;
    CM_RETURN_IFERR(wr_get_text(ack_pack, &ack_info));
    if (ack_info.len == 0 || ack_info.len >= WR_MAX_PATH_BUFFER_SIZE) {
        WR_THROW_ERROR(ERR_WR_CLI_EXEC_FAIL, wr_get_cmd_desc(WR_CMD_HANDSHAKE), "get home info length error");
        return CM_ERROR;
    }
    wr_get_server_info_t *output_info = (wr_get_server_info_t *)ack;
    output_info->home = ack_info.str;
    CM_RETURN_IFERR(wr_get_int32(ack_pack, (int32 *)&output_info->objectid));
    if (ack_pack->head->version >= WR_VERSION_2) {
        CM_RETURN_IFERR(wr_get_int32(ack_pack, (int32 *)&output_info->server_pid));
    }
    return CM_SUCCESS;
}

static status_t wr_encode_exist(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    return wr_put_str(pack, (const char *)send_info);
}

static status_t wr_decode_exist(wr_packet_t *ack_pack, void *ack)
{
    wr_exist_recv_info_t *info = (wr_exist_recv_info_t *)ack;
    if (wr_get_int32(ack_pack, &(info->result)) != CM_SUCCESS) {
        WR_THROW_ERROR(ERR_WR_CLI_EXEC_FAIL, wr_get_cmd_desc(WR_CMD_EXIST), "get result data error");
        LOG_DEBUG_ERR("get result data error.");
        return CM_ERROR;
    }
    if (wr_get_int32(ack_pack, &(info->type)) != CM_SUCCESS) {
        WR_THROW_ERROR(ERR_WR_CLI_EXEC_FAIL, wr_get_cmd_desc(WR_CMD_EXIST), "get type data error");
        LOG_DEBUG_ERR("get type data error.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t wr_encode_getcfg(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    return wr_put_str(pack, (const char *)send_info);
}

static status_t wr_decode_getcfg(wr_packet_t *ack_pack, void *ack)
{
    text_t *info = (text_t *)ack;
    if (wr_get_text(ack_pack, info) != CM_SUCCESS) {
        WR_THROW_ERROR(ERR_WR_CLI_EXEC_FAIL, wr_get_cmd_desc(WR_CMD_GETCFG), "get cfg connect error");
        return CM_ERROR;
    }
    if (info->len >= WR_MAX_PACKET_SIZE - sizeof(wr_packet_head_t) - sizeof(int32)) {
        WR_THROW_ERROR(ERR_WR_CLI_EXEC_FAIL, wr_get_cmd_desc(WR_CMD_GETCFG), "get cfg length error");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t wr_decode_get_inst_status(wr_packet_t *ack_pack, void *ack)
{
    text_t *info = (text_t *)ack;
    if (wr_get_text(ack_pack, info) != CM_SUCCESS) {
        WR_THROW_ERROR(ERR_WR_CLI_EXEC_FAIL, wr_get_cmd_desc(WR_CMD_GET_INST_STATUS), "get inst status error");
        return CM_ERROR;
    }
    if (info->len != sizeof(wr_server_status_t)) {
        WR_THROW_ERROR(
            ERR_WR_CLI_EXEC_FAIL, wr_get_cmd_desc(WR_CMD_GET_INST_STATUS), "get inst status length error");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t wr_decode_get_time_stat(wr_packet_t *ack_pack, void *ack)
{
    text_t *time_stat = (text_t *)ack;
    if (wr_get_text(ack_pack, time_stat) != CM_SUCCESS) {
        WR_THROW_ERROR(ERR_WR_CLI_EXEC_FAIL, wr_get_cmd_desc(WR_CMD_GET_TIME_STAT), "get time stat error");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t wr_encode_truncate_file(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_truncate_file_info_t *info = (wr_truncate_file_info_t *)send_info;
    CM_RETURN_IFERR(wr_put_int64(pack, info->fid));
    CM_RETURN_IFERR(wr_put_int64(pack, info->ftid));
    CM_RETURN_IFERR(wr_put_int64(pack, info->length));
    CM_RETURN_IFERR(wr_put_str(pack, info->vg_name));
    CM_RETURN_IFERR(wr_put_int32(pack, info->vg_id));
    return CM_SUCCESS;
}

static status_t wr_encode_extend_file(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_extend_info_t *info = (wr_extend_info_t *)send_info;
    // 1. fid
    CM_RETURN_IFERR(wr_put_int64(pack, info->fid));
    // 2. ftid
    CM_RETURN_IFERR(wr_put_int64(pack, info->ftid));
    // 3. offset
    CM_RETURN_IFERR(wr_put_int64(pack, (uint64)info->offset));
    // 4. size
    CM_RETURN_IFERR(wr_put_int64(pack, (uint64)info->size));
    // 5. vg name
    CM_RETURN_IFERR(wr_put_str(pack, info->vg_name));
    // 6. vgid
    CM_RETURN_IFERR(wr_put_int32(pack, info->vg_id));
    return CM_SUCCESS;
}

static status_t wr_encode_rename_file(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_rename_file_info_t *info = (wr_rename_file_info_t *)send_info;
    CM_RETURN_IFERR(wr_put_str(pack, info->src));
    CM_RETURN_IFERR(wr_put_str(pack, info->dst));
    return CM_SUCCESS;
}

static status_t wr_encode_make_dir(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_make_dir_info_t *info = (wr_make_dir_info_t *)send_info;
    // 1. dir_name
    CM_RETURN_IFERR(wr_put_str(pack, info->name));
    return CM_SUCCESS;
}

static status_t wr_encode_remove_dir(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_remove_dir_info_t *info = (wr_remove_dir_info_t *)send_info;
    // 1. dir_name
    CM_RETURN_IFERR(wr_put_str(pack, info->name));
    // 2. recursive -r
    CM_RETURN_IFERR(wr_put_int32(pack, info->recursive));
    return CM_SUCCESS;
}

static status_t wr_encode_open_dir(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_open_dir_info_t *info = (wr_open_dir_info_t *)send_info;
    /* 1. dir name */
    CM_RETURN_IFERR(wr_put_str(pack, info->dir_path));
    /* 2. flag */
    CM_RETURN_IFERR(wr_put_int32(pack, info->refresh_recursive));
    return CM_SUCCESS;
}

static status_t wr_decode_open_dir(wr_packet_t *ack_pack, void *ack)
{
    CM_RETURN_IFERR(wr_get_data(ack_pack, sizeof(wr_find_node_t), (void **)ack));
    return CM_SUCCESS;
}

static status_t wr_encode_open_file(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_open_file_info_t *info = (wr_open_file_info_t *)send_info;
    /* 1. file name */
    CM_RETURN_IFERR(wr_put_str(pack, info->file_path));
    /* 2. flag */
    CM_RETURN_IFERR(wr_put_int32(pack, (uint32)info->flag));
    return CM_SUCCESS;
}

static status_t wr_encode_close_dir(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_close_dir_info_t *info = (wr_close_dir_info_t *)send_info;
    CM_RETURN_IFERR(wr_put_int64(pack, info->pftid));
    CM_RETURN_IFERR(wr_put_str(pack, info->vg_name));
    CM_RETURN_IFERR(wr_put_int32(pack, info->vg_id));
    return CM_SUCCESS;
}

static status_t wr_encode_close_file(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_close_file_info_t *info = (wr_close_file_info_t *)send_info;
    CM_RETURN_IFERR(wr_put_int64(pack, info->fid));
    CM_RETURN_IFERR(wr_put_str(pack, info->vg_name));
    CM_RETURN_IFERR(wr_put_int32(pack, info->vg_id));
    CM_RETURN_IFERR(wr_put_int64(pack, info->ftid));
    return CM_SUCCESS;
}

static status_t wr_encode_create_file(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_create_file_info_t *info = (wr_create_file_info_t *)send_info;
    CM_RETURN_IFERR(wr_put_str(pack, info->file_path));
    CM_RETURN_IFERR(wr_put_int32(pack, info->flag));
    return CM_SUCCESS;
}

static status_t wr_encode_delete_file(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    return wr_put_str(pack, (const char *)send_info);
}

static status_t wr_decode_open_file(wr_packet_t *ack_pack, void *ack)
{
    CM_RETURN_IFERR(wr_get_data(ack_pack, sizeof(wr_find_node_t), (void **)ack));
    return CM_SUCCESS;
}

static status_t wr_encode_kickh(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    CM_RETURN_IFERR(wr_put_int64(pack, *(uint64 *)send_info));
    return CM_SUCCESS;
}

static status_t wr_encode_fallocate_file(wr_conn_t *conn, wr_packet_t *pack, void *send_info)
{
    wr_fallocate_info_t *info = (wr_fallocate_info_t *)send_info;
    CM_RETURN_IFERR(wr_put_int64(pack, info->fid));
    CM_RETURN_IFERR(wr_put_int64(pack, info->ftid));
    CM_RETURN_IFERR(wr_put_int64(pack, (uint64)info->offset));
    CM_RETURN_IFERR(wr_put_int64(pack, (uint64)info->size));
    CM_RETURN_IFERR(wr_put_int32(pack, info->vg_id));
    CM_RETURN_IFERR(wr_put_int32(pack, (uint32)info->mode));
    return CM_SUCCESS;
}

typedef status_t (*wr_encode_packet_proc_t)(wr_conn_t *conn, wr_packet_t *pack, void *send_info);
typedef status_t (*wr_decode_packet_proc_t)(wr_packet_t *ack_pack, void *ack);
typedef struct st_wr_packet_proc {
    wr_encode_packet_proc_t encode_proc;
    wr_decode_packet_proc_t decode_proc;
    char *cmd_info;
} wr_packet_proc_t;

wr_packet_proc_t g_wr_packet_proc[WR_CMD_END] = {[WR_CMD_MKDIR] = {wr_encode_make_dir, NULL, "make dir"},
    [WR_CMD_RMDIR] = {wr_encode_remove_dir, NULL, "remove dir"},
    [WR_CMD_OPEN_DIR] = {wr_encode_open_dir, wr_decode_open_dir, "open dir"},
    [WR_CMD_CLOSE_DIR] = {wr_encode_close_dir, NULL, "close dir"},
    [WR_CMD_OPEN_FILE] = {wr_encode_open_file, wr_decode_open_file, "open file"},
    [WR_CMD_CLOSE_FILE] = {wr_encode_close_file, NULL, "close file"},
    [WR_CMD_CREATE_FILE] = {wr_encode_create_file, NULL, "create file"},
    [WR_CMD_DELETE_FILE] = {wr_encode_delete_file, NULL, "delete file"},
    [WR_CMD_EXTEND_FILE] = {wr_encode_extend_file, NULL, "extend file"},
    [WR_CMD_RENAME_FILE] = {wr_encode_rename_file, NULL, "rename file"},
    [WR_CMD_TRUNCATE_FILE] = {wr_encode_truncate_file, NULL, "truncate file"},
    [WR_CMD_KICKH] = {wr_encode_kickh, NULL, "kickh"},
    [WR_CMD_STOP_SERVER] = {NULL, NULL, "stop server"},
    [WR_CMD_SETCFG] = {wr_encode_setcfg, NULL, "setcfg"},
    [WR_CMD_SET_MAIN_INST] = {NULL, NULL, "set main inst"},
    [WR_CMD_HANDSHAKE] = {wr_encode_handshake, wr_decode_handshake, "handshake with server"},
    [WR_CMD_FALLOCATE_FILE] = {wr_encode_fallocate_file, NULL, "fallocate file"},
    [WR_CMD_EXIST] = {wr_encode_exist, wr_decode_exist, "exist"},
    [WR_CMD_GETCFG] = {wr_encode_getcfg, wr_decode_getcfg, "getcfg"},
    [WR_CMD_GET_INST_STATUS] = {NULL, wr_decode_get_inst_status, "get inst status"},
    [WR_CMD_GET_TIME_STAT] = {NULL, wr_decode_get_time_stat, "get time stat"},
};

status_t wr_decode_packet(wr_packet_proc_t *make_proc, wr_packet_t *ack_pack, void *ack)
{
    if (ack == NULL || make_proc->decode_proc == NULL) {
        return CM_SUCCESS;
    }
    wr_init_get(ack_pack);
    status_t ret = make_proc->decode_proc(ack_pack, ack);
    WR_RETURN_IFERR2(ret, LOG_DEBUG_ERR("Decode %s msg failed", make_proc->cmd_info));
    return ret;
}

status_t wr_msg_interact(wr_conn_t *conn, uint8 cmd, void *send_info, void *ack)
{
    wr_packet_t *send_pack = &conn->pack;
    wr_packet_t *ack_pack = &conn->pack;
    wr_packet_proc_t *make_proc;
    do {
        wr_init_packet(&conn->pack, conn->pipe.options);
        wr_init_set(&conn->pack, conn->proto_version);
        send_pack->head->cmd = cmd;
        send_pack->head->flags = 0;
        make_proc = &g_wr_packet_proc[cmd];
        if (make_proc->encode_proc != NULL) {
            WR_RETURN_IF_ERROR(make_proc->encode_proc(conn, send_pack, send_info));
        }
        ack_pack = &conn->pack;
        WR_RETURN_IF_ERROR(wr_call_ex(&conn->pipe, send_pack, ack_pack));

        // check return state
        if (ack_pack->head->result != CM_SUCCESS) {
            int32 errcode = wr_get_pack_err(conn, ack_pack);
            if (errcode == ERR_WR_VERSION_NOT_MATCH) {
                continue;
            }
            return errcode;
        }
        break;
    } while (1);
    conn->server_version = wr_get_version(ack_pack);
    conn->proto_version = MIN(WR_PROTO_VERSION, conn->server_version);
    return wr_decode_packet(make_proc, ack_pack, ack);
}

void wr_set_conn_wait_event(wr_conn_t *conn, wr_wait_event_e event)
{
    if (conn->session != NULL) {
        wr_set_stat(&((wr_session_t *)conn->session)->stat_ctx, event);
    }
}

void wr_unset_conn_wait_event(wr_conn_t *conn)
{
    if (conn->session != NULL) {
        wr_unset_stat(&((wr_session_t *)conn->session)->stat_ctx);
    }
}

status_t wr_msg_interact_with_stat(wr_conn_t *conn, uint8 cmd, void *send_info, void *ack)
{
    timeval_t begin_tv;
    wr_begin_stat(&begin_tv);
    status_t status = wr_msg_interact(conn, cmd, send_info, ack);
    if (status == CM_SUCCESS && conn->session != NULL) {
        wr_session_t *session = (wr_session_t *)conn->session;
        wr_end_stat_ex(&session->stat_ctx, &session->wr_session_stat[session->stat_ctx.wait_event], &begin_tv);
    }
    return status;
}

#ifdef __cplusplus
}
#endif
