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
 * gr_api_impl.c
 *
 *
 * IDENTIFICATION
 *    src/common_api/gr_api_impl.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_system.h"
#include "cm_date.h"
#include "gr_defs.h"
#include "gr_diskgroup.h"
#include "gr_file.h"
#include "gr_file_def.h"
#include "gr_latch.h"
#include "gr_malloc.h"
#include "gr_api_impl.h"
#include "gr_defs.h"
#include "gr_thv.h"
#include "gr_stats.h"
#include "gr_cli_conn.h"
#include <stdint.h>
#include <openssl/sha.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GR_ACCMODE 00000003
#define GR_OPEN_MODE(flag) ((flag + 1) & GR_ACCMODE)
int32_t g_gr_tcp_conn_timeout = GR_TCP_CONNECT_TIMEOUT;


typedef struct str_files_rw_ctx {
    int32_t handle;
    int32_t size;
    bool32 read;
    int64 offset;
} files_rw_ctx_t;

status_t gr_connect(const char *server_locator, gr_conn_opt_t *options, gr_conn_t *conn)
{
    LOG_DEBUG_INF("gr connect entry, server_locator:%s", server_locator);
    if (server_locator == NULL) {
        GR_THROW_ERROR(ERR_GR_TCP_INVALID_URL, "NULL", 0);
        return CM_ERROR;
    }

    if ((conn->flag == CM_TRUE) && (conn->pipe.link.tcp.closed == CM_FALSE)) {
        LOG_DEBUG_INF("gr connect already connected");
        return CM_SUCCESS;
    }

    conn->flag = CM_FALSE;

    conn->cli_vg_handles = NULL;
    conn->pipe.options = 0;
    int32_t timeout = options != NULL ? options->timeout : g_gr_tcp_conn_timeout;
    conn->pipe.connect_timeout = timeout < 0 ? GR_TCP_CONNECT_TIMEOUT : timeout;
    conn->pipe.socket_timeout = GR_TCP_SOCKET_TIMEOUT;
    conn->pipe.link.tcp.sock = CS_INVALID_SOCKET;
    conn->pipe.link.tcp.closed = CM_FALSE;
    conn->pipe.type = CS_TYPE_SSL;
    conn->session = NULL;
    status_t ret = cs_connect(
        server_locator, &conn->pipe, NULL);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("connect server failed, ip port:%s", server_locator);
        return ret;
    }
    gr_init_packet(&conn->pack, conn->pipe.options);

    conn->flag = CM_TRUE;

    return CM_SUCCESS;
}

void gr_disconnect(gr_conn_t *conn)
{
    LOG_DEBUG_INF("gr disconnect entry");
    gr_set_thv_run_ctx_item(GR_THV_RUN_CTX_ITEM_SESSION, NULL);
    if (conn->flag == CM_TRUE) {
        cs_disconnect(&conn->pipe);
        gr_free_packet_buffer(&conn->pack);
        conn->flag = CM_FALSE;
    }
    LOG_DEBUG_INF("gr disconnect leave");
    return;
}

status_t gr_set_session_id(gr_conn_t *conn, uint32_t objectid)
{
    if (objectid >= gr_get_max_total_session_cnt()) {
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "objectid error, objectid is %u, max session cnt is %u.", objectid,
            gr_get_max_total_session_cnt());
        return ERR_GR_SESSION_INVALID_ID;
    }
    return CM_SUCCESS;
}

static status_t gr_set_server_info(gr_conn_t *conn, char *home, uint32_t objectid, uint32_t max_open_file)
{
    status_t status = gr_init_client(max_open_file, home);
    GR_RETURN_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "gr client init failed."), gr_disconnect(conn));

    status = cli_init_ssl(&conn->cli_ssl_inst);
    GR_RETURN_IFERR3(status,
                     LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "gr client init ssl failed."), gr_disconnect(conn));

    status = gr_set_session_id(conn, objectid);
    GR_RETURN_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "gr client failed to initialize session."),
        gr_disconnect(conn));
    return CM_SUCCESS;
}

status_t gr_cli_handshake(gr_conn_t *conn, uint32_t max_open_file)
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
        LOG_RUN_ERR("System call strcpy_s error %d.", err);
        return CM_ERROR;
    }
    conn->cli_info.connect_time = cm_clock_monotonic_now();
    gr_get_server_info_t output_info = {NULL, GR_INVALID_SESSIONID, CM_FALSE};
    CM_RETURN_IFERR(gr_msg_interact(conn, GR_CMD_HANDSHAKE, (void *)&conn->cli_info, (void *)&output_info));

    if (getenv(GR_ENV_HOME) != NULL) {
        output_info.home = getenv(GR_ENV_HOME);
    }
    
    conn->hash_auth_enable = output_info.hash_auth_enable;
    LOG_RUN_INF("[GR_CONNECT]Client received HASH_AUTH_ENABLE=%d from server", conn->hash_auth_enable);
    
    return gr_set_server_info(conn, output_info.home, output_info.objectid, max_open_file);
}

status_t gr_cli_ssl_connect(gr_conn_t *conn)
{
    LOG_DEBUG_INF("gr cli ssl connect entry");
    status_t status = cli_ssl_connect(&conn->cli_ssl_inst, &conn->pipe);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to do cli ssl certification.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("gr cli ssl connect leave");
    return CM_SUCCESS;
}

void gr_disconnect_ex(gr_conn_t *conn)
{
    gr_env_t *gr_env = gr_get_env();

    gr_disconnect(conn);
    gr_latch_x(&gr_env->conn_latch);
    if (gr_env->conn_count > 0) {
        gr_env->conn_count--;
    }

    if (gr_env->conn_count == 0) {
        gr_destroy();
    }
    uint32_t count = gr_env->conn_count;
    gr_unlatch(&gr_env->conn_latch);
    LOG_DEBUG_INF("Remain conn count:%u when disconnect.", count);

    return;
}

status_t gr_vfs_create_impl(gr_conn_t *conn, const char *dir_name, unsigned long long attrFlag)
{
    text_t text;
    cm_str2text((char *)dir_name, &text);
    if (text.len >= GR_MAX_NAME_LEN) {
        GR_THROW_ERROR_EX(
            ERR_GR_DIR_CREATE, "Length of dir name(%s) is too long, maximum is %u.", T2S(&text), GR_MAX_NAME_LEN);
        return CM_ERROR;
    }
    GR_RETURN_IF_ERROR(gr_check_name(dir_name));
    LOG_DEBUG_INF("gr make dir entry, dir_name:%s", dir_name);
    gr_make_dir_info_t send_info;
    send_info.name = dir_name;
    send_info.attrFlag = attrFlag;
    status_t status = gr_msg_interact(conn, GR_CMD_MKDIR, (void *)&send_info, NULL);
    LOG_DEBUG_INF("gr make dir leave");
    return status;
}

status_t gr_vfs_delete_impl(gr_conn_t *conn, const char *dir, unsigned long long attrFlag)
{
    GR_RETURN_IF_ERROR(gr_check_device_path(dir));
    LOG_DEBUG_INF("gr remove dir entry, dir:%s", dir);
    gr_remove_dir_info_t send_info;
    send_info.name = dir;
    send_info.attrFlag = attrFlag;
    status_t status = gr_msg_interact(conn, GR_CMD_RMDIR, (void *)&send_info, NULL);
    LOG_DEBUG_INF("gr remove dir leave");
    return status;
}

status_t gr_vfs_mount_impl(gr_conn_t *conn, gr_vfs_handle *vfs_handle, unsigned long long attrFlag)
{
    if (vfs_handle == NULL || vfs_handle->vfs_name[0] == '\0') {
        LOG_RUN_ERR("vfs handle is NULL or vfs name is empty.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("gr mount vfs entry, vfs_name:%s", vfs_handle->vfs_name);
    gr_mount_vfs_info_t send_info;
    send_info.vfs_name = vfs_handle->vfs_name;
    send_info.dir = 0; 
    status_t status = gr_msg_interact(conn, GR_CMD_MOUNT_VFS, (void *)&send_info,  (void *)&send_info);
    vfs_handle->dir_handle = send_info.dir;
    LOG_DEBUG_INF("gr mount vfs leave");
    return status;
}

status_t gr_vfs_unmount_impl(gr_conn_t *conn, gr_vfs_handle *vfs_handle)
{
    if (vfs_handle == NULL || vfs_handle->vfs_name[0] == '\0') {
        LOG_RUN_ERR("vfs handle is NULL or vfs name is empty.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("gr unmount vfs entry, vfs_name:%s", vfs_handle->vfs_name);
    gr_mount_vfs_info_t send_info;
    send_info.dir = vfs_handle->dir_handle; 
    status_t status = gr_msg_interact(conn, GR_CMD_UNMOUNT_VFS, (void *)&send_info,  (void *)&send_info);
    LOG_DEBUG_INF("gr unmount vfs leave");
    return status;
}

status_t gr_vfs_query_file_num_impl(gr_conn_t *conn, gr_vfs_handle vfs_handle, uint32_t *file_num)
{
    LOG_DEBUG_INF("gr query file num entry");
    gr_query_file_num_info_t send_info;
    send_info.dir = vfs_handle.dir_handle;
    send_info.file_num = *file_num;
    status_t status = gr_msg_interact(conn, GR_CMD_QUERY_FILE_NUM, (void *)&send_info, (void *)&send_info);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("gr query file num error");
        return CM_ERROR;
    }
    *file_num = send_info.file_num;
    LOG_DEBUG_INF("gr query file num leave");
    return status;
}

status_t gr_vfs_query_file_info_impl(gr_conn_t *conn, gr_vfs_handle vfs_handle, gr_file_item_t *file_info, bool is_continue)
{
    LOG_DEBUG_INF("Client query file info entry, vfs_name: %s", vfs_handle.vfs_name);
    gr_query_file_num_info_t send_info;
    send_info.dir = vfs_handle.dir_handle;
    send_info.is_continue = is_continue;
    status_t status = gr_msg_interact(conn, GR_CMD_QUERY_FILE_INFO, (void *)&send_info, (void *)file_info);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to interact with server for file info query");
        return CM_ERROR;
    }

    LOG_DEBUG_INF("Client query file info leave.");
    return CM_SUCCESS;
}

status_t gr_create_file_impl(gr_conn_t *conn, const char *file_path, int flag)
{
    LOG_DEBUG_INF("gr create file entry, file path:%s, flag:%d", file_path, flag);
    GR_RETURN_IF_ERROR(gr_check_device_path(file_path));
    gr_create_file_info_t send_info;
    send_info.file_path = file_path;
    send_info.flag = (uint32_t)flag;
    status_t status = gr_msg_interact(conn, GR_CMD_CREATE_FILE, (void *)&send_info, NULL);
    LOG_DEBUG_INF("gr create file leave");
    return status;
}

status_t gr_remove_file_impl(gr_conn_t *conn, const char *file_path, unsigned long long attrFlag)
{
    LOG_DEBUG_INF("gr remove file entry, file path:%s", file_path);
    GR_RETURN_IF_ERROR(gr_check_device_path(file_path));
    gr_remove_file_info_t send_info;
    send_info.name = file_path;
    send_info.attrFlag = attrFlag;
    status_t status = gr_msg_interact(conn, GR_CMD_DELETE_FILE, (void *)&send_info, NULL);
    LOG_DEBUG_INF("gr remove file leave");
    return status;
}

status_t gr_open_file_on_server(gr_conn_t *conn, const char *file_path, int flag, gr_file_handle *file_handle)
{
    LOG_DEBUG_INF("gr open file on server entry, file_path:%s, flag:%d", file_path, flag);
    gr_open_file_info_t send_info;
    send_info.file_path = file_path;
    send_info.flag = flag;
    return gr_msg_interact(conn, GR_CMD_OPEN_FILE, (void*)&send_info, (void*)file_handle);
}

status_t gr_open_file_impl(gr_conn_t *conn, const char *file_path, int flag, gr_file_handle* file_handle)
{
    LOG_DEBUG_INF("gr begin to open file, file path:%s, flag:%d", file_path, flag);
    GR_RETURN_IF_ERROR(gr_check_device_path(file_path));
    GR_RETURN_IF_ERROR(gr_check_file_flag(flag));
    if (gr_open_file_on_server(conn, file_path, flag, file_handle) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to open file on server, file path:%s, flag:%d", file_path, flag);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("gr open file successfully, file_path:%s, flag:%d, handle:%d", file_path, flag, file_handle->fd);
    return CM_SUCCESS;
}

status_t gr_postpone_file_time_impl(gr_conn_t *conn, const char *file_name, const char *time)
{
    LOG_DEBUG_INF("gr extend file expired time, file name: %s, add time: %s", file_name, time);
    GR_RETURN_IF_ERROR(gr_check_device_path(file_name));
    gr_postpone_file_time_t send_info;
    send_info.file_name = file_name;
    send_info.file_atime = time;
    status_t status = gr_msg_interact(conn, GR_CMD_POSTPONE_FILE_TIME, (void *)&send_info, NULL);
    LOG_DEBUG_INF("gr extend file expired time");

    return status;
}

status_t gr_close_file_impl(gr_conn_t *conn, int handle, bool need_lock)
{
    LOG_DEBUG_INF("gr close file entry, handle:%d", handle);
    status_t ret = gr_close_file_on_server(conn, handle, need_lock);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_INF("Failed to fclose, handle:%d.", handle);
        return ret;
    }
    LOG_DEBUG_INF("Success to fclose, handle:%d.", handle);
    return CM_SUCCESS;
}

status_t gr_exist_impl(gr_conn_t *conn, const char *path, bool32 *result, gft_item_type_t *type)
{
    LOG_DEBUG_INF("gr exits file entry, name:%s", path);
    GR_RETURN_IF_ERROR(gr_check_device_path(path));
    gr_exist_recv_info_t recv_info;
    GR_RETURN_IF_ERROR(gr_msg_interact(conn, GR_CMD_EXIST, (void *)path, (void *)&recv_info));
    *result = (bool32)recv_info.result;
    *type = (gft_item_type_t)recv_info.type;
    LOG_DEBUG_INF("gr exits file or dir leave, name:%s, result:%d, type:%u", path, *result, *type);
    return CM_SUCCESS;
}

status_t gr_check_path_exist(gr_conn_t *conn, const char *path)
{
    bool32 exist = false;
    gft_item_type_t type;

    GR_RETURN_IFERR2(
        gr_exist_impl(conn, path, &exist, &type),
            GR_THROW_ERROR(ERR_GR_FILE_NOT_EXIST, "Failed to check the path %s exists.\n", path));
    if (!exist) {
        GR_THROW_ERROR(ERR_GR_FILE_NOT_EXIST, "%s not exist, please check", path);
        return CM_ERROR;
    }
    if (type != GFT_PATH) {
        LOG_RUN_ERR("%s is not a directory.\n", path);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t gr_check_file_exist(gr_conn_t *conn, const char *path, bool *is_exist)
{
    if (is_exist == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "is_exist parameter is NULL");
        return CM_ERROR;
    }
    
    bool32 exist = false;
    gft_item_type_t type;
    status_t status = gr_exist_impl(conn, path, &exist, &type);
    if (status != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_FILE_NOT_EXIST, "Failed to check the path %s exists.", path);
        LOG_RUN_ERR("Failed to check the path %s exists.", path);
        return status;
    }

    *is_exist = (exist && type == GFT_FILE);
    return CM_SUCCESS;
}

status_t gr_check_file_flag(int flag)
{
    if ((flag & O_CREAT) == O_CREAT || (flag & O_TRUNC) == O_TRUNC) {
        GR_THROW_ERROR(ERR_GR_FILE_INVALID_FLAG);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int64 gr_pwrite_file_impl(gr_conn_t *conn, gr_file_handle *file_handle, const void *buf, unsigned long long size, long long offset)
{
    LOG_DEBUG_INF("gr pwrite file entry, handle:%d, size:%lld, offset:%lld",
                    HANDLE_VALUE(file_handle->fd), size, offset);

    gr_write_file_info_t send_info;
    send_info.handle = HANDLE_VALUE(file_handle->fd);

    status_t status;
    unsigned long long total_size = 0;
    unsigned long long remaining_size = size;
    long long int rel_size = 0;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    const char *buf_ptr = (const char *)buf;

    while (total_size < size) {
        const unsigned long long curr_size = (remaining_size > GR_RW_STEP_SIZE) ? 
                                           GR_RW_STEP_SIZE : remaining_size;
        
        send_info.offset = offset + total_size;
        send_info.size = curr_size;
        send_info.buf = (char *)(buf_ptr + total_size);

        if (conn->hash_auth_enable) {
            status = calculate_data_hash(send_info.buf, curr_size, hash);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Failed to calculate data hash.");
                GR_THROW_ERROR(ERR_GR_HASH_AUTH_FAILED, "Failed to calculate data hash.");
                return CM_ERROR;
            }

            status = xor_sha256_hash(hash, file_handle->hash, send_info.hash);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Failed to calculate combine_hash.");
                GR_THROW_ERROR(ERR_GR_HASH_AUTH_FAILED, "Failed to calculate combine_hash.");
                return CM_ERROR;
            }
        }

        status = gr_msg_interact(conn, GR_CMD_WRITE_FILE, (void *)&send_info, (void *)&rel_size);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to write file, total_size:%lld, remaining:%lld, offset:%lld.",
                total_size, remaining_size, offset);
            return CM_ERROR;
        }
        
        if (rel_size != curr_size) {
            LOG_RUN_WAR("Partial write: expected %lld, actual %lld, total_size:%lld, offset:%lld",
                curr_size, rel_size, total_size, offset);
            total_size += rel_size;
            break;
        }

        total_size += curr_size;
        remaining_size -= curr_size;
        
        errno_t errcode = memcpy_s(file_handle->hash, SHA256_DIGEST_LENGTH,
                                    send_info.hash, SHA256_DIGEST_LENGTH);
        if (errcode != EOK) {
            LOG_RUN_ERR("Failed to memcpy hash, size:%d.", SHA256_DIGEST_LENGTH);
            GR_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }
    }

    LOG_DEBUG_INF("gr pwrite file leave, total written: %lld", total_size);
    return total_size;
}

int64 gr_append_file_impl(gr_conn_t *conn, gr_file_handle *file_handle, const void *buf, unsigned long long size)
{
    LOG_DEBUG_INF("gr append file entry, handle:%d, size:%lld",
                    HANDLE_VALUE(file_handle->fd), size);

    gr_write_file_info_t send_info;
    send_info.handle = HANDLE_VALUE(file_handle->fd);
    send_info.size = size;
    send_info.buf = (char *)buf;

    status_t status;
    unsigned long long total_size = 0;
    unsigned long long remaining_size = size;
    long long int rel_size = 0;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    const char *buf_ptr = (const char *)buf;

    while (total_size < size) {
        const unsigned long long curr_size = (remaining_size > GR_RW_STEP_SIZE) ? 
                                           GR_RW_STEP_SIZE : remaining_size;
        
        send_info.size = curr_size;
        send_info.buf = (char *)(buf_ptr + total_size);

        if (conn->hash_auth_enable) {
            status = calculate_data_hash(send_info.buf, curr_size, hash);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Failed to calculate data hash.");
                GR_THROW_ERROR(ERR_GR_HASH_AUTH_FAILED, "Failed to calculate data hash.");
                return CM_ERROR;
            }

            status = xor_sha256_hash(hash, file_handle->hash, send_info.hash);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Failed to calculate combine_hash.");
                GR_THROW_ERROR(ERR_GR_HASH_AUTH_FAILED, "Failed to calculate combine_hash.");
                return CM_ERROR;
            }
        }

        status = gr_msg_interact(conn, GR_CMD_APPEND_FILE, (void *)&send_info, (void *)&rel_size);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to append file, total_size:%lld, remaining:%lld.",
                total_size, remaining_size);
            return CM_ERROR;
        }
        
        if (rel_size != curr_size) {
            LOG_RUN_WAR("Partial append: expected %lld, actual %lld, total_size:%lld",
                curr_size, rel_size, total_size);
            total_size += rel_size;
            break;
        }

        total_size += curr_size;
        remaining_size -= curr_size;
        
        errno_t errcode = memcpy_s(file_handle->hash, SHA256_DIGEST_LENGTH,
                                    send_info.hash, SHA256_DIGEST_LENGTH);
        if (errcode != EOK) {
            LOG_RUN_ERR("Failed to memcpy hash, size:%d.", SHA256_DIGEST_LENGTH);
            GR_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }
    }

    LOG_DEBUG_INF("gr append file leave, total written: %lld", total_size);
    return total_size;
}

int64 gr_pread_file_impl(gr_conn_t *conn, int handle, const void *buf, unsigned long long size, long long offset)
{
    if (size < 0) {
        LOG_RUN_ERR("File size is invalid: %lld.", size);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("gr pread file entry, handle:%d, size:%lld, offset:%lld", handle, size, offset);

    gr_read_file_info_t send_info;
    send_info.handle = handle;

    status_t status;
    int64 total_size = 0;
    int64 curr_size = 0;
    int64 remaining_size = size;

    while (total_size < size) {
        curr_size = (remaining_size > GR_RW_STEP_SIZE) ? GR_RW_STEP_SIZE : remaining_size;
        send_info.offset = offset + total_size;
        send_info.size = curr_size;
        send_info.buf = (char *)buf + total_size;

        status = gr_msg_interact(conn, GR_CMD_READ_FILE, (void *)&send_info, (void *)&send_info);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to read file, total_size:%lld, size:%lld, offset:%lld, errmsg:%s.",
                total_size, size - total_size, offset, strerror(errno));
            return CM_ERROR;
        }

        if (send_info.rel_size != curr_size) {
            LOG_RUN_WAR("Failed to read file, total_size:%lld, size:%lld, offset:%lld, rel_size:%lld, errmsg:%s.",
                total_size, size - total_size, offset, send_info.rel_size, strerror(errno));
            total_size += send_info.rel_size;
            break;
        }

        total_size += curr_size;
        remaining_size -= curr_size;
    }

    LOG_DEBUG_INF("gr pread file leave");
    return total_size;
}

status_t gr_truncate_impl(gr_conn_t *conn, int handle, long long length, int truncateType)
{
    LOG_DEBUG_INF("gr truncate file entry, handle:%d, length:%lld, truncateType:%d", handle, length, truncateType);
    if (length < 0) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "length must be a positive integer");
        LOG_RUN_ERR("File length is invalid:%lld.", length);
        return CM_ERROR;
    }

    if (length > (int64)GR_MAX_FILE_SIZE) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "length must less than GR_MAX_FILE_SIZE");
        LOG_RUN_ERR("File length is invalid:%lld.", length);
        return CM_ERROR;
    }

    gr_truncate_file_info_t send_info;
    send_info.handle = handle;
    send_info.length = length;
    send_info.truncateType = truncateType;

    status_t status = gr_msg_interact(conn, GR_CMD_TRUNCATE_FILE, (void *)&send_info, NULL);
    LOG_DEBUG_INF("gr truncate file leave, status:%d", status);
    return status;
}

status_t gr_stat_file_impl(
    gr_conn_t *conn, const char *fileName, long long *offset, unsigned long long *size, int *mode, char **time)
{
    LOG_DEBUG_INF("gr stat file entry, fileName:%s", fileName);
    gr_stat_file_info_t send_info;
    send_info.name = fileName;
    send_info.offset = 0;
    send_info.size = 0;
    send_info.mode = 0;
    send_info.expire_time = NULL;
    status_t status = gr_msg_interact(conn, GR_CMD_STAT_FILE, (void *)&send_info, (void *)&send_info);
    *offset = send_info.offset;
    *size = send_info.size;
    *mode = (int)send_info.mode;
    *time = send_info.expire_time;
    LOG_DEBUG_INF("gr stat file leave, offset:%lld, size:%llu, mode:%d", *offset, *size, *mode);
    return status;
}

void gr_heartbeat_entry(thread_t *thread)
{
    return;
}

static status_t gr_init_err_proc(
    gr_env_t *gr_env, const char *errmsg, status_t errcode)
{
    gr_unlatch(&gr_env->latch);

    if (errmsg != NULL) {
        LOG_RUN_ERR("init error: %s", errmsg);
    }

    return errcode;
}

status_t gr_init_client(uint32_t max_open_files, char *home)
{
    LOG_DEBUG_INF("gr init client entry, max_open_files:%u, home:%s", max_open_files, home ? home : "NULL");
    if (max_open_files > GR_MAX_OPEN_FILES) {
        GR_THROW_ERROR(ERR_INVALID_VALUE, "max_open_files", max_open_files);
        return CM_ERROR;
    }

    gr_env_t *gr_env = gr_get_env();
    if (gr_env->initialized) {
        LOG_DEBUG_INF("gr init client already initialized");
        return CM_SUCCESS;
    }

    gr_latch_x(&gr_env->latch);
    if (gr_env->initialized) {
#ifdef ENABLE_GRTEST
        if (gr_env->inittor_pid == getpid()) {
#endif
            return gr_init_err_proc(gr_env, NULL, CM_SUCCESS);
#ifdef ENABLE_GRTEST
        } else {
            LOG_RUN_INF("gr client need re-initalization gr env, last init pid:%llu.", (uint64)gr_env->inittor_pid);
            (void)gr_init_err_proc(gr_env, "need reinit by a new process", CM_SUCCESS);

            gr_env->initialized = CM_FALSE;
            gr_env->inittor_pid = 0;
        }
#endif
    }

    status_t status = gr_set_cfg_dir(home, &gr_env->inst_cfg);
    if (status != CM_SUCCESS) {
        return gr_init_err_proc(gr_env, "Environment variant GR_HOME not found", status);
    }

    status = gr_load_config(&gr_env->inst_cfg);
    if (status != CM_SUCCESS) {
        return gr_init_err_proc(gr_env, "load config failed", status);
    }

    status = gr_load_cli_ssl(&gr_env->inst_cfg);
    if (status != CM_SUCCESS) {
        return gr_init_err_proc(gr_env, "load client ssl config failed", status);
    }

    status = cm_create_thread(gr_heartbeat_entry, SIZE_K(512), NULL, &gr_env->thread_heartbeat);
    if (status != CM_SUCCESS) {
        return gr_init_err_proc(gr_env, "GR failed to create heartbeat thread", status);
    }

#ifdef ENABLE_GRTEST
    gr_env->inittor_pid = getpid();
#endif

    gr_env->initialized = CM_TRUE;
    gr_unlatch(&gr_env->latch);

    return CM_SUCCESS;
}

void gr_destroy(void)
{
    LOG_DEBUG_INF("gr destroy entry");
    gr_env_t *gr_env = gr_get_env();
    gr_latch_x(&gr_env->latch);
    if (!gr_env->initialized) {
        gr_unlatch(&gr_env->latch);
        LOG_DEBUG_INF("gr destroy already destroyed");
        return;
    }

    cm_close_thread_nowait(&gr_env->thread_heartbeat);
    gr_env->initialized = 0;
    gr_unlatch(&gr_env->latch);
    LOG_DEBUG_INF("gr destroy leave");
}

status_t gr_setcfg_impl(gr_conn_t *conn, const char *name, const char *value, const char *scope)
{
    LOG_DEBUG_INF("gr set cfg entry, name:%s, value:%s, scope:%s", name, value, scope);
    GR_RETURN_IF_ERROR(gr_check_str_not_null(name, "name"));
    GR_RETURN_IF_ERROR(gr_check_str_not_null(value, "value"));
    GR_RETURN_IF_ERROR(gr_check_str_not_null(scope, "scope"));
    gr_setcfg_info_t send_info;
    send_info.name = name;
    send_info.value = value;
    send_info.scope = scope;
    status_t status = gr_msg_interact(conn, GR_CMD_SETCFG, (void *)&send_info, NULL);
    LOG_DEBUG_INF("gr set cfg leave");
    return status;
}

status_t gr_getcfg_impl(gr_conn_t *conn, const char *name, char *out_str, size_t str_len)
{
    LOG_DEBUG_INF("gr get cfg entry, name:%s", name);
    GR_RETURN_IF_ERROR(gr_check_str_not_null(name, "name"));
    text_t extra_info = CM_NULL_TEXT;
    GR_RETURN_IF_ERROR(gr_msg_interact(conn, GR_CMD_GETCFG, (void *)name, (void *)&extra_info));
    if (extra_info.len == 0) {
        LOG_DEBUG_INF("Client get cfg is NULL.");
        return CM_SUCCESS;
    }

    errno_t err = strncpy_s(out_str, str_len, extra_info.str, extra_info.len);
    if (SECUREC_UNLIKELY(err != EOK)) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "value of str_len is not large enough when getcfg.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("gr get cfg leave, value:%s", (strlen(out_str) == 0) ? "NULL" : out_str);
    return CM_SUCCESS;
}

status_t gr_get_inst_status_on_server(gr_conn_t *conn, gr_server_status_t *gr_status)
{
    LOG_DEBUG_INF("gr get inst status entry");
    if (gr_status == NULL) {
        GR_THROW_ERROR_EX(ERR_GR_INVALID_PARAM, "gr_status");
        return CM_ERROR;
    }
    text_t extra_info = CM_NULL_TEXT;
    GR_RETURN_IF_ERROR(gr_msg_interact(conn, GR_CMD_GET_INST_STATUS, NULL, (void *)&extra_info));
    *gr_status = *(gr_server_status_t *)extra_info.str;
    LOG_DEBUG_INF("gr get inst status leave, status:%s", gr_status->instance_status);
    return CM_SUCCESS;
}

status_t gr_get_time_stat_on_server(gr_conn_t *conn, gr_stat_item_t *time_stat, uint64 size)
{
    LOG_DEBUG_INF("gr get time stat entry");
    text_t stat_info = CM_NULL_TEXT;
    GR_RETURN_IF_ERROR(gr_msg_interact(conn, GR_CMD_GET_TIME_STAT, NULL, (void *)&stat_info));
    for (uint64 i = 0; i < GR_EVT_COUNT; i++) {
        time_stat[i] = *(gr_stat_item_t *)(stat_info.str + i * (uint64)sizeof(gr_stat_item_t));
    }
    LOG_DEBUG_INF("gr get time stat leave");
    return CM_SUCCESS;
}

status_t gr_set_main_inst_impl(gr_conn_t *conn)
{
    LOG_DEBUG_INF("gr set main inst entry");
    status_t status = gr_msg_interact(conn, GR_CMD_SET_MAIN_INST, NULL, NULL);
    LOG_DEBUG_INF("gr set main inst leave, status:%d", status);
    return status;
}

status_t gr_reload_certs_impl(gr_conn_t *conn)
{
    LOG_DEBUG_INF("gr reload certs entry");
    status_t status = gr_msg_interact(conn, GR_CMD_RELOAD_CERTS, NULL, NULL);
    LOG_DEBUG_INF("gr reload certs leave, status:%d", status);
    return status;
}

status_t gr_reload_cfg_impl(gr_conn_t *conn)
{
    return gr_msg_interact(conn, GR_CMD_RELOAD_CFG, NULL, NULL);
}

status_t gr_get_disk_usage_impl(gr_conn_t *conn, gr_disk_usage_info_t *info)
{
    LOG_DEBUG_INF("gr get disk usage entry");
    gr_disk_usage_ack_t ack_info = {0};
    GR_RETURN_IF_ERROR(gr_msg_interact(conn, GR_CMD_GET_DISK_USAGE, NULL, (void *)&ack_info));
    info->available_bytes = ack_info.available_bytes;
    info->total_bytes = ack_info.total_bytes;
    info->used_bytes = ack_info.used_bytes;
    info->usage_percent = ack_info.usage_percent;
    LOG_DEBUG_INF("gr get disk usage leave, total:%lu, used:%lu, avail:%lu",
        info->total_bytes, info->used_bytes, info->available_bytes);
    return CM_SUCCESS;
}

status_t gr_close_file_on_server(gr_conn_t *conn, int64 fd, bool need_lock)
{
    LOG_DEBUG_INF("gr close file on server entry, fd:%lld, need_lock:%d", fd, need_lock);
    gr_close_file_info_t send_info;
    send_info.fd = fd;
    send_info.need_lock = (int)need_lock;
    return gr_msg_interact(conn, GR_CMD_CLOSE_FILE, (void *)&send_info, NULL);
}

status_t gr_stop_server_impl(gr_conn_t *conn)
{
    LOG_DEBUG_INF("gr stop server entry");
    status_t status = gr_msg_interact(conn, GR_CMD_STOP_SERVER, NULL, NULL);
    LOG_DEBUG_INF("gr stop server leave, status:%d", status);
    return status;
}

static status_t gr_encode_setcfg(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_setcfg_info_t *info = (gr_setcfg_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_str(pack, info->name));
    CM_RETURN_IFERR(gr_put_str(pack, info->value));
    CM_RETURN_IFERR(gr_put_str(pack, info->scope));
    return CM_SUCCESS;
}

static status_t gr_encode_postpone_file_time(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_postpone_file_time_t *info = (gr_postpone_file_time_t *)send_info;
    CM_RETURN_IFERR(gr_put_str(pack, info->file_name));
    CM_RETURN_IFERR(gr_put_str(pack, info->file_atime));
    return CM_SUCCESS;
}

static status_t gr_encode_handshake(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    CM_RETURN_IFERR(gr_put_data(pack, send_info, sizeof(gr_cli_info_t)));
    return CM_SUCCESS;
}

static status_t gr_encode_mount_vfs(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_mount_vfs_info_t *info = (gr_mount_vfs_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_str(pack, info->vfs_name));
    return CM_SUCCESS;
}

static status_t gr_encode_unmount_vfs(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_mount_vfs_info_t *info = (gr_mount_vfs_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_int64(pack, (int64)info->dir));
    return CM_SUCCESS;
}

static status_t gr_encode_query_file_num(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_query_file_num_info_t *info = (gr_query_file_num_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_int64(pack, (int64)info->dir));
    return CM_SUCCESS;
}

static status_t gr_encode_query_file_info(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_query_file_num_info_t *info = (gr_query_file_num_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_int32(pack, info->is_continue));
    CM_RETURN_IFERR(gr_put_int64(pack, (int64)info->dir));
    return CM_SUCCESS;
}

static status_t gr_decode_stat_file(gr_packet_t *ack_pack, void *ack)
{
    gr_stat_file_info_t *info = (gr_stat_file_info_t *)ack;
    CM_RETURN_IFERR(gr_get_int64(ack_pack, &(info->offset)));
    CM_RETURN_IFERR(gr_get_int64(ack_pack, &(info->size)));
    CM_RETURN_IFERR(gr_get_int32(ack_pack, &(info->mode)));
    CM_RETURN_IFERR(gr_get_str(ack_pack, &(info->expire_time)));
    return CM_SUCCESS;
}

static status_t gr_decode_mount_vfs(gr_packet_t *ack_pack, void *ack)
{
    gr_mount_vfs_info_t *info = (gr_mount_vfs_info_t *)ack;
    CM_RETURN_IFERR(gr_get_int64(ack_pack, (int64*)&(info->dir)));
    return CM_SUCCESS;
}

static status_t gr_decode_query_file_num(gr_packet_t *ack_pack, void *ack)
{
    gr_query_file_num_info_t *info = (gr_query_file_num_info_t *)ack;
    CM_RETURN_IFERR(gr_get_int32(ack_pack, (int32*)&(info->file_num)));
    return CM_SUCCESS;
}

static status_t gr_decode_query_file_info(gr_packet_t *ack_pack, void *ack)
{
    int32_t file_num = 0;
    gr_file_item_t *info = (gr_file_item_t *)ack;
    gr_file_item_t *tmp;

    CM_RETURN_IFERR(gr_get_int32(ack_pack, &file_num));

    for (uint32_t i = 0; i < file_num; i++) {
        CM_RETURN_IFERR(gr_get_data(ack_pack, sizeof(gr_file_item_t), (void **)&tmp));
        memcpy_s(&info[i], sizeof(gr_file_item_t), tmp, sizeof(gr_file_item_t));
    }

    return CM_SUCCESS;
}

static status_t gr_decode_write_file(gr_packet_t *ack_pack, void *ack)
{
    int64 *info = (int64*)ack;
    CM_RETURN_IFERR(gr_get_int64(ack_pack, info));
    return CM_SUCCESS;
}

static status_t gr_decode_append_file(gr_packet_t *ack_pack, void *ack)
{
    int64 *info = (int64*)ack;
    CM_RETURN_IFERR(gr_get_int64(ack_pack, info));
    return CM_SUCCESS;
}

static status_t gr_decode_read_file(gr_packet_t *ack_pack, void *ack)
{
    text_t ack_info = CM_NULL_TEXT;
    gr_read_file_info_t *info = (gr_read_file_info_t *)ack;
    CM_RETURN_IFERR(gr_get_text(ack_pack, &ack_info));
    info->rel_size = ack_info.len;
    if (ack_info.len == 0) {
        return CM_SUCCESS;
    }
    errno_t errcode = memcpy_s(info->buf, info->size, ack_info.str, ack_info.len);
    if (errcode != EOK) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_READ_FILE), "get read file data error");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t gr_decode_handshake(gr_packet_t *ack_pack, void *ack)
{
    text_t ack_info = CM_NULL_TEXT;
    CM_RETURN_IFERR(gr_get_text(ack_pack, &ack_info));
    if (ack_info.len == 0 || ack_info.len >= GR_MAX_PATH_BUFFER_SIZE) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_HANDSHAKE), "get home info length error");
        return CM_ERROR;
    }
    gr_get_server_info_t *output_info = (gr_get_server_info_t *)ack;
    output_info->home = ack_info.str;
    CM_RETURN_IFERR(gr_get_int32(ack_pack, (int32_t *)&output_info->objectid));
    
    // 读取HASH_AUTH_ENABLE参数
    int32_t hash_auth_enable_int;
    CM_RETURN_IFERR(gr_get_int32(ack_pack, &hash_auth_enable_int));
    output_info->hash_auth_enable = (bool32)hash_auth_enable_int;
    LOG_RUN_INF("[GR_CONNECT]Received HASH_AUTH_ENABLE=%d from server", output_info->hash_auth_enable);
    
    return CM_SUCCESS;
}

static status_t gr_encode_exist(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    return gr_put_str(pack, (const char *)send_info);
}

static status_t gr_decode_exist(gr_packet_t *ack_pack, void *ack)
{
    gr_exist_recv_info_t *info = (gr_exist_recv_info_t *)ack;
    if (gr_get_int32(ack_pack, &(info->result)) != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_EXIST), "get result data error");
        LOG_RUN_ERR("get result data error.");
        return CM_ERROR;
    }
    if (gr_get_int32(ack_pack, &(info->type)) != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_EXIST), "get type data error");
        LOG_RUN_ERR("get type data error.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t gr_encode_getcfg(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    return gr_put_str(pack, (const char *)send_info);
}

static status_t gr_decode_getcfg(gr_packet_t *ack_pack, void *ack)
{
    text_t *info = (text_t *)ack;
    if (gr_get_text(ack_pack, info) != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_GETCFG), "get cfg connect error");
        return CM_ERROR;
    }
    if (info->len >= GR_MAX_PACKET_SIZE - sizeof(gr_packet_head_t) - sizeof(int32_t)) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_GETCFG), "get cfg length error");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t gr_decode_get_inst_status(gr_packet_t *ack_pack, void *ack)
{
    text_t *info = (text_t *)ack;
    if (gr_get_text(ack_pack, info) != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_GET_INST_STATUS), "get inst status error");
        return CM_ERROR;
    }
    if (info->len != sizeof(gr_server_status_t)) {
        GR_THROW_ERROR(
            ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_GET_INST_STATUS), "get inst status length error");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t gr_decode_get_time_stat(gr_packet_t *ack_pack, void *ack)
{
    text_t *time_stat = (text_t *)ack;
    if (gr_get_text(ack_pack, time_stat) != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_GET_TIME_STAT), "get time stat error");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t gr_decode_get_disk_usage(gr_packet_t *ack_pack, void *ack)
{
    gr_disk_usage_ack_t *info = (gr_disk_usage_ack_t *)ack;
    if (gr_get_int64(ack_pack, &info->total_bytes) != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_GET_DISK_USAGE), "get total_bytes error");
        return CM_ERROR;
    }
    if (gr_get_int64(ack_pack, &info->used_bytes) != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_GET_DISK_USAGE), "get used_bytes error");
        return CM_ERROR;
    }
    if (gr_get_int64(ack_pack, &info->available_bytes) != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_GET_DISK_USAGE), "get available_bytes error");
        return CM_ERROR;
    }
    if (gr_get_int64(ack_pack, (int64*)&info->usage_percent) != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_CLI_EXEC_FAIL, gr_get_cmd_desc(GR_CMD_GET_DISK_USAGE), "get usage_percent error");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t gr_encode_truncate_file(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_truncate_file_info_t *info = (gr_truncate_file_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_int64(pack, info->length));
    CM_RETURN_IFERR(gr_put_int32(pack, info->handle));
    CM_RETURN_IFERR(gr_put_int64(pack, info->truncateType));
    return CM_SUCCESS;
}

static status_t gr_encode_stat_file(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_stat_file_info_t *info = (gr_stat_file_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_str(pack, info->name));
    return CM_SUCCESS;
}

static status_t gr_encode_write_file(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_write_file_info_t *info = (gr_write_file_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_int64(pack, info->offset));
    CM_RETURN_IFERR(gr_put_int32(pack, info->handle));
    CM_RETURN_IFERR(gr_put_int64(pack, info->size));
    CM_RETURN_IFERR(gr_put_sha256(pack, info->hash));
    CM_RETURN_IFERR(gr_put_data(pack, info->buf, info->size));
    return CM_SUCCESS;
}

static status_t gr_encode_append_file(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_write_file_info_t *info = (gr_write_file_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_int32(pack, info->handle));
    CM_RETURN_IFERR(gr_put_int64(pack, info->size));
    CM_RETURN_IFERR(gr_put_sha256(pack, info->hash));
    CM_RETURN_IFERR(gr_put_data(pack, info->buf, info->size));
    return CM_SUCCESS;
}

static status_t gr_encode_read_file(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_read_file_info_t *info = (gr_read_file_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_int64(pack, info->offset));
    CM_RETURN_IFERR(gr_put_int32(pack, info->handle));
    CM_RETURN_IFERR(gr_put_int64(pack, info->size));
    return CM_SUCCESS;
}

static status_t gr_encode_rename_file(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_rename_file_info_t *info = (gr_rename_file_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_str(pack, info->src));
    CM_RETURN_IFERR(gr_put_str(pack, info->dst));
    return CM_SUCCESS;
}

static status_t gr_encode_make_dir(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_make_dir_info_t *info = (gr_make_dir_info_t *)send_info;
    // 1. dir_name
    CM_RETURN_IFERR(gr_put_str(pack, info->name));
    return CM_SUCCESS;
}

static status_t gr_encode_remove_dir(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_remove_dir_info_t *info = (gr_remove_dir_info_t *)send_info;
    // 1. dir_name
    CM_RETURN_IFERR(gr_put_str(pack, info->name));
    // 2. attrFlag
    CM_RETURN_IFERR(gr_put_int64(pack, info->attrFlag));
    return CM_SUCCESS;
}

static status_t gr_encode_open_file(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_open_file_info_t *info = (gr_open_file_info_t *)send_info;
    /* 1. file name */
    CM_RETURN_IFERR(gr_put_str(pack, info->file_path));
    /* 2. flag */
    CM_RETURN_IFERR(gr_put_int32(pack, (uint32_t)info->flag));
    return CM_SUCCESS;
}

static status_t gr_encode_close_file(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_close_file_info_t *info = (gr_close_file_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_int64(pack, info->fd));
    CM_RETURN_IFERR(gr_put_int32(pack, info->need_lock));
    return CM_SUCCESS;
}

static status_t gr_encode_create_file(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_create_file_info_t *info = (gr_create_file_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_str(pack, info->file_path));
    CM_RETURN_IFERR(gr_put_int32(pack, info->flag));
    return CM_SUCCESS;
}

static status_t gr_decode_create_file(gr_packet_t *ack_pack, void *ack)
{
    CM_RETURN_IFERR(gr_get_sha256(ack_pack, (uint8_t *)ack));
    return CM_SUCCESS;
}

static status_t gr_encode_delete_file(gr_conn_t *conn, gr_packet_t *pack, void *send_info)
{
    gr_remove_file_info_t *info = (gr_remove_file_info_t *)send_info;
    CM_RETURN_IFERR(gr_put_str(pack, info->name));
    CM_RETURN_IFERR(gr_put_int64(pack, info->attrFlag));
    return CM_SUCCESS;
}

static status_t gr_decode_open_file(gr_packet_t *ack_pack, void *ack)
{
    gr_file_handle *file_handle = (gr_file_handle*)ack;
    CM_RETURN_IFERR(gr_get_int32(ack_pack, &file_handle->fd));
    CM_RETURN_IFERR(gr_get_sha256(ack_pack, file_handle->hash));
    return CM_SUCCESS;
}

typedef status_t (*gr_encode_packet_proc_t)(gr_conn_t *conn, gr_packet_t *pack, void *send_info);
typedef status_t (*gr_decode_packet_proc_t)(gr_packet_t *ack_pack, void *ack);
typedef struct st_gr_packet_proc {
    gr_encode_packet_proc_t encode_proc;
    gr_decode_packet_proc_t decode_proc;
    char *cmd_info;
} gr_packet_proc_t;

gr_packet_proc_t g_gr_packet_proc[GR_CMD_END] = 
{   
    [GR_CMD_MKDIR] = {gr_encode_make_dir, NULL, "make dir"},
    [GR_CMD_RMDIR] = {gr_encode_remove_dir, NULL, "remove dir"}, 
    [GR_CMD_MOUNT_VFS] = {gr_encode_mount_vfs, gr_decode_mount_vfs, "mount vfs"},
    [GR_CMD_UNMOUNT_VFS] = {gr_encode_unmount_vfs, NULL, "unmount vfs"},
    [GR_CMD_QUERY_FILE_NUM] = {gr_encode_query_file_num, gr_decode_query_file_num, "query file num"},
    [GR_CMD_QUERY_FILE_INFO] = {gr_encode_query_file_info, gr_decode_query_file_info, "query file info"},
    [GR_CMD_OPEN_FILE] = {gr_encode_open_file, gr_decode_open_file, "open file"},
    [GR_CMD_CLOSE_FILE] = {gr_encode_close_file, NULL, "close file"},
    [GR_CMD_CREATE_FILE] = {gr_encode_create_file, gr_decode_create_file, "create file"},
    [GR_CMD_DELETE_FILE] = {gr_encode_delete_file, NULL, "delete file"},
    [GR_CMD_WRITE_FILE] = {gr_encode_write_file, gr_decode_write_file, "write file"},
    [GR_CMD_APPEND_FILE] = {gr_encode_append_file, gr_decode_append_file, "append file"},
    [GR_CMD_READ_FILE] = {gr_encode_read_file, gr_decode_read_file, "read file"},
    [GR_CMD_RENAME_FILE] = {gr_encode_rename_file, NULL, "rename file"},
    [GR_CMD_TRUNCATE_FILE] = {gr_encode_truncate_file, NULL, "truncate file"},
    [GR_CMD_STAT_FILE] = {gr_encode_stat_file, gr_decode_stat_file, "stat file"},
    [GR_CMD_STOP_SERVER] = {NULL, NULL, "stop server"},
    [GR_CMD_SETCFG] = {gr_encode_setcfg, NULL, "setcfg"},
    [GR_CMD_SET_MAIN_INST] = {NULL, NULL, "set main inst"},
    [GR_CMD_POSTPONE_FILE_TIME] = {gr_encode_postpone_file_time, NULL, "postpone file expired time"},
    [GR_CMD_HANDSHAKE] = {gr_encode_handshake, gr_decode_handshake, "handshake with server"},
    [GR_CMD_EXIST] = {gr_encode_exist, gr_decode_exist, "exist"},
    [GR_CMD_GETCFG] = {gr_encode_getcfg, gr_decode_getcfg, "getcfg"},
    [GR_CMD_GET_INST_STATUS] = {NULL, gr_decode_get_inst_status, "get inst status"},
    [GR_CMD_GET_TIME_STAT] = {NULL, gr_decode_get_time_stat, "get time stat"},
    [GR_CMD_GET_DISK_USAGE] = {NULL, gr_decode_get_disk_usage, "get disk usage"},
    [GR_CMD_RELOAD_CFG] = {NULL, NULL, "reload cfg"},
};

status_t gr_decode_packet(gr_packet_proc_t *make_proc, gr_packet_t *ack_pack, void *ack)
{
    if (ack == NULL || make_proc->decode_proc == NULL) {
        return CM_SUCCESS;
    }
    gr_init_get(ack_pack);
    status_t ret = make_proc->decode_proc(ack_pack, ack);
    GR_RETURN_IFERR2(ret, LOG_RUN_ERR("Decode %s msg failed", make_proc->cmd_info));
    return ret;
}

status_t gr_msg_interact(gr_conn_t *conn, uint8 cmd, void *send_info, void *ack)
{
    gr_packet_t *send_pack = &conn->pack;
    gr_packet_t *ack_pack = &conn->pack;
    gr_packet_proc_t *make_proc;
    do {
        gr_init_packet(&conn->pack, conn->pipe.options);
        gr_init_set(&conn->pack, conn->proto_version);
        send_pack->head->cmd = cmd;
        send_pack->head->flags = 0;
        make_proc = &g_gr_packet_proc[cmd];
        if (make_proc->encode_proc != NULL) {
            status_t ret = make_proc->encode_proc(conn, send_pack, send_info);
            if (ret != CM_SUCCESS) {
                LOG_RUN_ERR("Encode %s msg failed", make_proc->cmd_info);
                return ret;
            }
        }
        ack_pack = &conn->pack;
        GR_RETURN_IF_ERROR(gr_call_ex(&conn->pipe, send_pack, ack_pack));

        // check return state
        if (ack_pack->head->result != CM_SUCCESS) {
            int32_t errcode = gr_get_pack_err(conn, ack_pack);
            if (errcode == ERR_GR_VERSION_NOT_MATCH) {
                continue;
            }
            return errcode;
        }
        break;
    } while (1);
    conn->server_version = gr_get_version(ack_pack);
    conn->proto_version = MIN(GR_PROTO_VERSION, conn->server_version);
    return gr_decode_packet(make_proc, ack_pack, ack);
}

void gr_clean_file_handle(gr_file_handle *file_handle)
{
    file_handle->fd = -1;
    file_handle->hash[0] = '\0';
    file_handle->file_name[0] = '\0';
}

bool32 gr_get_conn_hash_auth_enable(gr_conn_t *conn)
{
    if (conn == NULL) {
        return CM_FALSE;
    }
    return conn->hash_auth_enable;
}

#ifdef __cplusplus
}
#endif
