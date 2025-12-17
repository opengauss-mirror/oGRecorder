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
 * gr_api.c
 *
 *
 * IDENTIFICATION
 *    src/interface/gr_api.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_api.h"
#include "cm_types.h"
#include "cm_thread.h"
#include "gr_malloc.h"
#include "gr_api_impl.h"
#include "cm_log.h"
#include "cm_timer.h"
#include "gr_cli_conn.h"

#ifdef _WIN64
#if !defined(__x86_64__)
#define __x86_64__
#endif
#elif defined _WIN32
#if !defined(__i386__)
#define __i386__
#endif
#endif

#ifdef WIN32
typedef struct {
    unsigned long sig[];
} sigset_t;
#endif
#ifndef WIN32
#include "config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

// 统一参数验证宏
#define VALIDATE_PARAM_RETURN(condition, func_name, param_name, error_msg) \
    do { \
        if (!(condition)) { \
            LOG_RUN_ERR("%s: %s %s", func_name, param_name, error_msg); \
            GR_THROW_ERROR(ERR_GR_INVALID_PARAM, param_name " " error_msg); \
            return GR_ERROR; \
        } \
    } while(0)

static int validate_instance_handle(gr_instance_handle inst_handle, const char *func_name)
{
    VALIDATE_PARAM_RETURN(inst_handle != NULL, func_name, "instance handle", "is NULL");
    
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    VALIDATE_PARAM_RETURN(hdl->conn != NULL, func_name, "connection", "is NULL");
    
    return GR_SUCCESS;
}

static int validate_vfs_handle(gr_vfs_handle vfs_handle, const char *func_name)
{
    VALIDATE_PARAM_RETURN(vfs_handle.handle != NULL, func_name, "vfs handle", "is NULL");
    return validate_instance_handle(vfs_handle.handle, func_name);
}

static int validate_file_name(const char *name, const char *func_name)
{
    VALIDATE_PARAM_RETURN(name != NULL && name[0] != '\0', func_name, "file name", "is NULL or empty");
    VALIDATE_PARAM_RETURN(strpbrk(name, "\\:*?\"<>|") == NULL, func_name, "file name", "contains invalid characters");
    return GR_SUCCESS;
}

static int validate_string_param(const char *param, const char *param_name, const char *func_name)
{
    if (param == NULL) {
        LOG_RUN_ERR("%s: %s is NULL.", func_name, param_name);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "%s is NULL", param_name);
        return GR_ERROR;
    }
    if (strlen(param) == 0) {
        LOG_RUN_ERR("%s: %s is empty.", func_name, param_name);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "%s is empty", param_name);
        return GR_ERROR;
    }
    return GR_SUCCESS;
}

static int validate_pointer_param(const void *param, const char *param_name, const char *func_name)
{
    if (param == NULL) {
        LOG_RUN_ERR("%s: %s is NULL.", func_name, param_name);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "%s is NULL", param_name);
        return GR_ERROR;
    }
    return GR_SUCCESS;
}

static int validate_size_param(long long size, const char *param_name, const char *func_name)
{
    if (size < 0) {
        LOG_RUN_ERR("%s: %s is invalid: %lld.", func_name, param_name, size);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "%s must be a positive integer", param_name);
        return GR_ERROR;
    }
    if (size > (int64_t)GR_MAX_FILE_SIZE) {
        LOG_RUN_ERR("%s: %s exceeds maximum size: %lld.", func_name, param_name, size);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "%s must less than GR_MAX_FILE_SIZE", param_name);
        return GR_ERROR;
    }
    return GR_SUCCESS;
}

static int validate_timeout_param(int32_t timeout, const char *func_name)
{
    if (timeout < 0 && timeout != GR_CONN_NEVER_TIMEOUT) {
        LOG_RUN_ERR("%s: invalid timeout value: %d.", func_name, timeout);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid timeout when set connection timeout");
        return GR_ERROR;
    }
    return GR_SUCCESS;
}

static int build_full_path(const char *vfs_name, const char *file_name, char *full_path, size_t path_size, const char *func_name)
{
    if (validate_string_param(vfs_name, "vfs_name", func_name) != GR_SUCCESS ||
        validate_string_param(file_name, "file_name", func_name) != GR_SUCCESS) {
        return GR_ERROR;
    }
    
    errno_t err = sprintf_s(full_path, path_size, "%s/%s", vfs_name, file_name);
    if (SECUREC_UNLIKELY(err < 0)) {
        LOG_RUN_ERR("%s: failed to build full path.", func_name);
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }
    return GR_SUCCESS;
}

void gr_set_default_conn_timeout(int timeout)
{
    if (timeout <= 0) {
        g_gr_tcp_conn_timeout = GR_CONN_NEVER_TIMEOUT;
        return;
    }
    g_gr_tcp_conn_timeout = timeout;
}

int gr_create_inst(const char *storageServerAddr, gr_instance_handle *inst_handle)
{
    if (validate_string_param(storageServerAddr, "storageServerAddr", "gr_create_inst") != GR_SUCCESS ||
        validate_pointer_param(inst_handle, "inst_handle", "gr_create_inst") != GR_SUCCESS) {
        return GR_ERROR;
    }

    if (check_server_addr_format(storageServerAddr) != GR_SUCCESS) {
        LOG_RUN_ERR("gr_create_inst: invalid address: %s.", storageServerAddr);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid address format");
        return GR_ERROR;
    }

    st_gr_instance_handle *hdl = (st_gr_instance_handle*)malloc(sizeof(st_gr_instance_handle));
    if (hdl == NULL) {
        LOG_RUN_ERR("failed to allocate memory for instance handle");
        GR_THROW_ERROR(ERR_GR_ALLOC_MEMORY, sizeof(st_gr_instance_handle), "gr_create_inst");
        return GR_ERROR;
    }
    hdl->conn = NULL;

    size_t addr_len = strlen(storageServerAddr);
    errno_t err = memcpy_s(hdl->addr, addr_len + 1, storageServerAddr, addr_len + 1);
    if (err != EOK) {
        LOG_RUN_ERR("Error occured when copying addr, errno code is %d.\n", err);
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        free(hdl);
        return GR_ERROR;
    }

    status_t ret = gr_enter_api(&hdl->conn, storageServerAddr);
    if (ret != GR_SUCCESS) {
        LOG_RUN_ERR("create instance get conn error.");
        free(hdl);
        return (int)ret;
    }
    *inst_handle = (gr_instance_handle)hdl;
    return (int)ret;
}

static int parse_server_addresses(const char *serverAddrs, char **addresses, int max_count, int *actual_count)
{
    if (serverAddrs == NULL || addresses == NULL || actual_count == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid parameters for parse_server_addresses");
        return GR_ERROR;
    }

    *actual_count = 0;
    char *input_copy = strdup(serverAddrs);
    if (input_copy == NULL) {
        LOG_RUN_ERR("failed to allocate memory for parsing server addresses");
        GR_THROW_ERROR(ERR_GR_ALLOC_MEMORY, 0, "parse_server_addresses");
        return GR_ERROR;
    }

    const char *delimiters = ",; ";
    char *token = strtok(input_copy, delimiters);
    
    while (token != NULL && *actual_count < max_count) {
        while (*token == ' ' || *token == '\t') {
            token++;
        }
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }
        
        if (strlen(token) > 0) {
            addresses[*actual_count] = strdup(token);
            if (addresses[*actual_count] == NULL) {
                LOG_RUN_ERR("failed to allocate memory for address: %s", token);
                for (int i = 0; i < *actual_count; i++) {
                    free(addresses[i]);
                }
                free(input_copy);
                GR_THROW_ERROR(ERR_GR_ALLOC_MEMORY, 0, "parse_server_addresses");
                return GR_ERROR;
            }
            (*actual_count)++;
        }
        token = strtok(NULL, delimiters);
    }
    
    free(input_copy);
    return GR_SUCCESS;
}

int gr_create_inst_only_primary(const char *serverAddrs, gr_instance_handle *inst_handle)
{
    if (serverAddrs == NULL || inst_handle == NULL) {
        LOG_RUN_ERR("gr_create_inst_only_primary get invalid parameter.");
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid parameters for gr_create_inst_only_primary");
        return GR_ERROR;
    }

    #define MAX_SERVER_COUNT 8
    char *addresses[MAX_SERVER_COUNT];
    int addrCount = 0;

    int ret = parse_server_addresses(serverAddrs, addresses, MAX_SERVER_COUNT, &addrCount);
    if (ret != GR_SUCCESS || addrCount == 0) {
        LOG_RUN_ERR("failed to parse server addresses or no valid addresses found");
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "failed to parse server addresses or no valid addresses found");
        return GR_ERROR;
    }

    int primary_found = 0;
    int primary_master_id = -1;
    gr_instance_handle primary_handle = NULL;

    LOG_RUN_INF("Starting primary server search among %d addresses", addrCount);
    for (int i = 0; i < addrCount; i++) {
        if (addresses[i] == NULL) {
            LOG_RUN_ERR("server address at index %d is NULL", i);
            continue;
        }

        if (check_server_addr_format(addresses[i]) != GR_SUCCESS) {
            LOG_RUN_ERR("invalid address at index %d: %s.", i, addresses[i]);
            continue;
        }

        gr_instance_handle tmp = NULL;
        int cret = gr_create_inst(addresses[i], &tmp);
        if (cret != GR_SUCCESS || tmp == NULL) {
            LOG_RUN_ERR("failed to create instance for server %s", addresses[i]);
            continue;
        }

        int instance_status_id = 0, server_status_id = 0, local_instance_id = -1, master_id = -1;
        int sret = gr_get_inst_status(tmp, &instance_status_id, &server_status_id, &local_instance_id, &master_id);
        if (sret == GR_SUCCESS) {
            LOG_RUN_INF("Server %s: instance_status=%d, server_status=%d, local_id=%d, master_id=%d",
                addresses[i], instance_status_id, server_status_id, local_instance_id, master_id);

            if (master_id == local_instance_id) {
                if (primary_handle != NULL) {
                    LOG_RUN_INF("Found new primary, releasing previous connection");
                    (void)gr_delete_inst(primary_handle);
                    primary_handle = NULL;
                }
                primary_handle = tmp;
                primary_master_id = master_id;
                primary_found = 1;
                
                LOG_RUN_INF("Primary server found at %s, stopping search", addresses[i]);
                break;
            }
        } else {
            LOG_RUN_ERR("failed to get status for server %s", addresses[i]);
        }
        
        (void)gr_delete_inst(tmp);
    }

    // 清理地址数组
    for (int i = 0; i < addrCount; i++) {
        free(addresses[i]);
    }

    if (!primary_found || primary_handle == NULL) {
        LOG_RUN_ERR("no primary server found");
        GR_THROW_ERROR(ERR_GR_SERVER_IS_DOWN, "no primary server found");
        return GR_ERROR;
    }

    *inst_handle = primary_handle;
    LOG_RUN_INF("Successfully connected to primary server with master_id=%d", primary_master_id);
    return GR_SUCCESS;
}

int gr_delete_inst(gr_instance_handle inst_handle)
{
    if (inst_handle == NULL) {
        LOG_RUN_WAR("inst handle is null.");
        return GR_SUCCESS;   
    }

    st_gr_instance_handle *hdl = (st_gr_instance_handle *)inst_handle;
    if (hdl->conn != NULL) {
        gr_disconnect(hdl->conn);
        cli_ssl_uninit(&hdl->conn->cli_ssl_inst);
        free(hdl->conn);
        hdl->conn = NULL;
    }
    free(hdl);
    hdl = NULL;
    return GR_SUCCESS;
}

int gr_vfs_create(gr_instance_handle inst_handle, const char *vfs_name, unsigned long long attrFlag)
{
    if (validate_instance_handle(inst_handle, "gr_vfs_create") != GR_SUCCESS ||
        validate_string_param(vfs_name, "vfs_name", "gr_vfs_create") != GR_SUCCESS) {
        return GR_ERROR;
    }
    
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    status_t ret = gr_vfs_create_impl(hdl->conn, vfs_name, attrFlag);
    return (int)ret;
}

int gr_vfs_delete(gr_instance_handle inst_handle, const char *vfs_name, unsigned long long attrFlag)
{
    if (validate_instance_handle(inst_handle, "gr_vfs_delete") != GR_SUCCESS ||
        validate_string_param(vfs_name, "vfs_name", "gr_vfs_delete") != GR_SUCCESS) {
        return GR_ERROR;
    }
    
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    status_t ret = gr_vfs_delete_impl(hdl->conn, vfs_name, attrFlag);
    return (int)ret;
}

int gr_vfs_mount(gr_instance_handle inst_handle, const char *vfs_name, gr_vfs_handle *vfs_handle)
{
    if (validate_instance_handle(inst_handle, "gr_vfs_mount") != GR_SUCCESS ||
        validate_pointer_param(vfs_handle, "vfs_handle", "gr_vfs_mount") != GR_SUCCESS ||
        validate_string_param(vfs_name, "vfs_name", "gr_vfs_mount") != GR_SUCCESS) {
        return GR_ERROR;
    }
    
    errno_t err = memset_s(vfs_handle, sizeof(gr_vfs_handle), 0, sizeof(gr_vfs_handle));
    if (SECUREC_UNLIKELY(err != EOK)) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }

    st_gr_instance_handle *hdl = (st_gr_instance_handle *)inst_handle;
    if (gr_check_path_exist(hdl->conn, vfs_name) != GR_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_DIR_NOT_EXIST, "VFS path does not exist: %s", vfs_name);
        return GR_ERROR;
    }

    vfs_handle->handle = inst_handle;
    err = memcpy_s(vfs_handle->vfs_name, GR_MAX_NAME_LEN, vfs_name, strlen(vfs_name));
    if (SECUREC_UNLIKELY(err != EOK)) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }
    status_t ret = gr_vfs_mount_impl(hdl->conn, vfs_handle, 0);
    return (int)ret;
}

int gr_vfs_unmount(gr_vfs_handle *vfs_handle)
{
    if (vfs_handle == NULL) {
        LOG_RUN_ERR("vfs_handle is NULL.");
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "vfs_handle is NULL");
        return GR_ERROR;
    }
    if (vfs_handle->handle == NULL) {
        LOG_RUN_ERR("vfs_handle->handle is NULL.");
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "vfs_handle->handle is NULL");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)vfs_handle->handle;
    if (hdl == NULL || hdl->conn == NULL) {
        LOG_RUN_ERR("dremove get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }
    status_t ret = gr_vfs_unmount_impl(hdl->conn, vfs_handle);
    vfs_handle->handle = NULL;
    vfs_handle->vfs_name[0] = '\0';
    vfs_handle->dir_handle = 0;

    return ret; 
}

int gr_vfs_query_file_num(gr_vfs_handle vfs_handle, int *file_num)
{
    if (validate_pointer_param(file_num, "file_num", "gr_vfs_query_file_num") != GR_SUCCESS ||
        validate_vfs_handle(vfs_handle, "gr_vfs_query_file_num") != GR_SUCCESS) {
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("lstat get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }

    status_t ret = gr_vfs_query_file_num_impl(hdl->conn, vfs_handle, (uint32_t *)file_num);
    if (ret != GR_SUCCESS) {
        *file_num = 0;
        LOG_DEBUG_INF("vfs query file num error");
        return GR_ERROR;
    }
    return GR_SUCCESS;
}

int gr_vfs_query_file_info(gr_vfs_handle vfs_handle, gr_file_item_t *result, bool is_continue)
{
    if (validate_pointer_param(result, "result", "gr_vfs_query_file_info") != GR_SUCCESS ||
        validate_vfs_handle(vfs_handle, "gr_vfs_query_file_info") != GR_SUCCESS) {
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("lstat get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }

    status_t ret = gr_vfs_query_file_info_impl(hdl->conn, vfs_handle, result, is_continue);
    if (ret != GR_SUCCESS) {
        LOG_DEBUG_INF("vfs query file info :%s error", vfs_handle.vfs_name);
        return GR_ERROR;
    }
    return GR_SUCCESS;
}

int gr_file_create(gr_vfs_handle vfs_handle, const char *name, const FileParameter *param)
{
    if (validate_vfs_handle(vfs_handle, "gr_file_create") != GR_SUCCESS ||
        validate_file_name(name, "gr_file_create") != GR_SUCCESS) {
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fcreate get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }
    char full_name[GR_MAX_NAME_LEN];
    errno_t err = sprintf_s(full_name, GR_MAX_NAME_LEN, "%s/%s", vfs_handle.vfs_name, name);
    if (SECUREC_UNLIKELY(err < 0)) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }

    int flag = 0;
    status_t ret = gr_create_file_impl(hdl->conn, full_name, flag);
    return (int)ret;
}

int gr_file_delete(gr_vfs_handle vfs_handle, const char *name, unsigned long long attrFlag)
{
    if (validate_vfs_handle(vfs_handle, "gr_file_delete") != GR_SUCCESS ||
        validate_file_name(name, "gr_file_delete") != GR_SUCCESS) {
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fremove get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }

    char full_name[GR_MAX_NAME_LEN];
    errno_t err = sprintf_s(full_name, GR_MAX_NAME_LEN, "%s/%s", vfs_handle.vfs_name, name);
    if (SECUREC_UNLIKELY(err < 0)) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }
    status_t ret = gr_remove_file_impl(hdl->conn, full_name, attrFlag);
    return (int)ret;
}

int gr_file_exist(gr_vfs_handle vfs_handle, const char *name, bool *is_exist)
{
    if (validate_vfs_handle(vfs_handle, "gr_file_exist") != GR_SUCCESS ||
        validate_file_name(name, "gr_file_exist") != GR_SUCCESS ||
        validate_pointer_param(is_exist, "is_exist", "gr_file_exist") != GR_SUCCESS) {
        return GR_ERROR;
    }

    char full_name[GR_MAX_NAME_LEN];
    if (build_full_path(vfs_handle.vfs_name, name, full_name, sizeof(full_name), "gr_file_exist") != GR_SUCCESS) {
        return GR_ERROR;
    }
    
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    status_t ret = gr_check_file_exist(hdl->conn, full_name, is_exist);
    return (int)ret;
}

int gr_file_open(gr_vfs_handle vfs_handle, const char *name, int flag, gr_file_handle *file_handle)
{
    if (validate_vfs_handle(vfs_handle, "gr_file_open") != GR_SUCCESS ||
        validate_string_param(name, "name", "gr_file_open") != GR_SUCCESS ||
        validate_pointer_param(file_handle, "file_handle", "gr_file_open") != GR_SUCCESS) {
        return GR_ERROR;
    }

    timeval_t begin_tv;
    file_handle->fd = -1;
    gr_begin_stat(&begin_tv);
    
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fopen get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }

    size_t name_len = strlen(name);
    errno_t err = memcpy_s(hdl->addr, name_len + 1, name, name_len + 1);
    if (SECUREC_UNLIKELY(err < 0)) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }

    char full_name[GR_MAX_NAME_LEN];
    err = sprintf_s(full_name, GR_MAX_NAME_LEN, "%s/%s", vfs_handle.vfs_name, name);
    if (SECUREC_UNLIKELY(err < 0)) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }
    status_t ret = gr_open_file_impl(hdl->conn, full_name, flag, file_handle);
    // if open fails, -1 is returned. DB determines based on -1
    if (ret == GR_SUCCESS) {
        file_handle->fd += GR_HANDLE_BASE;
    }
    gr_session_end_stat(hdl->conn->session, &begin_tv, GR_FOPEN);
    return (int)ret;
}

int gr_file_postpone(gr_vfs_handle vfs_handle, const char *file, const char *time)
{
    if (validate_vfs_handle(vfs_handle, "gr_file_postpone") != GR_SUCCESS ||
        validate_string_param(file, "file", "gr_file_postpone") != GR_SUCCESS ||
        validate_string_param(time, "time", "gr_file_postpone") != GR_SUCCESS) {
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fcreate get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }
    char full_name[GR_MAX_NAME_LEN];
    errno_t err = sprintf_s(full_name, GR_MAX_NAME_LEN, "%s/%s", vfs_handle.vfs_name, file);
    if (SECUREC_UNLIKELY(err < 0)) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }

    status_t ret = gr_postpone_file_time_impl(hdl->conn, full_name, time);
    return (int)ret;
}

int gr_get_inst_status(gr_instance_handle inst_handle, 
                       int *instance_status_id, int *server_status_id,
                       int *local_instance_id, int *master_id)
{
    if (validate_instance_handle(inst_handle, "gr_get_inst_status") != GR_SUCCESS ||
        validate_pointer_param(instance_status_id, "instance_status_id", "gr_get_inst_status") != GR_SUCCESS ||
        validate_pointer_param(server_status_id, "server_status_id", "gr_get_inst_status") != GR_SUCCESS ||
        validate_pointer_param(local_instance_id, "local_instance_id", "gr_get_inst_status") != GR_SUCCESS ||
        validate_pointer_param(master_id, "master_id", "gr_get_inst_status") != GR_SUCCESS) {
        return GR_ERROR;
    }
    
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("get conn error when get inst status.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }
    
    gr_server_status_t temp_status = {0};
    status_t ret = gr_get_inst_status_on_server(hdl->conn, &temp_status);
    if (ret != CM_SUCCESS) {
        return (int)ret;
    }
    
    *instance_status_id = (int)temp_status.instance_status_id;
    *server_status_id = (int)temp_status.server_status_id;
    *local_instance_id = temp_status.local_instance_id;
    *master_id = temp_status.master_id;
    
    return GR_SUCCESS;
}

int gr_get_disk_usage(gr_instance_handle inst_handle,
                      long long *total_bytes, long long *used_bytes, long long *available_bytes)
{
    if (validate_instance_handle(inst_handle, "gr_get_disk_usage") != GR_SUCCESS ||
        validate_pointer_param(total_bytes, "total_bytes", "gr_get_disk_usage") != GR_SUCCESS ||
        validate_pointer_param(used_bytes, "used_bytes", "gr_get_disk_usage") != GR_SUCCESS ||
        validate_pointer_param(available_bytes, "available_bytes", "gr_get_disk_usage") != GR_SUCCESS) {
        return GR_ERROR;
    }
    
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("get conn error when get disk usage.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }
    
    gr_disk_usage_info_t temp_info = {0};
    status_t ret = gr_get_disk_usage_impl(hdl->conn, &temp_info);
    if (ret != CM_SUCCESS) {
        return (int)ret;
    }
    
    *total_bytes = temp_info.total_bytes;
    *used_bytes = temp_info.used_bytes;
    *available_bytes = temp_info.available_bytes;
    
    return GR_SUCCESS;
}

int gr_set_main_inst(const char *storageServerAddr)
{
    if (validate_string_param(storageServerAddr, "storageServerAddr", "gr_set_main_inst") != GR_SUCCESS) {
        return GR_ERROR;
    }

    if (check_server_addr_format(storageServerAddr) != GR_SUCCESS) {
        LOG_RUN_ERR("invalid address: %s.", storageServerAddr);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid address format");
        return GR_ERROR;
    }
    st_gr_instance_handle hdl;
    status_t ret = gr_enter_api(&hdl.conn, storageServerAddr);
    if (ret != GR_SUCCESS) {
        LOG_RUN_ERR("gr_set_main_inst get conn error.");
        return (int)ret;
    }

    ret = gr_set_main_inst_impl(hdl.conn);
    return (int)ret;
}

int gr_file_close(gr_vfs_handle vfs_handle, gr_file_handle *file_handle, bool need_lock)
{
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "vfs_handle.handle is NULL");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fclose get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }

    status_t ret = gr_close_file_impl(hdl->conn, HANDLE_VALUE(file_handle->fd), need_lock);
    (void)gr_clean_file_handle(file_handle);
    return (int)ret;
}

long long int gr_file_pwrite(
    gr_vfs_handle vfs_handle, gr_file_handle *file_handle, const void *buf, unsigned long long count, long long offset)
{
    if (validate_vfs_handle(vfs_handle, "gr_file_pwrite") != GR_SUCCESS ||
        validate_pointer_param(file_handle, "file_handle", "gr_file_pwrite") != GR_SUCCESS ||
        validate_pointer_param(buf, "buf", "gr_file_pwrite") != GR_SUCCESS ||
        validate_size_param(count, "count", "gr_file_pwrite") != GR_SUCCESS ||
        validate_size_param(offset, "offset", "gr_file_pwrite") != GR_SUCCESS) {
        return GR_ERROR;
    }

    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    long long int ret = gr_pwrite_file_impl(hdl->conn, file_handle, buf, count, offset);
    return ret;
}

long long int gr_file_append(
    gr_vfs_handle vfs_handle, gr_file_handle *file_handle, const void *buf, unsigned long long count)
{
    if (validate_vfs_handle(vfs_handle, "gr_file_append") != GR_SUCCESS ||
        validate_pointer_param(file_handle, "file_handle", "gr_file_append") != GR_SUCCESS ||
        validate_pointer_param(buf, "buf", "gr_file_append") != GR_SUCCESS ||
        validate_size_param(count, "count", "gr_file_append") != GR_SUCCESS) {
        return GR_ERROR;
    }

    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("append get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }

    long long int ret = gr_append_file_impl(hdl->conn, file_handle, buf, count);
    return ret;
}

long long int gr_file_pread(
    gr_vfs_handle vfs_handle, gr_file_handle file_handle, void *buf, unsigned long long count, long long offset)
{
    timeval_t begin_tv;
    gr_begin_stat(&begin_tv);

    if (validate_vfs_handle(vfs_handle, "gr_file_pread") != GR_SUCCESS ||
        validate_pointer_param(buf, "buf", "gr_file_pread") != GR_SUCCESS ||
        validate_size_param(count, "count", "gr_file_pread") != GR_SUCCESS ||
        validate_size_param(offset, "offset", "gr_file_pread") != GR_SUCCESS) {
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("pread get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }

    long long int ret = gr_pread_file_impl(hdl->conn, HANDLE_VALUE(file_handle.fd), buf, count, offset);
    if (ret == count) {
        gr_session_end_stat((gr_session_t *)hdl->conn->session, &begin_tv, GR_PREAD);
    }
    return ret;
}

int gr_file_truncate(gr_vfs_handle vfs_handle, gr_file_handle file_handle, int truncateType, long long offset)
{
    if (validate_vfs_handle(vfs_handle, "gr_file_truncate") != GR_SUCCESS ||
        validate_size_param(offset, "offset", "gr_file_truncate") != GR_SUCCESS) {
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("ftruncate get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }
    status_t ret = gr_truncate_impl(hdl->conn, HANDLE_VALUE(file_handle.fd), offset, truncateType);
    return (int)ret;
}

int gr_file_stat(
    gr_vfs_handle vfs_handle, const char *fileName, long long *offset, unsigned long long *count, int *mode, char **time)
{
    if (validate_vfs_handle(vfs_handle, "gr_file_stat") != GR_SUCCESS ||
        validate_string_param(fileName, "fileName", "gr_file_stat") != GR_SUCCESS ||
        validate_pointer_param(offset, "offset", "gr_file_stat") != GR_SUCCESS ||
        validate_pointer_param(count, "count", "gr_file_stat") != GR_SUCCESS ||
        validate_pointer_param(mode, "mode", "gr_file_stat") != GR_SUCCESS ||
        validate_pointer_param(time, "time", "gr_file_stat") != GR_SUCCESS) {
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fcreate get conn error.");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED, "connection is NULL or closed");
        return GR_ERROR;
    }
    char full_name[GR_MAX_NAME_LEN];
    errno_t err = sprintf_s(full_name, GR_MAX_NAME_LEN, "%s/%s", vfs_handle.vfs_name, fileName);
    if (SECUREC_UNLIKELY(err < 0)) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }

    status_t ret = gr_stat_file_impl(hdl->conn, full_name, offset, count, mode, time);
    return (int)ret;
}

int gr_get_error(int *errcode, const char **errmsg)
{
    cm_get_error(errcode, errmsg);
    return CM_SUCCESS;
}

void gr_register_log_callback(gr_log_output cb_log_output, unsigned int log_level)
{
    cm_log_param_instance()->log_write = (usr_cb_log_output_t)cb_log_output;
    cm_log_param_instance()->log_level = log_level;
}

void gr_set_log_level(unsigned int log_level)
{
    cm_log_param_instance()->log_level = log_level;
}

static int32_t init_single_logger_core(log_param_t *log_param, log_type_t log_id, char *file_name, uint32_t file_name_len)
{
    int32_t ret;
    switch (log_id) {
        case CM_LOG_RUN:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/GR/run/%s", log_param->log_home, "gr.rlog");
            break;
        case CM_LOG_DEBUG:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/GR/debug/%s", log_param->log_home, "gr.dlog");
            break;
        case CM_LOG_ALARM:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/GR/alarm/%s", log_param->log_home, "gr.alog");
            break;
        case CM_LOG_AUDIT:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/GR/audit/%s", log_param->log_home, "gr.aud");
            break;
        case CM_LOG_BLACKBOX:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/GR/blackbox/%s", log_param->log_home, "gr.blog");
            break;
        default:
            ret = 0;
            break;
    }

    return (ret != -1) ? GR_SUCCESS : ERR_GR_INIT_LOGGER_FAILED;
}

static int32_t init_single_logger(log_param_t *log_param, log_type_t log_id)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE] = {'\0'};
    CM_RETURN_IFERR(init_single_logger_core(log_param, log_id, file_name, CM_FILE_NAME_BUFFER_SIZE));
    (void)cm_log_init(log_id, (const char *)file_name);
    cm_log_open_compress(log_id, GR_TRUE);
    return GR_SUCCESS;
}

void gr_refresh_logger(char *log_field, unsigned long long *value)
{
    if (log_field == NULL) {
        return;
    }

    if (strcmp(log_field, "LOG_LEVEL") == 0) {
        uint32_t new_level = (uint32_t)(*value);
        cm_log_param_instance()->log_level = new_level;
        uint32_t audit_val = 0;
        if ((new_level & LOG_AUDIT_MODIFY_LEVEL) != 0) {
            audit_val |= GR_AUDIT_MODIFY;
        }
        if ((new_level & LOG_AUDIT_QUERY_LEVEL) != 0) {
            audit_val |= GR_AUDIT_QUERY;
        }
        cm_log_param_instance()->audit_level = audit_val;
    } else if (strcmp(log_field, "LOG_MAX_FILE_SIZE") == 0) {
        cm_log_param_instance()->max_log_file_size = (uint64)(*value);
        cm_log_param_instance()->max_audit_file_size = (uint64)(*value);
    } else if (strcmp(log_field, "LOG_FILE_COUNT") == 0) {
        cm_log_param_instance()->log_backup_file_count = (uint32_t)(*value);
        cm_log_param_instance()->audit_backup_file_count = (uint32_t)(*value);
    }
}

int gr_set_conn_timeout(int32_t timeout)
{
    if (validate_timeout_param(timeout, "gr_set_conn_timeout") != GR_SUCCESS) {
        return GR_ERROR;
    }
    g_gr_tcp_conn_timeout = timeout;
    return GR_SUCCESS;
}

int gr_set_thread_conn_timeout(gr_conn_opt_t *thv_opts, int32_t timeout)
{
    if (validate_pointer_param(thv_opts, "thv_opts", "gr_set_thread_conn_timeout") != GR_SUCCESS ||
        validate_timeout_param(timeout, "gr_set_thread_conn_timeout") != GR_SUCCESS) {
        return GR_ERROR;
    }
    thv_opts->timeout = timeout;
    return GR_SUCCESS;
}

int gr_set_conn_opts(gr_conn_opt_key_e key, void *value, const char *addr)
{
    gr_clt_env_init();
    gr_conn_opt_t *thv_opts = NULL;
    if (cm_get_thv(GLOBAL_THV_OBJ1, CM_TRUE, (pointer_t *)&thv_opts, addr) != CM_SUCCESS) {
        return CM_ERROR;
    }
    switch (key) {
        case GR_CONN_OPT_TIME_OUT:
            return gr_set_thread_conn_timeout(thv_opts, *(int32_t *)value);
        default:
            GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid key when set connection options");
            return GR_ERROR;
    }
}

int gr_set_conf(gr_instance_handle inst_handle, const char *name, const char *value)
{
    if (validate_instance_handle(inst_handle, "gr_set_conf") != GR_SUCCESS ||
        validate_string_param(name, "name", "gr_set_conf") != GR_SUCCESS ||
        validate_string_param(value, "value", "gr_set_conf") != GR_SUCCESS) {
        return GR_ERROR;
    }

    if (cm_strcmpi(name, "LOG_LEVEL") != 0 && cm_strcmpi(name, "LOG_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "LOG_FILE_COUNT") != 0 && cm_strcmpi(name, "AUDIT_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "AUDIT_BACKUP_FILE_COUNT") != 0 && cm_strcmpi(name, "DATA_FILE_PATH") != 0) {
        LOG_RUN_ERR("gr_set_conf: invalid configuration name: %s", name);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid name when set cfg");
        return GR_ERROR;
    }

    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    /* both = memory + file */
    status_t ret = gr_setcfg_impl(hdl->conn, name, value, "both");
    return (int)ret;
}

int gr_get_conf(gr_instance_handle inst_handle, const char *name, char *value)
{
    if (validate_instance_handle(inst_handle, "gr_get_conf") != GR_SUCCESS ||
        validate_string_param(name, "name", "gr_get_conf") != GR_SUCCESS ||
        validate_pointer_param(value, "value", "gr_get_conf") != GR_SUCCESS) {
        return GR_ERROR;
    }

    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    status_t ret = gr_getcfg_impl(hdl->conn, name, value, GR_PARAM_BUFFER_SIZE);
    return (int)ret;
}

int gr_get_lib_version(void)
{
    return GR_LOCAL_MAJOR_VERSION * GR_LOCAL_MAJOR_VER_WEIGHT + GR_LOCAL_MINOR_VERSION * GR_LOCAL_MINOR_VER_WEIGHT +
           GR_LOCAL_VERSION;
}

void gr_show_version(char *version)
{
    if (snprintf_s(version, GR_VERSION_MAX_LEN, GR_VERSION_MAX_LEN - 1, "libgr.so %s", (char *)DEF_GR_VERSION) ==
        -1) {
        cm_panic(0);
    }
}

int gr_init(const gr_param_t param)
{
    log_param_t *log_param = cm_log_param_instance();
    errno_t ret = memset_s(log_param, sizeof(log_param_t), 0, sizeof(log_param_t));
    if (ret != EOK) {
        return ERR_GR_INIT_LOGGER_FAILED;
    }

    log_param->log_level = param.log_level;
    log_param->log_backup_file_count = param.log_backup_file_count;
    log_param->audit_backup_file_count = param.log_backup_file_count;
    log_param->max_log_file_size = param.log_max_file_size;
    log_param->max_audit_file_size = param.log_max_file_size;
    uint32_t audit_val = 0;
    if ((log_param->log_level & LOG_AUDIT_MODIFY_LEVEL) != 0) {
        audit_val |= GR_AUDIT_MODIFY;
    }
    if ((log_param->log_level & LOG_AUDIT_QUERY_LEVEL) != 0) {
        audit_val |= GR_AUDIT_QUERY;
    }
    log_param->audit_level = audit_val;
    log_param->log_compressed = GR_TRUE;
    if (log_param->log_compress_buf == NULL) {
        log_param->log_compress_buf = malloc(CM_LOG_COMPRESS_BUFSIZE);
        if (log_param->log_compress_buf == NULL) {
            return ERR_GR_INIT_LOGGER_FAILED;
        }
    }
    cm_log_set_file_permissions(600);
    cm_log_set_path_permissions(700);
    (void)cm_set_log_module_name("GR", sizeof("GR"));
    ret = strcpy_sp(log_param->instance_name, CM_MAX_NAME_LEN, "GR");
    if (ret != EOK) {
        return ERR_GR_INIT_LOGGER_FAILED;
    }

    ret = strcpy_sp(log_param->log_home, CM_MAX_LOG_HOME_LEN, param.log_home);
    if (ret != EOK) {
        return ERR_GR_INIT_LOGGER_FAILED;
    }

    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_RUN));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_DEBUG));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_ALARM));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_AUDIT));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_BLACKBOX));
    if (cm_start_timer(g_timer()) != CM_SUCCESS) {
        return ERR_GR_INIT_LOGGER_FAILED;
    }
    log_param->log_instance_startup = (bool32)CM_TRUE;

    return GR_SUCCESS;
}

int gr_exit(void)
{
    CM_FREE_PTR(cm_log_param_instance()->log_compress_buf);
    return GR_SUCCESS;
}


#ifdef __cplusplus
}
#endif
