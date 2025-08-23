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
    if (storageServerAddr == NULL || inst_handle == NULL) {
        LOG_RUN_ERR("create instance get invalid parameter.");
        return GR_ERROR;
    }

    if (check_server_addr_format(storageServerAddr) != GR_SUCCESS) {
        LOG_RUN_ERR("invalid address: %s.", storageServerAddr);
        return GR_ERROR;
    }

    st_gr_instance_handle *hdl = (st_gr_instance_handle*)malloc(sizeof(st_gr_instance_handle));
    if (hdl == NULL) {
        LOG_RUN_ERR("failed to allocate memory for instance handle");
        return GR_ERROR;
    }
    hdl->conn = NULL;
    errno_t err = memcpy_s(hdl->addr, strlen(storageServerAddr) + 1, 
                            storageServerAddr, strlen(storageServerAddr) + 1);
    if (err != EOK) {
        LOG_RUN_ERR("Error occured when copying addr, errno code is %d.\n", err);
        free(hdl);
        return (int)err;
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
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("vfs create get conn error.");
        return GR_ERROR;
    }
    status_t ret = gr_vfs_create_impl(hdl->conn, vfs_name, attrFlag);
    return (int)ret;
}

int gr_vfs_delete(gr_instance_handle inst_handle, const char *vfs_name, unsigned long long attrFlag)
{
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("dremove get conn error.");
        return GR_ERROR;
    }
    status_t ret = gr_vfs_delete_impl(hdl->conn, vfs_name, attrFlag);
    return (int)ret;
}

int gr_vfs_mount(gr_instance_handle inst_handle, const char *vfs_name, gr_vfs_handle *vfs_handle)
{
    if (inst_handle == NULL || vfs_handle == NULL) {
        LOG_RUN_ERR("instance handle or vfs_handle is NULL.");
        return GR_ERROR;
    }
    if (vfs_name == NULL || vfs_name[0] == '\0') {
        LOG_RUN_ERR("invalid argument vfs_name.");
        return GR_ERROR;
    }
    errno_t err = memset_s(vfs_handle, sizeof(gr_vfs_handle), 0, sizeof(gr_vfs_handle));
    if (SECUREC_UNLIKELY(err != EOK)) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }

    st_gr_instance_handle *hdl = (st_gr_instance_handle *)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("mount get conn error.");
        return GR_ERROR;
    }
    if (gr_check_path_exist(hdl->conn, vfs_name) != GR_SUCCESS) {
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
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)vfs_handle->handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("dremove get conn error.");
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
    if (file_num == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "file_num");
        return GR_ERROR;
    }
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("lstat get conn error.");
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
    if (result == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "result");
        return GR_ERROR;
    }
   if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("lstat get conn error.");
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
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fcreate get conn error.");
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

int gr_file_delete(gr_vfs_handle vfs_handle, const char *name)
{
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fremove get conn error.");
        return GR_ERROR;
    }

    char full_name[GR_MAX_NAME_LEN];
    errno_t err = sprintf_s(full_name, GR_MAX_NAME_LEN, "%s/%s", vfs_handle.vfs_name, name);
    if (SECUREC_UNLIKELY(err < 0)) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }
    status_t ret = gr_remove_file_impl(hdl->conn, full_name);
    // (void)gr_clean_file_handle(file_handle);
    return (int)ret;
}

int gr_file_exist(gr_vfs_handle vfs_handle, const char *name, bool *is_exist)
{
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("gr_file_exist get conn error.");
        return GR_ERROR;
    }

    char full_name[GR_MAX_NAME_LEN];
    errno_t err = sprintf_s(full_name, GR_MAX_NAME_LEN, "%s/%s", vfs_handle.vfs_name, name);
    if (SECUREC_UNLIKELY(err < 0)) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return GR_ERROR;
    }
    status_t ret = gr_check_file_exist(hdl->conn, full_name, is_exist);
    return (int)ret;
}

int gr_file_open(gr_vfs_handle vfs_handle, const char *name, int flag, gr_file_handle *file_handle)
{
    timeval_t begin_tv;
    file_handle->fd = -1;

    gr_begin_stat(&begin_tv);
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fopen get conn error.");
        return GR_ERROR;
    }

    errno_t err = memcpy_s(hdl->addr, strlen(name) + 1, name, strlen(name) + 1);
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
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    if (file == NULL || strlen(file) == 0) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "fileName is NULL or empty");
        return GR_ERROR;
    }
    if (strpbrk(file, "\\:*?\"<>|") != NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "fileName contains invalid characters.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fcreate get conn error.");
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

int gr_get_inst_status(gr_server_status_t *gr_status, gr_instance_handle inst_handle)
{
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("get conn error when get inst status.");
        return GR_ERROR;
    }
    status_t ret = gr_get_inst_status_on_server(hdl->conn, gr_status);
    return (int)ret;
}

int gr_is_maintain(unsigned int *is_maintain, gr_instance_handle inst_handle)
{
    if (is_maintain == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "expected is_maintain not a null pointer");
        return CM_ERROR;
    }
    gr_server_status_t gr_status = {0};
    status_t ret = gr_get_inst_status(&gr_status, inst_handle);
    GR_RETURN_IFERR2(ret, LOG_RUN_ERR("get error when get inst status"));
    *is_maintain = gr_status.is_maintain;
    return CM_SUCCESS;
}

int gr_set_main_inst(const char *storageServerAddr)
{
    if (storageServerAddr == NULL) {
        LOG_RUN_ERR("gr_set_main_inst get invalid parameter.");
        return GR_ERROR;
    }

    if (check_server_addr_format(storageServerAddr) != GR_SUCCESS) {
        LOG_RUN_ERR("invalid address: %s.", storageServerAddr);
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
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fclose get conn error.");
        return GR_ERROR;
    }

    status_t ret = gr_close_file_impl(hdl->conn, HANDLE_VALUE(file_handle->fd), need_lock);
    (void)gr_clean_file_handle(file_handle);
    return (int)ret;
}

long long int gr_file_pwrite(
    gr_vfs_handle vfs_handle, gr_file_handle *file_handle, const void *buf, unsigned long long count, long long offset)
{
    timeval_t begin_tv;
    gr_begin_stat(&begin_tv);
    if (count < 0) {
        LOG_RUN_ERR("File size is invalid:%lld.", count);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "size must be a positive integer");
        return CM_ERROR;
    }
    if (offset > (int64_t)GR_MAX_FILE_SIZE) {
        LOG_RUN_ERR("Invalid parameter offset:%lld.", offset);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "offset must less than GR_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("pwrite get conn error.");
        return GR_ERROR;
    }

    long long int ret = gr_pwrite_file_impl(hdl->conn, file_handle, buf, count, offset);
    if (ret == count) {
        gr_session_end_stat(hdl->conn->session, &begin_tv, GR_PWRITE);
    }
    return ret;
}

long long int gr_file_pread(
    gr_vfs_handle vfs_handle, gr_file_handle file_handle, void *buf, unsigned long long count, long long offset)
{
    timeval_t begin_tv;
    gr_begin_stat(&begin_tv);

    if (count < 0) {
        LOG_RUN_ERR("File size is invalid:%lld.", count);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "size must be a positive integer");
        return CM_ERROR;
    }
    if (offset > (int64_t)GR_MAX_FILE_SIZE) {
        LOG_RUN_ERR("Invalid parameter offset:%lld.", offset);
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "offset must less than GR_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("pread get conn error.");
        return GR_ERROR;
    }

    long long int ret = gr_pread_file_impl(hdl->conn, HANDLE_VALUE(file_handle.fd), buf, count, offset);
    if (ret == count) {
        gr_session_end_stat(hdl->conn->session, &begin_tv, GR_PREAD);
    }
    return ret;
}

int gr_file_truncate(gr_vfs_handle vfs_handle, gr_file_handle file_handle, int truncateType, long long offset)
{
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("ftruncate get conn error.");
        return GR_ERROR;
    }
    status_t ret = gr_truncate_impl(hdl->conn, HANDLE_VALUE(file_handle.fd), offset, truncateType);
    return (int)ret;
}

int gr_file_stat(
    gr_vfs_handle vfs_handle, const char *fileName, long long *offset, unsigned long long *count, int *mode, char **time)
{
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    if (fileName == NULL || strlen(fileName) == 0) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "fileName is NULL or empty");
        return GR_ERROR;
    }
    if (strpbrk(fileName, "\\:*?\"<>|") != NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "fileName contains invalid characters.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fcreate get conn error.");
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

int gr_file_pwrite_async()
{
    return GR_SUCCESS;
}

int gr_file_pread_async()
{
    return GR_SUCCESS;
}

int gr_file_performance()
{
    return GR_SUCCESS;
}

int gr_get_error(int *errcode, const char **errmsg)
{
    cm_get_error(errcode, errmsg);
    cm_reset_error();
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
        cm_log_param_instance()->log_level = (uint32_t)(*value);
    } else if (strcmp(log_field, "LOG_MAX_FILE_SIZE") == 0) {
        cm_log_param_instance()->max_log_file_size = (uint64)(*value);
        cm_log_param_instance()->max_audit_file_size = (uint64)(*value);
    } else if (strcmp(log_field, "LOG_BACKUP_FILE_COUNT") == 0) {
        cm_log_param_instance()->log_backup_file_count = (uint32_t)(*value);
        cm_log_param_instance()->audit_backup_file_count = (uint32_t)(*value);
    }
}

int gr_set_conn_timeout(int32_t timeout)
{
    if (timeout < 0 && timeout != GR_CONN_NEVER_TIMEOUT) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid timeout when set connection timeout");
        return CM_ERROR;
    }
    g_gr_tcp_conn_timeout = timeout;
    return CM_SUCCESS;
}

int gr_set_thread_conn_timeout(gr_conn_opt_t *thv_opts, int32_t timeout)
{
    if (timeout < 0 && timeout != GR_CONN_NEVER_TIMEOUT) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid timeout when set connection timeout");
        return CM_ERROR;
    }
    thv_opts->timeout = timeout;
    return CM_SUCCESS;
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
            return CM_ERROR;
    }
}

int gr_set_conf(gr_instance_handle inst_handle, const char *name, const char *value)
{
    if (name == NULL || value == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid name or value when set cfg");
        return GR_ERROR;
    }

    if (strlen(name) == 0 || strlen(value) == 0) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "name or value is empty");
        return GR_ERROR;
    }

    if (cm_strcmpi(name, "LOG_LEVEL") != 0 && cm_strcmpi(name, "LOG_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "LOG_BACKUP_FILE_COUNT") != 0 && cm_strcmpi(name, "AUDIT_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "AUDIT_BACKUP_FILE_COUNT") != 0 && cm_strcmpi(name, "AUDIT_LEVEL") != 0 && 
        cm_strcmpi(name, "DATA_FILE_PATH") != 0) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid name when set cfg");
        return GR_ERROR;
    }

    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("setcfg get conn error.");
        return GR_ERROR;
    }

    /* both = memory + file */
    status_t ret = gr_setcfg_impl(hdl->conn, name, value, "both");
    return (int)ret;
}

int gr_get_conf(gr_instance_handle inst_handle, const char *name, char *value)
{
    if (name == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid name when get cfg");
        return GR_ERROR;
    }
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return GR_ERROR;
    }
    st_gr_instance_handle *hdl = (st_gr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("getcfg get conn error.");
        return GR_ERROR;
    }

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
