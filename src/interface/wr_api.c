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
 * wr_api.c
 *
 *
 * IDENTIFICATION
 *    src/interface/wr_api.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_api.h"
#include "cm_types.h"
#include "cm_thread.h"
#include "wr_malloc.h"
#include "wr_api_impl.h"
#include "cm_log.h"
#include "cm_timer.h"
#include "wr_cli_conn.h"

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
#include "libaio.h"
#ifndef WIN32
#include "config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif


void wr_set_default_conn_timeout(int timeout)
{
    if (timeout <= 0) {
        g_wr_tcp_conn_timeout = WR_CONN_NEVER_TIMEOUT;
        return;
    }
    g_wr_tcp_conn_timeout = timeout;
}

int wr_create_inst(const char *storageServerAddr, wr_instance_handle *inst_handle)
{
    if (storageServerAddr == NULL || inst_handle == NULL) {
        LOG_RUN_ERR("create instance get invalid parameter.");
        return WR_ERROR;
    }

    if (check_server_addr_format(storageServerAddr) != WR_SUCCESS) {
        LOG_RUN_ERR("invalid address: %s.", storageServerAddr);
        return WR_ERROR;
    }

    st_wr_instance_handle *hdl = (st_wr_instance_handle*)malloc(sizeof(st_wr_instance_handle));
    if (hdl == NULL) {
        LOG_RUN_ERR("failed to allocate memory for instance handle");
        return WR_ERROR;
    }
    hdl->conn = NULL;
    errno_t err = memcpy_s(hdl->addr, strlen(storageServerAddr) + 1, 
                            storageServerAddr, strlen(storageServerAddr) + 1);
    if (err != EOK) {
        LOG_RUN_ERR("Error occured when copying addr, errno code is %d.\n", err);
        free(hdl);
        return (int)err;
    }

    status_t ret = wr_enter_api(&hdl->conn, storageServerAddr);
    if (ret != WR_SUCCESS) {
        LOG_RUN_ERR("create instance get conn error.");
        free(hdl);
        return (int)ret;
    }
    *inst_handle = (wr_instance_handle)hdl;
    return (int)ret;
}

int wr_delete_inst(wr_instance_handle inst_handle)
{
    if (inst_handle == NULL) {
        LOG_RUN_WAR("inst handle is null.");
        return WR_SUCCESS;   
    }

    st_wr_instance_handle *hdl = (st_wr_instance_handle *)inst_handle;
    if (hdl->conn != NULL) {
        free(hdl->conn);
        hdl->conn = NULL;
    }
    free(hdl);
    hdl = NULL;
    return WR_SUCCESS;
}

int wr_vfs_create(wr_instance_handle inst_handle, const char *vfs_name, unsigned long long attrFlag)
{
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("vfs create get conn error.");
        return WR_ERROR;
    }
    status_t ret = wr_vfs_create_impl(hdl->conn, vfs_name, attrFlag);
    return (int)ret;
}

int wr_vfs_delete(wr_instance_handle inst_handle, const char *vfs_name, unsigned long long attrFlag)
{
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("dremove get conn error.");
        return WR_ERROR;
    }
    status_t ret = wr_vfs_delete_impl(hdl->conn, vfs_name, attrFlag);
    return (int)ret;
}

int wr_vfs_mount(wr_instance_handle inst_handle, const char *vfs_name, wr_vfs_handle *vfs_handle)
{
    if (inst_handle == NULL || vfs_handle == NULL) {
        LOG_RUN_ERR("instance handle or vfs_handle is NULL.");
        return WR_ERROR;
    }
    if (vfs_name == NULL || vfs_name[0] == '\0') {
        LOG_RUN_ERR("invalid argument vfs_name.");
        return WR_ERROR;
    }
    errno_t err = memset_s(vfs_handle, sizeof(wr_vfs_handle), 0, sizeof(wr_vfs_handle));
    if (SECUREC_UNLIKELY(err != EOK)) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return WR_ERROR;
    }

    st_wr_instance_handle *hdl = (st_wr_instance_handle *)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("mount get conn error.");
        return WR_ERROR;
    }
    if (wr_check_path_exist(hdl->conn, vfs_name) != WR_SUCCESS) {
        return WR_ERROR;
    }

    vfs_handle->handle = inst_handle;
    err = memcpy_s(vfs_handle->vfs_name, WR_MAX_NAME_LEN, vfs_name, strlen(vfs_name));
    if (SECUREC_UNLIKELY(err != EOK)) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return WR_ERROR;
    }
    return WR_SUCCESS;
}

int wr_vfs_unmount(wr_vfs_handle *vfs_handle)
{
    vfs_handle->handle = NULL;
    vfs_handle->vfs_name[0] = '\0';
    return WR_SUCCESS; 
}

int wr_vfs_control(void)
{
    return WR_SUCCESS;
}

int wr_stat(const char *path, wr_stat_info_t item, wr_instance_handle inst_handle)
{
    if (item == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "wr_stat_info_t");
        return WR_ERROR;
    }
    timeval_t begin_tv;
    wr_begin_stat(&begin_tv);

    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("stat get conn error.");
        return WR_ERROR;
    }

    gft_node_t *node = wr_get_node_by_path_impl(hdl->conn, path);
    if (node == NULL) {
        return WR_ERROR;
    }

    int ret = wr_set_stat_info(item, node);
    wr_session_end_stat(hdl->conn->session, &begin_tv, WR_STAT);
    return ret;
}

int wr_vfs_query_file_num(wr_instance_handle inst_handle, const char *vfs_name, int *file_num)
{
    if (file_num == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "file_num");
        return WR_ERROR;
    }
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("lstat get conn error.");
        return WR_ERROR;
    }

    status_t ret = wr_vfs_query_file_num_impl(hdl->conn, vfs_name, (uint32_t *)file_num);
    if (ret != WR_SUCCESS) {
        *file_num = 0;
        LOG_DEBUG_INF("vfs query file num :%s error", vfs_name);
        return WR_ERROR;
    }
    return WR_SUCCESS;
}

int wr_file_create(wr_vfs_handle vfs_handle, const char *name, const FileParameter *param)
{
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fcreate get conn error.");
        return WR_ERROR;
    }
    char full_name[WR_MAX_NAME_LEN];
    errno_t err = sprintf_s(full_name, WR_MAX_NAME_LEN, "%s/%s", vfs_handle.vfs_name, name);
    if (SECUREC_UNLIKELY(err < 0)) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return WR_ERROR;
    }

    int flag = 0;
    status_t ret = wr_create_file_impl(hdl->conn, full_name, flag);
    return (int)ret;
}

int wr_file_delete(wr_vfs_handle vfs_handle, const char *name)
{
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fremove get conn error.");
        return WR_ERROR;
    }

    char full_name[WR_MAX_NAME_LEN];
    errno_t err = sprintf_s(full_name, WR_MAX_NAME_LEN, "%s/%s", vfs_handle.vfs_name, name);
    if (SECUREC_UNLIKELY(err < 0)) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return WR_ERROR;
    }
    status_t ret = wr_remove_file_impl(hdl->conn, full_name);
    return (int)ret;
}

int wr_file_open(wr_vfs_handle vfs_handle, const char *name, int flag, int *fd)
{
    timeval_t begin_tv;
    *fd = -1;

    wr_begin_stat(&begin_tv);
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fopen get conn error.");
        return WR_ERROR;
    }

    char full_name[WR_MAX_NAME_LEN];
    errno_t err = sprintf_s(full_name, WR_MAX_NAME_LEN, "%s/%s", vfs_handle.vfs_name, name);
    if (SECUREC_UNLIKELY(err < 0)) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return WR_ERROR;
    }
    status_t ret = wr_open_file_impl(hdl->conn, full_name, flag, fd);
    // if open fails, -1 is returned. DB determines based on -1
    if (ret == WR_SUCCESS) {
        *fd += WR_HANDLE_BASE;
    }
    wr_session_end_stat(hdl->conn->session, &begin_tv, WR_FOPEN);
    return (int)ret;
}

int wr_get_inst_status(wr_server_status_t *wr_status, wr_instance_handle inst_handle)
{
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("get conn error when get inst status.");
        return WR_ERROR;
    }
    status_t ret = wr_get_inst_status_on_server(hdl->conn, wr_status);
    return (int)ret;
}

int wr_is_maintain(unsigned int *is_maintain, wr_instance_handle inst_handle)
{
    if (is_maintain == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "expected is_maintain not a null pointer");
        return CM_ERROR;
    }
    wr_server_status_t wr_status = {0};
    status_t ret = wr_get_inst_status(&wr_status, inst_handle);
    WR_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get error when get inst status"));
    *is_maintain = wr_status.is_maintain;
    return CM_SUCCESS;
}

int wr_set_main_inst(wr_instance_handle inst_handle)
{
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("get conn error when set main inst.");
        return WR_ERROR;
    }
    status_t ret = wr_set_main_inst_on_server(hdl->conn);
    return (int)ret;
}

int wr_file_close(wr_vfs_handle vfs_handle, int fd)
{
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fclose get conn error.");
        return WR_ERROR;
    }

    status_t ret = wr_close_file_impl(hdl->conn, HANDLE_VALUE(fd));
    return (int)ret;
}

long long int wr_file_pwrite(wr_vfs_handle vfs_handle, int fd, const void *buf, unsigned long long count, long long offset)
{
    timeval_t begin_tv;
    wr_begin_stat(&begin_tv);
    if (count < 0) {
        LOG_DEBUG_ERR("File size is invalid:%lld.", count);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "size must be a positive integer");
        return CM_ERROR;
    }
    if (offset > (int64_t)WR_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Invalid parameter offset:%lld.", offset);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "offset must less than WR_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("pwrite get conn error.");
        return WR_ERROR;
    }

    long long int ret = wr_pwrite_file_impl(hdl->conn, HANDLE_VALUE(fd), buf, count, offset);
    if (ret == count) {
        wr_session_end_stat(hdl->conn->session, &begin_tv, WR_PWRITE);
    }
    return ret;
}

long long int wr_file_pread(wr_vfs_handle vfs_handle, int fd, void *buf, unsigned long long count, long long offset)
{
    timeval_t begin_tv;
    wr_begin_stat(&begin_tv);

    if (count < 0) {
        LOG_DEBUG_ERR("File size is invalid:%lld.", count);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "size must be a positive integer");
        return CM_ERROR;
    }
    if (offset > (int64_t)WR_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Invalid parameter offset:%lld.", offset);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "offset must less than WR_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("pread get conn error.");
        return WR_ERROR;
    }

    long long int ret = wr_pread_file_impl(hdl->conn, HANDLE_VALUE(fd), buf, count, offset);
    if (ret == count) {
        wr_session_end_stat(hdl->conn->session, &begin_tv, WR_PREAD);
    }
    return ret;
}

int wr_file_truncate(wr_vfs_handle vfs_handle, int fd, int truncateType, long long offset)
{
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("ftruncate get conn error.");
        return WR_ERROR;
    }
    status_t ret = wr_truncate_impl(hdl->conn, HANDLE_VALUE(fd), offset, truncateType);
    return (int)ret;
}

int wr_file_stat(wr_vfs_handle vfs_handle, const char *fileName, long long *offset, unsigned long long *count)
{
    if (vfs_handle.handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    if (fileName == NULL || strlen(fileName) == 0) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "fileName is NULL or empty");
        return WR_ERROR;
    }
    if (strpbrk(fileName, "\\:*?\"<>|") != NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "fileName contains invalid characters.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)(vfs_handle.handle);
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fcreate get conn error.");
        return WR_ERROR;
    }
    char full_name[WR_MAX_NAME_LEN];
    errno_t err = sprintf_s(full_name, WR_MAX_NAME_LEN, "%s/%s", vfs_handle.vfs_name, fileName);
    if (SECUREC_UNLIKELY(err < 0)) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return WR_ERROR;
    }

    status_t ret = wr_stat_file_impl(hdl->conn, full_name, offset, count);
    return (int)ret;
}

int wr_file_pwrite_async()
{
    return WR_SUCCESS;
}

int wr_file_pread_async()
{
    return WR_SUCCESS;
}

int wr_file_performance()
{
    return WR_SUCCESS;
}

/*
static void wr_fsize_with_options(const char *fname, long long *fsize, int origin, wr_instance_handle inst_handle)
{
    int32_t handle;
    status_t status;
    *fsize = CM_INVALID_INT64;

    if (fname == NULL) {
        return;
    }

    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fszie with option get conn error.");
        return;
    }

    status = wr_open_file_impl(hdl->conn, fname, O_RDONLY, &handle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Open file :%s failed.\n", fname);
        return;
    }

    *fsize = wr_seek_file_impl(hdl->conn, handle, 0, origin);
    if (*fsize == CM_INVALID_INT64) {
        LOG_DEBUG_ERR("Seek file :%s failed.\n", fname);
    }

    (void)wr_close_file_impl(hdl->conn, handle);
}
*/

int wr_fsize_physical(int handle, long long *fsize, wr_instance_handle inst_handle)
{
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fszie get conn error.");
        return WR_ERROR;
    }
    status_t ret = wr_get_phy_size_impl(hdl->conn, HANDLE_VALUE(handle), fsize);
    return (int)ret;
}

int wr_get_error(int *errcode, const char **errmsg)
{
    cm_get_error(errcode, errmsg);
    return CM_SUCCESS;
}

int wr_get_fname(int handle, char *fname, int fname_size)
{
    status_t ret = wr_get_fname_impl(HANDLE_VALUE(handle), fname, fname_size);
    wr_get_api_volume_error();
    return (int)ret;
}

int wr_fallocate(int handle, int mode, long long offset, long long length, wr_instance_handle inst_handle)
{
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("fallocate get conn error.");
        return WR_ERROR;
    }
    status_t ret = wr_fallocate_impl(hdl->conn, HANDLE_VALUE(handle), mode, offset, length);

    return (int)ret;
}

void wr_register_log_callback(wr_log_output cb_log_output, unsigned int log_level)
{
    cm_log_param_instance()->log_write = (usr_cb_log_output_t)cb_log_output;
    cm_log_param_instance()->log_level = log_level;
}

void wr_set_log_level(unsigned int log_level)
{
    cm_log_param_instance()->log_level = log_level;
}

static int32_t init_single_logger_core(log_param_t *log_param, log_type_t log_id, char *file_name, uint32_t file_name_len)
{
    int32_t ret;
    switch (log_id) {
        case CM_LOG_RUN:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/WR/run/%s", log_param->log_home, "wr.rlog");
            break;
        case CM_LOG_DEBUG:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/WR/debug/%s", log_param->log_home, "wr.dlog");
            break;
        case CM_LOG_ALARM:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/WR/alarm/%s", log_param->log_home, "wr.alog");
            break;
        case CM_LOG_AUDIT:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/WR/audit/%s", log_param->log_home, "wr.aud");
            break;
        case CM_LOG_BLACKBOX:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/WR/blackbox/%s", log_param->log_home, "wr.blog");
            break;
        default:
            ret = 0;
            break;
    }

    return (ret != -1) ? WR_SUCCESS : ERR_WR_INIT_LOGGER_FAILED;
}

static int32_t init_single_logger(log_param_t *log_param, log_type_t log_id)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE] = {'\0'};
    CM_RETURN_IFERR(init_single_logger_core(log_param, log_id, file_name, CM_FILE_NAME_BUFFER_SIZE));
    (void)cm_log_init(log_id, (const char *)file_name);
    cm_log_open_compress(log_id, WR_TRUE);
    return WR_SUCCESS;
}

void wr_refresh_logger(char *log_field, unsigned long long *value)
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

int wr_set_conn_timeout(int32_t timeout)
{
    if (timeout < 0 && timeout != WR_CONN_NEVER_TIMEOUT) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid timeout when set connection timeout");
        return CM_ERROR;
    }
    g_wr_tcp_conn_timeout = timeout;
    return CM_SUCCESS;
}

int wr_set_thread_conn_timeout(wr_conn_opt_t *thv_opts, int32_t timeout)
{
    if (timeout < 0 && timeout != WR_CONN_NEVER_TIMEOUT) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid timeout when set connection timeout");
        return CM_ERROR;
    }
    thv_opts->timeout = timeout;
    return CM_SUCCESS;
}

int wr_set_conn_opts(wr_conn_opt_key_e key, void *value, const char *addr)
{
    wr_clt_env_init();
    wr_conn_opt_t *thv_opts = NULL;
    if (cm_get_thv(GLOBAL_THV_OBJ1, CM_TRUE, (pointer_t *)&thv_opts, addr) != CM_SUCCESS) {
        return CM_ERROR;
    }
    switch (key) {
        case WR_CONN_OPT_TIME_OUT:
            return wr_set_thread_conn_timeout(thv_opts, *(int32_t *)value);
        default:
            WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid key when set connection options");
            return CM_ERROR;
    }
}

int wr_aio_prep_pread(void *iocb, int handle, void *buf, size_t count, long long offset)
{
    return CM_SUCCESS;
}

int wr_aio_prep_pwrite(void *iocb, int handle, void *buf, size_t count, long long offset)
{
    return CM_SUCCESS;
}

int wr_aio_post_pwrite(void *iocb, int handle, size_t count, long long offset)
{
    return CM_SUCCESS;
}

int wr_set_conf(wr_instance_handle inst_handle, const char *name, const char *value)
{
    if (name == NULL || value == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid name or value when set cfg");
        return WR_ERROR;
    }

    if (strlen(name) == 0 || strlen(value) == 0) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "name or value is empty");
        return WR_ERROR;
    }

    if (cm_strcmpi(name, "_LOG_LEVEL") != 0 && cm_strcmpi(name, "_LOG_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "_LOG_BACKUP_FILE_COUNT") != 0 && cm_strcmpi(name, "_AUDIT_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "_AUDIT_BACKUP_FILE_COUNT") != 0 && cm_strcmpi(name, "_AUDIT_LEVEL") != 0) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid name when set cfg");
        return WR_ERROR;
    }

    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("setcfg get conn error.");
        return WR_ERROR;
    }

    /* both = memory + file */
    status_t ret = wr_setcfg_impl(hdl->conn, name, value, "both");
    return (int)ret;
}

int wr_get_conf(wr_instance_handle inst_handle, const char *name, char *value)
{
    if (name == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid name when get cfg");
        return WR_ERROR;
    }
    if (inst_handle == NULL) {
        LOG_RUN_ERR("instance handle is NULL.");
        return WR_ERROR;
    }
    st_wr_instance_handle *hdl = (st_wr_instance_handle*)inst_handle;
    if (hdl->conn == NULL) {
        LOG_RUN_ERR("getcfg get conn error.");
        return WR_ERROR;
    }

    status_t ret = wr_getcfg_impl(hdl->conn, name, value, WR_PARAM_BUFFER_SIZE);
    return (int)ret;
}

int wr_get_lib_version(void)
{
    return WR_LOCAL_MAJOR_VERSION * WR_LOCAL_MAJOR_VER_WEIGHT + WR_LOCAL_MINOR_VERSION * WR_LOCAL_MINOR_VER_WEIGHT +
           WR_LOCAL_VERSION;
}

void wr_show_version(char *version)
{
    if (snprintf_s(version, WR_VERSION_MAX_LEN, WR_VERSION_MAX_LEN - 1, "libwr.so %s", (char *)DEF_WR_VERSION) ==
        -1) {
        cm_panic(0);
    }
}

int wr_init(const wr_param_t param)
{
    log_param_t *log_param = cm_log_param_instance();
    errno_t ret = memset_s(log_param, sizeof(log_param_t), 0, sizeof(log_param_t));
    if (ret != EOK) {
        return ERR_WR_INIT_LOGGER_FAILED;
    }

    log_param->log_level = param.log_level;
    log_param->log_backup_file_count = param.log_backup_file_count;
    log_param->audit_backup_file_count = param.log_backup_file_count;
    log_param->max_log_file_size = param.log_max_file_size;
    log_param->max_audit_file_size = param.log_max_file_size;
    log_param->log_compressed = WR_TRUE;
    if (log_param->log_compress_buf == NULL) {
        log_param->log_compress_buf = malloc(CM_LOG_COMPRESS_BUFSIZE);
        if (log_param->log_compress_buf == NULL) {
            return ERR_WR_INIT_LOGGER_FAILED;
        }
    }
    cm_log_set_file_permissions(600);
    cm_log_set_path_permissions(700);
    (void)cm_set_log_module_name("WR", sizeof("WR"));
    ret = strcpy_sp(log_param->instance_name, CM_MAX_NAME_LEN, "WR");
    if (ret != EOK) {
        return ERR_WR_INIT_LOGGER_FAILED;
    }

    ret = strcpy_sp(log_param->log_home, CM_MAX_LOG_HOME_LEN, param.log_home);
    if (ret != EOK) {
        return ERR_WR_INIT_LOGGER_FAILED;
    }

    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_RUN));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_DEBUG));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_ALARM));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_AUDIT));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_BLACKBOX));
    if (cm_start_timer(g_timer()) != CM_SUCCESS) {
        return ERR_WR_INIT_LOGGER_FAILED;
    }
    log_param->log_instance_startup = (bool32)CM_TRUE;

    return WR_SUCCESS;
}

int wr_exit(void)
{
    return WR_SUCCESS;
}


#ifdef __cplusplus
}
#endif
