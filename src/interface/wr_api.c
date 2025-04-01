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
        g_wr_uds_conn_timeout = WR_CONN_NEVER_TIMEOUT;
        return;
    }
    g_wr_uds_conn_timeout = timeout;
}

int wr_vfs_create(const char *vfs_name)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("dmake get conn error."));
    ret = wr_vfs_create_impl(conn, vfs_name);
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int wr_vfs_delete(const char *vfs_name)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("dremove get conn error."));
    ret = wr_vfs_delete_impl(conn, vfs_name);
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int wr_vfs_mount(const char *vfs_name, wr_vfs_handle *vfs_handle)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("wr_vfs_mount get conn error.");
        return CM_ERROR;
    }
    wr_vfs_t *dir = wr_open_dir_impl(conn, vfs_name, CM_TRUE);
    wr_leave_api(conn, CM_TRUE);
    *vfs_handle = (wr_vfs_handle)dir;
    return CM_SUCCESS;
}

int wr_vfs_unmount(wr_vfs_handle vfs_handle)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("wr_vfs_unmount get conn error"));
    ret = wr_close_dir_impl(conn, (wr_vfs_t *)vfs_handle);
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int wr_dread(wr_vfs_handle dir, wr_dir_item_t item, wr_dir_item_t *result)
{
    if (item == NULL || result == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "wr_dir_item_t");
        return WR_ERROR;
    }
    *result = NULL;
    if (dir == NULL) {
        return WR_SUCCESS;
    }
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("dread get conn error."));

    gft_node_t *node = wr_read_dir_impl(conn, (wr_vfs_t *)dir, CM_TRUE);
    wr_leave_api(conn, CM_FALSE);
    if (node == NULL) {
        return WR_SUCCESS;
    }
    item->d_type = (wr_item_type_t)node->type;
    int32 errcode = memcpy_s(item->d_name, WR_MAX_NAME_LEN, node->name, WR_MAX_NAME_LEN);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return WR_ERROR;
    }
    *result = item;
    return WR_SUCCESS;
}

int wr_stat(const char *path, wr_stat_info_t item)
{
    if (item == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "wr_stat_info_t");
        return WR_ERROR;
    }
    timeval_t begin_tv;
    wr_begin_stat(&begin_tv);
    wr_conn_t *conn = NULL;
    status_t status = wr_enter_api(&conn);
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("stat get conn error."));
    gft_node_t *node = wr_get_node_by_path_impl(conn, path);
    if (node == NULL) {
        wr_leave_api(conn, CM_FALSE);
        return WR_ERROR;
    }

    int ret = wr_set_stat_info(item, node);
    wr_session_end_stat(conn->session, &begin_tv, WR_STAT);
    wr_leave_api(conn, CM_FALSE);
    return ret;
}

int wr_lstat(const char *path, wr_stat_info_t item)
{
    if (item == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "wr_stat_info_t");
        return WR_ERROR;
    }
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("lstat get conn error."));
    gft_node_t *node = wr_get_node_by_path_impl(conn, path);
    wr_leave_api(conn, CM_FALSE);
    if (node == NULL) {
        LOG_DEBUG_INF("lstat get node by path :%s error", path);
        return WR_ERROR;
    }
    return wr_set_stat_info(item, node);
}

int wr_fstat(int handle, wr_stat_info_t item)
{
    wr_conn_t *conn = NULL;
    if (item == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "wr_stat_info_t");
        return WR_ERROR;
    }
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("fstat get conn error"));
    ret = wr_fstat_impl(conn, HANDLE_VALUE(handle), item);
    wr_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int wr_file_create(const char *name, int flag)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("fcreate get conn error"));
    ret = wr_create_file_impl(conn, name, flag);
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int wr_file_delete(const char *file)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("fremove get conn error"));
    ret = wr_remove_file_impl(conn, file);
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int wr_file_open(const char *file, int flag, int *handle)
{
    timeval_t begin_tv;
    *handle = -1;

    wr_begin_stat(&begin_tv);
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("fopen get conn error"));

    ret = wr_open_file_impl(conn, file, flag, handle);
    // if open fails, -1 is returned. DB determines based on -1
    if (ret == CM_SUCCESS) {
        *handle += WR_HANDLE_BASE;
    }
    wr_session_end_stat(conn->session, &begin_tv, WR_FOPEN);
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int wr_get_inst_status(wr_server_status_t *wr_status)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get conn error when get inst status"));
    ret = wr_get_inst_status_on_server(conn, wr_status);
    wr_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int wr_is_maintain(unsigned int *is_maintain)
{
    if (is_maintain == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "expected is_maintain not a null pointer");
        return CM_ERROR;
    }
    wr_server_status_t wr_status = {0};
    status_t ret = wr_get_inst_status(&wr_status);
    WR_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get error when get inst status"));
    *is_maintain = wr_status.is_maintain;
    return CM_SUCCESS;
}

int wr_set_main_inst(void)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get conn error when set main inst"));
    ret = wr_set_main_inst_on_server(conn);
    wr_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int wr_file_close(int handle)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_DEBUG_ERR("fclose get conn error"));

    ret = wr_close_file_impl(conn, HANDLE_VALUE(handle));
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

long long wr_fseek(int handle, long long offset, int origin)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("fseek get conn error."));

    long long status = wr_seek_file_impl(conn, HANDLE_VALUE(handle), offset, origin);
    wr_leave_api(conn, CM_TRUE);
    return status;
}

int wr_file_write(int handle, const void *buf, int size)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("fwrite get conn error"));

    ret = wr_write_file_impl(conn, HANDLE_VALUE(handle), buf, size);
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int wr_file_read(int handle, void *buf, int size, int *read_size)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("fread get conn error."));

    ret = wr_read_file_impl(conn, HANDLE_VALUE(handle), buf, size, read_size);
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int wr_file_pwrite(int handle, const void *buf, int size, long long offset)
{
    timeval_t begin_tv;
    wr_begin_stat(&begin_tv);
    if (size < 0) {
        LOG_DEBUG_ERR("File size is invalid:%d.", size);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "size must be a positive integer");
        return CM_ERROR;
    }
    if (offset > (int64)WR_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Invalid parameter offset:%lld.", offset);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "offset must less than WR_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("pwrite get conn error."));

    ret = wr_pwrite_file_impl(conn, HANDLE_VALUE(handle), buf, size, offset);
    if (ret == CM_SUCCESS) {
        wr_session_end_stat(conn->session, &begin_tv, WR_PWRITE);
    }
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int wr_file_pread(int handle, void *buf, int size, long long offset, int *read_size)
{
    timeval_t begin_tv;
    wr_begin_stat(&begin_tv);

    if (read_size == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "read _size is NULL");
        return CM_ERROR;
    }
    if (size < 0) {
        LOG_DEBUG_ERR("File size is invalid:%d.", size);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "size must be a positive integer");
        return CM_ERROR;
    }
    if (offset > (int64)WR_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Invalid parameter offset:%lld.", offset);
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "offset must less than WR_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("pread get conn error."));

    ret = wr_pread_file_impl(conn, HANDLE_VALUE(handle), buf, size, offset, read_size);
    if (ret == CM_SUCCESS) {
        wr_session_end_stat(conn->session, &begin_tv, WR_PREAD);
    }
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int wr_frename(const char *src, const char *dst)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("frename get conn error."));

    ret = wr_rename_file_impl(conn, src, dst);
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int wr_file_truncate(int handle, long long length)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("ftruncate get conn error."));
    ret = wr_truncate_impl(conn, HANDLE_VALUE(handle), length);
    wr_leave_api(conn, CM_TRUE);
    return (int)ret;
}


static void wr_fsize_with_options(const char *fname, long long *fsize, int origin)
{
    int32 handle;
    status_t status;
    *fsize = CM_INVALID_INT64;

    if (fname == NULL) {
        return;
    }

    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("fszie with options get conn error.");
        return;
    }

    status = wr_open_file_impl(conn, fname, O_RDONLY, &handle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Open file :%s failed.\n", fname);
        wr_leave_api(conn, CM_FALSE);
        return;
    }

    *fsize = wr_seek_file_impl(conn, handle, 0, origin);
    if (*fsize == CM_INVALID_INT64) {
        LOG_DEBUG_ERR("Seek file :%s failed.\n", fname);
        wr_leave_api(conn, CM_FALSE);
    }

    (void)wr_close_file_impl(conn, handle);
    wr_leave_api(conn, CM_FALSE);
}

int wr_fsize_physical(int handle, long long *fsize)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("get conn error."));
    ret = wr_get_phy_size_impl(conn, HANDLE_VALUE(handle), fsize);
    wr_leave_api(conn, CM_FALSE);
    return (int)ret;
}

void wr_fsize_maxwr(const char *fname, long long *fsize)
{
    wr_fsize_with_options(fname, fsize, WR_SEEK_MAXWR);
}

void wr_get_error(int *errcode, const char **errmsg)
{
    cm_get_error(errcode, errmsg);
}

int wr_get_fname(int handle, char *fname, int fname_size)
{
    status_t ret = wr_get_fname_impl(HANDLE_VALUE(handle), fname, fname_size);
    wr_get_api_volume_error();
    return (int)ret;
}

int wr_fallocate(int handle, int mode, long long offset, long long length)
{
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("fallocate get conn error."));
    ret = wr_fallocate_impl(conn, HANDLE_VALUE(handle), mode, offset, length);
    wr_leave_api(conn, CM_TRUE);

    return (int)ret;
}

int wr_set_svr_path(const char *conn_path)
{
    if (conn_path == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "conn path");
        return WR_ERROR;
    }

    size_t len = strlen(conn_path);
    if (len == 0) {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, conn_path, ", conn path is empty");
        return WR_ERROR;
    } else if (len > CM_MAX_PATH_LEN) {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, conn_path, ", conn path is too long");
        return WR_ERROR;
    }
    if (strcpy_s(g_wr_inst_path, CM_MAX_PATH_LEN, conn_path) != EOK) {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, conn_path, ", conn path copy fail");
        return WR_ERROR;
    }
    return WR_SUCCESS;
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

static int32 init_single_logger_core(log_param_t *log_param, log_type_t log_id, char *file_name, uint32 file_name_len)
{
    int32 ret;
    switch (log_id) {
        case LOG_RUN:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/WR/run/%s", log_param->log_home, "wr.rlog");
            break;
        case LOG_DEBUG:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/WR/debug/%s", log_param->log_home, "wr.dlog");
            break;
        case LOG_ALARM:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/WR/alarm/%s", log_param->log_home, "wr.alog");
            break;
        case LOG_AUDIT:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/WR/audit/%s", log_param->log_home, "wr.aud");
            break;
        case LOG_BLACKBOX:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/WR/blackbox/%s", log_param->log_home, "wr.blog");
            break;
        default:
            ret = 0;
            break;
    }

    return (ret != -1) ? WR_SUCCESS : ERR_WR_INIT_LOGGER_FAILED;
}

static int32 init_single_logger(log_param_t *log_param, log_type_t log_id)
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
        cm_log_param_instance()->log_level = (uint32)(*value);
    } else if (strcmp(log_field, "LOG_MAX_FILE_SIZE") == 0) {
        cm_log_param_instance()->max_log_file_size = (uint64)(*value);
        cm_log_param_instance()->max_audit_file_size = (uint64)(*value);
    } else if (strcmp(log_field, "LOG_BACKUP_FILE_COUNT") == 0) {
        cm_log_param_instance()->log_backup_file_count = (uint32)(*value);
        cm_log_param_instance()->audit_backup_file_count = (uint32)(*value);
    }
}

int wr_init_logger(
    char *log_home, unsigned int log_level, unsigned int log_backup_file_count, unsigned long long log_max_file_size)
{
    errno_t ret;
    log_param_t *log_param = cm_log_param_instance();
    ret = memset_s(log_param, sizeof(log_param_t), 0, sizeof(log_param_t));
    if (ret != EOK) {
        return ERR_WR_INIT_LOGGER_FAILED;
    }

    log_param->log_level = log_level;
    log_param->log_backup_file_count = log_backup_file_count;
    log_param->audit_backup_file_count = log_backup_file_count;
    log_param->max_log_file_size = log_max_file_size;
    log_param->max_audit_file_size = log_max_file_size;
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

    ret = strcpy_sp(log_param->log_home, CM_MAX_LOG_HOME_LEN, log_home);
    if (ret != EOK) {
        return ERR_WR_INIT_LOGGER_FAILED;
    }

    CM_RETURN_IFERR(init_single_logger(log_param, LOG_RUN));
    CM_RETURN_IFERR(init_single_logger(log_param, LOG_DEBUG));
    CM_RETURN_IFERR(init_single_logger(log_param, LOG_ALARM));
    CM_RETURN_IFERR(init_single_logger(log_param, LOG_AUDIT));
    CM_RETURN_IFERR(init_single_logger(log_param, LOG_BLACKBOX));
    if (cm_start_timer(g_timer()) != CM_SUCCESS) {
        return ERR_WR_INIT_LOGGER_FAILED;
    }
    log_param->log_instance_startup = (bool32)CM_TRUE;

    return WR_SUCCESS;
}

int wr_set_conn_timeout(int32 timeout)
{
    if (timeout < 0 && timeout != WR_CONN_NEVER_TIMEOUT) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid timeout when set connection timeout");
        return CM_ERROR;
    }
    g_wr_uds_conn_timeout = timeout;
    return CM_SUCCESS;
}

int wr_set_thread_conn_timeout(wr_conn_opt_t *thv_opts, int32 timeout)
{
    if (timeout < 0 && timeout != WR_CONN_NEVER_TIMEOUT) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid timeout when set connection timeout");
        return CM_ERROR;
    }
    thv_opts->timeout = timeout;
    return CM_SUCCESS;
}

int wr_set_conn_opts(wr_conn_opt_key_e key, void *value)
{
    wr_clt_env_init();
    wr_conn_opt_t *thv_opts = NULL;
    if (cm_get_thv(GLOBAL_THV_OBJ1, CM_TRUE, (pointer_t *)&thv_opts) != CM_SUCCESS) {
        return CM_ERROR;
    }
    switch (key) {
        case WR_CONN_OPT_TIME_OUT:
            return wr_set_thread_conn_timeout(thv_opts, *(int32 *)value);
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

int wr_set_conf(const char *name, const char *value, const char *scope)
{
    if (name == NULL || value == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid name or value when set cfg");
        return WR_ERROR;
    }
    if (cm_strcmpi(name, "_LOG_LEVEL") != 0 && cm_strcmpi(name, "_LOG_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "_LOG_BACKUP_FILE_COUNT") != 0 && cm_strcmpi(name, "_AUDIT_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "_AUDIT_BACKUP_FILE_COUNT") != 0 && cm_strcmpi(name, "_AUDIT_LEVEL") != 0) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid name when set cfg");
        return WR_ERROR;
    }

    char *tmp_scope = NULL;
    if (scope == NULL) {
        tmp_scope = (char *)"both";
    } else {
        tmp_scope = (char *)scope;
    }

    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IF_ERROR(ret);

    ret = wr_setcfg_impl(conn, name, value, tmp_scope);
    wr_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int wr_get_conf(const char *name, char *value, int value_size)
{
    if (name == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid name when get cfg");
        return WR_ERROR;
    }
    if (value_size <= 0) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid value_size when get cfg");
        return WR_ERROR;
    }
    wr_conn_t *conn = NULL;
    status_t ret = wr_enter_api(&conn);
    WR_RETURN_IFERR2(ret, LOG_RUN_ERR("getcfg get conn error."));

    ret = wr_getcfg_impl(conn, name, value, (size_t)value_size);
    wr_leave_api(conn, CM_FALSE);
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

#ifdef __cplusplus
}
#endif
