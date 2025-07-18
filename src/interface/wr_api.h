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
 * wr_api.h
 *
 *
 * IDENTIFICATION
 *    src/interface/wr_api.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_API_H__
#define __WR_API_H__

#include <stdio.h>
#include <stdbool.h>
#include <limits.h>
#include "wr_errno.h"
#include "time.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#if defined(WR_EXPORTS)
#define WR_DECLARE __declspec(dllexport)
#elif defined(WR_IMPORTS)
#define WR_DECLARE __declspec(dllimport)
#else
#define WR_DECLARE
#endif
#else
#define WR_DECLARE __attribute__((visibility("default")))
#endif

struct __wr_instance_handle;
typedef struct __wr_instance_handle *wr_instance_handle;

typedef enum en_wr_log_level {
    WR_LOG_LEVEL_ERROR = 0,  // error conditions
    WR_LOG_LEVEL_WARN,       // warning conditions
    WR_LOG_LEVEL_INFO,       // informational messages
    WR_LOG_LEVEL_COUNT,
} wr_log_level_t;

typedef enum en_wr_log_id {
    WR_LOG_ID_RUN = 0,
    WR_LOG_ID_DEBUG,
    WR_LOG_ID_COUNT,
} wr_log_id_t;

typedef struct st_wr_param {
    char log_home[PATH_MAX];
    unsigned int log_level;
    unsigned int log_backup_file_count;
    unsigned long long log_max_file_size;
} wr_param_t;

#define WR_SEEK_MAXWR 3                         /* Used for seek actual file size for openGauss */
#define WR_MAX_NAME_LEN 64                      /* Consistent with wr_defs.h */
#define WR_FILE_PATH_MAX_LENGTH (SIZE_K(1) + 1) /* Consistent with wr_defs.h */
#define WR_MAX_VOLUME_PATH_LEN 64               /* Consistent with wr_defs.h */

/* make the wr handle start from this value, to be distinguished from file system handle value */
#define WR_HANDLE_BASE 0x20000000
#define WR_CONN_NEVER_TIMEOUT (-1)
#define WR_VERSION_MAX_LEN 256
#define SHA256_DIGEST_LENGTH_H 32

typedef enum en_wr_item_type {
    WR_PATH,
    WR_FILE,
    WR_LINK,
    WR_LINK_TO_PATH,
    WR_LINK_TO_FILE,
} wr_item_type_t;

typedef struct st_wr_dirent {
    wr_item_type_t d_type;
    char d_name[WR_MAX_NAME_LEN];
} wr_dirent_t;

typedef struct wr_vfs_handle {
    wr_instance_handle handle;
    unsigned long long dir_handle; /* handle for directory */
    char vfs_name[WR_MAX_NAME_LEN];
} wr_vfs_handle;

typedef struct FileParameter {
    unsigned long long attrFlag;
    unsigned long long fileSize;
    unsigned long long blockSize;
    unsigned long long maxFileSize;
    unsigned long long maxOpenFiles;
    unsigned long long maxOpenFilesPerInstance;
} FileParameter;

typedef enum en_wr_rdwr_type_e {
    WR_STATUS_NORMAL = 0,
    WR_STATUS_READONLY,
    WR_STATUS_READWRITE,
    WR_SERVER_STATUS_END,
} wr_rdwr_type_e;

typedef enum en_wr_instance_status {
    WR_STATUS_PREPARE = 0,
    WR_STATUS_RECOVERY,
    WR_STATUS_SWITCH,
    WR_STATUS_OPEN,
    WR_INSTANCE_STATUS_END,
} wr_instance_status_e;

#define WR_MAX_STATUS_LEN 16
typedef struct st_wr_server_status_t {
    wr_instance_status_e instance_status_id;
    char instance_status[WR_MAX_STATUS_LEN];
    wr_rdwr_type_e server_status_id;
    char server_status[WR_MAX_STATUS_LEN];
    unsigned int local_instance_id;
    unsigned int master_id;
    unsigned int is_maintain;
} wr_server_status_t;

typedef struct st_wr_stat {
    unsigned long long size;
    unsigned long long written_size;
    time_t create_time;
    time_t update_time;
    char name[WR_MAX_NAME_LEN];
    wr_item_type_t type;
} wr_stat_t;

typedef struct st_wr_file_item {
    char name[WR_MAX_NAME_LEN];
} wr_file_item_t;

typedef enum en_wr_conn_opt_key {
    WR_CONN_OPT_TIME_OUT = 0,
} wr_conn_opt_key_e;

typedef struct st_wr_file_handle {
    int fd;
    char file_name[WR_MAX_NAME_LEN];
    unsigned char hash[SHA256_DIGEST_LENGTH_H];
} wr_file_handle;

#define WR_LOCAL_MAJOR_VER_WEIGHT 1000000
#define WR_LOCAL_MINOR_VER_WEIGHT 1000
#define WR_LOCAL_MAJOR_VERSION 0
#define WR_LOCAL_MINOR_VERSION 0
#define WR_LOCAL_VERSION 5

// menas no need caller to write zero to init file content before read from the file
#define WR_FILE_FLAG_INNER_INITED 0x80000000

typedef struct st_wr_dirent *wr_dir_item_t;
typedef struct st_wr_stat *wr_stat_info_t;
typedef void (*wr_log_output)(wr_log_id_t log_type, wr_log_level_t log_level, const char *code_file_name,
    unsigned int code_line_num, const char *module_name, const char *format, ...);
typedef void (*wr_exit_error_callback_t)(int exit_code);
// vfs
WR_DECLARE int wr_vfs_create(wr_instance_handle inst_handle, const char *vfs_name, unsigned long long attrFlag);
WR_DECLARE int wr_vfs_delete(wr_instance_handle inst_handle, const char *vfs_name, unsigned long long attrFlag);
WR_DECLARE int wr_vfs_mount(wr_instance_handle inst_handle, const char *vfs_name, wr_vfs_handle *vfs_handle);
WR_DECLARE int wr_vfs_unmount(wr_vfs_handle *vfs_handle);
WR_DECLARE int wr_vfs_query_file_info(wr_vfs_handle vfs_handle, wr_file_item_t *result, bool is_continue);
WR_DECLARE int wr_vfs_query_file_num(wr_vfs_handle vfs_handle, int *file_num);

// file
WR_DECLARE int wr_file_create(wr_vfs_handle vfs_handle, const char *name, const FileParameter *param);
WR_DECLARE int wr_file_delete(wr_vfs_handle vfs_handle, const char *name);
WR_DECLARE int wr_file_exist(wr_vfs_handle vfs_handle, const char *name, bool *is_exist);
WR_DECLARE int wr_file_open(wr_vfs_handle vfs_handle, const char *name, int flag, wr_file_handle *file_handle);
WR_DECLARE int wr_file_close(wr_vfs_handle vfs_handle, wr_file_handle *file_handle, bool need_lock);
WR_DECLARE int wr_file_truncate(wr_vfs_handle vfs_handle, wr_file_handle file_handle, int truncateType, long long offset);
WR_DECLARE long long int wr_file_pwrite(wr_vfs_handle vfs_handle,
                                        wr_file_handle *file_handle, const void *buf, unsigned long long count, long long offset);
WR_DECLARE long long int wr_file_pread(wr_vfs_handle vfs_handle,
                                        wr_file_handle file_handle, void *buf, unsigned long long count, long long offset);
WR_DECLARE int wr_file_stat(
    wr_vfs_handle vfs_handle, const char *fileName, long long *offset, unsigned long long *count, int *mode, char **time);
WR_DECLARE int wr_file_performance();
WR_DECLARE int wr_file_postpone(wr_vfs_handle vfs_handle, const char *file, const char *time);

// aio
WR_DECLARE int wr_file_pwrite_async();
WR_DECLARE int wr_file_pread_async();

// log
WR_DECLARE int wr_get_error(int *errcode, const char **errmsg);
WR_DECLARE void wr_register_log_callback(wr_log_output cb_log_output, unsigned int log_level);
WR_DECLARE void wr_set_log_level(unsigned int log_level);
WR_DECLARE void wr_refresh_logger(char *log_field, unsigned long long *value);

// connection
WR_DECLARE int wr_set_conn_timeout(int timeout);
WR_DECLARE int wr_set_conn_opts(wr_conn_opt_key_e key, void *value, const char *addr);
WR_DECLARE void wr_set_default_conn_timeout(int timeout);
WR_DECLARE int wr_create_inst(const char *storageServerAddr, wr_instance_handle *inst_handle);
WR_DECLARE int wr_delete_inst(wr_instance_handle inst_handle);

// instance param
WR_DECLARE int wr_set_main_inst(const char *storageServerAddr);
WR_DECLARE int wr_get_inst_status(wr_server_status_t *wr_status, wr_instance_handle inst_handle);
WR_DECLARE int wr_is_maintain(unsigned int *is_maintain, wr_instance_handle inst_handle);

// config
WR_DECLARE int wr_set_conf(wr_instance_handle inst_handle, const char *name, const char *value);
WR_DECLARE int wr_get_conf(wr_instance_handle inst_handle, const char *name, char *value);

// version
WR_DECLARE int wr_get_lib_version(void);
WR_DECLARE void wr_show_version(char *version);
WR_DECLARE void wr_show_version(char *version);

// SDK
WR_DECLARE int wr_init(const wr_param_t param);
WR_DECLARE int wr_exit(void);

#ifdef __cplusplus
}
#endif
#endif
