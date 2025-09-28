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
 * gr_api.h
 *
 *
 * IDENTIFICATION
 *    src/interface/gr_api.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_API_H__
#define __GR_API_H__

#include <stdio.h>
#include <stdbool.h>
#include <limits.h>
#include "gr_errno.h"
#include "time.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#if defined(GR_EXPORTS)
#define GR_DECLARE __declspec(dllexport)
#elif defined(GR_IMPORTS)
#define GR_DECLARE __declspec(dllimport)
#else
#define GR_DECLARE
#endif
#else
#define GR_DECLARE __attribute__((visibility("default")))
#endif

struct __gr_instance_handle;
typedef struct __gr_instance_handle *gr_instance_handle;

typedef enum en_gr_log_level {
    GR_LOG_LEVEL_ERROR = 0,  // error conditions
    GR_LOG_LEVEL_WARN,       // warning conditions
    GR_LOG_LEVEL_INFO,       // informational messages
    GR_LOG_LEVEL_COUNT,
} gr_log_level_t;

typedef enum en_gr_log_id {
    GR_LOG_ID_RUN = 0,
    GR_LOG_ID_DEBUG,
    GR_LOG_ID_COUNT,
} gr_log_id_t;

typedef struct st_gr_param {
    char log_home[PATH_MAX];
    unsigned int log_level;
    unsigned int log_backup_file_count;
    unsigned long long log_max_file_size;
} gr_param_t;

#define GR_SEEK_MAXGR 3                         /* Used for seek actual file size for openGauss */
#define GR_MAX_NAME_LEN 64                      /* Consistent with gr_defs.h */
#define GR_FILE_PATH_MAX_LENGTH (SIZE_K(1) + 1) /* Consistent with gr_defs.h */
#define GR_MAX_VOLUME_PATH_LEN 64               /* Consistent with gr_defs.h */

/* make the gr handle start from this value, to be distinguished from file system handle value */
#define GR_HANDLE_BASE 0x20000000
#define GR_CONN_NEVER_TIMEOUT (-1)
#define GR_VERSION_MAX_LEN 256
#define SHA256_DIGEST_LENGTH_H 32

typedef enum en_gr_item_type {
    GR_PATH,
    GR_FILE,
    GR_LINK,
    GR_LINK_TO_PATH,
    GR_LINK_TO_FILE,
} gr_item_type_t;

typedef struct st_gr_dirent {
    gr_item_type_t d_type;
    char d_name[GR_MAX_NAME_LEN];
} gr_dirent_t;

typedef struct gr_vfs_handle {
    gr_instance_handle handle;
    unsigned long long dir_handle; /* handle for directory */
    char vfs_name[GR_MAX_NAME_LEN];
} gr_vfs_handle;

typedef struct FileParameter {
    unsigned long long attrFlag;
    unsigned long long fileSize;
    unsigned long long blockSize;
    unsigned long long maxFileSize;
    unsigned long long maxOpenFiles;
    unsigned long long maxOpenFilesPerInstance;
} FileParameter;

typedef enum en_gr_rdgr_type_e {
    GR_STATUS_NORMAL = 0,
    GR_STATUS_READONLY,
    GR_STATUS_READWRITE,
    GR_SERVER_STATUS_END,
} gr_rdgr_type_e;

typedef enum en_gr_instance_status {
    GR_STATUS_PREPARE = 0,
    GR_STATUS_RECOVERY,
    GR_STATUS_SWITCH,
    GR_STATUS_OPEN,
    GR_INSTANCE_STATUS_END,
} gr_instance_status_e;

#define GR_MAX_STATUS_LEN 16
typedef struct st_gr_server_status_t {
    gr_instance_status_e instance_status_id;
    char instance_status[GR_MAX_STATUS_LEN];
    gr_rdgr_type_e server_status_id;
    char server_status[GR_MAX_STATUS_LEN];
    unsigned int local_instance_id;
    unsigned int master_id;
    unsigned int is_maintain;
} gr_server_status_t;

typedef struct st_gr_stat {
    unsigned long long size;
    unsigned long long written_size;
    long long create_time;
    long long update_time;
    char name[GR_MAX_NAME_LEN];
    gr_item_type_t type;
} gr_stat_t;


typedef struct st_gr_disk_usage_info {
    unsigned long total_bytes;
    unsigned long used_bytes;
    unsigned long available_bytes;
    double usage_percent;
} gr_disk_usage_info_t;

typedef struct st_gr_file_item {
    char name[GR_MAX_NAME_LEN];
} gr_file_item_t;

typedef enum en_gr_conn_opt_key {
    GR_CONN_OPT_TIME_OUT = 0,
} gr_conn_opt_key_e;

typedef struct st_gr_file_handle {
    int fd;
    char file_name[GR_MAX_NAME_LEN];
    unsigned char hash[SHA256_DIGEST_LENGTH_H];
} gr_file_handle;

#define GR_LOCAL_MAJOR_VER_WEIGHT 1000000
#define GR_LOCAL_MINOR_VER_WEIGHT 1000
#define GR_LOCAL_MAJOR_VERSION 0
#define GR_LOCAL_MINOR_VERSION 0
#define GR_LOCAL_VERSION 5

// menas no need caller to write zero to init file content before read from the file
#define GR_FILE_FLAG_INNER_INITED 0x80000000

typedef struct st_gr_dirent *gr_dir_item_t;
typedef struct st_gr_stat *gr_stat_info_t;
typedef void (*gr_log_output)(gr_log_id_t log_type, gr_log_level_t log_level, const char *code_file_name,
    unsigned int code_line_num, const char *module_name, const char *format, ...);
typedef void (*gr_exit_error_callback_t)(int exit_code);
// vfs
GR_DECLARE int gr_vfs_create(gr_instance_handle inst_handle, const char *vfs_name, unsigned long long attrFlag);
GR_DECLARE int gr_vfs_delete(gr_instance_handle inst_handle, const char *vfs_name, unsigned long long attrFlag);
GR_DECLARE int gr_vfs_mount(gr_instance_handle inst_handle, const char *vfs_name, gr_vfs_handle *vfs_handle);
GR_DECLARE int gr_vfs_unmount(gr_vfs_handle *vfs_handle);
GR_DECLARE int gr_vfs_query_file_info(gr_vfs_handle vfs_handle, gr_file_item_t *result, bool is_continue);
GR_DECLARE int gr_vfs_query_file_num(gr_vfs_handle vfs_handle, int *file_num);

// file
GR_DECLARE int gr_file_create(gr_vfs_handle vfs_handle, const char *name, const FileParameter *param);
GR_DECLARE int gr_file_delete(gr_vfs_handle vfs_handle, const char *name);
GR_DECLARE int gr_file_exist(gr_vfs_handle vfs_handle, const char *name, bool *is_exist);
GR_DECLARE int gr_file_open(gr_vfs_handle vfs_handle, const char *name, int flag, gr_file_handle *file_handle);
GR_DECLARE int gr_file_close(gr_vfs_handle vfs_handle, gr_file_handle *file_handle, bool need_lock);
GR_DECLARE int gr_file_truncate(gr_vfs_handle vfs_handle, gr_file_handle file_handle, int truncateType, long long offset);
GR_DECLARE long long int gr_file_pwrite(gr_vfs_handle vfs_handle,
                                        gr_file_handle *file_handle, const void *buf, unsigned long long count, long long offset);
GR_DECLARE long long int gr_file_pread(gr_vfs_handle vfs_handle,
                                        gr_file_handle file_handle, void *buf, unsigned long long count, long long offset);
GR_DECLARE int gr_file_stat(
    gr_vfs_handle vfs_handle, const char *fileName, long long *offset, unsigned long long *count, int *mode, char **time);
GR_DECLARE int gr_file_performance();
GR_DECLARE int gr_file_postpone(gr_vfs_handle vfs_handle, const char *file, const char *time);

// log
GR_DECLARE int gr_get_error(int *errcode, const char **errmsg);
GR_DECLARE void gr_register_log_callback(gr_log_output cb_log_output, unsigned int log_level);
GR_DECLARE void gr_set_log_level(unsigned int log_level);
GR_DECLARE void gr_refresh_logger(char *log_field, unsigned long long *value);

// connection
GR_DECLARE int gr_set_conn_timeout(int timeout);
GR_DECLARE int gr_set_conn_opts(gr_conn_opt_key_e key, void *value, const char *addr);
GR_DECLARE void gr_set_default_conn_timeout(int timeout);
GR_DECLARE int gr_create_inst(const char *storageServerAddr, gr_instance_handle *inst_handle);
GR_DECLARE int gr_create_inst_only_primary(const char *serverAddrs, gr_instance_handle *inst_handle);
GR_DECLARE int gr_delete_inst(gr_instance_handle inst_handle);

// instance param
GR_DECLARE int gr_set_main_inst(const char *storageServerAddr);
GR_DECLARE int gr_get_inst_status(gr_instance_handle inst_handle, 
                                  int *instance_status_id, int *server_status_id,
                                  int *local_instance_id, int *master_id);

GR_DECLARE int gr_get_disk_usage(gr_instance_handle inst_handle,
                                 long long *total_bytes, long long *used_bytes, long long *available_bytes);

// config
GR_DECLARE int gr_set_conf(gr_instance_handle inst_handle, const char *name, const char *value);
GR_DECLARE int gr_get_conf(gr_instance_handle inst_handle, const char *name, char *value);

// version
GR_DECLARE int gr_get_lib_version(void);
GR_DECLARE void gr_show_version(char *version);

// SDK
GR_DECLARE int gr_init(const gr_param_t param);
GR_DECLARE int gr_exit(void);

#ifdef __cplusplus
}
#endif
#endif
