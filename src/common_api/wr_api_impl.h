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
 * wr_api_impl.h
 *
 *
 * IDENTIFICATION
 *    src/common_api/wr_api_impl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_API_IMPL_H__
#define __WR_API_IMPL_H__

#include <stdio.h>
#include <stdbool.h>
#include "wr_errno.h"
#include "wr_au.h"
#include "wr_interaction.h"
#include "wr_session.h"
#include "wr_api.h"
#include "ssl_func.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_wr_conn wr_conn_t; 
typedef struct st_wr_conn_opt wr_conn_opt_t;

typedef struct st_wr_rw_param {
    wr_conn_t *conn;
    int32_t handle;
    wr_env_t *wr_env;
    wr_file_context_t *context;
    int64 offset;
    bool32 atom_oper;
    bool32 is_read;
} wr_rw_param_t;

typedef struct st_wr_load_ctrl_info {
    const char *vg_name;
    uint32_t index;
} wr_load_ctrl_info_t;

typedef struct st_wr_open_file_info {
    const char *file_path;
    int flag;
    uint8_t hash[SHA256_DIGEST_LENGTH];
} wr_open_file_info_t;

typedef struct st_wr_close_file_info {
    int64 fd;
    int32 need_lock;
} wr_close_file_info_t;

typedef struct st_wr_create_file_info {
    const char *file_path;
    uint32_t flag;
} wr_create_file_info_t;

typedef struct st_wr_add_or_remove_info {
    const char *vg_name;
    const char *volume_name;
} wr_add_or_remove_info_t;

typedef struct st_wr_extend_info {
    uint64 fid;
    uint64 ftid;
    int64 offset;
    int64 size;
    const char *vg_name;
    uint32_t vg_id;
} wr_extend_info_t;

typedef struct st_wr_rename_file_info {
    const char *src;
    const char *dst;
} wr_rename_file_info_t;

typedef struct st_wr_make_dir_info {
    const char *name;
    uint64 attrFlag;
} wr_make_dir_info_t;

typedef struct st_wr_refresh_file_info {
    uint64 fid;
    uint64 ftid;
    const char *vg_name;
    uint32_t vg_id;
    int64 offset;
} wr_refresh_file_info_t;

typedef struct st_wr_refresh_volume_info {
    uint32_t volume_id;
    const char *vg_name;
    uint32_t vg_id;
} wr_refresh_volume_info_t;

typedef struct st_wr_truncate_file_info {
    int handle;
    int64 length;
    int64 truncateType;
} wr_truncate_file_info_t;

typedef struct st_wr_stat_file_info {
    const char *name;
    int64 offset;
    int64 size;
    int32 mode;
    char *expire_time;
} wr_stat_file_info_t;
typedef struct st_wr_write_file_info {
    int handle;
    int64 offset;
    int64 size;
    int64 rel_size;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    void *buf;
} wr_write_file_info_t;

typedef struct st_wr_read_file_info {
    int handle;
    int64 offset;
    int64 size;
    int64 rel_size;
    void *buf;
} wr_read_file_info_t;

typedef struct st_wr_query_file_num_info {
    uint64 dir;
    uint32_t file_num;
    bool is_continue;
} wr_query_file_num_info_t;

typedef struct st_wr_update_written_size_info {
    uint64 fid;
    uint64 ftid;
    uint32_t vg_id;
    uint64 offset;
    uint64 size;
} wr_update_written_size_info_t;

typedef struct st_wr_setcfg_info {
    const char *name;
    const char *value;
    const char *scope;
} wr_setcfg_info_t;

typedef struct st_wr_symlink_info {
    const char *old_path;
    const char *new_path;
} wr_symlink_info_t;

typedef struct st_wr_remove_dir_info {
    const char *name;
    uint64 attrFlag;
} wr_remove_dir_info_t;

typedef struct st_wr_mount_vfs_info {
    const char *vfs_name;
    uint64_t dir;
} wr_mount_vfs_info_t;

typedef struct st_wr_get_server_info {
    char *home;
    uint32_t objectid;
    uint32_t server_pid;
} wr_get_server_info_t;

typedef struct st_wr_fallocate_info {
    uint64 fid;
    uint64 ftid;
    int64 offset;
    int64 size;
    uint32_t vg_id;
    int32_t mode;
} wr_fallocate_info_t;

typedef struct st_wr_exist_recv_info {
    int32_t result;
    int32_t type;
} wr_exist_recv_info_t;

typedef struct st_wr_postpone_file_time {
    const char *file_name;
    const char *file_atime;
} wr_postpone_file_time_t;

#define WRAPI_BLOCK_SIZE 512
#define WR_HOME "WR_HOME"
#define SYS_HOME "HOME"
#define WR_DEFAULT_UDS_PATH "UDS:/tmp/.wr_unix_d_socket"
#define SESSION_LOCK_TIMEOUT 500 // tickets

status_t wr_connect(const char *server_locator, wr_conn_opt_t *options, wr_conn_t *conn);
void wr_disconnect(wr_conn_t *conn);

// NOTE:just for wrcmd because not support many threads in one process.
void wr_disconnect_ex(wr_conn_t *conn);
status_t wr_vfs_create_impl(wr_conn_t *conn, const char *dir_name, unsigned long long attrFlag);
status_t wr_vfs_delete_impl(wr_conn_t *conn, const char *dir, unsigned long long attrFlag);
status_t wr_vfs_mount_impl(wr_conn_t *conn, wr_vfs_handle *vfs_handle, unsigned long long attrFlag);
status_t wr_vfs_unmount_impl(wr_conn_t *conn, wr_vfs_handle *vfs_handle);
status_t wr_create_file_impl(wr_conn_t *conn, const char *file_path, int flag);
status_t wr_remove_file_impl(wr_conn_t *conn, const char *file_path);
status_t wr_open_file_impl(wr_conn_t *conn, const char *file_path, int flag, wr_file_handle* file_handle);
status_t wr_close_file_impl(wr_conn_t *conn, int handle, bool need_lock);
status_t wr_exist_impl(wr_conn_t *conn, const char *path, bool32 *result, gft_item_type_t *type);
status_t wr_check_path_exist(wr_conn_t *conn, const char *path);
status_t wr_check_file_exist(wr_conn_t *conn, const char *path, bool *is_exist);
status_t wr_check_file_flag(int flag);
status_t wr_truncate_impl(wr_conn_t *conn, int handle, long long length, int truncateType);
status_t wr_stat_file_impl(
    wr_conn_t *conn, const char *fileName, long long *offset, unsigned long long *count, int *mode, char **time);
status_t wr_postpone_file_time_impl(wr_conn_t *conn, const char *file_name, const char *time);
void wr_clean_file_handle(wr_file_handle *file_handle);

status_t wr_cli_handshake(wr_conn_t *conn, uint32_t max_open_file);
status_t wr_cli_ssl_connect(wr_conn_t *conn);
status_t wr_init_client(uint32_t max_open_files, char *home);
void wr_destroy(void);
status_t wr_vfs_query_file_num_impl(wr_conn_t *conn, wr_vfs_handle vfs_handle, uint32_t *file_num);
status_t wr_vfs_query_file_info_impl(wr_conn_t *conn, wr_vfs_handle vfs_handle, wr_file_item_t *file_info, bool is_continue);

int64 wr_pwrite_file_impl(wr_conn_t *conn, wr_file_handle *file_handle, const void *buf, unsigned long long size, long long offset);
int64 wr_pread_file_impl(wr_conn_t *conn, int handle, const void *buf, unsigned long long size, long long offset);
status_t wr_setcfg_impl(wr_conn_t *conn, const char *name, const char *value, const char *scope);
status_t wr_getcfg_impl(wr_conn_t *conn, const char *name, char *out_str, size_t str_len);
status_t wr_stop_server_impl(wr_conn_t *conn);
status_t wr_msg_interact(wr_conn_t *conn, uint8 cmd, void *send_info, void *ack);

status_t wr_close_file_on_server(wr_conn_t *conn, int64 fd, bool need_lock);
status_t wr_get_inst_status_on_server(wr_conn_t *conn, wr_server_status_t *wr_status);
status_t wr_get_time_stat_on_server(wr_conn_t *conn, wr_stat_item_t *time_stat, uint64 size);
status_t wr_set_main_inst_impl(wr_conn_t *conn);
status_t wr_reload_certs_impl(wr_conn_t *conn);

#define WR_SET_PTR_VALUE_IF_NOT_NULL(ptr, value) \
    do {                                          \
        if (ptr) {                                \
            (*(ptr) = (value));                   \
        }                                         \
    } while (0)

#define WR_UNLOCK_VG_META_S(vg_item, session) \
    (void)wr_unlock_shm_meta_s_with_stack((session), (vg_item)->vg_latch, CM_FALSE)

#define WR_RW_STEP_SIZE (8192)

#ifdef __cplusplus
}
#endif

#endif  // __WR_API_IMPL_H__
