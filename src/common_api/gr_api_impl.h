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
 * gr_api_impl.h
 *
 *
 * IDENTIFICATION
 *    src/common_api/gr_api_impl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_API_IMPL_H__
#define __GR_API_IMPL_H__

#include <stdio.h>
#include <stdbool.h>
#include "gr_errno.h"
#include "gr_au.h"
#include "gr_interaction.h"
#include "gr_session.h"
#include "gr_api.h"
#include "gr_file.h"
#include "ssl_func.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_gr_conn gr_conn_t; 
typedef struct st_gr_conn_opt gr_conn_opt_t;

typedef struct st_gr_load_ctrl_info {
    const char *vg_name;
    uint32_t index;
} gr_load_ctrl_info_t;

typedef struct st_gr_open_file_info {
    const char *file_path;
    int flag;
    uint8_t hash[SHA256_DIGEST_LENGTH];
} gr_open_file_info_t;

typedef struct st_gr_close_file_info {
    int64 fd;
    int32 need_lock;
} gr_close_file_info_t;

typedef struct st_gr_create_file_info {
    const char *file_path;
    uint32_t flag;
} gr_create_file_info_t;

typedef struct st_gr_remove_file_info {
    const char *name;
    uint64 attrFlag;
} gr_remove_file_info_t;

typedef struct st_gr_add_or_remove_info {
    const char *vg_name;
    const char *volume_name;
} gr_add_or_remove_info_t;

typedef struct st_gr_extend_info {
    uint64 fid;
    uint64 ftid;
    int64 offset;
    int64 size;
    const char *vg_name;
    uint32_t vg_id;
} gr_extend_info_t;

typedef struct st_gr_rename_file_info {
    const char *src;
    const char *dst;
} gr_rename_file_info_t;

typedef struct st_gr_make_dir_info {
    const char *name;
    uint64 attrFlag;
} gr_make_dir_info_t;

typedef struct st_gr_refresh_file_info {
    uint64 fid;
    uint64 ftid;
    const char *vg_name;
    uint32_t vg_id;
    int64 offset;
} gr_refresh_file_info_t;

typedef struct st_gr_refresh_volume_info {
    uint32_t volume_id;
    const char *vg_name;
    uint32_t vg_id;
} gr_refresh_volume_info_t;

typedef struct st_gr_truncate_file_info {
    int handle;
    int64 length;
    int64 truncateType;
} gr_truncate_file_info_t;

typedef struct st_gr_stat_file_info {
    const char *name;
    int64 offset;
    int64 size;
    int32 mode;
    char *expire_time;
} gr_stat_file_info_t;
typedef struct st_gr_write_file_info {
    int handle;
    int64 offset;
    int64 size;
    int64 rel_size;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    void *buf;
} gr_write_file_info_t;

typedef struct st_gr_read_file_info {
    int handle;
    int64 offset;
    int64 size;
    int64 rel_size;
    void *buf;
} gr_read_file_info_t;

typedef struct st_gr_query_file_num_info {
    uint64 dir;
    uint32_t file_num;
    bool is_continue;
} gr_query_file_num_info_t;

typedef struct st_gr_update_written_size_info {
    uint64 fid;
    uint64 ftid;
    uint32_t vg_id;
    uint64 offset;
    uint64 size;
} gr_update_written_size_info_t;

typedef struct st_gr_setcfg_info {
    const char *name;
    const char *value;
    const char *scope;
} gr_setcfg_info_t;

typedef struct st_gr_symlink_info {
    const char *old_path;
    const char *new_path;
} gr_symlink_info_t;

typedef struct st_gr_remove_dir_info {
    const char *name;
    uint64 attrFlag;
} gr_remove_dir_info_t;

typedef struct st_gr_mount_vfs_info {
    const char *vfs_name;
    uint64_t dir;
} gr_mount_vfs_info_t;

typedef struct st_gr_get_server_info {
    char *home;
    uint32_t objectid;
    bool32 hash_auth_enable;
} gr_get_server_info_t;

bool32 gr_get_conn_hash_auth_enable(gr_conn_t *conn);

typedef struct st_gr_fallocate_info {
    uint64 fid;
    uint64 ftid;
    int64 offset;
    int64 size;
    uint32_t vg_id;
    int32_t mode;
} gr_fallocate_info_t;

typedef struct st_gr_exist_recv_info {
    int32_t result;
    int32_t type;
} gr_exist_recv_info_t;

typedef struct st_gr_postpone_file_time {
    const char *file_name;
    const char *file_atime;
} gr_postpone_file_time_t;

typedef struct {
    int64 total_bytes;
    int64 used_bytes;
    int64 available_bytes;
    double usage_percent;
} gr_disk_usage_ack_t;

#define GRAPI_BLOCK_SIZE 512
#define GR_HOME "GR_HOME"
#define SYS_HOME "HOME"
#define SESSION_LOCK_TIMEOUT 500 // tickets

status_t gr_connect(const char *server_locator, gr_conn_opt_t *options, gr_conn_t *conn);
void gr_disconnect(gr_conn_t *conn);

// NOTE:just for grcmd because not support many threads in one process.
void gr_disconnect_ex(gr_conn_t *conn);
status_t gr_vfs_create_impl(gr_conn_t *conn, const char *dir_name, unsigned long long attrFlag);
status_t gr_vfs_delete_impl(gr_conn_t *conn, const char *dir, unsigned long long attrFlag);
status_t gr_vfs_mount_impl(gr_conn_t *conn, gr_vfs_handle *vfs_handle, unsigned long long attrFlag);
status_t gr_vfs_unmount_impl(gr_conn_t *conn, gr_vfs_handle *vfs_handle);
status_t gr_create_file_impl(gr_conn_t *conn, const char *file_path, int flag);
status_t gr_remove_file_impl(gr_conn_t *conn, const char *file_path, unsigned long long attrFlag);
status_t gr_open_file_impl(gr_conn_t *conn, const char *file_path, int flag, gr_file_handle* file_handle);
status_t gr_close_file_impl(gr_conn_t *conn, int handle, bool need_lock);
status_t gr_exist_impl(gr_conn_t *conn, const char *path, bool32 *result, gft_item_type_t *type);
status_t gr_check_path_exist(gr_conn_t *conn, const char *path);
status_t gr_check_file_exist(gr_conn_t *conn, const char *path, bool *is_exist);
status_t gr_check_file_flag(int flag);
status_t gr_truncate_impl(gr_conn_t *conn, int handle, long long length, int truncateType);
status_t gr_stat_file_impl(
    gr_conn_t *conn, const char *fileName, long long *offset, unsigned long long *count, int *mode, char **time);
status_t gr_postpone_file_time_impl(gr_conn_t *conn, const char *file_name, const char *time);
void gr_clean_file_handle(gr_file_handle *file_handle);

status_t gr_cli_handshake(gr_conn_t *conn, uint32_t max_open_file);
status_t gr_cli_ssl_connect(gr_conn_t *conn);
status_t gr_init_client(uint32_t max_open_files, char *home);
void gr_destroy(void);
status_t gr_vfs_query_file_num_impl(gr_conn_t *conn, gr_vfs_handle vfs_handle, uint32_t *file_num);
status_t gr_vfs_query_file_info_impl(gr_conn_t *conn, gr_vfs_handle vfs_handle, gr_file_item_t *file_info, bool is_continue);

int64 gr_pwrite_file_impl(gr_conn_t *conn, gr_file_handle *file_handle, const void *buf, unsigned long long size, long long offset);
int64 gr_append_file_impl(gr_conn_t *conn, gr_file_handle *file_handle, const void *buf, unsigned long long size);
int64 gr_pread_file_impl(gr_conn_t *conn, int handle, const void *buf, unsigned long long size, long long offset);
status_t gr_setcfg_impl(gr_conn_t *conn, const char *name, const char *value, const char *scope);
status_t gr_getcfg_impl(gr_conn_t *conn, const char *name, char *out_str, size_t str_len);
status_t gr_stop_server_impl(gr_conn_t *conn);
status_t gr_msg_interact(gr_conn_t *conn, uint8 cmd, void *send_info, void *ack);

status_t gr_close_file_on_server(gr_conn_t *conn, int64 fd, bool need_lock);
status_t gr_get_inst_status_on_server(gr_conn_t *conn, gr_server_status_t *gr_status);
status_t gr_get_time_stat_on_server(gr_conn_t *conn, gr_stat_item_t *time_stat, uint64 size);
status_t gr_set_main_inst_impl(gr_conn_t *conn);
status_t gr_reload_certs_impl(gr_conn_t *conn);
status_t gr_reload_cfg_impl(gr_conn_t *conn);
status_t gr_get_disk_usage_impl(gr_conn_t *conn, gr_disk_usage_info_t *info);

#define GR_SET_PTR_VALUE_IF_NOT_NULL(ptr, value) \
    do {                                          \
        if (ptr) {                                \
            (*(ptr) = (value));                   \
        }                                         \
    } while (0)


#ifdef __cplusplus
}
#endif

#endif  // __GR_API_IMPL_H__
