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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_wr_conn wr_conn_t; 
typedef struct st_wr_conn_opt wr_conn_opt_t;

typedef struct st_wr_rw_param {
    wr_conn_t *conn;
    int32 handle;
    wr_env_t *wr_env;
    wr_file_context_t *context;
    int64 offset;
    bool32 atom_oper;
    bool32 is_read;
} wr_rw_param_t;

typedef struct st_wr_load_ctrl_info {
    const char *vg_name;
    uint32 index;
} wr_load_ctrl_info_t;

typedef struct st_wr_open_file_info {
    const char *file_path;
    int flag;
} wr_open_file_info_t;

typedef struct st_wr_close_file_info {
    int64_t fd;
} wr_close_file_info_t;

typedef struct st_wr_create_file_info {
    const char *file_path;
    uint32 flag;
} wr_create_file_info_t;

typedef struct st_wr_open_dir_info {
    const char *dir_path;
    bool32 refresh_recursive;
} wr_open_dir_info_t;

typedef struct st_wr_close_dir_info {
    uint64 pftid;
    const char *vg_name;
    uint32 vg_id;
} wr_close_dir_info_t;

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
    uint32 vg_id;
} wr_extend_info_t;

typedef struct st_wr_rename_file_info {
    const char *src;
    const char *dst;
} wr_rename_file_info_t;

typedef struct st_wr_make_dir_info {
    const char *name;
    uint64_t attrFlag;
} wr_make_dir_info_t;

typedef struct st_wr_refresh_file_info {
    uint64 fid;
    uint64 ftid;
    const char *vg_name;
    uint32 vg_id;
    int64 offset;
} wr_refresh_file_info_t;

typedef struct st_wr_refresh_volume_info {
    uint32 volume_id;
    const char *vg_name;
    uint32 vg_id;
} wr_refresh_volume_info_t;

typedef struct st_wr_truncate_file_info {
    int64 length;
    int64 handle;
    int64 truncateType;
} wr_truncate_file_info_t;

typedef struct st_wr_write_file_info {
    int64 offset;
    int64 handle;
    int64 size;
    void *buf;
} wr_write_file_info_t;

typedef struct st_wr_read_file_info {
    int64 offset;
    int64 handle;
    int64 size;
    void *buf;
} wr_read_file_info_t;

typedef struct st_wr_query_file_num_info {
    const char *vfs_name;
    uint32 file_num;
} wr_query_file_num_info_t;

typedef struct st_wr_refresh_file_table_info {
    uint64 block_id;
    const char *vg_name;
    uint32 vg_id;
} wr_refresh_file_table_info_t;

typedef struct st_wr_update_written_size_info {
    uint64 fid;
    uint64 ftid;
    uint32 vg_id;
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
    bool recursive;
} wr_remove_dir_info_t;

typedef struct st_wr_get_server_info {
    char *home;
    uint32 objectid;
    uint32 server_pid;
} wr_get_server_info_t;

typedef struct st_wr_fallocate_info {
    uint64 fid;
    uint64 ftid;
    int64 offset;
    int64 size;
    uint32 vg_id;
    int32 mode;
} wr_fallocate_info_t;

typedef struct st_wr_exist_recv_info {
    int32 result;
    int32 type;
} wr_exist_recv_info_t;

#define WRAPI_BLOCK_SIZE 512
#define WR_HOME "WR_HOME"
#define SYS_HOME "HOME"
#define WR_DEFAULT_UDS_PATH "UDS:/tmp/.wr_unix_d_socket"
#define SESSION_LOCK_TIMEOUT 500 // tickets

status_t wr_kick_host_sync(wr_conn_t *conn, int64 kick_hostid);
status_t wr_alloc_conn(wr_conn_t **conn);
void wr_free_conn(wr_conn_t *conn);
status_t wr_connect(const char *server_locator, wr_conn_opt_t *options, wr_conn_t *conn);
void wr_disconnect(wr_conn_t *conn);

// NOTE:just for wrcmd because not support many threads in one process.
status_t wr_connect_ex(const char *server_locator, wr_conn_opt_t *options, wr_conn_t *conn);
void wr_disconnect_ex(wr_conn_t *conn);
status_t wr_lock_vg_s(wr_vg_info_item_t *vg_item, wr_session_t *session);
status_t wr_cli_session_lock(wr_conn_t *conn, wr_session_t *session);
status_t wr_vfs_create_impl(wr_conn_t *conn, const char *dir_name, unsigned long long attrFlag);
status_t wr_vfs_delete_impl(wr_conn_t *conn, const char *dir, unsigned long long attrFlag);
wr_vfs_t *wr_open_dir_impl(wr_conn_t *conn, const char *dir_path, bool32 refresh_recursive);
gft_node_t *wr_read_dir_impl(wr_conn_t *conn, wr_vfs_t *dir, bool32 skip_delete);
status_t wr_close_dir_impl(wr_conn_t *conn, wr_vfs_t *dir);
status_t wr_create_file_impl(wr_conn_t *conn, const char *file_path, int flag);
status_t wr_remove_file_impl(wr_conn_t *conn, const char *file_path);
status_t wr_open_file_impl(wr_conn_t *conn, const char *file_path, int flag, int *handle);
status_t wr_close_file_impl(wr_conn_t *conn, int handle);
status_t wr_exist_impl(wr_conn_t *conn, const char *path, bool32 *result, gft_item_type_t *type);
int64 wr_seek_file_impl(wr_conn_t *conn, int handle, int64 offset, int origin);
status_t wr_write_file_impl(wr_conn_t *conn, int handle, const void *buf, unsigned long long size, long long int offset);
status_t wr_rename_file_impl(wr_conn_t *conn, const char *src, const char *dst);
status_t wr_truncate_impl(wr_conn_t *conn, int handle, long long length, int truncateType);
status_t wr_fstat_impl(wr_conn_t *conn, int handle, wr_stat_info_t item);
status_t wr_set_stat_info(wr_stat_info_t item, gft_node_t *node);

status_t wr_cli_handshake(wr_conn_t *conn, uint32 max_open_file);
status_t wr_init_client(uint32 max_open_files, char *home);
void wr_destroy(void);
status_t wr_get_fname_impl(int handle, char *fname, int fname_size);
status_t wr_vfs_query_file_num_impl(wr_conn_t *conn, const char *vfs_name, uint32 *file_num);

status_t wr_pwrite_file_impl(wr_conn_t *conn, int handle, const void *buf, int size, long long offset);
status_t wr_pread_file_impl(wr_conn_t *conn, int handle, const void *buf, unsigned long long size, long long offset);
status_t wr_get_addr_impl(wr_conn_t *conn, int32 handle, long long offset, char *pool_name, char *image_name,
    char *obj_addr, unsigned int *obj_id, unsigned long int *obj_offset);
gft_node_t *wr_get_node_by_path_impl(wr_conn_t *conn, const char *path);
status_t wr_setcfg_impl(wr_conn_t *conn, const char *name, const char *value, const char *scope);
status_t wr_getcfg_impl(wr_conn_t *conn, const char *name, char *out_str, size_t str_len);
status_t wr_stop_server_impl(wr_conn_t *conn);
void wr_get_api_volume_error(void);
status_t wr_get_phy_size_impl(wr_conn_t *conn, int handle, long long *size);
status_t wr_msg_interact(wr_conn_t *conn, uint8 cmd, void *send_info, void *ack);
status_t wr_fallocate_impl(wr_conn_t *conn, int handle, int mode, long long int offset, long long int length);

void wr_set_conn_wait_event(wr_conn_t *conn, wr_wait_event_e event);
void wr_unset_conn_wait_event(wr_conn_t *conn);
status_t wr_msg_interact_with_stat(wr_conn_t *conn, uint8 cmd, void *send_info, void *ack);

status_t wr_close_file_on_server(wr_conn_t *conn, int64_t fd);
status_t wr_get_inst_status_on_server(wr_conn_t *conn, wr_server_status_t *wr_status);
status_t wr_get_time_stat_on_server(wr_conn_t *conn, wr_stat_item_t *time_stat, uint64 size);
status_t wr_set_main_inst_on_server(wr_conn_t *conn);

#define WR_SET_PTR_VALUE_IF_NOT_NULL(ptr, value) \
    do {                                          \
        if (ptr) {                                \
            (*(ptr) = (value));                   \
        }                                         \
    } while (0)

#define WR_LOCK_VG_META_S_RETURN_ERROR(vg_item, session)                          \
    do {                                                                           \
        if (SECUREC_UNLIKELY(wr_lock_vg_s((vg_item), (session)) != CM_SUCCESS)) { \
            return CM_ERROR;                                                       \
        }                                                                          \
    } while (0)

#define WR_LOCK_VG_META_S_RETURN_NULL(vg_item, session)                           \
    do {                                                                           \
        if (SECUREC_UNLIKELY(wr_lock_vg_s((vg_item), (session)) != CM_SUCCESS)) { \
            return NULL;                                                           \
        }                                                                          \
    } while (0)

#define WR_UNLOCK_VG_META_S(vg_item, session) \
    (void)wr_unlock_shm_meta_s_with_stack((session), (vg_item)->vg_latch, CM_FALSE)

#define WR_RW_STEP_SIZE (8192)

#ifdef __cplusplus
}
#endif

#endif  // __WR_API_IMPL_H__
