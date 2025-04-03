/*
 * Copyright (c) Huawei Technologies Co.,Ltd. 2024-2024 all rigths reserved.
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
 * wr_cli_conn.h
 *
 *
 * IDENTIFICATION
 *    src/common_api/wr_cli_conn.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_CLI_CONN_H__
#define __WR_CLI_CONN_H__

#include <stdio.h>
#include <stdbool.h>
#include "wr_errno.h"
#include "time.h"
#include "cm_types.h"
#include "wr_thv.h"
#include "wr_protocol.h"
#include "wr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HANDLE_VALUE(handle) ((handle) - (WR_HANDLE_BASE))
#define DB_WR_DEFAULT_UDS_PATH "UDS:/tmp/.wr_unix_d_socket"
extern char g_wr_inst_path[CM_MAX_PATH_LEN];
extern int32 g_wr_uds_conn_timeout;

typedef struct st_wr_conn {
    wr_packet_t pack;  // for sending
    cs_pipe_t pipe;
    void *cli_vg_handles;
    bool32 flag;
    void *session;
    uint32 server_version;
    uint32 proto_version;
#ifdef ENABLE_WRTEST
    pid_t conn_pid;
#endif
    wr_cli_info_t cli_info;
} wr_conn_t;

typedef struct st_wr_conn_opt {
    int32 timeout;
    char *user_name;
} wr_conn_opt_t;

typedef struct st_wr_instance_handle {
    wr_conn_t *conn;
    char addr[CM_MAX_IP_LEN];
} st_wr_instance_handle;

status_t wr_conn_create(pointer_t *result, const char *addr);
status_t wr_conn_opts_create(pointer_t *result, const char *addr);
void wr_conn_opts_release(pointer_t thv_addr);
void wr_conn_release(pointer_t thv_addr);
status_t wr_try_conn(wr_conn_opt_t *options, wr_conn_t *conn, const char *addr);
void wr_clt_env_init(void);
status_t wr_enter_api(wr_conn_t **conn, const char *addr);
void wr_leave_api(wr_conn_t *conn, bool32 get_api_volume_error);

#ifdef __cplusplus
}
#endif


#endif // __WR_CLI_CONN_H__
