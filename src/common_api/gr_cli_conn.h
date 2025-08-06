/*
 * Copyright (c) Huawei Technologies Co.,Ltd. 2024-2024 all rigths reserved.
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
 * gr_cli_conn.h
 *
 *
 * IDENTIFICATION
 *    src/common_api/gr_cli_conn.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_CLI_CONN_H__
#define __GR_CLI_CONN_H__

#include <stdio.h>
#include <stdbool.h>
#include "gr_errno.h"
#include "time.h"
#include "cm_types.h"
#include "gr_thv.h"
#include "gr_protocol.h"
#include "gr_session.h"
#include "ssl_func.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HANDLE_VALUE(handle) ((handle) - (GR_HANDLE_BASE))
#define DB_GR_DEFAULT_UDS_PATH "UDS:/tmp/.gr_unix_d_socket"
extern char g_gr_inst_path[CM_MAX_PATH_LEN];
extern int32_t g_gr_tcp_conn_timeout;

typedef struct st_gr_conn {
    gr_packet_t pack;  // for sending
    cs_pipe_t pipe;
    ssl_instance_t cli_ssl_inst;
    void *cli_vg_handles;
    bool32 flag;
    void *session;
    uint32_t server_version;
    uint32_t proto_version;
#ifdef ENABLE_GRTEST
    pid_t conn_pid;
#endif
    gr_cli_info_t cli_info;
} gr_conn_t;

typedef struct st_gr_conn_opt {
    int32_t timeout;
    char *user_name;
} gr_conn_opt_t;

typedef struct st_gr_instance_handle {
    gr_conn_t *conn;
    char addr[CM_MAX_IP_LEN];
} st_gr_instance_handle;

status_t gr_conn_create(pointer_t *result, const char *addr);
status_t gr_conn_opts_create(pointer_t *result, const char *addr);
void gr_conn_opts_release(pointer_t thv_addr);
void gr_conn_release(pointer_t thv_addr);
status_t gr_try_conn(gr_conn_opt_t *options, gr_conn_t *conn, const char *addr);
void gr_clt_env_init(void);
status_t gr_enter_api(gr_conn_t **conn, const char *addr);
status_t check_server_addr_format(const char *server_addr);

#ifdef __cplusplus
}
#endif


#endif // __GR_CLI_CONN_H__
