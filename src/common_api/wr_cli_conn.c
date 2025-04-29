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
 * wr_cli_conn.c
 *
 *
 * IDENTIFICATION
 *    src/common_api/wr_cli_conn.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_cli_conn.h"
#include "wr_api_impl.h"
#include "wr_malloc.h"

#ifdef __cplusplus
extern "C" {
#endif

char g_wr_inst_path[CM_MAX_PATH_LEN] = {0};
typedef struct st_wr_conn_info {
    // protect connections
    latch_t conn_latch;
    uint32 conn_num;
    bool32 isinit;
    int32 timeout;  // - 1: never time out
} wr_conn_info_t;
static wr_conn_info_t g_wr_conn_info = {{0, 0, 0, 0, 0}, 0, CM_FALSE, 0};

void wr_conn_release(pointer_t thv_addr)
{
    wr_conn_t *conn = (wr_conn_t *)thv_addr;
    if (conn->pipe.link.uds.closed != CM_TRUE) {
        wr_disconnect(conn);
        cm_latch_x(&g_wr_conn_info.conn_latch, 1, NULL);
        g_wr_conn_info.conn_num--;
        if (g_wr_conn_info.conn_num == 0) {
            wr_destroy();
        }
        cm_unlatch(&g_wr_conn_info.conn_latch, NULL);
    }
    WR_FREE_POINT(conn);
}

void wr_conn_opts_release(pointer_t thv_addr)
{
    WR_FREE_POINT(thv_addr);
}

static thv_ctrl_t g_wr_thv_ctrls[] = {
    {NULL, wr_conn_create, wr_conn_release},
    {NULL, wr_conn_opts_create, wr_conn_opts_release},
};

void wr_clt_env_init(void)
{
    if (g_wr_conn_info.isinit == CM_FALSE) {
        cm_latch_x(&g_wr_conn_info.conn_latch, 1, NULL);
        if (g_wr_conn_info.isinit == CM_FALSE) {
            status_t status = cm_launch_thv(g_wr_thv_ctrls, sizeof(g_wr_thv_ctrls) / sizeof(g_wr_thv_ctrls[0]));
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("wr client initialization failed.");
                cm_unlatch(&g_wr_conn_info.conn_latch, NULL);
                return;
            }
            g_wr_conn_info.isinit = CM_TRUE;
        }
        cm_unlatch(&g_wr_conn_info.conn_latch, NULL);
    }
}

status_t wr_try_conn(wr_conn_opt_t *options, wr_conn_t *conn, const char *addr)
{
    // establish connection
    status_t status = CM_ERROR;
    cm_latch_x(&g_wr_conn_info.conn_latch, 1, NULL);
    do {
        // avoid buffer leak when disconnect
        wr_free_packet_buffer(&conn->pack);
        status = wr_connect(addr, options, conn);
        WR_BREAK_IFERR2(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "wr client connet server failed."));
        uint32 max_open_file = WR_MAX_OPEN_FILES;
        conn->proto_version = WR_PROTO_VERSION;
        status = wr_cli_handshake(conn, max_open_file);
        WR_BREAK_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "wr client handshake to server failed."),
            wr_disconnect(conn));

        g_wr_conn_info.conn_num++;
    } while (0);
    cm_unlatch(&g_wr_conn_info.conn_latch, NULL);
    return status;
}

status_t wr_conn_opts_create(pointer_t *result, const char *addr)
{
    wr_conn_opt_t *options = (wr_conn_opt_t *)cm_malloc(sizeof(wr_conn_opt_t));
    if (options == NULL) {
        WR_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(wr_conn_opt_t), "wr_conn_opts_create");
        return CM_ERROR;
    }
    (void)memset_s(options, sizeof(wr_conn_opt_t), 0, sizeof(wr_conn_opt_t));
    *result = options;
    return CM_SUCCESS;
}

static status_t wr_conn_sync(wr_conn_opt_t *options, wr_conn_t *conn, const char *addr)
{
    status_t ret = CM_ERROR;
    int timeout = (options != NULL ? options->timeout : g_wr_tcp_conn_timeout);
    do {
        ret = wr_try_conn(options, conn, addr);
        if (ret == CM_SUCCESS) {
            break;
        }
        if (cm_get_os_error() == ENOENT) {
            break;
        }
    } while (timeout == WR_CONN_NEVER_TIMEOUT);
    return ret;
}

status_t wr_conn_create(pointer_t *result, const char *addr)
{
    wr_conn_t *conn = (wr_conn_t *)cm_malloc(sizeof(wr_conn_t));
    if (conn == NULL) {
        WR_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(wr_conn_t), "wr_conn_create");
        return CM_ERROR;
    }

    (void)memset_s(conn, sizeof(wr_conn_t), 0, sizeof(wr_conn_t));

    // init packet
    wr_init_packet(&conn->pack, conn->pipe.options);
    wr_conn_opt_t *options = NULL;
    (void)cm_get_thv(GLOBAL_THV_OBJ1, CM_FALSE, (pointer_t *)&options, addr);
    if (wr_conn_sync(options, conn, addr) != CM_SUCCESS) {
        WR_THROW_ERROR(ERR_WR_CONNECT_FAILED, cm_get_os_error(), strerror(cm_get_os_error()));
        WR_FREE_POINT(conn);
        return CM_ERROR;
    }
#ifdef ENABLE_WRTEST
    conn->conn_pid = getpid();
#endif
    *result = conn;
    return CM_SUCCESS;
}

static status_t wr_get_conn(wr_conn_t **conn, const char *addr)
{
    cm_reset_error();
    wr_clt_env_init();
    if (cm_get_thv(GLOBAL_THV_OBJ0, CM_TRUE, (pointer_t *)conn, addr) != CM_SUCCESS) {
        LOG_RUN_ERR("[WR API] ABORT INFO : wr server stoped, application need restart.");
        cm_fync_logfile();
        wr_exit_error();
    }

#ifdef ENABLE_WRTEST
    if ((*conn)->flag && (*conn)->conn_pid != getpid()) {
        LOG_RUN_INF("wr client need re-connect, last conn pid:%llu.", (uint64)(*conn)->conn_pid);
        wr_disconnect(*conn);
        if (wr_conn_sync(NULL, *conn, addr) != CM_SUCCESS) {
            LOG_RUN_ERR("[WR API] ABORT INFO: wr server stoped, application need restart.");
            cm_fync_logfile();
            wr_exit_error();
        }
        (*conn)->conn_pid = getpid();
    }
#endif

    if ((*conn)->pipe.link.uds.closed) {
        LOG_RUN_ERR("[WR API] ABORT INFO : wr server stoped, application need restart.");
        cm_fync_logfile();
        wr_exit_error();
    }
    return CM_SUCCESS;
}

status_t wr_enter_api(wr_conn_t **conn, const char *addr)
{
    status_t status = wr_get_conn(conn, addr);
    if (status != CM_SUCCESS) {
        return status;
    }
    return CM_SUCCESS;
}

status_t check_server_addr_format(const char *server_addr)
{
    if (server_addr == NULL) {
        LOG_RUN_ERR("[WR API] ERROR INFO : server address is NULL.");
        return WR_ERROR;
    }

    size_t addr_len = strlen(server_addr);
    if (addr_len == 0 || addr_len >= CM_MAX_IP_LEN) {
        LOG_RUN_ERR("[WR API] ERROR INFO : invalid server address length: %zu.", addr_len);
        return WR_ERROR;
    }

    const char *port_sep = strrchr(server_addr, ':');
    if (port_sep == NULL) {
        LOG_RUN_ERR("[WR API] ERROR INFO : server address(%s) format error: missing port", server_addr);
        return WR_ERROR;
    }

    size_t ip_len = port_sep - server_addr;
    if (ip_len == 0 || ip_len >= CM_MAX_IP_LEN) {
        LOG_RUN_ERR("[WR API] ERROR INFO : invalid IP length in server address(%s)", server_addr);
        return WR_ERROR;
    }

    const char *port_str = port_sep + 1;
    if (*port_str == '\0') {
        LOG_RUN_ERR("[WR API] ERROR INFO : server address(%s) format error: empty port", server_addr);
        return WR_ERROR;
    }

    char *end_ptr = NULL;
    long port = strtol(port_str, &end_ptr, 10);
    if (*end_ptr != '\0' || port <= 0 || port > 65535) {
        LOG_RUN_ERR("[WR API] ERROR INFO : invalid port number in server address(%s)", server_addr);
        return WR_ERROR;
    }

    char ip_buf[CM_MAX_IP_LEN] = {0};
    errno_t rc = strncpy_s(ip_buf, CM_MAX_IP_LEN, server_addr, ip_len);
    if (rc != EOK) {
        LOG_RUN_ERR("[WR API] ERROR INFO : failed to copy IP address");
        return WR_ERROR;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_buf, &addr) != 1) {
        LOG_RUN_ERR("[WR API] ERROR INFO : invalid IP format in server address(%s)", server_addr);
        return WR_ERROR;
    }

    return WR_SUCCESS;
}

void wr_leave_api(wr_conn_t *conn, bool32 get_api_volume_error)
{
    cm_spin_unlock(&((wr_session_t *)(conn->session))->shm_lock);
    LOG_DEBUG_INF("Succeed to unlock session %u shm lock", ((wr_session_t *)(conn->session))->id);
    if (get_api_volume_error) {
        wr_get_api_volume_error();
    }
}

#ifdef __cplusplus
}
#endif
