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
 * gr_cli_conn.c
 *
 *
 * IDENTIFICATION
 *    src/common_api/gr_cli_conn.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_cli_conn.h"
#include "gr_api_impl.h"
#include "gr_malloc.h"

#ifdef __cplusplus
extern "C" {
#endif

char g_gr_inst_path[CM_MAX_PATH_LEN] = {0};
typedef struct st_gr_conn_info {
    // protect connections
    latch_t conn_latch;
    uint32_t conn_num;
    bool32 isinit;
    int32_t timeout;  // - 1: never time out
} gr_conn_info_t;
static gr_conn_info_t g_gr_conn_info = {{0, 0, 0, 0, 0}, 0, CM_FALSE, 0};

void gr_conn_release(pointer_t thv_addr)
{
    gr_conn_t *conn = (gr_conn_t *)thv_addr;
    if (conn->pipe.link.uds.closed != CM_TRUE) {
        gr_disconnect(conn);
        cm_latch_x(&g_gr_conn_info.conn_latch, 1, NULL);
        g_gr_conn_info.conn_num--;
        if (g_gr_conn_info.conn_num == 0) {
            gr_destroy();
        }
        cm_unlatch(&g_gr_conn_info.conn_latch, NULL);
    }
    GR_FREE_POINT(conn);
}

void gr_conn_opts_release(pointer_t thv_addr)
{
    GR_FREE_POINT(thv_addr);
}

static thv_ctrl_t g_gr_thv_ctrls[] = {
    {NULL, gr_conn_create, gr_conn_release},
    {NULL, gr_conn_opts_create, gr_conn_opts_release},
};

void gr_clt_env_init(void)
{
    if (g_gr_conn_info.isinit == CM_FALSE) {
        cm_latch_x(&g_gr_conn_info.conn_latch, 1, NULL);
        if (g_gr_conn_info.isinit == CM_FALSE) {
            status_t status = cm_launch_thv(g_gr_thv_ctrls, sizeof(g_gr_thv_ctrls) / sizeof(g_gr_thv_ctrls[0]));
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("gr client initialization failed.");
                cm_unlatch(&g_gr_conn_info.conn_latch, NULL);
                return;
            }
            g_gr_conn_info.isinit = CM_TRUE;
        }
        cm_unlatch(&g_gr_conn_info.conn_latch, NULL);
    }
}

status_t gr_try_conn(gr_conn_opt_t *options, gr_conn_t *conn, const char *addr)
{
    // establish connection
    status_t status = CM_ERROR;
    cm_latch_x(&g_gr_conn_info.conn_latch, 1, NULL);
    do {
        // avoid buffer leak when disconnect
        gr_free_packet_buffer(&conn->pack);
        status = gr_connect(addr, options, conn);
        GR_BREAK_IFERR2(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "gr client connet server failed."));
        uint32_t max_open_file = GR_MAX_OPEN_FILES;
        conn->proto_version = GR_PROTO_VERSION;
        status = gr_cli_handshake(conn, max_open_file);
        GR_BREAK_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "gr client handshake to server failed."),
            gr_disconnect(conn));
        status = gr_cli_ssl_connect(conn);
        GR_BREAK_IFERR2(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "gr client ssl connet server failed."));
        g_gr_conn_info.conn_num++;
    } while (0);
    cm_unlatch(&g_gr_conn_info.conn_latch, NULL);
    return status;
}

status_t gr_conn_opts_create(pointer_t *result, const char *addr)
{
    gr_conn_opt_t *options = (gr_conn_opt_t *)cm_malloc(sizeof(gr_conn_opt_t));
    if (options == NULL) {
        GR_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(gr_conn_opt_t), "gr_conn_opts_create");
        return CM_ERROR;
    }
    (void)memset_s(options, sizeof(gr_conn_opt_t), 0, sizeof(gr_conn_opt_t));
    *result = options;
    return CM_SUCCESS;
}

static status_t gr_conn_sync(gr_conn_opt_t *options, gr_conn_t *conn, const char *addr)
{
    status_t ret = CM_ERROR;
    int timeout = (options != NULL ? options->timeout : g_gr_tcp_conn_timeout);
    do {
        ret = gr_try_conn(options, conn, addr);
        if (ret == CM_SUCCESS) {
            break;
        }
        if (cm_get_os_error() == ENOENT) {
            break;
        }
    } while (timeout == GR_CONN_NEVER_TIMEOUT);
    return ret;
}

status_t gr_conn_create(pointer_t *result, const char *addr)
{
    gr_conn_t *conn = (gr_conn_t *)cm_malloc(sizeof(gr_conn_t));
    if (conn == NULL) {
        GR_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(gr_conn_t), "gr_conn_create");
        return CM_ERROR;
    }

    (void)memset_s(conn, sizeof(gr_conn_t), 0, sizeof(gr_conn_t));

    // init packet
    gr_init_packet(&conn->pack, conn->pipe.options);
    gr_conn_opt_t *options = NULL;
    (void)cm_get_thv(GLOBAL_THV_OBJ1, CM_FALSE, (pointer_t *)&options, addr);
    if (gr_conn_sync(options, conn, addr) != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_CONNECT_FAILED, cm_get_os_error(), strerror(cm_get_os_error()));
        GR_FREE_POINT(conn);
        return CM_ERROR;
    }
#ifdef ENABLE_GRTEST
    conn->conn_pid = getpid();
#endif
    *result = conn;
    return CM_SUCCESS;
}

static status_t gr_get_conn(gr_conn_t **conn, const char *addr)
{
    cm_reset_error();
    gr_clt_env_init();
    if (cm_get_thv(GLOBAL_THV_OBJ0, CM_TRUE, (pointer_t *)conn, addr) != CM_SUCCESS) {
        LOG_RUN_ERR("[GR API] connection failed, reason: %s", strerror(cm_get_os_error()));
        GR_THROW_ERROR(ERR_GR_CONNECT_FAILED, cm_get_os_error(), strerror(cm_get_os_error()));
        return CM_ERROR;
    }

    if ((*conn)->pipe.link.uds.closed) {
        LOG_RUN_ERR("[GR API] connection is closed");
        GR_THROW_ERROR(ERR_GR_CONNECTION_CLOSED);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_enter_api(gr_conn_t **conn, const char *addr)
{
    status_t status = gr_get_conn(conn, addr);
    if (status != CM_SUCCESS) {
        return status;
    }
    return CM_SUCCESS;
}

status_t check_server_addr_format(const char *server_addr)
{
    if (server_addr == NULL) {
        LOG_RUN_ERR("[GR API] ERROR INFO : server address is NULL.");
        return GR_ERROR;
    }

    size_t addr_len = strlen(server_addr);
    if (addr_len == 0 || addr_len >= CM_MAX_IP_LEN) {
        LOG_RUN_ERR("[GR API] ERROR INFO : invalid server address length: %zu.", addr_len);
        return GR_ERROR;
    }

    const char *port_sep = strrchr(server_addr, ':');
    if (port_sep == NULL) {
        LOG_RUN_ERR("[GR API] ERROR INFO : server address(%s) format error: missing port", server_addr);
        return GR_ERROR;
    }

    size_t ip_len = port_sep - server_addr;
    if (ip_len == 0 || ip_len >= CM_MAX_IP_LEN) {
        LOG_RUN_ERR("[GR API] ERROR INFO : invalid IP length in server address(%s)", server_addr);
        return GR_ERROR;
    }

    const char *port_str = port_sep + 1;
    if (*port_str == '\0') {
        LOG_RUN_ERR("[GR API] ERROR INFO : server address(%s) format error: empty port", server_addr);
        return GR_ERROR;
    }

    char *end_ptr = NULL;
    long port = strtol(port_str, &end_ptr, 10);
    if (*end_ptr != '\0' || port <= 0 || port > 65535) {
        LOG_RUN_ERR("[GR API] ERROR INFO : invalid port number in server address(%s)", server_addr);
        return GR_ERROR;
    }

    char ip_buf[CM_MAX_IP_LEN] = {0};
    errno_t rc = strncpy_s(ip_buf, CM_MAX_IP_LEN, server_addr, ip_len);
    if (rc != EOK) {
        LOG_RUN_ERR("[GR API] ERROR INFO : failed to copy IP address");
        return GR_ERROR;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_buf, &addr) != 1) {
        LOG_RUN_ERR("[GR API] ERROR INFO : invalid IP format in server address(%s)", server_addr);
        return GR_ERROR;
    }

    return GR_SUCCESS;
}

#ifdef __cplusplus
}
#endif
