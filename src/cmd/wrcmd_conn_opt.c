#include "wr_api_impl.h"
#include "wr_interaction.h"
#include "wrcmd.h"
#include "wrcmd_conn_opt.h"
#include "wr_cli_conn.h"

#define WR_SUBSTR_UDS_PATH "UDS:"

typedef struct {
    wr_conn_t conn;
    bool8 is_connected;
    char server_locator[WR_MAX_PATH_BUFFER_SIZE];
} wr_uds_conn_t;

static wr_uds_conn_t g_wr_uds_conn = {};  /* global connection for wrCmd */

/**
 * [brief] disconnect uds connection
 * @param [IN] wr_conn
 */
void wr_disconnect_ex_conn()
{
    if (g_wr_uds_conn.is_connected) {
        wr_disconnect_ex(&g_wr_uds_conn.conn);
        g_wr_uds_conn.is_connected = false;
        (void)memset_s(&g_wr_uds_conn.conn, sizeof(wr_conn_t), 0, sizeof(wr_conn_t));
    }
}

/**
 * [brief] disconnect all uds connection
 * */
void wr_conn_opt_exit()
{
    wr_disconnect_ex_conn();
}

/**
 * [brief] setup a new connection
 * @param [IN] server_locator
 * @param [OUT] wr_conn
 * @return
 */
static status_t wr_uds_set_up_connection(const char *server_locator, wr_uds_conn_t *wr_conn)
{
    status_t status = wr_connect_ex(server_locator, NULL, &wr_conn->conn);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to set up connect(url:%s)\n", server_locator);
        return status;
    }
    wr_conn->is_connected = true;
    return CM_SUCCESS;
}

/**
 * [brief] first setup a connection or use the exist connection
 * @param [IN] input_args
 * @return [OUT] uds connection
 */
wr_conn_t *wr_get_connection_opt(const char *input_args)
{
    if (g_wr_uds_conn.is_connected && input_args != NULL) {
        (void)printf("You are about to changing connection, the operation is not allowed!(%s)\n", input_args);
        return NULL;
    }
    /* use the connected conn if */
    if (g_wr_uds_conn.is_connected) {
        return &g_wr_uds_conn.conn;
    }

    status_t status = wr_uds_set_up_connection(g_wr_uds_conn.server_locator, &g_wr_uds_conn);
    if (status != CM_SUCCESS) {
        return NULL;
    }
    return &g_wr_uds_conn.conn;
}

bool8 wr_get_connection_opt_status()
{
    return g_wr_uds_conn.is_connected;
}