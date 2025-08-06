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
 * gr_interaction.c
 *
 *
 * IDENTIFICATION
 *    src/common_api/gr_interaction.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_interaction.h"
#include "gr_thv.h"
#include "gr_cli_conn.h"

#ifdef __cplusplus
extern "C" {
#endif

void gr_cli_get_err(gr_packet_t *pack, int32_t *errcode, char **errmsg)
{
    gr_init_get(pack);
    (void)gr_get_int32(pack, errcode);
    (void)gr_get_str(pack, errmsg);
    if (*errcode == ERR_GR_MES_ILL) {
        LOG_RUN_ERR("[GR API] ABORT INFO : server broadcast failed, errcode:%d, errmsg:%s.", *errcode, *errmsg);
        cm_fync_logfile();
        gr_exit_error();
    }
}

int32_t gr_get_pack_err(gr_conn_t *conn, gr_packet_t *pack)
{
    int32_t errcode = -1;
    char *errmsg = NULL;
    gr_cli_get_err(pack, &errcode, &errmsg);
    if (errcode == ERR_GR_VERSION_NOT_MATCH) {
        conn->server_version = gr_get_version(pack);
        uint32_t new_proto_version = MIN(GR_PROTO_VERSION, conn->server_version);
        LOG_RUN_INF(
            "[CHECK_PROTO]The client protocol version need be changed, old protocol version is %hhu, new protocol version is %hhu.",
            conn->proto_version, new_proto_version);
        conn->proto_version = new_proto_version;
        // if msg version has changed, you need to put new version msg;
        // if msg version has not changed, just change the proto_version and try again.
        gr_set_version(&conn->pack, conn->proto_version);
        gr_set_client_version(&conn->pack, GR_PROTO_VERSION);
        return errcode;
    } else {
        GR_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
}

#ifdef __cplusplus
}
#endif
