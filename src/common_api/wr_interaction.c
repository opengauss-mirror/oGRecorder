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
 * wr_interaction.c
 *
 *
 * IDENTIFICATION
 *    src/common_api/wr_interaction.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_interaction.h"
#include "wr_thv.h"
#include "wr_cli_conn.h"

#ifdef __cplusplus
extern "C" {
#endif

void wr_cli_get_err(wr_packet_t *pack, int32 *errcode, char **errmsg)
{
    wr_init_get(pack);
    (void)wr_get_int32(pack, errcode);
    (void)wr_get_str(pack, errmsg);
    if (*errcode == ERR_WR_MES_ILL) {
        LOG_RUN_ERR("[WR API] ABORT INFO : server broadcast failed, errcode:%d, errmsg:%s.", *errcode, *errmsg);
        cm_fync_logfile();
        wr_exit(1);
    }
}

int32 wr_get_pack_err(wr_conn_t *conn, wr_packet_t *pack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    wr_cli_get_err(pack, &errcode, &errmsg);
    if (errcode == ERR_WR_VERSION_NOT_MATCH) {
        conn->server_version = wr_get_version(pack);
        uint32 new_proto_version = MIN(WR_PROTO_VERSION, conn->server_version);
        LOG_RUN_INF(
            "[CHECK_PROTO]The client protocol version need be changed, old protocol version is %hhu, new protocol version is %hhu.",
            conn->proto_version, new_proto_version);
        conn->proto_version = new_proto_version;
        // if msg version has changed, you need to put new version msg;
        // if msg version has not changed, just change the proto_version and try again.
        wr_set_version(&conn->pack, conn->proto_version);
        wr_set_client_version(&conn->pack, WR_PROTO_VERSION);
        return errcode;
    } else {
        WR_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
}

#ifdef __cplusplus
}
#endif
