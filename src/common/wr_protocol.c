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
 * wr_protocol.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_protocol.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_errno.h"
#include "wr_log.h"
#include "wr_thv.h"
#include "wr_protocol.h"


static char *g_wr_cmd_desc[WR_CMD_TYPE_OFFSET(WR_CMD_END)] = {
    [WR_CMD_TYPE_OFFSET(WR_CMD_MKDIR)] = "mkdir",
    [WR_CMD_TYPE_OFFSET(WR_CMD_RMDIR)] = "rmdir",
    [WR_CMD_TYPE_OFFSET(WR_CMD_QUERY_FILE_NUM)] = "query file num",
    [WR_CMD_TYPE_OFFSET(WR_CMD_OPEN_DIR)] = "open dir",
    [WR_CMD_TYPE_OFFSET(WR_CMD_CLOSE_DIR)] = "close dir",
    [WR_CMD_TYPE_OFFSET(WR_CMD_OPEN_FILE)] = "open file",
    [WR_CMD_TYPE_OFFSET(WR_CMD_CLOSE_FILE)] = "close file",
    [WR_CMD_TYPE_OFFSET(WR_CMD_CREATE_FILE)] = "create file",
    [WR_CMD_TYPE_OFFSET(WR_CMD_DELETE_FILE)] = "delete file",
    [WR_CMD_TYPE_OFFSET(WR_CMD_WRITE_FILE)] = "write file",
    [WR_CMD_TYPE_OFFSET(WR_CMD_READ_FILE)] = "read file",
    [WR_CMD_TYPE_OFFSET(WR_CMD_EXTEND_FILE)] = "extend file",
    [WR_CMD_TYPE_OFFSET(WR_CMD_RENAME_FILE)] = "rename file",
    [WR_CMD_TYPE_OFFSET(WR_CMD_REFRESH_FILE)] = "refresh file",
    [WR_CMD_TYPE_OFFSET(WR_CMD_TRUNCATE_FILE)] = "truncate file",
    [WR_CMD_TYPE_OFFSET(WR_CMD_FALLOCATE_FILE)] = "fallocate file",
    [WR_CMD_TYPE_OFFSET(WR_CMD_KICKH)] = "kick off host",
    [WR_CMD_TYPE_OFFSET(WR_CMD_LOAD_CTRL)] = "load ctrl",
    [WR_CMD_TYPE_OFFSET(WR_CMD_UPDATE_WRITTEN_SIZE)] = "update written size",
    [WR_CMD_TYPE_OFFSET(WR_CMD_STOP_SERVER)] = "stopserver",
    [WR_CMD_TYPE_OFFSET(WR_CMD_SETCFG)] = "setcfg",
    [WR_CMD_TYPE_OFFSET(WR_CMD_SET_MAIN_INST)] = "set main inst",
    [WR_CMD_TYPE_OFFSET(WR_CMD_SWITCH_LOCK)] = "switch cm lock",
    [WR_CMD_TYPE_OFFSET(WR_CMD_HANDSHAKE)] = "handshake with server",
    [WR_CMD_TYPE_OFFSET(WR_CMD_EXIST)] = "exist item",
    [WR_CMD_TYPE_OFFSET(WR_CMD_GET_FTID_BY_PATH)] = "get ftid by path",
    [WR_CMD_TYPE_OFFSET(WR_CMD_GETCFG)] = "getcfg",
    [WR_CMD_TYPE_OFFSET(WR_CMD_GET_INST_STATUS)] = "get inst status",
    [WR_CMD_TYPE_OFFSET(WR_CMD_GET_TIME_STAT)] = "get time stat",
    [WR_CMD_TYPE_OFFSET(WR_CMD_EXEC_REMOTE)] = "exec remote",
    [WR_CMD_TYPE_OFFSET(WR_CMD_QUERY_HOTPATCH)] = "query status of hotpatch",
};

char *wr_get_cmd_desc(wr_cmd_type_e cmd_type)
{
    if (cmd_type < WR_CMD_BEGIN || cmd_type >= WR_CMD_END) {
        return "unknown";
    }
    return g_wr_cmd_desc[WR_CMD_TYPE_OFFSET(cmd_type)];
}

typedef status_t (*recv_func_t)(void *link, char *buf, uint32 size, int32 *recv_size);
typedef status_t (*recv_timed_func_t)(void *link, char *buf, uint32 size, uint32 timeout);
typedef status_t (*send_timed_func_t)(void *link, const char *buf, uint32 size, uint32 timeout);
typedef status_t (*wait_func_t)(void *link, uint32 wait_for, int32 timeout, bool32 *ready);

typedef struct st_vio {
    recv_func_t vio_recv;
    wait_func_t vio_wait;
    recv_timed_func_t vio_recv_timed;
    send_timed_func_t vio_send_timed;
} vio_t;

static const vio_t g_vio_list[] = {
    {NULL, NULL, NULL, NULL},

    // TCP io functions
    {(recv_func_t)cs_tcp_recv, (wait_func_t)cs_tcp_wait, (recv_timed_func_t)cs_tcp_recv_timed,
        (send_timed_func_t)cs_tcp_send_timed},

    // IPC not implemented
    {NULL, NULL, NULL, NULL},

    // UDS io functions
    {(recv_func_t)cs_uds_recv, (wait_func_t)cs_uds_wait, (recv_timed_func_t)cs_uds_recv_timed,
        (send_timed_func_t)cs_uds_send_timed},

    // SSL io functions
    {(recv_func_t)cs_ssl_recv, (wait_func_t)cs_ssl_wait, (recv_timed_func_t)cs_ssl_recv_timed,
        (send_timed_func_t)cs_ssl_send_timed},

    // CS_TYPE_EMBEDDED not implemented
    {NULL, NULL, NULL, NULL},

    // CS_TYPE_DIRECT not implemented
    {NULL, NULL, NULL, NULL},
};

/*
  Macro definitions for pipe I/O operations
  @note
    Performance sensitive, the pipe->type should be guaranteed by the caller.
      e.g. CS_TYPE_TCP, CS_TYPE_SSL, CS_TYPE_DOMAIN_SOCKET
*/
#define GET_VIO(pipe) (&g_vio_list[(pipe)->type])

#define VIO_SEND_TIMED(pipe, buf, size, timeout) GET_VIO(pipe)->vio_send_timed(&(pipe)->link, buf, size, timeout)

#define VIO_RECV(pipe, buf, size, len) GET_VIO(pipe)->vio_recv(&(pipe)->link, buf, size, len)

#define VIO_RECV_TIMED(pipe, buf, size, timeout) GET_VIO(pipe)->vio_recv_timed(&(pipe)->link, buf, size, timeout)

#define VIO_WAIT(pipe, ev, timeout, ready) GET_VIO(pipe)->vio_wait(&(pipe)->link, ev, timeout, ready)

status_t wr_put_text(wr_packet_t *pack, text_t *text)
{
    errno_t errcode;
    CM_ASSERT(pack != NULL);
    CM_ASSERT(text != NULL);

    /* put the length of text */
    (void)wr_put_int32(pack, text->len);
    if (text->len == 0) {
        return CM_SUCCESS;
    }
    /* put the string of text, and append the terminated sign */
    errcode = memcpy_s(WR_WRITE_ADDR(pack), WR_REMAIN_SIZE(pack), text->str, text->len);
    WR_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);

    pack->head->size += CM_ALIGN4(text->len);
    return CM_SUCCESS;
}

status_t wr_put_str_with_cutoff(wr_packet_t *pack, const char *str)
{
    uint32 size;
    char *addr = NULL;
    errno_t errcode = 0;

    CM_ASSERT(pack != NULL);
    CM_ASSERT(str != NULL);
    size = (uint32)strlen(str);
    addr = WR_WRITE_ADDR(pack);
    if (size != 0) {
        // for such as err msg , len max is 2K, too long for wr packet, which is fixed len at present, so cut it off
        // for '\0'
        if (WR_REMAIN_SIZE(pack) <= 1) {
            size = 0;
        } else if (size >= WR_REMAIN_SIZE(pack)) {
            // for '\0'
            size = WR_REMAIN_SIZE(pack) - 1;
        }
        errcode = memcpy_s(addr, WR_REMAIN_SIZE(pack), str, size);
        WR_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    }
    WR_WRITE_ADDR(pack)[size] = '\0';
    pack->head->size += CM_ALIGN4(size + 1);

    return CM_SUCCESS;
}

status_t wr_write_packet(cs_pipe_t *pipe, wr_packet_t *pack)
{
    if (pack->head->size > WR_MAX_PACKET_SIZE) {
        WR_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, pack->head->size, WR_MAX_PACKET_SIZE));
    }
    status_t status = VIO_SEND_TIMED(pipe, pack->buf, pack->head->size, WR_DEFAULT_NULL_VALUE);
    WR_RETURN_IFERR2(status, CM_THROW_ERROR(ERR_PACKET_SEND, pack->buf_size, pack->head->size, pack->head->size));
    return CM_SUCCESS;
}

status_t wr_write(cs_pipe_t *pipe, wr_packet_t *pack)
{
    CM_ASSERT(pipe != NULL);
    CM_ASSERT(pack != NULL);
    pack->options = pipe->options;

    return wr_write_packet(pipe, pack);
}

/* before call cs_read_tcp_packet(), cs_tcp_wait() is called */
static status_t wr_read_packet(cs_pipe_t *pipe, wr_packet_t *pack, bool32 cs_client)
{
    int32 remain_size, offset, recv_size;
    bool32 ready = CM_FALSE;

    offset = 0;
    status_t status;
    char *cs_mes = cs_client ? "read wait for server response" : "read wait for client request";
    for (;;) {
        status = VIO_RECV(pipe, pack->buf + offset, (uint32)(pack->buf_size - offset), &recv_size);
        WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_TCP_RECV, "uds", cm_get_sock_error()));
        offset += recv_size;
        if (offset >= (int32)sizeof(wr_packet_head_t)) {
            break;
        }
        status = VIO_WAIT(pipe, CS_WAIT_FOR_READ, CM_NETWORK_IO_TIMEOUT, &ready);
        WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_TCP_TIMEOUT, cs_mes));
        if (!ready) {
            WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_TCP_TIMEOUT_REMAIN, (uint32)(sizeof(uint32) - offset)));
        }
    }

    if (pack->head->size > pack->buf_size) {
        WR_THROW_ERROR_EX(ERR_TCP_RECV, "Receive protocol failed, head size is %u, buffer size is %u, errno %d.",
            pack->head->size, pack->buf_size, cm_get_sock_error());
        cm_fync_logfile();
        CM_ASSERT(0);
    }

    remain_size = (int32)pack->head->size - offset;
    if (remain_size <= 0) {
        return CM_SUCCESS;
    }

    status = VIO_WAIT(pipe, CS_WAIT_FOR_READ, CM_NETWORK_IO_TIMEOUT, &ready);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_TCP_TIMEOUT, cs_mes));

    if (!ready) {
       WR_THROW_ERROR(ERR_TCP_TIMEOUT, cs_mes);
       return CM_ERROR;
    }

    status = VIO_RECV_TIMED(pipe, pack->buf + offset, (uint32)remain_size, CM_NETWORK_IO_TIMEOUT);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_TCP_RECV, "Receive protocol failed."));

    return CM_SUCCESS;
}

status_t wr_read(cs_pipe_t *pipe, wr_packet_t *pack, bool32 cs_client)
{
    CM_ASSERT(pipe != NULL);
    CM_ASSERT(pack != NULL);
    pack->options = pipe->options;

    return wr_read_packet(pipe, pack, cs_client);
}

static status_t wr_call_base(cs_pipe_t *pipe, wr_packet_t *req, wr_packet_t *ack)
{
    bool32 ready = CM_FALSE;

    if (wr_write(pipe, req) != CM_SUCCESS) {
        LOG_RUN_ERR("wr write failed.");
        return CM_ERROR;
    }

    if (cs_wait(pipe, CS_WAIT_FOR_READ, pipe->socket_timeout, &ready) != CM_SUCCESS) {
        LOG_RUN_ERR("cs wait failed.");
        return CM_ERROR;
    }

    if (!ready) {
        WR_RETURN_IFERR2(
            CM_ERROR, WR_THROW_ERROR(ERR_SOCKET_TIMEOUT, pipe->socket_timeout / (int32)CM_TIME_THOUSAND_UN));
    }

    return wr_read(pipe, ack, CM_TRUE);
}

status_t wr_call_ex(cs_pipe_t *pipe, wr_packet_t *req, wr_packet_t *ack)
{
    status_t ret = wr_call_base(pipe, req, ack);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[WR] ABORT INFO: wr call server failed, ack command type:%d, application exit.", ack->head->cmd);
        cs_disconnect(pipe);
        cm_fync_logfile();
        wr_exit(1);
    }
    return ret;
}
