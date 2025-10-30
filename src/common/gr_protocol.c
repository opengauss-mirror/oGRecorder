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
 * gr_protocol.c
 *
 *
 * IDENTIFICATION
 *    src/common/gr_protocol.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_errno.h"
#include "gr_log.h"
#include "gr_thv.h"
#include "gr_protocol.h"


static char *g_gr_cmd_desc[GR_CMD_TYPE_OFFSET(GR_CMD_END)] = {
    [GR_CMD_TYPE_OFFSET(GR_CMD_MKDIR)] = "mkdir",
    [GR_CMD_TYPE_OFFSET(GR_CMD_RMDIR)] = "rmdir",
    [GR_CMD_TYPE_OFFSET(GR_CMD_MOUNT_VFS)] = "mount vfs",
    [GR_CMD_TYPE_OFFSET(GR_CMD_UNMOUNT_VFS)] = "unmount vfs",
    [GR_CMD_TYPE_OFFSET(GR_CMD_QUERY_FILE_NUM)] = "query file num",
    [GR_CMD_TYPE_OFFSET(GR_CMD_QUERY_FILE_INFO)] = "query file info",
    [GR_CMD_TYPE_OFFSET(GR_CMD_OPEN_FILE)] = "open file",
    [GR_CMD_TYPE_OFFSET(GR_CMD_CLOSE_FILE)] = "close file",
    [GR_CMD_TYPE_OFFSET(GR_CMD_CREATE_FILE)] = "create file",
    [GR_CMD_TYPE_OFFSET(GR_CMD_DELETE_FILE)] = "delete file",
    [GR_CMD_TYPE_OFFSET(GR_CMD_WRITE_FILE)] = "write file",
    [GR_CMD_TYPE_OFFSET(GR_CMD_READ_FILE)] = "read file",
    [GR_CMD_TYPE_OFFSET(GR_CMD_RENAME_FILE)] = "rename file",
    [GR_CMD_TYPE_OFFSET(GR_CMD_TRUNCATE_FILE)] = "truncate file",
    [GR_CMD_TYPE_OFFSET(GR_CMD_STAT_FILE)] = "stat file",
    [GR_CMD_TYPE_OFFSET(GR_CMD_LOAD_CTRL)] = "load ctrl",
    [GR_CMD_TYPE_OFFSET(GR_CMD_UPDATE_GRITTEN_SIZE)] = "update written size",
    [GR_CMD_TYPE_OFFSET(GR_CMD_STOP_SERVER)] = "stopserver",
    [GR_CMD_TYPE_OFFSET(GR_CMD_SETCFG)] = "setcfg",
    [GR_CMD_TYPE_OFFSET(GR_CMD_SET_MAIN_INST)] = "set main inst",
    [GR_CMD_TYPE_OFFSET(GR_CMD_SWITCH_LOCK)] = "switch cm lock",
    [GR_CMD_TYPE_OFFSET(GR_CMD_POSTPONE_FILE_TIME)] = "extend file expired time",
    [GR_CMD_TYPE_OFFSET(GR_CMD_HANDSHAKE)] = "handshake with server",
    [GR_CMD_TYPE_OFFSET(GR_CMD_RELOAD_CERTS)] = "reload gr server certs",
    [GR_CMD_TYPE_OFFSET(GR_CMD_GET_DISK_USAGE)] = "get disk usage",
    [GR_CMD_TYPE_OFFSET(GR_CMD_EXIST)] = "exist item",
    [GR_CMD_TYPE_OFFSET(GR_CMD_GET_FTID_BY_PATH)] = "get ftid by path",
    [GR_CMD_TYPE_OFFSET(GR_CMD_GETCFG)] = "getcfg",
    [GR_CMD_TYPE_OFFSET(GR_CMD_GET_INST_STATUS)] = "get inst status",
    [GR_CMD_TYPE_OFFSET(GR_CMD_GET_TIME_STAT)] = "get time stat",
    [GR_CMD_TYPE_OFFSET(GR_CMD_EXEC_REMOTE)] = "exec remote",
    [GR_CMD_TYPE_OFFSET(GR_CMD_QUERY_HOTPATCH)] = "query status of hotpatch",
};

char *gr_get_cmd_desc(gr_cmd_type_e cmd_type)
{
    if (cmd_type < GR_CMD_BEGIN || cmd_type >= GR_CMD_END) {
        return "unknown";
    }
    return g_gr_cmd_desc[GR_CMD_TYPE_OFFSET(cmd_type)];
}

typedef status_t (*recv_func_t)(void *link, char *buf, uint32_t size, int32_t *recv_size, uint32 *wait_event);
typedef status_t (*recv_timed_func_t)(void *link, char *buf, uint32_t size, uint32_t timeout);
typedef status_t (*send_timed_func_t)(void *link, const char *buf, uint32_t size, uint32_t timeout);
typedef status_t (*wait_func_t)(void *link, uint32_t wait_for, int32_t timeout, bool32 *ready);

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

#define VIO_RECV(pipe, buf, size, len, wait_event) GET_VIO(pipe)->vio_recv(&(pipe)->link, buf, size, len, wait_event)

#define VIO_RECV_TIMED(pipe, buf, size, timeout) GET_VIO(pipe)->vio_recv_timed(&(pipe)->link, buf, size, timeout)

#define VIO_WAIT(pipe, ev, timeout, ready) GET_VIO(pipe)->vio_wait(&(pipe)->link, ev, timeout, ready)

status_t gr_put_text(gr_packet_t *pack, text_t *text)
{
    errno_t errcode;
    CM_ASSERT(pack != NULL);
    CM_ASSERT(text != NULL);

    /* put the length of text */
    (void)gr_put_int32(pack, text->len);
    if (text->len == 0) {
        return CM_SUCCESS;
    }
    /* put the string of text, and append the terminated sign */
    errcode = memcpy_s(GR_WRITE_ADDR(pack), GR_REMAIN_SIZE(pack), text->str, text->len);
    GR_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);

    pack->head->size += CM_ALIGN4(text->len);
    return CM_SUCCESS;
}

status_t gr_put_str_with_cutoff(gr_packet_t *pack, const char *str)
{
    uint32_t size;
    errno_t errcode = 0;

    CM_ASSERT(pack != NULL);
    CM_ASSERT(str != NULL);
    size = (uint32_t)strlen(str);
    char *addr = GR_WRITE_ADDR(pack);
    if (size != 0) {
        // for such as err msg , len max is 2K, too long for gr packet, which is fixed len at present, so cut it off
        // for '\0'
        if (GR_REMAIN_SIZE(pack) <= 1) {
            size = 0;
        } else if (size >= GR_REMAIN_SIZE(pack)) {
            // for '\0'
            size = GR_REMAIN_SIZE(pack) - 1;
        }
        errcode = memcpy_s(addr, GR_REMAIN_SIZE(pack), str, size);
        GR_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    }
    GR_WRITE_ADDR(pack)[size] = '\0';
    pack->head->size += CM_ALIGN4(size + 1);

    return CM_SUCCESS;
}

status_t gr_write_packet(cs_pipe_t *pipe, gr_packet_t *pack)
{
    if (pack->head->size > GR_MAX_PACKET_SIZE) {
        GR_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, pack->head->size, GR_MAX_PACKET_SIZE));
    }
    status_t status = VIO_SEND_TIMED(pipe, pack->buf, pack->head->size, GR_DEFAULT_NULL_VALUE);
    GR_RETURN_IFERR2(status, CM_THROW_ERROR(ERR_PACKET_SEND, pack->buf_size, pack->head->size, pack->head->size));
    return CM_SUCCESS;
}

status_t gr_write(cs_pipe_t *pipe, gr_packet_t *pack)
{
    CM_ASSERT(pipe != NULL);
    CM_ASSERT(pack != NULL);
    pack->options = pipe->options;

    return gr_write_packet(pipe, pack);
}

/* before call cs_read_tcp_packet(), cs_tcp_wait() is called */
static status_t gr_read_packet(cs_pipe_t *pipe, gr_packet_t *pack, bool32 cs_client)
{
    int32_t remain_size, offset, recv_size;
    bool32 ready = CM_FALSE;
    uint32 wait_event;

    offset = 0;
    status_t status;
    char *cs_mes = cs_client ? "read wait for server response" : "read wait for client request";
    for (;;) {
        status = VIO_RECV(pipe, pack->buf + offset, (uint32_t)(pack->buf_size - offset), &recv_size, &wait_event);
        GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_TCP_RECV, "uds", cm_get_sock_error()));
        offset += recv_size;
        if (offset >= (int32_t)sizeof(gr_packet_head_t)) {
            break;
        }
        status = VIO_WAIT(pipe, CS_WAIT_FOR_READ, CM_NETWORK_IO_TIMEOUT, &ready);
        GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_TCP_TIMEOUT, cs_mes));
        if (!ready) {
            GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_TCP_TIMEOUT_REMAIN, (uint32_t)(sizeof(uint32_t) - offset)));
        }
    }

    if (pack->head->size > pack->buf_size) {
        GR_THROW_ERROR_EX(ERR_TCP_RECV, "Receive protocol failed, head size is %u, buffer size is %u, errno %d.",
            pack->head->size, pack->buf_size, cm_get_sock_error());
        cm_fync_logfile();
        CM_ASSERT(0);
    }

    remain_size = (int32_t)pack->head->size - offset;
    if (remain_size <= 0) {
        return CM_SUCCESS;
    }

    status = VIO_WAIT(pipe, CS_WAIT_FOR_READ, CM_NETWORK_IO_TIMEOUT, &ready);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_TCP_TIMEOUT, cs_mes));

    if (!ready) {
       GR_THROW_ERROR(ERR_TCP_TIMEOUT, cs_mes);
       return CM_ERROR;
    }

    status = VIO_RECV_TIMED(pipe, pack->buf + offset, (uint32_t)remain_size, CM_NETWORK_IO_TIMEOUT);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_TCP_RECV, "Receive protocol failed."));

    return CM_SUCCESS;
}

status_t gr_read(cs_pipe_t *pipe, gr_packet_t *pack, bool32 cs_client)
{
    CM_ASSERT(pipe != NULL);
    CM_ASSERT(pack != NULL);
    pack->options = pipe->options;

    return gr_read_packet(pipe, pack, cs_client);
}

static status_t gr_call_base(cs_pipe_t *pipe, gr_packet_t *req, gr_packet_t *ack)
{
    bool32 ready = CM_FALSE;

    if (gr_write(pipe, req) != CM_SUCCESS) {
        LOG_RUN_ERR("gr write failed.");
        return CM_ERROR;
    }

    if (cs_wait(pipe, CS_WAIT_FOR_READ, pipe->socket_timeout, &ready) != CM_SUCCESS) {
        LOG_RUN_ERR("cs wait failed.");
        return CM_ERROR;
    }

    if (!ready) {
        GR_RETURN_IFERR2(
            CM_ERROR, GR_THROW_ERROR(ERR_SOCKET_TIMEOUT, pipe->socket_timeout / (int32_t)CM_TIME_THOUSAND_UN));
    }

    return gr_read(pipe, ack, CM_TRUE);
}

status_t gr_call_ex(cs_pipe_t *pipe, gr_packet_t *req, gr_packet_t *ack)
{
    status_t ret = gr_call_base(pipe, req, ack);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[GR] ABORT INFO: gr call server failed, ack command type:%d, application exit.", ack->head->cmd);
        GR_THROW_ERROR(ERR_GR_CALL_SERVER_FAILED);
        cs_disconnect(pipe);
        cm_fync_logfile();
    }
    return ret;
}
