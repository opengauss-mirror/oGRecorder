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
 * gr_mes.h
 *
 *
 * IDENTIFICATION
 *    src/service/gr_mes.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_MES_H__
#define __GR_MES_H__

#include "mes_interface.h"
#include "gr_file_def.h"
#include "gr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_gr_mes_command {
    GR_CMD_REQ_BROADCAST = 0,
    GR_CMD_ACK_BROADCAST_WITH_MSG,
    GR_CMD_REQ_SYB2ACTIVE, /* Request command from the standby node to the active node */
    GR_CMD_ACK_SYB2ACTIVE,
    GR_CMD_REQ_JOIN_CLUSTER,
    GR_CMD_ACK_JOIN_CLUSTER,
    GR_CMD_CEIL,
} gr_mes_command_t;

typedef enum en_gr_msg_buffer_number {
    GR_MSG_BUFFER_NO_0 = 0,
    GR_MSG_BUFFER_NO_1,
    GR_MSG_BUFFER_NO_2,
    GR_MSG_BUFFER_NO_3,
    GR_MSG_BUFFER_NO_CEIL
} gr_msg_buffer_number_e;

#define GR_MES_THREAD_NUM 2
#define GR_MES_TRY_TIMES 100
#define GR_BROADCAST_WAIT_INFINITE (0xFFFFFFFF)
#define GR_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)
#define GR_MSG_BUFFER_QUEUE_NUM (8)
#define GR_MSG_FOURTH_BUFFER_QUEUE_NUM (1)
#define GR_FIRST_BUFFER_LENGTH (256)
#define GR_SECOND_BUFFER_LENGTH (SIZE_K(1) + 256)
#define GR_THIRD_BUFFER_LENGTH (SIZE_K(32) + 256)
#define GR_FOURTH_BUFFER_LENGTH (GR_LOADDISK_BUFFER_SIZE + 256)
#define GR_CKPT_NOTIFY_TASK_RATIO (1.0f / 4)
#define GR_CLEAN_EDP_TASK_RATIO (1.0f / 4)
#define GR_TXN_INFO_TASK_RATIO (1.0f / 16)
#define GR_RECV_WORK_THREAD_RATIO (1.0f / 4)
#define GR_FIRST_BUFFER_RATIO ((double)1.0 / 8)
#define GR_SECOND_BUFFER_RATIO ((double)3.0 / 8)
#define GR_THIRDLY_BUFFER_RATIO ((double)1.0 / 2)

typedef void (*gr_message_proc_t)(gr_session_t *session, mes_msg_t *msg);
typedef struct st_processor_func {
    gr_mes_command_t cmd_type;
    gr_message_proc_t proc;
    bool32 is_enqueue_work_thread;  // Whether to let the worker thread process
    const char *func_name;
} processor_func_t;

typedef struct st_gr_processor {
    gr_message_proc_t proc;
    bool32 is_enqueue;
    bool32 is_req;
    mes_priority_t prio_id;
    char *name;
} gr_processor_t;

typedef struct st_gr_mes_actnode {
    bool8 is_active;
    uint8 node_id;
    uint16 rsvd;
    uint32_t node_rsn;
} gr_mes_actnode_t;

typedef struct st_gr_mes_actlist {
    uint32_t count;
    gr_mes_actnode_t node[0];
} gr_mes_actlist_t;
// clang-format off
typedef enum st_gr_bcast_req_cmd {
    BCAST_REQ_DEL_DIR_FILE = 0,
    BCAST_REQ_INVALIDATE_META,
    BCAST_REQ_META_SYN,
    BCAST_REQ_PARAM_SYNC,
    BCAST_REQ_END
} gr_bcast_req_cmd_t;

typedef enum st_gr_bcast_ack_cmd {
    BCAST_ACK_DEL_FILE = 0,
    BCAST_ACK_INVALIDATE_META,
    BCAST_ACK_META_SYN,
    BCAST_ACK_PARAM_SYNC,
    BCAST_ACK_END
} gr_bcast_ack_cmd_t;

// clang-format on
typedef struct st_gr_bcast_req {
    gr_bcast_req_cmd_t type;
    char buffer[4];
} gr_bcast_req_t;

typedef struct st_gr_recv_msg {
    bool32 handle_recv_msg;
    bool32 cmd_ack;
    uint32_t broadcast_proto_ver;
    uint64 version_not_match_inst;
    uint64 succ_inst;
    bool32 ignore_ack;
    bool32 default_ack;
} gr_recv_msg_t;

typedef struct st_gr_message_head {
    uint32_t msg_proto_ver;
    uint32_t sw_proto_ver;
    uint16 src_inst;
    uint16 dst_inst;
    uint32_t gr_cmd;
    uint32_t size;
    uint32_t flags;
    ruid_type ruid;
    int32_t result;
    uint8 reserve[64];
} gr_message_head_t;

typedef struct st_gr_notify_req_msg {
    gr_message_head_t gr_head;
    gr_bcast_req_cmd_t type;
    uint64 ftid;
    char vg_name[GR_MAX_NAME_LEN];
} gr_notify_req_msg_t;

typedef struct st_gr_notify_req_msg_ex {
    gr_message_head_t gr_head;
    gr_bcast_req_cmd_t type;
    uint32_t data_size;
    char data[GR_MAX_META_BLOCK_SIZE];
} gr_notify_req_msg_ex_t;
typedef struct st_gr_notify_ack_msg {
    gr_message_head_t gr_head;
    gr_bcast_ack_cmd_t type;
    int32_t result;
    bool32 cmd_ack;
} gr_notify_ack_msg_t;

typedef struct st_gr_remote_exec_succ_ack {
    gr_message_head_t ack_head;
    char body_buf[4];
} gr_remote_exec_succ_ack_t;

typedef struct st_gr_remote_exec_fail_ack {
    gr_message_head_t ack_head;
    int32_t err_code;
    char err_msg[4];
} gr_remote_exec_fail_ack_t;

typedef struct st_big_packets_ctrl {
    gr_message_head_t gr_head;
    uint32_t offset;
    uint32_t cursize;
    uint32_t totalsize;
    uint16 seq;
    uint8 endflag;
    uint8 reseved;
} big_packets_ctrl_t;

typedef struct st_loaddisk_req {
    gr_message_head_t gr_head;
    uint32_t volumeid;
    uint32_t size;
    uint64 offset;
    char vg_name[GR_MAX_NAME_LEN];
} gr_loaddisk_req_t;

typedef struct st_join_cluster_req {
    gr_message_head_t gr_head;
    uint32_t reg_id;
} gr_join_cluster_req_t;

typedef struct st_join_cluster_ack {
    gr_message_head_t ack_head;
    bool32 is_reg;
} gr_join_cluster_ack_t;

typedef struct st_refresh_ft_req {
    gr_message_head_t gr_head;
    gr_block_id_t blockid;
    uint32_t vgid;
    char vg_name[GR_MAX_NAME_LEN];
} gr_refresh_ft_req_t;

typedef struct st_refresh_ft_ack {
    gr_message_head_t ack_head;
    bool32 is_ok;
} gr_refresh_ft_ack_t;

typedef struct st_get_ft_block_req {
    gr_message_head_t gr_head;
    char path[GR_FILE_PATH_MAX_LENGTH];
    gft_item_type_t type;
} gr_get_ft_block_req_t;

typedef struct st_get_ft_block_ack {
    gr_message_head_t ack_head;
    gr_block_id_t node_id;
    gr_block_id_t parent_node_id;
    char vg_name[GR_MAX_NAME_LEN];
    char block[GR_BLOCK_SIZE];
    char parent_block[GR_BLOCK_SIZE];
} gr_get_ft_block_ack_t;

#define GR_MES_MSG_HEAD_SIZE (sizeof(gr_message_head_t))
uint32_t gr_get_broadcast_proto_ver(uint64 succ_inst);
status_t gr_notify_sync(char *buffer, uint32_t size, gr_recv_msg_t *recv_msg);
status_t gr_notify_sync_ex(char *buffer, uint32_t size, gr_recv_msg_t *recv_msg);
status_t gr_exec_sync(gr_session_t *session, uint32_t remoteid, uint32_t currtid, status_t *remote_result);
void gr_check_mes_conn(uint64 cur_inst_map);
status_t gr_startup_mes(void);
void gr_stop_mes(void);
int32_t gr_process_broadcast_ack(gr_notify_ack_msg_t *ack, gr_recv_msg_t *recv_msg_output);
void gr_proc_broadcast_req(gr_session_t *session, mes_msg_t *msg);
void gr_proc_syb2active_req(gr_session_t *session, mes_msg_t *msg);
void gr_proc_loaddisk_req(gr_session_t *session, mes_msg_t *msg);
void gr_proc_join_cluster_req(gr_session_t *session, mes_msg_t *msg);
void gr_proc_refresh_ft_by_primary_req(gr_session_t *session, mes_msg_t *msg);

status_t gr_join_cluster(bool32 *join_succ);

#ifdef __cplusplus
}
#endif

#endif
