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
 * wr_mes.h
 *
 *
 * IDENTIFICATION
 *    src/service/wr_mes.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_MES_H__
#define __WR_MES_H__

#include "mes_interface.h"
#include "wr_file_def.h"
#include "wr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_wr_mes_command {
    WR_CMD_REQ_BROADCAST = 0,
    WR_CMD_ACK_BROADCAST_WITH_MSG,
    WR_CMD_REQ_SYB2ACTIVE, /* Request command from the standby node to the active node */
    WR_CMD_ACK_SYB2ACTIVE,
    WR_CMD_REQ_JOIN_CLUSTER,
    WR_CMD_ACK_JOIN_CLUSTER,
    WR_CMD_CEIL,
} wr_mes_command_t;

typedef enum en_wr_msg_buffer_number {
    WR_MSG_BUFFER_NO_0 = 0,
    WR_MSG_BUFFER_NO_1,
    WR_MSG_BUFFER_NO_2,
    WR_MSG_BUFFER_NO_3,
    WR_MSG_BUFFER_NO_CEIL
} wr_msg_buffer_number_e;

#define WR_MES_THREAD_NUM 2
#define WR_MES_TRY_TIMES 100
#define WR_BROADCAST_WAIT_INFINITE (0xFFFFFFFF)
#define WR_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)
#define WR_MSG_BUFFER_QUEUE_NUM (8)
#define WR_MSG_FOURTH_BUFFER_QUEUE_NUM (1)
#define WR_FIRST_BUFFER_LENGTH (256)
#define WR_SECOND_BUFFER_LENGTH (SIZE_K(1) + 256)
#define WR_THIRD_BUFFER_LENGTH (SIZE_K(32) + 256)
#define WR_FOURTH_BUFFER_LENGTH (WR_LOADDISK_BUFFER_SIZE + 256)
#define WR_CKPT_NOTIFY_TASK_RATIO (1.0f / 4)
#define WR_CLEAN_EDP_TASK_RATIO (1.0f / 4)
#define WR_TXN_INFO_TASK_RATIO (1.0f / 16)
#define WR_RECV_WORK_THREAD_RATIO (1.0f / 4)
#define WR_FIRST_BUFFER_RATIO ((double)1.0 / 8)
#define WR_SECOND_BUFFER_RATIO ((double)3.0 / 8)
#define WR_THIRDLY_BUFFER_RATIO ((double)1.0 / 2)

typedef void (*wr_message_proc_t)(wr_session_t *session, mes_msg_t *msg);
typedef struct st_processor_func {
    wr_mes_command_t cmd_type;
    wr_message_proc_t proc;
    bool32 is_enqueue_work_thread;  // Whether to let the worker thread process
    const char *func_name;
} processor_func_t;

typedef struct st_wr_processor {
    wr_message_proc_t proc;
    bool32 is_enqueue;
    bool32 is_req;
    mes_priority_t prio_id;
    char *name;
} wr_processor_t;

typedef struct st_wr_mes_actnode {
    bool8 is_active;
    uint8 node_id;
    uint16 rsvd;
    uint32_t node_rsn;
} wr_mes_actnode_t;

typedef struct st_wr_mes_actlist {
    uint32_t count;
    wr_mes_actnode_t node[0];
} wr_mes_actlist_t;
// clang-format off
typedef enum st_wr_bcast_req_cmd {
    BCAST_REQ_DEL_DIR_FILE = 0,
    BCAST_REQ_INVALIDATE_META,
    BCAST_REQ_META_SYN,
    BCAST_REQ_END
} wr_bcast_req_cmd_t;

typedef enum st_wr_bcast_ack_cmd {
    BCAST_ACK_DEL_FILE = 0,
    BCAST_ACK_INVALIDATE_META,
    BCAST_ACK_META_SYN,
    BCAST_ACK_END
} wr_bcast_ack_cmd_t;

// clang-format on
typedef struct st_wr_bcast_req {
    wr_bcast_req_cmd_t type;
    char buffer[4];
} wr_bcast_req_t;

typedef struct st_wr_recv_msg {
    bool32 handle_recv_msg;
    bool32 cmd_ack;
    uint32_t broadcast_proto_ver;
    uint64 version_not_match_inst;
    uint64 succ_inst;
    bool32 ignore_ack;
    bool32 default_ack;
} wr_recv_msg_t;

typedef struct st_wr_message_head {
    uint32_t msg_proto_ver;
    uint32_t sw_proto_ver;
    uint16 src_inst;
    uint16 dst_inst;
    uint32_t wr_cmd;
    uint32_t size;
    uint32_t flags;
    ruid_type ruid;
    int32_t result;
    uint8 reserve[64];
} wr_message_head_t;

typedef struct st_wr_notify_req_msg {
    wr_message_head_t wr_head;
    wr_bcast_req_cmd_t type;
    uint64 ftid;
    char vg_name[WR_MAX_NAME_LEN];
} wr_notify_req_msg_t;

typedef struct st_wr_notify_req_msg_ex {
    wr_message_head_t wr_head;
    wr_bcast_req_cmd_t type;
    uint32_t data_size;
    char data[WR_MAX_META_BLOCK_SIZE];
} wr_notify_req_msg_ex_t;
typedef struct st_wr_notify_ack_msg {
    wr_message_head_t wr_head;
    wr_bcast_ack_cmd_t type;
    int32_t result;
    bool32 cmd_ack;
} wr_notify_ack_msg_t;

typedef struct st_wr_remote_exec_succ_ack {
    wr_message_head_t ack_head;
    char body_buf[4];
} wr_remote_exec_succ_ack_t;

typedef struct st_wr_remote_exec_fail_ack {
    wr_message_head_t ack_head;
    int32_t err_code;
    char err_msg[4];
} wr_remote_exec_fail_ack_t;

typedef struct st_big_packets_ctrl {
    wr_message_head_t wr_head;
    uint32_t offset;
    uint32_t cursize;
    uint32_t totalsize;
    uint16 seq;
    uint8 endflag;
    uint8 reseved;
} big_packets_ctrl_t;

typedef struct st_loaddisk_req {
    wr_message_head_t wr_head;
    uint32_t volumeid;
    uint32_t size;
    uint64 offset;
    char vg_name[WR_MAX_NAME_LEN];
} wr_loaddisk_req_t;

typedef struct st_join_cluster_req {
    wr_message_head_t wr_head;
    uint32_t reg_id;
} wr_join_cluster_req_t;

typedef struct st_join_cluster_ack {
    wr_message_head_t ack_head;
    bool32 is_reg;
} wr_join_cluster_ack_t;

typedef struct st_refresh_ft_req {
    wr_message_head_t wr_head;
    wr_block_id_t blockid;
    uint32_t vgid;
    char vg_name[WR_MAX_NAME_LEN];
} wr_refresh_ft_req_t;

typedef struct st_refresh_ft_ack {
    wr_message_head_t ack_head;
    bool32 is_ok;
} wr_refresh_ft_ack_t;

typedef struct st_get_ft_block_req {
    wr_message_head_t wr_head;
    char path[WR_FILE_PATH_MAX_LENGTH];
    gft_item_type_t type;
} wr_get_ft_block_req_t;

typedef struct st_get_ft_block_ack {
    wr_message_head_t ack_head;
    wr_block_id_t node_id;
    wr_block_id_t parent_node_id;
    char vg_name[WR_MAX_NAME_LEN];
    char block[WR_BLOCK_SIZE];
    char parent_block[WR_BLOCK_SIZE];
} wr_get_ft_block_ack_t;

#define WR_MES_MSG_HEAD_SIZE (sizeof(wr_message_head_t))
uint32_t wr_get_broadcast_proto_ver(uint64 succ_inst);
status_t wr_notify_sync(char *buffer, uint32_t size, wr_recv_msg_t *recv_msg);
status_t wr_notify_sync_ex(char *buffer, uint32_t size, wr_recv_msg_t *recv_msg);

status_t wr_exec_sync(wr_session_t *session, uint32_t remoteid, uint32_t currtid, status_t *remote_result);
status_t wr_notify_expect_bool_ack(wr_vg_info_item_t *vg_item, wr_bcast_req_cmd_t cmd, uint64 ftid, bool32 *cmd_ack);
status_t wr_notify_data_expect_bool_ack(
    wr_vg_info_item_t *vg_item, wr_bcast_req_cmd_t cmd, char *data, uint32_t size, bool32 *cmd_ack);

status_t wr_invalidate_other_nodes(
    wr_vg_info_item_t *vg_item, char *meta_info, uint32_t meta_info_size, bool32 *cmd_ack);
status_t wr_broadcast_check_file_open(wr_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack);
status_t wr_syn_data2other_nodes(wr_vg_info_item_t *vg_item, char *meta_syn, uint32_t meta_syn_size, bool32 *cmd_ack);

void wr_check_mes_conn(uint64 cur_inst_map);
status_t wr_startup_mes(void);
void wr_stop_mes(void);
int32_t wr_process_broadcast_ack(wr_notify_ack_msg_t *ack, wr_recv_msg_t *recv_msg_output);
void wr_proc_broadcast_req(wr_session_t *session, mes_msg_t *msg);
void wr_proc_syb2active_req(wr_session_t *session, mes_msg_t *msg);
void wr_proc_loaddisk_req(wr_session_t *session, mes_msg_t *msg);
void wr_proc_join_cluster_req(wr_session_t *session, mes_msg_t *msg);
void wr_proc_refresh_ft_by_primary_req(wr_session_t *session, mes_msg_t *msg);

status_t wr_send2standby(big_packets_ctrl_t *ack, const char *buf);
status_t wr_join_cluster(bool32 *join_succ);

#ifdef __cplusplus
}
#endif

#endif
