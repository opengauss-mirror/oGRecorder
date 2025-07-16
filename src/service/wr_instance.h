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
 * wr_instance.h
 *
 *
 * IDENTIFICATION
 *    src/service/wr_instance.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_INSTANCE_H__
#define __WR_INSTANCE_H__

#include "cm_spinlock.h"
#include "cs_listener.h"
#include "wr_defs.h"
#include "wr_file.h"
#include "wr_session.h"
#include "wr_diskgroup.h"
#include "wr_param.h"
#include "cm_res_mgr.h"  // for cm_res_mgr_t
#include "wr_reactor.h"
#include "ssl_func.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_MAX_INSTANCE_OPEN_FILES 1
#define WR_LOGFILE_SIZE 10000
#define WR_LOG_LEVEL 0xffffffff

typedef enum {
    CM_RES_SUCCESS = 0,
    CM_RES_CANNOT_DO = 1,
    CM_RES_DDB_FAILED = 2,
    CM_RES_VERSION_WRONG = 3,
    CM_RES_CONNECT_ERROR = 4,
    CM_RES_TIMEOUT = 5,
    CM_RES_NO_LOCK_OWNER = 6,
} cm_err_code;

#define WR_CM_LOCK "wr cm lock"
#define WR_GET_CM_LOCK_LONG_SLEEP cm_sleep(500)

typedef struct st_wr_cm_res {
    spinlock_t init_lock;
    bool8 is_init;
    bool8 is_valid;
    cm_res_mgr_t mgr;
} wr_cm_res;

typedef struct st_wr_srv_args {
    char wr_home[WR_MAX_PATH_BUFFER_SIZE];
    bool is_maintain;
} wr_srv_args_t;

typedef struct st_wr_instance {
    int32_t lock_fd;
    latch_t switch_latch;
    wr_config_t inst_cfg;
    wr_instance_status_e status;
    tcp_lsnr_t lsnr;
    latch_t tcp_lsnr_latch;
    reactors_t reactors;
    thread_t *threads;
    int64 active_sessions;
    bool32 abort_status;
    wr_cm_res cm_res;
    uint64 inst_work_status_map;  // one bit one inst, bit value is 1 means inst ok, 0 means inst not ok
    spinlock_t inst_work_lock;
    int32_t cluster_proto_vers[WR_MAX_INSTANCES];
    bool8 is_maintain;
    bool8 is_cleaning;
    bool8 no_grab_lock;
    bool8 is_releasing_lock;
    bool8 is_checking;
    bool8 reserve[3];
    bool32 is_join_cluster;
    wr_session_t *handle_session;
    wr_bg_task_info_t syn_meta_task[WR_META_SYN_BG_TASK_NUM_MAX];

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    void *fi_run_ctx;
#endif
    wr_recycle_meta_t recycle_meta;
} wr_instance_t;

status_t wr_lock_instance(void);
status_t wr_startup(wr_instance_t *inst, wr_srv_args_t wr_args);

extern wr_instance_t g_wr_instance;
#define ZFS_INST (&g_wr_instance)
#define ZFS_CFG (&g_wr_instance.inst_cfg)

status_t wr_start_lsnr(wr_instance_t *inst);
void wr_uninit_cm(wr_instance_t *inst);
void wr_check_peer_inst(wr_instance_t *inst, uint64 inst_id);
void wr_free_log_ctrl();
void wr_check_peer_by_inst(wr_instance_t *inst, uint64 inst_id);
uint64 wr_get_inst_work_status(void);
void wr_set_inst_work_status(uint64 cur_inst_map);
status_t wr_get_cm_lock_owner(wr_instance_t *inst, bool32 *grab_lock, bool32 try_lock, uint32_t *master_id);
void wr_recovery_when_primary(wr_session_t *session, wr_instance_t *inst, uint32_t curr_id, bool32 grab_lock);
status_t wr_get_cm_res_lock_owner(wr_cm_res *cm_res, uint32_t *master_id);
void wr_get_cm_lock_and_recover(thread_t *thread);
void wr_delay_clean_proc(thread_t *thread);
void wr_hashmap_dynamic_extend_and_redistribute_proc(thread_t *thread);
bool32 wr_check_join_cluster();

#ifdef __cplusplus
}
#endif

#endif
