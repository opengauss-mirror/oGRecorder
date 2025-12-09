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
 * gr_instance.h
 *
 *
 * IDENTIFICATION
 *    src/service/gr_instance.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_INSTANCE_H__
#define __GR_INSTANCE_H__

#include "cm_spinlock.h"
#include "cs_listener.h"
#include "gr_defs.h"
#include "gr_file.h"
#include "gr_session.h"
#include "gr_diskgroup.h"
#include "gr_param.h"
#include "cm_res_mgr.h"  // for cm_res_mgr_t
#include "gr_reactor.h"
#include "ssl_func.h"
#include "gr_stats.h"
#include "gr_param_sync.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GR_MAX_INSTANCE_OPEN_FILES 1
#define GR_LOGFILE_SIZE 10000
#define GR_LOG_LEVEL 0xffffffff
#define GR_CM_SO_NAME "libclient.so"

typedef enum {
    CM_RES_SUCCESS = 0,
    CM_RES_CANNOT_DO = 1,
    CM_RES_DDB_FAILED = 2,
    CM_RES_VERSION_GRONG = 3,
    CM_RES_CONNECT_ERROR = 4,
    CM_RES_TIMEOUT = 5,
    CM_RES_NO_LOCK_OWNER = 6,
} cm_err_code;

#define GR_CM_LOCK "gr cm lock"
#define GR_GET_CM_LOCK_LONG_SLEEP cm_sleep(500)

typedef struct st_gr_cm_res {
    spinlock_t init_lock;
    bool8 is_init;
    bool8 is_valid;
    cm_res_mgr_t mgr;
} gr_cm_res;

typedef struct st_gr_srv_args {
    char gr_home[GR_MAX_PATH_BUFFER_SIZE];
    bool is_maintain;
} gr_srv_args_t;

typedef struct st_gr_instance {
    int32_t lock_fd;
    latch_t switch_latch;
    gr_config_t inst_cfg;
    gr_instance_status_e status;
    tcp_lsnr_t lsnr;
    latch_t tcp_lsnr_latch;
    reactors_t reactors;
    thread_t *threads;
    int64 active_sessions;
    bool32 abort_status;
    gr_cm_res cm_res;
    uint64 inst_work_status_map;  // one bit one inst, bit value is 1 means inst ok, 0 means inst not ok
    spinlock_t inst_work_lock;
    int32_t cluster_proto_vers[GR_MAX_INSTANCES];
    bool8 is_maintain;
    bool8 is_cleaning;
    bool8 no_grab_lock;
    bool8 is_releasing_lock;
    bool8 is_checking;
    bool8 reserve[3];
    bool32 is_join_cluster;
    // The most recently observed CM master_id in the recovery thread, used to detect master node switches
    uint32_t last_cm_master_id;
    gr_session_t *handle_session;
    gr_bg_task_info_t syn_meta_task[GR_META_SYN_BG_TASK_NUM_MAX];
    gr_stat_item_t gr_instance_stat[GR_EVT_COUNT];  // 实例级别的时延统计

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    void *fi_run_ctx;
#endif
    gr_recycle_meta_t recycle_meta;
} gr_instance_t;

status_t gr_lock_instance(void);
status_t gr_startup(gr_instance_t *inst, gr_srv_args_t gr_args);

extern gr_instance_t g_gr_instance;
#define ZFS_INST (&g_gr_instance)
#define ZFS_CFG (&g_gr_instance.inst_cfg)

status_t gr_start_lsnr(gr_instance_t *inst);
void gr_uninit_cm(gr_instance_t *inst);
void gr_check_peer_inst(gr_instance_t *inst, uint64 inst_id);
void gr_free_log_ctrl();
void gr_check_peer_by_inst(gr_instance_t *inst, uint64 inst_id);
uint64 gr_get_inst_work_status(void);
void gr_set_inst_work_status(uint64 cur_inst_map);
status_t gr_get_cm_lock_owner(gr_instance_t *inst, bool32 *grab_lock, bool32 try_lock, uint32_t *master_id);
void gr_recovery_when_primary(gr_session_t *session, gr_instance_t *inst, uint32_t curr_id, bool32 grab_lock);
status_t gr_get_cm_res_lock_owner(gr_cm_res *cm_res, uint32_t *master_id);
void gr_get_cm_lock_and_recover(thread_t *thread);
void gr_delay_clean_proc(thread_t *thread);
void gr_alarm_check_proc(thread_t *thread);
void gr_hashmap_dynamic_extend_and_redistribute_proc(thread_t *thread);
bool32 gr_check_join_cluster();

#ifdef __cplusplus
}
#endif

#endif
