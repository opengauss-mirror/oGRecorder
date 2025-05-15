/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * wr_reactor.h
 *
 *
 * IDENTIFICATION
 *    src/service/wr_reactor.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_REACTOR_H__
#define __WR_REACTOR_H__

#include "cm_defs.h"
#include "cm_error.h"
#include "cm_queue.h"
#include "cm_sync.h"
#include "cm_thread_pool.h"
#include "cm_spinlock.h"
#include "cm_thread.h"
#include "wr_defs.h"
#include "wr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_EV_WAIT_NUM 256
#define WR_EV_WAIT_TIMEOUT 16

typedef struct st_wr_session wr_session_t;
struct st_reactor;
struct st_wr_workthread;

typedef struct st_wr_workthread {
    pooling_thread_t *thread_obj;
    void *current_session;
    thread_task_t task;
    thread_stat_t status;
} wr_workthread_t;

typedef enum en_reactor_status {
    REACTOR_STATUS_RUNNING,
    REACTOR_STATUS_PAUSING,
    REACTOR_STATUS_PAUSED,
    REACTOR_STATUS_STOPPED,
} reactor_status_t;

typedef struct st_reactor {
    uint32_t id;
    thread_t iothread;
    int epollfd;
    atomic32_t session_count;
    reactor_status_t status;
    uint32_t workthread_count;
    cm_event_t idle_evnt;
    thread_lock_t lock;
    cm_thread_pool_t workthread_pool;
    wr_workthread_t workthread_ctx[WR_MAX_WORKTHREADS_CFG];
} reactor_t;

typedef struct st_reactors {
    uint32_t reactor_count;
    atomic_t roudroubin;
    reactor_t *reactor_arr;
} reactors_t;

status_t wr_create_reactors();
void wr_destroy_reactors();
status_t wr_reactors_add_session(wr_session_t *session);
void wr_reactors_del_session(wr_session_t *session);
status_t wr_reactor_set_oneshot(wr_session_t *session);
void wr_reactor_attach_workthread(wr_session_t *session);
void wr_session_detach_workthread(wr_session_t *session);
void wr_clean_reactor_session(wr_session_t *session);
void wr_pause_reactors();
void wr_continue_reactors();

#ifdef __cplusplus
}
#endif

#endif  // __WR_REACTOR_H__