/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * wr_reactor.c
 *
 *
 * IDENTIFICATION
 *    src/service/wr_reactor.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_epoll.h"
#include "wr_reactor.h"
#include "wr_instance.h"
#include "wr_service.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t wr_reactor_set_oneshot(wr_session_t *session)
{
    struct epoll_event ev;
    int fd = (int)session->pipe.link.uds.sock;

    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.ptr = session;
    reactor_t *reactor = (reactor_t *)(session->reactor);
    if (epoll_ctl(reactor->epollfd, EPOLL_CTL_MOD, fd, &ev) != 0) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static wr_workthread_t *wr_reactor_get_workthread(reactor_t *reactor)
{
    uint32_t pos = 0;
    for (pos = 0; pos < reactor->workthread_count; pos++) {
        if (reactor->workthread_ctx[pos].status == THREAD_STATUS_IDLE &&
            reactor->workthread_ctx[pos].thread_obj->task == NULL) {
            break;
        }
    }

    if (pos == reactor->workthread_count) {
        return NULL;
    }

    reactor->workthread_ctx[pos].status = THREAD_STATUS_PROCESSSING;
    return &reactor->workthread_ctx[pos];
}

static void wr_reactor_session_entry(void *param)
{
    wr_workthread_t *workthread_ctx = (wr_workthread_t *)param;
    pooling_thread_t *thread_obj = workthread_ctx->thread_obj;
    wr_session_t *session = (wr_session_t *)workthread_ctx->current_session;
    LOG_DEBUG_INF("session %u with workthread %u begin.", session->id, thread_obj->spid);

    if (session->is_closed) {
        wr_clean_reactor_session(session);
        LOG_DEBUG_WAR("session %u is closed.", session->id);
        return;
    }
    wr_init_packet(&session->recv_pack, CM_FALSE);
    wr_init_packet(&session->send_pack, CM_FALSE);
    session->pipe.socket_timeout = (int32_t)CM_SOCKET_TIMEOUT;
    (void)wr_process_single_cmd(&session);
    // do NOT add any code after here, and can not use any data of wr_workthread_t from here
    if (session != NULL) {
        if (wr_reactor_set_oneshot(session) != CM_SUCCESS) {
            LOG_RUN_ERR("[reactor] set oneshot flag of socket failed, session %u, reactor %u, os error %d", session->id,
                ((reactor_t *)session->reactor)->id, cm_get_sock_error());
        }
    }
}

void wr_reactor_attach_workthread(wr_session_t *session)
{
    reactor_t *reactor = (reactor_t *)session->reactor;
    if (reactor == NULL) {
        return;
    }
    while (CM_TRUE) {
        cm_thread_lock(&reactor->lock);
        wr_workthread_t *workthread_ctx = wr_reactor_get_workthread(reactor);
        if (workthread_ctx != NULL) {
            workthread_ctx->task.action = wr_reactor_session_entry;
            workthread_ctx->current_session = session;
            workthread_ctx->task.param = workthread_ctx;
            session->workthread_ctx = workthread_ctx;
            cm_dispatch_pooling_thread(workthread_ctx->thread_obj, &workthread_ctx->task);
            LOG_DEBUG_INF("[reactor] attach workthread %u to session %u sucessfully, active_sessions is %lld.", workthread_ctx->thread_obj->spid,
                session->id, g_wr_instance.active_sessions);
            break;
        }
        if (reactor->status != REACTOR_STATUS_RUNNING || reactor->iothread.closed) {
            break;
        }
        cm_thread_unlock(&reactor->lock);
        cm_event_wait(&reactor->idle_evnt);
    }
    cm_thread_unlock(&reactor->lock);
}

static inline void wr_reset_workthread_ctx(wr_workthread_t *workthread_ctx)
{
    workthread_ctx->task.action = NULL;
    workthread_ctx->current_session = NULL;
    workthread_ctx->task.param = NULL;
    workthread_ctx->status = THREAD_STATUS_IDLE;
}

static inline void wr_session_detach_workthread_inner(wr_session_t *session)
{
    wr_workthread_t *workthread_ctx = (wr_workthread_t *)session->workthread_ctx;
    session->workthread_ctx = NULL;
    session->status = WR_SESSION_STATUS_IDLE;
    LOG_DEBUG_INF("[reactor] detach workthread %u to session %u sucessfully, active_sessions is %lld.",
        workthread_ctx->thread_obj->spid, session->id, g_wr_instance.active_sessions);
    return;
}

void wr_session_detach_workthread(wr_session_t *session)
{
    wr_workthread_t *workthread_ctx = (wr_workthread_t *)session->workthread_ctx;
    reactor_t *reactor = (reactor_t *)session->reactor;
    wr_session_detach_workthread_inner(session);
    cm_thread_lock(&reactor->lock);
    wr_reset_workthread_ctx(workthread_ctx);
    cm_thread_unlock(&reactor->lock);
    cm_event_notify(&reactor->idle_evnt);
}

static void wr_reactor_poll_events(reactor_t *reactor)
{
    wr_session_t *sess = NULL;
    int loop, nfds;
    struct epoll_event events[WR_EV_WAIT_NUM];
    struct epoll_event *ev = NULL;

    if (reactor->status != REACTOR_STATUS_RUNNING) {
        return;
    }

    nfds = epoll_wait(reactor->epollfd, events, WR_EV_WAIT_NUM, WR_EV_WAIT_TIMEOUT);
    if (nfds == -1) {
        if (errno != EINTR) {
            LOG_RUN_ERR("Failed to wait for connection request, OS error:%d", cm_get_os_error());
        }
        return;
    }

    if (nfds == 0) {
        return;
    }

    for (loop = 0; loop < nfds; ++loop) {
        ev = &events[loop];
        sess = (wr_session_t *)ev->data.ptr;
        if (reactor->status != REACTOR_STATUS_RUNNING) {
            if (wr_reactor_set_oneshot(sess) != CM_SUCCESS) {
                LOG_RUN_ERR("[reactor] set oneshot flag of socket failed, session %u, "
                            "reactor %u, os error %d, event %u",
                    sess->id, reactor->id, cm_get_sock_error(), ev->events);
            }
            continue;
        }

        wr_reactor_attach_workthread(sess);
    }
}

static void wr_reactor_entry(thread_t *thread)
{
    reactor_t *reactor = (reactor_t *)thread->argument;
    cm_set_thread_name("reactor");
    LOG_RUN_INF("reactor thread[%d] started.", reactor->id);
    while (!thread->closed) {
        wr_reactor_poll_events(reactor);
        if (reactor->status == REACTOR_STATUS_PAUSING) {
            reactor->status = REACTOR_STATUS_PAUSED;
        }
    }
    LOG_RUN_INF("reactor thead[%d] closed.", reactor->id);
    (void)epoll_close(reactor->epollfd);
}

static status_t wr_reactor_start_threadpool(reactor_t *reactor)
{
    // init thread pool
    cm_init_thread_pool(&reactor->workthread_pool);
    cm_init_thread_lock(&reactor->lock);
    status_t ret = cm_create_thread_pool(&reactor->workthread_pool, SIZE_K(512), reactor->workthread_count);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[reactor] failed to create reactor work thread pool, errno %d", cm_get_os_error());
        return ret;
    }

    pooling_thread_t *poolingthread = NULL;
    for (uint32_t pos = 0; pos < reactor->workthread_count; pos++) {
        if (cm_get_idle_pooling_thread(&reactor->workthread_pool, &poolingthread) != CM_SUCCESS) {
            LOG_RUN_ERR("[reactor] failed to get idle work thread pool, errno %d", cm_get_os_error());
            return CM_ERROR;
        }
        reactor->workthread_ctx[pos].thread_obj = poolingthread;
        reactor->workthread_ctx[pos].status = THREAD_STATUS_IDLE;
        reactor->workthread_ctx[pos].task.action = NULL;
        reactor->workthread_ctx[pos].task.param = NULL;
    }

    return CM_SUCCESS;
}

static status_t wr_reactors_start()
{
    reactor_t *reactor = NULL;
    reactors_t *pool = &g_wr_instance.reactors;
    for (uint32_t i = 0; i < pool->reactor_count; i++) {
        reactor = &pool->reactor_arr[i];
        reactor->id = i;
        reactor->workthread_count = g_wr_instance.inst_cfg.params.workthread_count;
        if (cm_event_init(&reactor->idle_evnt) != CM_SUCCESS) {
            LOG_RUN_ERR("[reactor] failed to init reactor idle event, errno %d", cm_get_os_error());
            return CM_ERROR;
        }
        if (wr_reactor_start_threadpool(reactor) != CM_SUCCESS) {
            return CM_ERROR;
        }
        reactor->epollfd = epoll_create1(0);
        if (reactor->epollfd == -1) {
            LOG_RUN_ERR("[reactor] failed to create epoll fd, errno %d", cm_get_os_error());
            return CM_ERROR;
        }
        reactor->status = REACTOR_STATUS_RUNNING;
        if (cm_create_thread(wr_reactor_entry, SIZE_K(512), reactor, &reactor->iothread) != CM_SUCCESS) {
            LOG_RUN_ERR("[reactor] failed to create reactor thread, errno %d", cm_get_os_error());
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t wr_create_reactors()
{
    reactors_t *pool = &g_wr_instance.reactors;
    (void)cm_atomic_set(&pool->roudroubin, 0);
    pool->reactor_count = g_wr_instance.inst_cfg.params.iothread_count;
    size_t size = sizeof(reactor_t) * pool->reactor_count;
    if ((size == 0) || (size / sizeof(reactor_t) != pool->reactor_count)) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)0, "creating reactors");
        return CM_ERROR;
    }

    pool->reactor_arr = (reactor_t *)malloc(size);
    if (pool->reactor_arr == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "creating reactors");
        return CM_ERROR;
    }

    errno_t err = memset_s(pool->reactor_arr, size, 0, size);
    if (err != EOK) {
        CM_FREE_PTR(pool->reactor_arr);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, (err));
        return CM_ERROR;
    }
    if (wr_reactors_start() != CM_SUCCESS) {
        wr_destroy_reactors();
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void wr_pause_reactors()
{
    reactors_t *pool = &g_wr_instance.reactors;
    reactor_t *reactor = NULL;
    if (pool->reactor_arr == NULL) {
        return;
    }
    for (uint32_t i = 0; i < pool->reactor_count; i++) {
        reactor = &pool->reactor_arr[i];
        reactor->status = REACTOR_STATUS_PAUSING;
        while (reactor->status != REACTOR_STATUS_PAUSED && !reactor->iothread.closed) {
            cm_sleep(5);
        }
    }
}

void wr_continue_reactors()
{
    reactors_t *pool = &g_wr_instance.reactors;
    reactor_t *reactor = NULL;
    if (pool->reactor_arr == NULL) {
        return;
    }

    for (uint32_t i =0; i < pool->reactor_count; i++) {
        reactor = &pool->reactor_arr[i];
        reactor->status = REACTOR_STATUS_RUNNING;
    }
}

void wr_destroy_reactors()
{
    reactor_t *reactor = NULL;
    reactors_t *pool = &g_wr_instance.reactors;
    if (pool->reactor_arr == NULL) {
        return;
    }
    for (uint32_t pos = 0; pos < pool->reactor_count; pos++) {
        reactor = &pool->reactor_arr[pos];
        (void)epoll_close(reactor->epollfd);
        if (reactor->iothread.closed == CM_FALSE) {
            cm_close_thread(&reactor->iothread);
        }
        reactor->status = REACTOR_STATUS_STOPPED;
        cm_destroy_thread_pool(&reactor->workthread_pool);
    }
    pool->reactor_count = 0;
    CM_FREE_PTR(pool->reactor_arr);
}

status_t wr_reactors_add_session(wr_session_t *session)
{
    reactors_t *pool = &g_wr_instance.reactors;
    uint32_t reactor_idx = cm_atomic_inc(&pool->roudroubin) % pool->reactor_count;
    reactor_t *reactor = &pool->reactor_arr[reactor_idx];
    session->reactor = reactor;
    struct epoll_event ev;
    int fd = (int)session->pipe.link.uds.sock;

    (void)cm_atomic32_inc(&reactor->session_count);
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.ptr = session;
    if (epoll_ctl(reactor->epollfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        LOG_RUN_ERR("[reactor] add session to reactor failed, session %u, reactor %u, os error %d", session->id,
            reactor->id, cm_get_sock_error());
        (void)cm_atomic32_dec(&reactor->session_count);
        return CM_ERROR;
    }

    session->reactor_added = CM_TRUE;
    LOG_DEBUG_INF("[reactor] add session %u to reactor %u sucessfully, current session count %d", session->id,
        reactor->id, reactor->session_count);
    return CM_SUCCESS;
}

void wr_reactors_del_session(wr_session_t *session)
{
    int fd = (int)session->pipe.link.uds.sock;
    reactor_t *reactor = (reactor_t *)session->reactor;
    (void)epoll_ctl(reactor->epollfd, EPOLL_CTL_DEL, fd, NULL);

    (void)cm_atomic32_dec(&reactor->session_count);
    session->reactor_added = CM_FALSE;
    session->reactor = NULL;
    LOG_DEBUG_INF("[reactor] delete session %u to reactor %u sucessfully, current session count %d", session->id,
        reactor->id, reactor->session_count);
}

void wr_clean_reactor_session(wr_session_t *session)
{
    wr_workthread_t *workthread_ctx = (wr_workthread_t *)session->workthread_ctx;
    wr_reactors_del_session(session);
    wr_session_detach_workthread_inner(session);
    wr_release_session_res(session);
    // must be the last step
    wr_reset_workthread_ctx(workthread_ctx);
}

#ifdef __cplusplus
}
#endif