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
 * cm_thv.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_thv.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_thread.h"
#include "cm_error.h"
#include "wr_log.h"
#include "cm_log.h"
#include "wr_thv.h"
#ifndef WIN32
#include <sys/time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
static __thread wr_thv_run_ctx_t wr_thv_run_ctx = {0};
#else
__declspec(thread) wr_thv_run_ctx_t wr_thv_run_ctx = {0};
#endif

#ifndef WIN32
/* ****Thread variable defined begin.**** */
// THV --> THREAD VARIANT
// Thread variable control function.
static thv_ctrl_t g_thv_ctrl_func[MAX_THV_TYPE];

// Thread variant address, it will be created in function create_var_func and released in function release_var_func.
static __thread pointer_t g_thv_addr[MAX_THV_TYPE] = {0};
static pthread_key_t g_thv_key;

void wr_exit_error()
{
    LOG_RUN_INF("Try to exit.");
    _exit(1);
}
// destroy all thread variable content when thread exit
static void cm_destroy_thv(pointer_t thread_var)
{
    if (thread_var == NULL) {
        return;
    }
    pointer_t *curr_thread_var = (pointer_t *)thread_var;
    for (uint32_t i = 0; i < MAX_THV_TYPE; i++) {
        if (curr_thread_var[i] != NULL) {
            if (g_thv_ctrl_func[i].release != NULL) {
                g_thv_ctrl_func[i].release(curr_thread_var[i]);
            }
            curr_thread_var[i] = NULL;
        }
    }
}

void wr_destroy_thv(thv_type_e type)
{
    cm_destroy_thv(&g_thv_addr[type]);
}

status_t cm_create_thv_ctrl(void)
{
    int32_t ret = pthread_key_create(&g_thv_key, cm_destroy_thv);
    if (ret != EOK) {
        LOG_RUN_ERR("call pthread_key_create failed");
        return CM_ERROR;
    }
    errno_t errcode =
        memset_s(g_thv_ctrl_func, sizeof(thv_ctrl_t) * MAX_THV_TYPE, 0, sizeof(thv_ctrl_t) * MAX_THV_TYPE);
    securec_check_ret(errcode);
    return CM_SUCCESS;
}

status_t cm_set_thv_args_by_id(
    thv_type_e var_type, init_thv_func init, create_thv_func create, release_thv_func release)
{
    if (var_type >= MAX_THV_TYPE) {
        LOG_RUN_ERR("invalid var type %u", (uint32_t)var_type);
        return CM_ERROR;
    }

    g_thv_ctrl_func[var_type].init = init;

    if (create == NULL) {
        LOG_RUN_ERR("create_thv_func cannot be null");
        return CM_ERROR;
    }
    g_thv_ctrl_func[var_type].create = create;
    g_thv_ctrl_func[var_type].release = release;

    return CM_SUCCESS;
}

void cm_init_thv(void)
{
    for (uint32_t var_type = 0; var_type < MAX_THV_TYPE; var_type++) {
        if (g_thv_ctrl_func[var_type].init != NULL) {
            g_thv_ctrl_func[var_type].init();
        }
    }
}

status_t cm_get_thv(thv_type_e var_type, bool32 is_create, pointer_t *result, const char* addr)
{
    if (is_create) {
        int32_t ret = g_thv_ctrl_func[var_type].create(result, addr);
        if (ret != EOK) {
            LOG_RUN_ERR("create thread variable failed, var_type %u", (uint32_t)var_type);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t cm_launch_thv(thv_ctrl_t *thv_ctrls, uint32_t thv_ctrl_cnt)
{
    // now begin init thread variant
    if (cm_create_thv_ctrl() != CM_SUCCESS) {
        return CM_ERROR;
    }

    for (uint32_t i = 0; i < thv_ctrl_cnt; i++) {
        if (cm_set_thv_args_by_id(i, thv_ctrls[i].init, thv_ctrls[i].create, thv_ctrls[i].release) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    cm_init_thv();

    return CM_SUCCESS;
}

/* ****Thread variable defined end.**** */
#else

status_t cm_create_thv_ctrl(void)
{
    return CM_SUCCESS;
}

status_t cm_set_thv_args_by_id(
    thv_type_e var_type, init_thv_func init, create_thv_func create, release_thv_func release)
{
    return CM_SUCCESS;
}

void cm_init_thv(void)
{}

status_t cm_get_thv(thv_type_e var_type, bool32 is_create, pointer_t *result, const char* addr)
{
    return CM_ERROR;
}

status_t cm_launch_thv(thv_ctrl_t *thv_ctrls, uint32_t thv_ctrl_cnt)
{
    return CM_SUCCESS;
}

#endif

uint32_t wr_get_current_thread_id()
{
    if (wr_thv_run_ctx.thread_id != 0) {
        return wr_thv_run_ctx.thread_id;
    }
    wr_thv_run_ctx.thread_id = cm_get_current_thread_id();
    return wr_thv_run_ctx.thread_id;
}

void wr_set_thv_run_ctx_item(wr_thv_run_ctx_item_e item, void *item_addr)
{
    if (item < WR_THV_RUN_CTX_ITEM_MAX) {
        wr_thv_run_ctx.item_addr[item] = item_addr;
    }
}

void *wr_get_thv_run_ctx_item(wr_thv_run_ctx_item_e item)
{
    if (item < WR_THV_RUN_CTX_ITEM_MAX) {
        return wr_thv_run_ctx.item_addr[item];
    }
    return NULL;
}

#ifdef __cplusplus
}
#endif
