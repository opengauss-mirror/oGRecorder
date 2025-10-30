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
 * grserver.c
 *
 *
 * IDENTIFICATION
 *    src/service/grserver.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#endif
#include "cm_types.h"
#include "cm_signal.h"
#include "cm_utils.h"
#include "gr_errno.h"
// #include "gr_shm.h"
#include "gr_instance.h"
#include "gr_mes.h"
#include "gr_zero.h"
#include "cm_utils.h"
#include "gr_meta_buf.h"
#include "gr_syn_meta.h"
#include "gr_thv.h"
#include "ssl_func.h"

#ifndef _NSIG
#define MAX_SIG_NUM 32
#else
#define MAX_SIG_NUM _NSIG
#endif

#ifdef __cplusplus
extern "C" {
#endif

static void gr_close_background_task(gr_instance_t *inst)
{
    uint32_t bg_task_base_id = gr_get_uwression_startid() - (uint32_t)GR_BACKGROUND_TASK_NUM;
    for (uint32_t i = 0; i < GR_BACKGROUND_TASK_NUM; i++) {
        uint32_t bg_task_id = bg_task_base_id + i;
        if (inst->threads[bg_task_id].id != 0) {
            cm_close_thread(&inst->threads[bg_task_id]);
        }
    }
}

static void gr_close_thread(gr_instance_t *inst)
{
    // pause lsnr thread
    tcp_lsnr_t *lsnr = &inst->lsnr;
    cm_latch_x(&inst->tcp_lsnr_latch, GR_DEFAULT_SESSIONID, NULL);
    cs_pause_tcp_lsnr(lsnr);
    cm_unlatch(&inst->tcp_lsnr_latch, NULL);
    // close worker thread
    gr_destroy_reactors();

    if (inst->threads != NULL) {
        gr_close_background_task(inst);
        GR_FREE_POINT(inst->threads);
    }

    // close lsnr thread
    cs_stop_tcp_lsnr(lsnr);
    lsnr->status = LSNR_STATUS_STOPPED;

    // close time thread, should at end, no timer, no time
    cm_close_timer(g_timer());
}

static void gr_clean_server()
{
    gr_close_thread(&g_gr_instance);
    gr_stop_mes();
    ser_ssl_uninit();
    gr_uninit_cm(&g_gr_instance);
    gr_free_log_ctrl();
    if (g_gr_instance.lock_fd != CM_INVALID_INT32) {
        (void)cm_unlock_fd(g_gr_instance.lock_fd);
        cm_close_file(g_gr_instance.lock_fd);
    }
    CM_FREE_PTR(cm_log_param_instance()->log_compress_buf);
    gr_uninit_zero_buf();
    for (uint32_t i = 0; i < g_gr_session_ctrl.alloc_sessions; i++) {
        if (g_gr_session_ctrl.sessions[i] != NULL) {
            CM_FREE_PTR(g_gr_session_ctrl.sessions[i]);
        }
    }
    CM_FREE_PTR(g_gr_session_ctrl.sessions);
}

static void handle_main_wait(void)
{
    int64 periods = 0;
    uint32_t interval = 500;
    do {
        if (g_gr_instance.abort_status == CM_TRUE) {
            break;
        }
        if (!g_gr_instance.is_maintain) {
            gr_check_peer_inst(&g_gr_instance, GR_INVALID_ID64);
        }
        if (periods == MILLISECS_PER_SECOND * SECONDS_PER_DAY / interval) {
            periods = 0;
            gr_ssl_ca_cert_expire();
        }

        gr_clean_all_sessions_latch();
        cm_sleep(interval);
        periods++;
    } while (CM_TRUE);
    gr_clean_server();
}

static status_t gr_recovery_background_task(gr_instance_t *inst)
{
    LOG_RUN_INF("create gr recovery background task.");
    uint32_t recovery_thread_id = gr_get_uwression_startid() - (uint32_t)GR_BACKGROUND_TASK_NUM;
    status_t status = cm_create_thread(
        gr_get_cm_lock_and_recover, 0, &g_gr_instance, &(g_gr_instance.threads[recovery_thread_id]));
    return status;
}

static status_t gr_delay_clean_background_task(gr_instance_t *inst)
{
    LOG_RUN_INF("create gr delay clean background task.");
    uint32_t delay_clean_idx = gr_get_delay_clean_task_idx();
    status_t status =
        cm_create_thread(gr_delay_clean_proc, 0, &g_gr_instance, &(g_gr_instance.threads[delay_clean_idx]));
    return status;
}

static status_t gr_alarm_check_background_task(gr_instance_t *inst)
{
    LOG_RUN_INF("create gr alarm check background task.");
    uint32 vg_usgae_alarm_thread_id = gr_get_alarm_check_task_idx();
    status_t status =
        cm_create_thread(gr_alarm_check_proc, 0, &g_gr_instance, &(g_gr_instance.threads[vg_usgae_alarm_thread_id]));
    return status;
}

static status_t gr_init_background_tasks(void)
{
    status_t status = gr_recovery_background_task(&g_gr_instance);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create gr recovery background task failed.");
        return status;
    }

    status = gr_delay_clean_background_task(&g_gr_instance);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create gr delay clean background task failed.");
        return status;
    }
    status = gr_alarm_check_background_task(&g_gr_instance);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create gr disk usage alarm background task failed.");
        return status;
    }
    return status;
}

typedef status_t (*gr_srv_arg_parser)(int argc, char **argv, int *argIdx, gr_srv_args_t *gr_args);
typedef struct st_gr_srv_arg_handler {
    char name[GR_MAX_PATH_BUFFER_SIZE];
    gr_srv_arg_parser parser;
} gr_srv_arg_handler_t;

status_t gr_srv_parse_home(int argc, char **argv, int *argIdx, gr_srv_args_t *gr_args)
{
    if ((*argIdx + 1) >= argc || argv[*argIdx + 1] == NULL) {
        (void)printf("-D should specified home path.\n");
        return CM_ERROR;
    }
    char *home = (char *)argv[*argIdx + 1];
    uint32_t len = (uint32_t)strlen(home);
    if (len == 0 || len >= GR_MAX_PATH_BUFFER_SIZE) {
        (void)printf("the len of path specified by -D is invalid.\n");
        return CM_ERROR;
    }
    if (realpath_file(home, gr_args->gr_home, GR_MAX_PATH_BUFFER_SIZE) != CM_SUCCESS) {
        (void)printf("The path specified by -D is invalid.\n");
        return CM_ERROR;
    }
    if (!cm_dir_exist(gr_args->gr_home) || (access(gr_args->gr_home, R_OK) != 0)) {
        (void)printf("The path specified by -D is invalid.\n");
        return CM_ERROR;
    }
    (*argIdx)++;
    return CM_SUCCESS;
}

status_t gr_srv_parse_maintain(int argc, char **argv, int *argIdx, gr_srv_args_t *gr_args)
{
    gr_args->is_maintain = true;
    return CM_SUCCESS;
}

gr_srv_arg_handler_t g_gr_args_handler[] = {{"-D", gr_srv_parse_home}, {"-M", gr_srv_parse_maintain}};

status_t gr_srv_parse_one_agr(int argc, char **argv, gr_srv_args_t *gr_args, int *argIdx)
{
    int support_args_count = sizeof(g_gr_args_handler) / sizeof(g_gr_args_handler[0]);
    for (int support_idx = 0; support_idx < support_args_count; support_idx++) {
        if (cm_str_equal(argv[*argIdx], g_gr_args_handler[support_idx].name)) {
            return g_gr_args_handler[support_idx].parser(argc, argv, argIdx, gr_args);
        }
    }
    (void)printf("invalid argument: %s\n", argv[*argIdx]);
    return CM_ERROR;
}

status_t gr_srv_parse_agrs(int argc, char **argv, gr_srv_args_t *gr_args)
{
    status_t ret;
    for (int i = 1; i < argc; i++) {
        ret = gr_srv_parse_one_agr(argc, argv, gr_args, &i);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    }
    return CM_SUCCESS;
}

static void gr_srv_usage()
{
    (void)printf("Usage:\n"
                 "       grserver [-h]\n"
                 "       grserver [-D gr_home_path]\n"
                 "Option:\n"
                 "\t -M                 GR_MAINTAIN mode.\n"
                 "\t -h                 show the help information.\n"
                 "\t -D                 specify gr server home path.\n");
}

int main(int argc, char **argv)
{
#ifndef WIN32
    // check root
    if (geteuid() == 0 || getuid() != geteuid()) {
        (void)printf("The root user is not permitted to execute the grserver "
                     "and the real uids must be the same as the effective uids.\n");
        (void)fflush(stdout);
        return CM_ERROR;
    }
#endif

    if (argc == 2) {
        if (cm_str_equal(argv[1], "-h")) {
            gr_srv_usage();
            return CM_SUCCESS;
        }
    }
    gr_srv_args_t gr_args;
    errno_t errcode = memset_s(&gr_args, sizeof(gr_args), 0, sizeof(gr_args));
    securec_check_ret(errcode);
    if (gr_srv_parse_agrs(argc, argv, &gr_args) != CM_SUCCESS) {
        (void)fflush(stdout);
        gr_exit_error();
    }
#ifndef WIN32
    sigset_t sign_old_mask;
    (void)sigprocmask(0, NULL, &sign_old_mask);
    (void)sigprocmask(SIG_UNBLOCK, &sign_old_mask, NULL);
#endif
    if (gr_startup(&g_gr_instance, gr_args) != CM_SUCCESS) {
        (void)printf("gr failed to startup.\n");
        fflush(stdout);
        gr_clean_server();
        LOG_RUN_ERR("gr failed to startup.");
        gr_exit_error();
    }
    if (gr_init_background_tasks() != CM_SUCCESS) {
        (void)printf("GR SERVER END.\n");
        fflush(stdout);
        gr_clean_server();
        LOG_RUN_ERR("gr failed to startup.");
        LOG_RUN_INF("GR SERVER STARTED.\n");
        gr_exit_error();
    }
    (void)printf("GR SERVER STARTED.\n");
    LOG_RUN_INF("GR SERVER STARTED.\n");
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_instance_starting = CM_FALSE;
    handle_main_wait();
    (void)printf("GR SERVER END.\n");
    LOG_RUN_INF("GR SERVER END.\n");
    return 0;
}

#ifdef __cplusplus
}
#endif
