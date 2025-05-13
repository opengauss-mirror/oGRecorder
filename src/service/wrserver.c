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
 * wrserver.c
 *
 *
 * IDENTIFICATION
 *    src/service/wrserver.c
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
#include "wr_errno.h"
#include "wr_shm.h"
#include "wr_instance.h"
#include "wr_mes.h"
#include "wr_zero.h"
#include "cm_utils.h"
#include "wr_meta_buf.h"
#include "wr_syn_meta.h"
#include "wr_thv.h"

#ifndef _NSIG
#define MAX_SIG_NUM 32
#else
#define MAX_SIG_NUM _NSIG
#endif

#ifdef __cplusplus
extern "C" {
#endif

static void wr_close_background_task(wr_instance_t *inst)
{
    uint32_t bg_task_base_id = wr_get_uwression_startid() - (uint32_t)WR_BACKGROUND_TASK_NUM;
    for (uint32_t i = 0; i < WR_BACKGROUND_TASK_NUM; i++) {
        uint32_t bg_task_id = bg_task_base_id + i;
        if (inst->threads[bg_task_id].id != 0) {
            cm_close_thread(&inst->threads[bg_task_id]);
        }
    }
}

static void wr_close_thread(wr_instance_t *inst)
{
    // pause lsnr thread
    tcp_lsnr_t *lsnr = &inst->lsnr;
    cm_latch_x(&inst->tcp_lsnr_latch, WR_DEFAULT_SESSIONID, NULL);
    cs_pause_tcp_lsnr(lsnr);
    cm_unlatch(&inst->tcp_lsnr_latch, NULL);
    // close worker thread
    wr_destroy_reactors();

    if (inst->threads != NULL) {
        wr_close_background_task(inst);
        WR_FREE_POINT(inst->threads);
    }

    // close lsnr thread
    cs_stop_tcp_lsnr(lsnr);
    lsnr->status = LSNR_STATUS_STOPPED;

    // close time thread, should at end, no timer, no time
    cm_close_timer(g_timer());
}

static void wr_clean_server()
{
    wr_close_thread(&g_wr_instance);
    wr_stop_mes();
    wr_uninit_cm(&g_wr_instance);
    wr_free_log_ctrl();
    if (g_wr_instance.lock_fd != CM_INVALID_INT32) {
        (void)cm_unlock_fd(g_wr_instance.lock_fd);
        cm_close_file(g_wr_instance.lock_fd);
    }
    CM_FREE_PTR(cm_log_param_instance()->log_compress_buf);
    wr_uninit_zero_buf();
    CM_FREE_PTR(g_wr_session_ctrl.sessions);
}

static void handle_main_wait(void)
{
    int64 periods = 0;
    uint32_t interval = 500;
    do {
        if (g_wr_instance.abort_status == CM_TRUE) {
            break;
        }
        if (!g_wr_instance.is_maintain) {
            wr_check_peer_inst(&g_wr_instance, WR_INVALID_ID64);
        }
        if (periods == MILLISECS_PER_SECOND * SECONDS_PER_DAY / interval) {
            periods = 0;
            wr_ssl_ca_cert_expire();
        }

        wr_clean_all_sessions_latch();
        cm_sleep(interval);
        periods++;
    } while (CM_TRUE);
    wr_clean_server();
}

static status_t wr_recovery_background_task(wr_instance_t *inst)
{
    LOG_RUN_INF("create wr recovery background task.");
    uint32_t recovery_thread_id = wr_get_uwression_startid() - (uint32_t)WR_BACKGROUND_TASK_NUM;
    status_t status = cm_create_thread(
        wr_get_cm_lock_and_recover, 0, &g_wr_instance, &(g_wr_instance.threads[recovery_thread_id]));
    return status;
}

static status_t wr_delay_clean_background_task(wr_instance_t *inst)
{
    LOG_RUN_INF("create wr delay clean background task.");
    uint32_t delay_clean_idx = wr_get_delay_clean_task_idx();
    status_t status =
        cm_create_thread(wr_delay_clean_proc, 0, &g_wr_instance, &(g_wr_instance.threads[delay_clean_idx]));
    return status;
}

static status_t wr_init_background_tasks(void)
{
    status_t status = wr_recovery_background_task(&g_wr_instance);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create wr recovery background task failed.");
        return status;
    }

    status = wr_delay_clean_background_task(&g_wr_instance);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create wr delay clean background task failed.");
        return status;
    }
    return status;
}

typedef status_t (*wr_srv_arg_parser)(int argc, char **argv, int *argIdx, wr_srv_args_t *wr_args);
typedef struct st_wr_srv_arg_handler {
    char name[WR_MAX_PATH_BUFFER_SIZE];
    wr_srv_arg_parser parser;
} wr_srv_arg_handler_t;

status_t wr_srv_parse_home(int argc, char **argv, int *argIdx, wr_srv_args_t *wr_args)
{
    if ((*argIdx + 1) >= argc || argv[*argIdx + 1] == NULL) {
        (void)printf("-D should specified home path.\n");
        return CM_ERROR;
    }
    char *home = (char *)argv[*argIdx + 1];
    uint32_t len = (uint32_t)strlen(home);
    if (len == 0 || len >= WR_MAX_PATH_BUFFER_SIZE) {
        (void)printf("the len of path specified by -D is invalid.\n");
        return CM_ERROR;
    }
    if (realpath_file(home, wr_args->wr_home, WR_MAX_PATH_BUFFER_SIZE) != CM_SUCCESS) {
        (void)printf("The path specified by -D is invalid.\n");
        return CM_ERROR;
    }
    if (!cm_dir_exist(wr_args->wr_home) || (access(wr_args->wr_home, R_OK) != 0)) {
        (void)printf("The path specified by -D is invalid.\n");
        return CM_ERROR;
    }
    (*argIdx)++;
    return CM_SUCCESS;
}

status_t wr_srv_parse_maintain(int argc, char **argv, int *argIdx, wr_srv_args_t *wr_args)
{
    wr_args->is_maintain = true;
    return CM_SUCCESS;
}

wr_srv_arg_handler_t g_wr_args_handler[] = {{"-D", wr_srv_parse_home}, {"-M", wr_srv_parse_maintain}};

status_t wr_srv_parse_one_agr(int argc, char **argv, wr_srv_args_t *wr_args, int *argIdx)
{
    int support_args_count = sizeof(g_wr_args_handler) / sizeof(g_wr_args_handler[0]);
    for (int support_idx = 0; support_idx < support_args_count; support_idx++) {
        if (cm_str_equal(argv[*argIdx], g_wr_args_handler[support_idx].name)) {
            return g_wr_args_handler[support_idx].parser(argc, argv, argIdx, wr_args);
        }
    }
    (void)printf("invalid argument: %s\n", argv[*argIdx]);
    return CM_ERROR;
}

status_t wr_srv_parse_agrs(int argc, char **argv, wr_srv_args_t *wr_args)
{
    status_t ret;
    for (int i = 1; i < argc; i++) {
        ret = wr_srv_parse_one_agr(argc, argv, wr_args, &i);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    }
    return CM_SUCCESS;
}

static void wr_srv_usage()
{
    (void)printf("Usage:\n"
                 "       wrserver [-h]\n"
                 "       wrserver [-D wr_home_path]\n"
                 "Option:\n"
                 "\t -M                 WR_MAINTAIN mode.\n"
                 "\t -h                 show the help information.\n"
                 "\t -D                 specify wr server home path.\n");
}

int main(int argc, char **argv)
{
#ifndef WIN32
    // check root
    if (geteuid() == 0 || getuid() != geteuid()) {
        (void)printf("The root user is not permitted to execute the wrserver "
                     "and the real uids must be the same as the effective uids.\n");
        (void)fflush(stdout);
        return CM_ERROR;
    }
#endif

    if (argc == 2) {
        if (cm_str_equal(argv[1], "-h")) {
            wr_srv_usage();
            return CM_SUCCESS;
        }
    }
    wr_srv_args_t wr_args;
    errno_t errcode = memset_s(&wr_args, sizeof(wr_args), 0, sizeof(wr_args));
    securec_check_ret(errcode);
    if (wr_srv_parse_agrs(argc, argv, &wr_args) != CM_SUCCESS) {
        (void)fflush(stdout);
        wr_exit_error();
    }
#ifndef WIN32
    sigset_t sign_old_mask;
    (void)sigprocmask(0, NULL, &sign_old_mask);
    (void)sigprocmask(SIG_UNBLOCK, &sign_old_mask, NULL);
#endif
    if (wr_startup(&g_wr_instance, wr_args) != CM_SUCCESS) {
        (void)printf("wr failed to startup.\n");
        fflush(stdout);
        wr_clean_server();
        LOG_RUN_ERR("wr failed to startup.");
        wr_exit_error();
    }
    if (wr_init_background_tasks() != CM_SUCCESS) {
        (void)printf("WR SERVER END.\n");
        fflush(stdout);
        wr_clean_server();
        LOG_RUN_ERR("wr failed to startup.");
        LOG_RUN_INF("WR SERVER STARTED.\n");
        wr_exit_error();
    }
    (void)printf("WR SERVER STARTED.\n");
    LOG_RUN_INF("WR SERVER STARTED.\n");
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_instance_starting = CM_FALSE;
    handle_main_wait();
    (void)printf("WR SERVER END.\n");
    LOG_RUN_INF("WR SERVER END.\n");
    return 0;
}

#ifdef __cplusplus
}
#endif
