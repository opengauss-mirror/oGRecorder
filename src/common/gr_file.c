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
 * gr_file.c
 *
 *
 * IDENTIFICATION
 *    src/common/gr_file.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_date.h"
#include "cm_hash.h"
#include "gr_defs.h"
#include "gr_malloc.h"
#include "cm_system.h"
#include "gr_latch.h"
#include "gr_session.h"
#include "gr_zero.h"
#include "gr_syn_meta.h"
#include "gr_thv.h"
#include "gr_filesystem.h"
#include "gr_file.h"
#include <pthread.h>
#include <sys/statvfs.h>

#define MAX_SESSION_CLEANUP_ATTEMPTS 3
#define SESSION_CLEANUP_TIMEOUT_MS 1000

static pthread_mutex_t g_gr_disk_usage_lock = PTHREAD_MUTEX_INITIALIZER;
static gr_disk_usage_info_t g_gr_disk_usage_info = {0};

gr_env_t g_gr_env;
gr_env_t *gr_get_env(void)
{
    return &g_gr_env;
}

// CAUTION: gr_admin manager command just like gr_create_vg,cannot call it,
gr_config_t *gr_get_inst_cfg(void)
{
    if (gr_is_server()) {
        return g_inst_cfg;
    } else {
        gr_env_t *gr_env = gr_get_env();
        return &gr_env->inst_cfg;
    }
}

int gr_check_readwrite(const char* name)
{
    if (gr_is_readwrite()) {
        return CM_SUCCESS;
    } else {
        GR_THROW_ERROR(ERR_GR_READONLY, name);
        LOG_RUN_ERR("The instance is in read-only mode, cannot execute %s command.", name);
        return CM_ERROR;
    }
}

//    return 1 is letter
//    return 0 is not letter
int is_letter(char c)
{
    return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
}

//    return 1 is number
//    return 0 is not number
int is_number(char c)
{
    return (c >= '0' && c <= '9');
}

static status_t gr_is_valid_name_char(char name)
{
    if (!is_number(name) && !is_letter(name) && name != '_' && name != '.' && name != '-') {
        return CM_ERROR;
    }
    
        return CM_SUCCESS;
    }
    
static status_t gr_is_valid_path_char(char name)
{
    if (name != '/' && gr_is_valid_name_char(name) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t gr_check_name_is_valid(const char *name, uint32_t path_max_size)
{
    size_t name_len = strlen(name);
    if (name_len >= path_max_size) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_FILE_PATH_ILL, name, ", name is too long"));
    }
    if (cm_str_equal(name, GR_DIR_PARENT) || cm_str_equal(name, GR_DIR_SELF)) {
        GR_THROW_ERROR(ERR_GR_FILE_PATH_ILL, name, ", cannot be '..' or '.'");
        return CM_ERROR;
    }

    for (uint32_t i = 0; i < name_len; i++) {
        status_t status = gr_is_valid_name_char(name[i]);
        GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_FILE_PATH_ILL, name, ", name should be [0~9,a~z,A~Z,-,_,.]"));
    }
    return CM_SUCCESS;
}

static status_t gr_check_path_is_valid(const char *path, uint32_t path_max_size)
{
    size_t path_len = strlen(path);
    if (path_len >= path_max_size) {
        GR_THROW_ERROR(ERR_GR_FILE_PATH_ILL, path, ", path is too long\n");
        return CM_ERROR;
    }

    for (uint32_t i = 0; i < path_len; i++) {
        if (gr_is_valid_path_char(path[i]) != CM_SUCCESS) {
            GR_RETURN_IFERR2(
                CM_ERROR, GR_THROW_ERROR(ERR_GR_FILE_PATH_ILL, path, ", path should be [0~9,a~z,A~Z,-,_,/,.]"));
        }
    }
    return CM_SUCCESS;
}

status_t gr_check_str_not_null(const char *str, const char *desc)
{
    if (str == NULL || str[0] == '\0') {
        GR_THROW_ERROR(ERR_GR_FILE_PATH_ILL, "[null]", ", %s cannot be a null or empty string.", desc);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_check_name(const char *name)
{
    gr_check_str_not_null(name, "name");
    return gr_check_name_is_valid(name, GR_MAX_NAME_LEN);
}

status_t gr_check_device_path(const char *path)
{
    gr_check_str_not_null(path, "device path");
    return gr_check_path_is_valid(path + 1, (GR_FILE_PATH_MAX_LENGTH - 1));
}

status_t gr_postpone_file(gr_session_t *session, const char *file, const char *time)
{
    status_t status;
    GR_LOG_DEBUG_OP("Begin to extend file %s expired time to %s", file, time);
    status = gr_filesystem_postpone(file, time);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS]Failed to extend file %s expired time to %s.", file, time);
        return CM_ERROR;
    }
    GR_LOG_DEBUG_OP("Succeed to extend file %s expired time to %s.", file, time);
    return CM_SUCCESS;
}

status_t gr_exist_item(gr_session_t *session, const char *item, bool32 *result, gft_item_type_t *output_type)
{
    CM_ASSERT(item != NULL);
    status_t status;
    *result = CM_FALSE;

    status = CM_ERROR;
    do {
        status = gr_filesystem_exist_item(item, result, output_type);
        if (status != CM_SUCCESS) {
            GR_BREAK_IFERR2(CM_ERROR, LOG_RUN_ERR("Failed to check item, errcode:%d.", status));
        }
        status = CM_SUCCESS;
    } while (0);

    return status;
}

status_t gr_open_file(gr_session_t *session, const char *file, int32_t flag, int *fd)
{
    status_t status;
    GR_LOG_DEBUG_OP("Begin to open file:%s, session id:%u.", file, session->id);
    status = gr_filesystem_open(file, flag, fd);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS]Failed to open file:%s.", file);
        return CM_ERROR;
    }
    GR_LOG_DEBUG_OP("Succeed to open file:%s, fd:%d, session:%u.", file, *fd, session->id);
    return CM_SUCCESS;
}

typedef status_t (*gr_invalidate_other_nodes_proc_t)();
gr_invalidate_other_nodes_proc_t invalidate_other_nodes_proc = NULL;

typedef status_t (*gr_broadcast_check_file_open_proc_t)();
gr_broadcast_check_file_open_proc_t broadcast_check_file_open_proc = NULL;

void regist_invalidate_other_nodes_proc(gr_invalidate_other_nodes_proc_t proc)
{
    invalidate_other_nodes_proc = proc;
}

void regist_broadcast_check_file_open_proc(gr_broadcast_check_file_open_proc_t proc)
{
    broadcast_check_file_open_proc = proc;
}

status_t gr_check_open_file_remote(gr_session_t *session, const char *vg_name, uint64 ftid, bool32 *is_open)
{
    return CM_SUCCESS;
}

void gr_clean_all_sessions_latch()
{
    uint64 cli_pid = 0;
    int64 start_time = 0;
    bool32 cli_pid_alived = 0;

    // check all used && connected session may occopy latch by dead client
    gr_session_ctrl_t *session_ctrl = gr_get_session_ctrl();
    CM_ASSERT(session_ctrl != NULL);
    
    for (uint32_t sid = 0; sid < session_ctrl->alloc_sessions && sid < session_ctrl->total; sid++) {
        gr_session_t *session = gr_get_session(sid);
        CM_ASSERT(session != NULL);
        
        // connected make sure the cli_pid and start_time are valid
        if (!session->is_used || !session->connected) {
            continue;
        }

        // 优化：避免重复的进程存活检查
        uint64 current_pid = session->cli_info.cli_pid;
        int64 current_start_time = session->cli_info.start_time; 
        
        if (current_pid == 0) {
            continue;
        }
        
        // 如果进程信息相同且已经检查过存活状态，直接使用之前的结果
        if (current_pid == cli_pid && current_start_time == start_time) {
            if (cli_pid_alived) {
                continue;
            }
        } else {
            // 新的进程，需要检查存活状态
            cli_pid = current_pid;
            start_time = current_start_time;
            cli_pid_alived = cm_sys_process_alived(cli_pid, start_time);
            if (cli_pid_alived) {
                continue;
            }
        }
        LOG_RUN_INF("[CLEAN_LATCH]session id %u, pid %llu, start_time %lld, process name:%s, objectid %u.", session->id,
            cli_pid, start_time, session->cli_info.process_name, session->objectid);
        // clean the session lock and latch
        if (!cm_spin_try_lock(&session->lock)) {
            continue;
        }
        while (!cm_spin_timed_lock(&session->shm_lock, GR_SERVER_SESS_TIMEOUT)) {
            // unlock if the client goes offline
            cm_spin_unlock(&session->shm_lock);
            LOG_RUN_INF("Succeed to unlock session %u shm lock", session->id);
            cm_sleep(CM_SLEEP_500_FIXED);
        }
        LOG_DEBUG_INF("Succeed to lock session %u shm lock", session->id);
        gr_clean_session_latch(session, CM_TRUE);
        gr_server_session_unlock(session);
    }
}

void gr_get_disk_usage_info(gr_disk_usage_info_t *info)
{
    pthread_mutex_lock(&g_gr_disk_usage_lock);
    *info = g_gr_disk_usage_info;
    pthread_mutex_unlock(&g_gr_disk_usage_lock);
}

static void gr_set_disk_usage_info(unsigned long total, unsigned long used, unsigned long avail, double usage)
{
    pthread_mutex_lock(&g_gr_disk_usage_lock);
    g_gr_disk_usage_info.total_bytes = total;
    g_gr_disk_usage_info.used_bytes = used;
    g_gr_disk_usage_info.available_bytes = avail;
    g_gr_disk_usage_info.usage_percent = usage;
    pthread_mutex_unlock(&g_gr_disk_usage_lock);
}

void gr_alarm_check_disk_usage()
{
    const char *data_path = g_inst_cfg->params.data_file_path;
    struct statvfs stat;
    if (statvfs(data_path, &stat) != 0) {
        LOG_RUN_ERR("[ALARM] Failed to get disk usage for %s, errno=%d", data_path, errno);
        gr_set_disk_usage_info(0, 0, 0, 0);
        return;
    }

    unsigned long total = stat.f_blocks * stat.f_frsize;
    unsigned long available = stat.f_bavail * stat.f_frsize;
    unsigned long used = total - available;
    double usage = (total == 0) ? 0 : (double)used / (double)total * 100.0;

    LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "[ALARM] Disk usage of %s: total=%.2fGB, used=%.2fGB, available=%.2fGB, usage=%.2f%%.",
        data_path, total / 1073741824.0, used / 1073741824.0, available / 1073741824.0, usage);
    gr_set_disk_usage_info(total, used, available, usage);
}