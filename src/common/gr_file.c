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
#include "gr_error_handler.h"
#include "gr_param_validator.h"
#include "gr_config_mgr.h"
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

// CAUTION: gr_admin manager command just like gr_create_vg, cannot call it.
gr_config_t *gr_get_inst_cfg(void)
{
    /*
     * Maintain backward compatibility: server uses g_inst_cfg directly,
     * client uses g_gr_env->inst_cfg.
     * For more complex multi-instance/hot-reload support in the future,
     * extend the interface in gr_config_mgr.
     */
    if (gr_is_server()) {
        return gr_cfg_get_server_inst();
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
        GR_ERROR_RETURN(GR_ERR_CATEGORY_RESOURCE, ERR_GR_READONLY, CM_ERROR,
                       "The instance is in read-only mode, cannot execute %s command", name);
    }
}

// return 1 if the character is a letter, 0 otherwise
int is_letter(char c)
{
    return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
}

// return 1 if the character is a digit, 0 otherwise
int is_number(char c)
{
    return (c >= '0' && c <= '9');
}

// Use functions from gr_param_validator.h instead of local implementations.
// gr_is_valid_name_char and gr_is_valid_path_char are now defined in gr_param_validator.c.

static status_t gr_check_name_is_valid(const char *name, uint32_t path_max_size)
{
    GR_RETURN_IF_ERROR(gr_validate_file_name(name));
    
    size_t name_len = strlen(name);
    if (name_len >= path_max_size) {
        GR_PARAM_ERROR_RETURN(ERR_GR_FILE_PATH_ILL, "name is too long: %s (max: %u)", name, path_max_size - 1);
    }
    if (cm_str_equal(name, GR_DIR_PARENT) || cm_str_equal(name, GR_DIR_SELF)) {
        GR_PARAM_ERROR_RETURN(ERR_GR_FILE_PATH_ILL, "name cannot be '..' or '.': %s", name);
    }
    return CM_SUCCESS;
}

static status_t gr_check_path_is_valid(const char *path, uint32_t path_max_size)
{
    GR_RETURN_IF_ERROR(gr_validate_path(path, path_max_size));
    
    for (uint32_t i = 0; path[i] != '\0'; i++) {
        if (!gr_is_valid_path_char(path[i])) {
            GR_PARAM_ERROR_RETURN(ERR_GR_FILE_PATH_ILL, 
                                  "path contains invalid character '%c' at position %u: %s", path[i], i, path);
        }
    }
    return CM_SUCCESS;
}

status_t gr_check_str_not_null(const char *str, const char *desc)
{
    return gr_validate_string(str, 0, desc);
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
    GR_LOG_DEBUG_OP("Begin to extend file %s expired time to %s", file, time);
    GR_CALL_RETURN(gr_filesystem_postpone(file, time), 
                   "Failed to extend file %s expired time to %s", file, time);
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
    GR_LOG_DEBUG_OP("Begin to open file:%s, session id:%u.", file, session->id);
    GR_CALL_RETURN(gr_filesystem_open(file, flag, fd), 
                   "Failed to open file:%s", file);
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
    uint64_t cli_pid = 0;
    int64_t start_time = 0;
    bool32 cli_pid_alive = CM_FALSE;

    // Check all used & connected sessions that may hold a latch by a dead client
    gr_session_ctrl_t *session_ctrl = gr_get_session_ctrl();
    CM_ASSERT(session_ctrl != NULL);
    
    for (uint32_t sid = 0; sid < session_ctrl->alloc_sessions && sid < session_ctrl->total; sid++) {
        gr_session_t *session = gr_get_session(sid);
        CM_ASSERT(session != NULL);
        
        // For connected sessions, cli_pid and start_time must be valid
        if (!session->is_used || !session->connected) {
            continue;
        }

        // Optimization: avoid repeating process liveness checks
        uint64_t current_pid = session->cli_info.cli_pid;
        int64_t current_start_time = session->cli_info.start_time; 
        
        if (current_pid == 0) {
            continue;
        }
        
        // If process information is the same and we have already checked liveness, reuse the previous result
        if (current_pid == cli_pid && current_start_time == start_time) {
            if (cli_pid_alive) {
                continue;
            }
        } else {
            // New process information, need to check liveness
            cli_pid = current_pid;
            start_time = current_start_time;
            cli_pid_alive = cm_sys_process_alived(cli_pid, start_time);
            if (cli_pid_alive) {
                continue;
            }
        }
        LOG_RUN_INF("[CLEAN_LATCH]session id %u, pid %llu, start_time %lld, process name:%s, objectid %u.",
                    session->id, (unsigned long long)cli_pid, (long long)start_time,
                    session->cli_info.process_name, session->objectid);
        // Clean the session lock and latch
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