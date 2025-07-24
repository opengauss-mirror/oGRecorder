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
 * wr_file.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_file.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_date.h"
#include "wr_ga.h"
#include "cm_hash.h"
#include "wr_defs.h"
#include "wr_hashmap.h"
#include "wr_shm.h"
#include "wr_malloc.h"
#include "wr_open_file.h"
#include "cm_system.h"
#include "wr_latch.h"
#include "wr_session.h"
#include "wr_zero.h"
#include "wr_syn_meta.h"
#include "wr_thv.h"
#include "wr_filesystem.h"
#include "wr_file.h"
#include <pthread.h>
#include <sys/statvfs.h>

static pthread_mutex_t g_wr_disk_usage_lock = PTHREAD_MUTEX_INITIALIZER;
static wr_disk_usage_info_t g_wr_disk_usage_info = {0};

wr_env_t g_wr_env;
wr_env_t *wr_get_env(void)
{
    return &g_wr_env;
}

// CAUTION: wr_admin manager command just like wr_create_vg,cannot call it,
wr_config_t *wr_get_inst_cfg(void)
{
    if (wr_is_server()) {
        return g_inst_cfg;
    } else {
        wr_env_t *wr_env = wr_get_env();
        return &wr_env->inst_cfg;
    }
}

int wr_check_readwrite(const char* name)
{
    if (wr_is_readwrite()) {
        return CM_SUCCESS;
    } else {
        WR_THROW_ERROR(ERR_WR_READONLY, name);
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

static status_t wr_is_valid_name_char(char name)
{
    if (!is_number(name) && !is_letter(name) && name != '_' && name != '.' && name != '-') {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t wr_is_valid_path_char(char name)
{
    if (name != '/' && wr_is_valid_name_char(name) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t wr_check_name_is_valid(const char *name, uint32_t path_max_size)
{
    if (strlen(name) >= path_max_size) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, name, ", name is too long"));
    }
    if (cm_str_equal(name, WR_DIR_PARENT) || cm_str_equal(name, WR_DIR_SELF)) {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, name, ", cannot be '..' or '.'");
        return CM_ERROR;
    }

    for (uint32_t i = 0; i < strlen(name); i++) {
        status_t status = wr_is_valid_name_char(name[i]);
        WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, name, ", name should be [0~9,a~z,A~Z,-,_,.]"));
    }
    return CM_SUCCESS;
}

static status_t wr_check_path_is_valid(const char *path, uint32_t path_max_size)
{
    if (strlen(path) >= path_max_size) {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, path, ", path is too long\n");
        return CM_ERROR;
    }

    for (uint32_t i = 0; i < strlen(path); i++) {
        if (wr_is_valid_path_char(path[i]) != CM_SUCCESS) {
            WR_RETURN_IFERR2(
                CM_ERROR, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, path, ", path should be [0~9,a~z,A~Z,-,_,/,.]"));
        }
    }
    return CM_SUCCESS;
}

status_t wr_check_str_not_null(const char *str, const char *desc)
{
    if (str == NULL || str[0] == '\0') {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, "[null]", ", %s cannot be a null or empty string.", desc);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_check_name(const char *name)
{
    wr_check_str_not_null(name, "name");
    return wr_check_name_is_valid(name, WR_MAX_NAME_LEN);
}

status_t wr_check_device_path(const char *path)
{
    wr_check_str_not_null(path, "device path");
    return wr_check_path_is_valid(path + 1, (WR_FILE_PATH_MAX_LENGTH - 1));
}

status_t wr_postpone_file(wr_session_t *session, const char *file, const char *time)
{
    status_t status;
    WR_LOG_DEBUG_OP("Begin to extend file %s expired time to %s", file, time);
    status = wr_filesystem_postpone(file, time);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS]Failed to extend file %s expired time to %s.", file, time);
        return CM_ERROR;
    }
    WR_LOG_DEBUG_OP("Succeed to extend file %s expired time to %s.", file, time);
    return CM_SUCCESS;
}

static status_t wr_exist_item_core(
    wr_session_t *session, const char *dir_path, bool32 *result, gft_item_type_t *output_type)
{
    if (dir_path == NULL || dir_path[0] == '\0') {
        return CM_ERROR;
    }

    *result = false;
    *output_type = -1;
    struct stat st;

    static char path[WR_FILE_PATH_MAX_LENGTH];
    int err = snprintf_s(path, WR_FILE_PATH_MAX_LENGTH, WR_FILE_PATH_MAX_LENGTH - 1,
                               "%s/%s", g_inst_cfg->params.data_file_path, (dir_path));
    WR_SECUREC_SS_RETURN_IF_ERROR(err, CM_ERROR);

    if (lstat(path, &st) != 0) {
        LOG_RUN_ERR("failed to get stat for path %s, errno %d.\n", path, errno);
        return CM_ERROR;
    }

    if (S_ISREG(st.st_mode)) {
        *output_type = GFT_FILE;
    } else if (S_ISDIR(st.st_mode)) {
        *output_type = GFT_PATH;
    } else if (S_ISLNK(st.st_mode)) {
        *output_type = GFT_LINK;
    } else {
        LOG_RUN_ERR("file %s type is %o, not supported", path, st.st_mode);
        *output_type = -1;
        return CM_ERROR;
    }
    *result = true;

    return CM_SUCCESS;
}

status_t wr_exist_item(wr_session_t *session, const char *item, bool32 *result, gft_item_type_t *output_type)
{
    CM_ASSERT(item != NULL);
    status_t status;
    *result = CM_FALSE;

    status = CM_ERROR;
    do {
        status = wr_exist_item_core(session, item, result, output_type);
        if (status != CM_SUCCESS) {
            if (status == ERR_WR_FILE_NOT_EXIST) {
                LOG_DEBUG_INF("Reset error %d when check dir failed.", status);
                cm_reset_error();
            } else {
                WR_BREAK_IFERR2(CM_ERROR, LOG_RUN_ERR("Failed to check item, errcode:%d.", status));
            }
        }
        status = CM_SUCCESS;
    } while (0);

    return status;
}

status_t wr_open_file(wr_session_t *session, const char *file, int32_t flag, int *fd)
{
    status_t status;
    WR_LOG_DEBUG_OP("Begin to open file:%s, session id:%u.", file, session->id);
    status = wr_filesystem_open(file, flag, fd);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS]Failed to open file:%s.", file);
        return CM_ERROR;
    }
    WR_LOG_DEBUG_OP("Succeed to open file:%s, fd:%d, session:%u.", file, *fd, session->id);
    return CM_SUCCESS;
}

wr_invalidate_other_nodes_proc_t invalidate_other_nodes_proc = NULL;
wr_broadcast_check_file_open_proc_t broadcast_check_file_open_proc = NULL;

void regist_invalidate_other_nodes_proc(wr_invalidate_other_nodes_proc_t proc)
{
    invalidate_other_nodes_proc = proc;
}

void regist_broadcast_check_file_open_proc(wr_broadcast_check_file_open_proc_t proc)
{
    broadcast_check_file_open_proc = proc;
}

status_t wr_check_open_file_remote(wr_session_t *session, const char *vg_name, uint64 ftid, bool32 *is_open)
{
    *is_open = CM_FALSE;

    WR_LOG_DEBUG_OP("[WR-MES-CB]Begin to check file-open %llu.", ftid);
    wr_vg_info_item_t *vg_item = wr_find_vg_item(vg_name);
    if (vg_item == NULL) {
        WR_RETURN_IFERR3(
            CM_ERROR, WR_THROW_ERROR(ERR_WR_VG_NOT_EXIST, vg_name), LOG_RUN_ERR("Failed to find vg, %s.", vg_name));
    }

    status_t status = wr_check_open_file(session, vg_item, ftid, is_open);
    WR_RETURN_IFERR2(status, LOG_RUN_ERR("Failed to check open file, vg:%s, ftid:%llu.", vg_name, ftid));
    return CM_SUCCESS;
}

void wr_clean_all_sessions_latch()
{
    uint64 cli_pid = 0;
    int64 start_time = 0;
    bool32 cli_pid_alived = 0;
    uint32_t sid = 0;
    wr_session_t *session = NULL;

    // check all used && connected session may occopy latch by dead client
    wr_session_ctrl_t *session_ctrl = wr_get_session_ctrl();
    CM_ASSERT(session_ctrl != NULL);
    while (sid < session_ctrl->alloc_sessions && sid < session_ctrl->total) {
        session = wr_get_session(sid);
        CM_ASSERT(session != NULL);
        // ready next session
        sid++;
        // connected make sure the cli_pid and start_time are valid
        if (!session->is_used || !session->connected) {
            continue;
        }

        if (session->cli_info.cli_pid == 0 ||
            (session->cli_info.cli_pid == cli_pid && start_time == session->cli_info.start_time && cli_pid_alived)) {
            continue;
        }

        cli_pid = session->cli_info.cli_pid;
        start_time = session->cli_info.start_time;
        cli_pid_alived = cm_sys_process_alived(cli_pid, start_time);
        if (cli_pid_alived) {
            continue;
        }
        LOG_RUN_INF("[CLEAN_LATCH]session id %u, pid %llu, start_time %lld, process name:%s, objectid %u.", session->id,
            cli_pid, start_time, session->cli_info.process_name, session->objectid);
        // clean the session lock and latch
        if (!cm_spin_try_lock(&session->lock)) {
            continue;
        }
        while (!cm_spin_timed_lock(&session->shm_lock, WR_SERVER_SESS_TIMEOUT)) {
            // unlock if the client goes offline
            cm_spin_unlock(&session->shm_lock);
            LOG_RUN_INF("Succeed to unlock session %u shm lock", session->id);
            cm_sleep(CM_SLEEP_500_FIXED);
        }
        LOG_DEBUG_INF("Succeed to lock session %u shm lock", session->id);
        wr_clean_session_latch(session, CM_TRUE);
        wr_server_session_unlock(session);
    }
}

void wr_get_disk_usage_info(wr_disk_usage_info_t *info)
{
    pthread_mutex_lock(&g_wr_disk_usage_lock);
    *info = g_wr_disk_usage_info;
    pthread_mutex_unlock(&g_wr_disk_usage_lock);
}

static void wr_set_disk_usage_info(unsigned long total, unsigned long used, unsigned long avail, double usage)
{
    pthread_mutex_lock(&g_wr_disk_usage_lock);
    g_wr_disk_usage_info.total_bytes = total;
    g_wr_disk_usage_info.used_bytes = used;
    g_wr_disk_usage_info.available_bytes = avail;
    g_wr_disk_usage_info.usage_percent = usage;
    pthread_mutex_unlock(&g_wr_disk_usage_lock);
}

void wr_alarm_check_disk_usage()
{
    const char *data_path = g_inst_cfg->params.data_file_path;
    struct statvfs stat;
    if (statvfs(data_path, &stat) != 0) {
        LOG_RUN_ERR("[ALARM] Failed to get disk usage for %s, errno=%d", data_path, errno);
        wr_set_disk_usage_info(0, 0, 0, 0);
        return;
    }

    unsigned long total = stat.f_blocks * stat.f_frsize;
    unsigned long available = stat.f_bavail * stat.f_frsize;
    unsigned long used = total - available;
    double usage = (total == 0) ? 0 : (double)used / (double)total * 100.0;

    LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "[ALARM] Disk usage of %s: total=%.2fGB, used=%.2fGB, available=%.2fGB, usage=%.2f%%.",
        data_path, total / 1073741824.0, used / 1073741824.0, available / 1073741824.0, usage);
    wr_set_disk_usage_info(total, used, available, usage);
}