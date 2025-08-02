/*
 * Copyright (c) 2023Huawei Technologies Co.,Ltd.
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
 * wr_simulation_cm.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_simulation_cm.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_errno.h"
#include "cm_num.h"
#include "cm_utils.h"
#include "cm_res_mgr.h"
#include "wr_malloc.h"
#include "wr_file.h"
#include "wr_simulation_cm.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ENABLE_WRTEST
simulation_cm_t g_simulation_cm;
static config_item_t g_cm_params[] = {
    { CM_LOCK_OWNER_ID, CM_TRUE, CM_FALSE, "0", NULL, NULL, "-", "[0, 63]", "INTEGER", NULL, CM_PARAM_LOCK_OWNER_ID,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { CM_BITMAP_ONLINE, CM_TRUE, CM_FALSE, "1", NULL, NULL, "-", "-", "BIG INTEGER", NULL, CM_PARAM_BITMAP_ONLINE,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
};
char g_cm_config_realpath[CM_MAX_PATH_LEN];
static void wr_simulation_init()
{
    g_simulation_cm.params.lock_owner_id = CM_INVALID_ID32;
    g_simulation_cm.params.bitmap_online = 0;
    GS_INIT_SPIN_LOCK(g_simulation_cm.lock);
}

void wr_simulation_cm_refresh(void)
{
    char *value = cm_get_config_value(&g_simulation_cm.config, CM_LOCK_OWNER_ID);
    if (cm_str2uint32(value, &g_simulation_cm.params.lock_owner_id) != CM_SUCCESS) {
        LOG_RUN_ERR("[GR][simulation_cm]fail to get LOCK_OWNER_ID");
        return;
    }
    if (g_simulation_cm.params.lock_owner_id < WR_MIN_INST_ID || g_simulation_cm.params.lock_owner_id >= WR_MAX_INST_ID) {
        LOG_RUN_ERR("[GR][simulation_cm]the value of 'LOCK_OWNER_ID' is invalid");
        return;
    }
    value = cm_get_config_value(&g_simulation_cm.config, CM_BITMAP_ONLINE);
    if (cm_str2uint64(value, &g_simulation_cm.params.bitmap_online) != CM_SUCCESS) {
        LOG_RUN_ERR("[GR][simulation_cm]fail to get BITMAP_ONLINE");
        return;
    }
}

// load config and refresh global variables
static void wr_simulation_cm_thread(thread_t *thread)
{
    cm_set_thread_name("simulation_cm");
    while (!thread->closed) {
        char *cm_config_realpath = (char *)thread->argument;
        cm_spin_lock(&g_simulation_cm.lock, NULL);
        status_t status =
            cm_load_config(g_cm_params, CM_PARAM_COUNT, cm_config_realpath, &g_simulation_cm.config, CM_FALSE);
        if (status != CM_SUCCESS) {
            cm_spin_unlock(&g_simulation_cm.lock);
            LOG_RUN_ERR("[GR][simulation_cm]fail to load cm simulation");
            cm_sleep(WR_LONG_TIMEOUT);
            continue;
        }
        wr_simulation_cm_refresh();
        cm_spin_unlock(&g_simulation_cm.lock);
        cm_sleep(WR_LONG_TIMEOUT);
    }
}

status_t wr_simulation_cm_lsnr(void)
{
    char *cm_config_path = getenv(CM_CONFIG_PATH);
    if (cm_config_path == NULL) {
        LOG_RUN_ERR("[GR][simulation_cm]fail to get CM_CONFIG_PATH");
        return CM_ERROR;
    }

    int status = realpath_file(cm_config_path, g_cm_config_realpath, CM_MAX_PATH_LEN);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[GR][simulation_cm]invalid cfg dir");
        return CM_ERROR;
    }
    LOG_RUN_INF("[GR][simulation_cm]wr_simulation_cm thread started");
    wr_simulation_init();
    int ret = cm_create_thread(wr_simulation_cm_thread, 0, g_cm_config_realpath, &g_simulation_cm.thread);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[GR][simulation_cm]fail to create wr_simulation_cm_thread");
        return CM_ERROR;
    }
    return ret;
}

status_t wr_refresh_cm_config_lock_owner_id(unsigned int inst_id)
{
    status_t status = CM_SUCCESS;
    char lock_owner_buf[CM_BUFLEN_32];
    int ret = sprintf_s(lock_owner_buf, CM_BUFLEN_32, "%d", (int)inst_id);
    if (ret == -1) {
        LOG_RUN_ERR("[GR][simulation_cm]fail to copy inst_id");
        return CM_ERROR;
    }
    cm_spin_lock(&g_simulation_cm.lock, NULL);
    status = cm_alter_config(&g_simulation_cm.config, CM_LOCK_OWNER_ID, lock_owner_buf, CONFIG_SCOPE_BOTH, CM_TRUE);
    if (status != CM_SUCCESS) {
        cm_spin_unlock(&g_simulation_cm.lock);
        LOG_RUN_ERR("[GR][simulation_cm]fail to modify LOCK_OWNER_ID");
        return CM_ERROR;
    }
    wr_simulation_cm_refresh();
    cm_spin_unlock(&g_simulation_cm.lock);
    return CM_SUCCESS;
}

status_t wr_simulation_cm_init(unsigned int instance_id, const char *res_name, cm_notify_func_t func)
{
    status_t status = wr_simulation_cm_lsnr();
    if(status == CM_SUCCESS) {
        LOG_RUN_INF("[GR][simulation_cm]cm_res_init success");
    } else {
        LOG_RUN_ERR("[GR][simulation_cm]cm_res_init fail");
    }
    return status;
}

char *wr_simulation_cm_get_res_stat(void)
{
    uint64 bitmap_online = g_simulation_cm.params.bitmap_online;
    char *result = (char *)malloc(CM_MAX_INT64_STRLEN + 1);
    if (result == NULL) {
        LOG_RUN_ERR("[GR][simulation_cm]fail to malloc bitmap online.");
        return NULL;
    }
    int ret =
        snprintf_s(result, CM_MAX_INT64_STRLEN + 1, CM_MAX_INT64_STRLEN, PRINT_FMT_BIGINT, (long long)bitmap_online);
    if (ret == -1) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        CM_FREE_PTR(result);
        return NULL;
    }
    return result;
}

void wr_simulation_cm_free_res_stat(char *res_stat)
{
    if (res_stat != NULL) {
        cm_free(res_stat);
    }
}

status_t wr_simulation_cm_res_lock(const char *lock_name)
{
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32_t curr_id = (uint32_t)inst_cfg->params.inst_id;
    LOG_RUN_INF("[GR][simulation_cm]Simulate to lock %s.", lock_name);
    if (g_simulation_cm.params.lock_owner_id == CM_INVALID_ID32) {
        return wr_refresh_cm_config_lock_owner_id(curr_id);
    }
    return CM_SUCCESS;
}

status_t wr_simulation_cm_res_unlock(const char *lock_name)
{
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    uint32_t curr_id = (uint32_t)inst_cfg->params.inst_id;
    LOG_RUN_INF("[GR][simulation_cm]Simulate to unlock %s.", lock_name);
    if (g_simulation_cm.params.lock_owner_id == curr_id) {
        return wr_refresh_cm_config_lock_owner_id(CM_INVALID_ID32);
    }
    return CM_SUCCESS;
}

status_t wr_simulation_cm_res_get_lock_owner(const char *lock_name, unsigned int *inst_id)
{
    *inst_id = g_simulation_cm.params.lock_owner_id;
    LOG_RUN_INF_INHIBIT(
        LOG_INHIBIT_LEVEL4, "[GR][simulation_cm]master id is %u when get cm lock %s.", *inst_id, lock_name);
    return CM_SUCCESS;
}

status_t wr_simulation_cm_res_trans_lock(const char *lock_name, unsigned int inst_id)
{
    LOG_RUN_INF("[GR][simulation_cm]Simulate to trans lock %s.", lock_name);
    return wr_refresh_cm_config_lock_owner_id(inst_id);
}

#define CM_SIMULATION_PATH_LEN 10
status_t wr_simulation_cm_res_mgr_init(const char *so_lib_path, cm_res_mgr_t *cm_res_mgr, cm_allocator_t *alloc)
{
    if (so_lib_path == NULL || strlen(so_lib_path) == 0) {
        cm_res_mgr->so_hanle = NULL;
        return CM_SUCCESS;
    }
    if (strcmp("simulation", so_lib_path) != 0) {
        g_simulation_cm.simulation = CM_FALSE;
        LOG_RUN_INF("[GR][simulation_cm]Start simulate cm with so.");
        return cm_res_mgr_init(so_lib_path, cm_res_mgr, alloc);
    }
    LOG_RUN_INF("[GR][simulation_cm]Start simulate cm.");
    char *cm_simulation_path = (char *)malloc(CM_SIMULATION_PATH_LEN + 1);
    if (cm_simulation_path == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, CM_SIMULATION_PATH_LEN + 1, "simulation cm");
        return CM_ERROR;
    }
    errno_t rc = strcpy_s(cm_simulation_path, CM_SIMULATION_PATH_LEN + 1, so_lib_path);
    if (rc != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        CM_FREE_PTR(cm_simulation_path);
        return CM_ERROR;
    }
    g_simulation_cm.simulation = CM_TRUE;
    cm_res_mgr->so_hanle = (char *)cm_simulation_path;
    cm_res_mgr->cm_init = wr_simulation_cm_init;
    cm_res_mgr->cm_get_res_stat = wr_simulation_cm_get_res_stat;
    cm_res_mgr->cm_free_res_stat = wr_simulation_cm_free_res_stat;
    cm_res_mgr->cm_res_lock = wr_simulation_cm_res_lock;
    cm_res_mgr->cm_res_unlock = wr_simulation_cm_res_unlock;
    cm_res_mgr->cm_res_get_lock_owner = wr_simulation_cm_res_get_lock_owner;
    cm_res_mgr->cm_res_trans_lock = wr_simulation_cm_res_trans_lock;
    return CM_SUCCESS;
}

void wr_simulation_cm_res_mgr_uninit(cm_res_mgr_t *cm_res_mgr)
{
    if (cm_res_mgr->so_hanle != NULL) {
        if (g_simulation_cm.simulation) {
            cm_free(cm_res_mgr->so_hanle);
            cm_res_mgr->so_hanle = NULL;
            return;
        }
        cm_res_mgr_uninit(cm_res_mgr);
    }
}
#endif

#ifdef __cplusplus
}
#endif
