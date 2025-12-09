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
 * gr_param_sync.c
 *
 *
 * IDENTIFICATION
 *    src/params/gr_param_sync.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_param_sync.h"
#include <stdint.h>
#include <sys/stat.h>
#include "gr_log.h"
#include "gr_errno.h"
#include "cm_log.h"
#include "cm_file.h"
#include "cm_utils.h"
#include "cm_defs.h"
#include "cm_sync.h"
#include "cm_config.h"
#include "gr_param.h"
#include "gr_param_verify.h"
#include "../common/persist/gr_diskgroup.h"
// Only grserver needs broadcast message headers
#ifndef GR_CMD_BUILD
#include "../service/gr_mes.h" // broadcast message types and declarations
#endif

#ifdef __cplusplus
extern "C" {
#endif
// Parameters that participate in cluster sync (values only)
const char *gr_sync_param[] = {
    "LOG_LEVEL",               /**< log level */
    "MAX_SESSION_NUMS",        /**< max session count */
    "GR_NODES_LIST",           /**< cluster nodes list */
    "RECV_MSG_POOL_SIZE",      /**< recv message pool size */
    "IP_WHITE_LIST",           /**< IP white list */
    "LOG_COMPRESSED",          /**< log compression switch */
    "DATA_FILE_PATH"           /**< data file path */
};

const char *gr_reserve_param[] = {
    "LOG_HOME",
    "LOG_FILE_COUNT",
    "INST_ID",
    "LISTEN_ADDR"
};

#define GR_SYNC_PARAM_COUNT    (sizeof(gr_sync_param) / sizeof(char *))
#define GR_RESERVE_PARAM_COUNT (sizeof(gr_reserve_param) / sizeof(char *))
#define GR_WORM_MEMORY_CFG_NAME "gr_memory_sync.ini"  // 主节点内存参数快照
#define GR_WORM_PFILE_CFG_NAME  "gr_pfile_sync.ini"   // 主节点 pfile 参数快照
#define GR_WORM_FILE_PERMISSION 0644
// Sync context
gr_config_sync_context_t g_config_sync_ctx = {0};

static status_t gr_copy_worm_to_local_safe(const char *worm_file, const char *local_file);
static void gr_free_config_items(config_t *cfg, config_item_t *items)
{
    cm_free_config_buf(cfg);
    if (items != NULL) {
        free(items);
    }
}

static status_t gr_build_cfg_path(const gr_config_t *cfg, char *buf, size_t len, bool8 is_worm, bool8 is_memory)
{
    if (cfg == NULL || buf == NULL || len == 0) {
        return CM_ERROR;
    }

    int ret;
    const char *file_name = is_worm ? (is_memory ? GR_WORM_MEMORY_CFG_NAME : GR_WORM_PFILE_CFG_NAME) : GR_CFG_NAME;
    const char *dir = is_worm ? cfg->params.data_file_path : cfg->home;

    if (dir == NULL || file_name == NULL) {
        return CM_ERROR;
    }

    if (is_worm) {
        ret = snprintf_s(buf, len, len - 1, "%s/%s", dir, file_name);
    } else {
        ret = snprintf_s(buf, len, len - 1, "%s/cfg/%s", dir, file_name);
    }
    return (ret == -1) ? CM_ERROR : CM_SUCCESS;
}

// Check whether the name is a synchronizable parameter (case-insensitive)
bool32 gr_is_sync_param(const char *name)
{
    if (name == NULL) {
        return CM_FALSE;
    }

    for (uint32 i = 0; i < GR_SYNC_PARAM_COUNT; i++) {
        if (cm_strcmpi(name, gr_sync_param[i]) == 0) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

/* Initialize configuration WORM storage. */
status_t gr_init_config_worm()
{
    gr_config_t *config = gr_get_g_inst_cfg();
    char *data_path = config->params.data_file_path;
    if (config == NULL || data_path == NULL) {
        return CM_ERROR;
    }

    // check config file directory
    if (access(data_path, F_OK) == 0) {
        GR_THROW_ERROR(ERR_GR_DIR_CREATE_DUPLICATED, data_path);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_apply_cfg_to_memory(gr_config_t *inst_cfg, bool8 is_worm, bool8 is_memory, bool8 is_sync)
{
    config_item_t *base_items = NULL;
    config_item_t *apply_items = NULL;
    char apply_file[CM_MAX_PATH_LEN];
    config_t apply_config = {0};
    uint32 param_count = 0;
    status_t res = CM_SUCCESS;
    errno_t rc;

    if (inst_cfg == NULL) {
        return CM_ERROR;
    }

    if (gr_build_cfg_path(inst_cfg, apply_file, sizeof(apply_file), is_worm, is_memory) != CM_SUCCESS) {
        return CM_ERROR;
    }

    gr_get_param_items(&base_items, &param_count);

    apply_items = (config_item_t *)malloc(sizeof(config_item_t) * param_count);
    if (apply_items == NULL) {
        LOG_RUN_ERR("malloc for config items failed.");
        gr_free_config_items(&apply_config, apply_items);
        return CM_ERROR;
    }

    rc = memcpy_s(apply_items, sizeof(config_item_t) * param_count,
        base_items, sizeof(config_item_t) * param_count);
    if (rc != EOK) {
        LOG_RUN_ERR("memcpy_s local_items failed, rc=%d", rc);
        gr_free_config_items(&apply_config, apply_items);
        return CM_ERROR;
    }

    for (uint32 i = 0; i < param_count; i++) {
        apply_items[i].verify = NULL;
        apply_items[i].is_default = CM_TRUE;
        apply_items[i].value = NULL;
        apply_items[i].pfile_value = NULL;
        apply_items[i].runtime_value = NULL;
        apply_items[i].comment = NULL;
    }

    cm_init_config(apply_items, param_count, &apply_config);
    apply_config.ignore = CM_TRUE;

    if (cm_read_config(apply_file, &apply_config) != CM_SUCCESS) {
        LOG_RUN_ERR("read local file failed, file=%s, errno=%d, err=%s",
            apply_file, errno, strerror(errno));
        gr_free_config_items(&apply_config, apply_items);
        return CM_ERROR;
    }

    for (uint32_t i = 0; i < (is_sync ? GR_SYNC_PARAM_COUNT : GR_RESERVE_PARAM_COUNT); i++) {
        const char *param_name = is_sync ? gr_sync_param[i] : gr_reserve_param[i];
        char name_buf[CM_PARAM_BUFFER_SIZE];
        if (strncpy_s(name_buf, CM_PARAM_BUFFER_SIZE, param_name, CM_PARAM_BUFFER_SIZE - 1) != EOK) {
            LOG_RUN_ERR("copy param name failed: %s", param_name);
            res = CM_ERROR;
            continue;
        }
        text_t name_txt;
        cm_str2text(name_buf, &name_txt);
        config_item_t *item = cm_get_config_item(&apply_config, &name_txt, CM_FALSE);
        if (item == NULL || item->effect == EFFECT_REBOOT) {  // 跳过需要重启的参数
            continue;
        }

        char *apply_val = cm_get_config_value(&apply_config, param_name);
        char *cur_val = cm_get_config_value(&inst_cfg->config, param_name);
        if (apply_val == NULL || (cur_val != NULL && cm_str_equal(cur_val, apply_val))) {
            continue;
        }

        LOG_RUN_INF("apply_cfg_to_memory: param %s memory change %s -> %s",
            param_name, cur_val ? cur_val : "NULL", apply_val);
        if (gr_set_cfg_param(name_buf, apply_val, "memory") != CM_SUCCESS) {
            res = CM_ERROR;
        }
    }

    gr_free_config_items(&apply_config, apply_items);
    return res;
}


// Master node parameter broadcast function.
static status_t gr_master_node_param_broadcast(gr_config_t *inst_cfg)
{
    uint32_t current_inst_id = (uint32_t)inst_cfg->params.inst_id;
    LOG_RUN_INF("Current node is master (ID: %u), broadcasting parameter sync message.", current_inst_id);
#ifndef GR_CMD_BUILD
    gr_notify_req_msg_t req;
    gr_recv_msg_t recv_msg;
    uint16 src_inst = (uint16)current_inst_id;
    uint32_t version = GR_PROTO_VERSION;
  
    // Init message header
    (void)memset_s(&req, sizeof(gr_notify_req_msg_t), 0, sizeof(gr_notify_req_msg_t));
    req.gr_head.sw_proto_ver = GR_PROTO_VERSION;
    req.gr_head.msg_proto_ver = version;
    req.gr_head.size = sizeof(gr_notify_req_msg_t);
    req.gr_head.gr_cmd = GR_CMD_REQ_BROADCAST;
    req.gr_head.src_inst = src_inst;
    req.gr_head.dst_inst = 0;
    req.gr_head.flags = 0;
    req.gr_head.ruid = 0;
    req.type = BCAST_REQ_PARAM_SYNC;    // Set broadcast type to param sync
    
    // Send broadcast and wait for ACK; retry policy in MES layer (gr_broadcast_msg_with_try)
    (void)memset_s(&recv_msg, sizeof(recv_msg), 0, sizeof(recv_msg));
    recv_msg.ignore_ack = CM_FALSE;  // wait for ACK
    recv_msg.default_ack = CM_TRUE;  // expect all nodes cmd_ack = TRUE

    if (gr_notify_sync_ex((char *)&req, sizeof(gr_notify_req_msg_t), &recv_msg) != CM_SUCCESS) {
        LOG_RUN_ERR("Broadcast parameter sync message failed, succ_inst=0x%llx",
            (unsigned long long)recv_msg.succ_inst);
        return CM_ERROR;
    }
    LOG_RUN_INF("Successfully broadcast parameter sync message with full ACK.");
#else
    LOG_RUN_INF("Skipping parameter broadcast (GR_CMD_BUILD mode).");
#endif
    return CM_SUCCESS;
}

// Standby writes WORM content into local config file.
status_t gr_standby_node_worm_write(gr_config_t *inst_cfg)
{
    char worm_file[GR_UNIX_PATH_MAX];
    char local_file[CM_MAX_PATH_LEN];

    if (gr_build_cfg_path(inst_cfg, worm_file, sizeof(worm_file), CM_TRUE, CM_FALSE) != CM_SUCCESS ||
            gr_build_cfg_path(inst_cfg, local_file, sizeof(local_file), CM_FALSE, CM_FALSE) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to build config file path.");
        return CM_ERROR;
    }

    if (access(worm_file, F_OK) != 0) {
        LOG_RUN_ERR("WORM file does not exist: %s, errno: %d", worm_file, errno);
        return CM_ERROR;
    }

    if (gr_copy_worm_to_local_safe(worm_file, local_file) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to copy WORM file to local configuration file.");
        return CM_ERROR;
    }
    LOG_RUN_INF("Successfully copied WORM file to local configuration file: %s", local_file);
    return CM_SUCCESS;
}

// Parameter broadcast thread
void gr_param_broadcast_thread(thread_t *thread)
{
    (void)thread;
    LOG_RUN_INF("Parameter broadcast thread started.");
    
    while (g_config_sync_ctx.broadcast_thread_running) {
        // Wait for broadcast event
        int32 ret = cm_event_timedwait(&g_config_sync_ctx.broadcast_event, 0xFFFFFFFF);
        if (ret != CM_SUCCESS) {
            LOG_RUN_INF("Broadcast event wait returned %d, skip this round.", ret);
            continue;
        }
        
        if (!g_config_sync_ctx.broadcast_thread_running) {
            break;
        }
        
        LOG_RUN_INF("Received parameter broadcast event.");
        
        gr_config_t *inst_cfg = gr_get_g_inst_cfg();
        if (inst_cfg == NULL) {
            LOG_RUN_ERR("Failed to get instance config for broadcast.");
            continue;
        }
        
        uint32_t current_inst_id = (uint32_t)inst_cfg->params.inst_id;
        uint32_t master_inst_id = gr_get_master_id();
        LOG_RUN_INF("Current inst id is %u, master inst id is %u.", current_inst_id, master_inst_id);

        if (current_inst_id == master_inst_id) {
            LOG_RUN_INF("Current node is master, start broadcast param sync message.");
            gr_master_node_param_broadcast(inst_cfg);
        } else {
            LOG_RUN_INF("Current node is standby, skip local param sync broadcast (handled by MES).");
        }
    }
    
    LOG_RUN_INF("Parameter broadcast thread exited.");
}

// Trigger parameter broadcast
status_t gr_trigger_param_broadcast(void)
{
    if (!g_config_sync_ctx.broadcast_thread_running) {
        LOG_RUN_ERR("Broadcast thread is not running.");
        return CM_ERROR;
    }
    
    LOG_RUN_INF("Triggering parameter broadcast.");
    cm_event_notify(&g_config_sync_ctx.broadcast_event);
    return CM_SUCCESS;
}

/* Initialize config sync context. */
status_t gr_init_config_sync_context(void)
{
    cm_init_thread_lock(&g_config_sync_ctx.lock);
    if (cm_event_init(&g_config_sync_ctx.broadcast_event) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to initialize broadcast event.");
        cm_destroy_thread_lock(&g_config_sync_ctx.lock);
        return CM_ERROR;
    }
    
    g_config_sync_ctx.broadcast_thread_running = CM_TRUE;
    if (cm_create_thread(gr_param_broadcast_thread, 0, NULL, &g_config_sync_ctx.broadcast_thread) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to create broadcast thread.");
        g_config_sync_ctx.broadcast_thread_running = CM_FALSE;
        cm_event_destory(&g_config_sync_ctx.broadcast_event);
        cm_destroy_thread_lock(&g_config_sync_ctx.lock);
        return CM_ERROR;
    }
    
    LOG_RUN_INF("Config sync context initialized successfully.");
    return CM_SUCCESS;
}

status_t gr_write_config_to_worm(gr_config_t *inst_cfg)
{
    char worm_mem_file[GR_UNIX_PATH_MAX];          // 内存参数快照
    char worm_pfile_file[GR_UNIX_PATH_MAX];        // pfile 参数快照
    char local_file[CM_MAX_PATH_LEN];
    config_item_t *base_items = NULL;
    uint32 param_count = 0;
    gr_get_param_items(&base_items, &param_count);
    config_t local_config = {0};
    config_item_t *local_items = NULL;
    FILE *mem_file = NULL;
    FILE *pfile_file = NULL;
    errno_t rc;
    status_t ret_code = CM_SUCCESS;

    LOG_RUN_INF("Begin writing sync params to WORM storage (from local config file).");
    /* Build WORM config file path */
    if (gr_build_cfg_path(inst_cfg, local_file, sizeof(local_file), CM_FALSE, CM_FALSE) != CM_SUCCESS ||
        gr_build_cfg_path(inst_cfg, worm_mem_file, sizeof(worm_mem_file), CM_TRUE, CM_TRUE) != CM_SUCCESS ||
        gr_build_cfg_path(inst_cfg, worm_pfile_file, sizeof(worm_pfile_file), CM_TRUE, CM_FALSE) != CM_SUCCESS) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid config file path");
        return CM_ERROR;
    }

    /* Init temp config_t from full g_gr_params, then read local gr_inst.ini */
    local_items = (config_item_t *)malloc(sizeof(config_item_t) * param_count);
    if (local_items == NULL) {
        LOG_RUN_ERR("malloc for config items failed.");
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }

    rc = memcpy_s(local_items, sizeof(config_item_t) * param_count,
        base_items, sizeof(config_item_t) * param_count);
    if (rc != EOK) {
        LOG_RUN_ERR("memcpy_s local_items failed, rc=%d", rc);
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }

    for (uint32_t i = 0; i < param_count; i++) {
        local_items[i].verify = NULL;
        local_items[i].is_default = CM_TRUE;
        local_items[i].value = NULL;
        local_items[i].pfile_value = NULL;
        local_items[i].runtime_value = NULL;
        local_items[i].comment = NULL;
    }

    cm_init_config(local_items, param_count, &local_config);
    local_config.ignore = CM_TRUE;

    if (cm_read_config(local_file, &local_config) != CM_SUCCESS) {
        LOG_RUN_ERR("read local file failed, file=%s, errno=%d, err=%s",
            local_file, errno, strerror(errno));
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }

    pfile_file = fopen(worm_pfile_file, "w");
    mem_file = fopen(worm_mem_file, "w");
    if (pfile_file == NULL || mem_file == NULL) {
        LOG_RUN_ERR("failed to open worm files for write, pfile=%p, memory=%p, errno=%d",
            (void *)pfile_file, (void *)mem_file, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }

    for (uint32_t i = 0; i < GR_SYNC_PARAM_COUNT; i++) {
        const char *param_name = gr_sync_param[i];
        char *pfile_val = cm_get_config_value(&local_config, param_name);
        char *mem_val = cm_get_config_value(&inst_cfg->config, param_name);

        if (pfile_val != NULL) {
            LOG_RUN_INF("set worm pfile param %s = %s (from local file)", param_name, pfile_val);
            if (fprintf(pfile_file, "%s=%s\n", param_name, pfile_val) < 0) {
                LOG_RUN_ERR("fprintf to pfile worm file failed for %s, errno=%d", param_name, errno);
                GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
                ret_code = CM_ERROR;
                break;
            }
        }

        if (mem_val != NULL) {
            LOG_RUN_INF("set worm memory param %s = %s (from runtime)", param_name, mem_val);
            if (fprintf(mem_file, "%s=%s\n", param_name, mem_val) < 0) {
                LOG_RUN_ERR("fprintf to memory worm file failed for %s, errno=%d", param_name, errno);
                GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
                ret_code = CM_ERROR;
                break;
            }
        }
    }

    if (pfile_file != NULL && fclose(pfile_file) != 0) {
        LOG_RUN_ERR("failed to close worm pfile: %s, errno=%d", worm_pfile_file, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }
    if (mem_file != NULL && fclose(mem_file) != 0) {
        LOG_RUN_ERR("failed to close worm memory: %s, errno=%d", worm_mem_file, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }

    if (ret_code == CM_SUCCESS &&
        (chmod(worm_pfile_file, GR_WORM_FILE_PERMISSION) != 0 || chmod(worm_mem_file, GR_WORM_FILE_PERMISSION) != 0)) {
        LOG_RUN_ERR("Failed to set permissions for WORM files: pfile=%s, memory=%s, errno=%d",
            worm_pfile_file, worm_mem_file, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }

    LOG_RUN_INF("successfully wrote sync params to WORM storage from local file: %s -> [%s, %s]",
        local_file, worm_pfile_file, worm_mem_file);
    gr_free_config_items(&local_config, local_items);
    return ret_code;
}

/* Delete WORM files when instance/cluster stops to avoid using stale config next start. */
status_t gr_delete_worm_file(gr_config_t *inst_cfg)
{
    if (inst_cfg == NULL) {
        LOG_RUN_ERR("gr_delete_worm_file: inst_cfg is NULL.");
        return CM_ERROR;
    }

    char worm_mem_file[GR_UNIX_PATH_MAX] = {0};
    char worm_pfile_file[GR_UNIX_PATH_MAX] = {0};
    if (gr_build_cfg_path(inst_cfg, worm_mem_file, sizeof(worm_mem_file), CM_TRUE, CM_TRUE) != CM_SUCCESS ||
        gr_build_cfg_path(inst_cfg, worm_pfile_file, sizeof(worm_pfile_file), CM_TRUE, CM_FALSE) != CM_SUCCESS) {
        LOG_RUN_ERR("gr_delete_worm_file: invalid WORM file path, data_file_path=%s",
            inst_cfg->params.data_file_path ? inst_cfg->params.data_file_path : "NULL");
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid worm config file path");
        return CM_ERROR;
    }

    const char *targets[] = { worm_mem_file, worm_pfile_file };
    for (uint32 i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        const char *file = targets[i];
        if (access(file, F_OK) != 0) {
            LOG_RUN_INF("gr_delete_worm_file: WORM file does not exist, skip delete: %s", file);
            continue;
        }
        if (remove(file) != 0) {
            LOG_RUN_ERR("gr_delete_worm_file: failed to remove WORM file: %s, errno=%d", file, errno);
            GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
            return CM_ERROR;
        }
        LOG_RUN_INF("gr_delete_worm_file: successfully removed WORM file: %s", file);
    }
    return CM_SUCCESS;
}

static status_t gr_rebuild_single_worm(const gr_config_t *inst_cfg, bool8 is_memory)
{
    char worm_file[GR_UNIX_PATH_MAX];
    char new_file[GR_UNIX_PATH_MAX];
    int ret;
    FILE *in = NULL;
    FILE *out = NULL;
    char buf[4096];
    size_t nread;
    size_t nwrite;

    ret = gr_build_cfg_path(inst_cfg, worm_file, sizeof(worm_file), CM_TRUE, is_memory);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("invalid worm file path when rebuild.");
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid worm config file path");
        return CM_ERROR;
    }

    ret = snprintf_s(new_file, sizeof(new_file), sizeof(new_file) - 1, "%s.new", worm_file);
    if (ret == -1) {
        LOG_RUN_ERR("failed to build new worm file path from %s.", worm_file);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    in = fopen(worm_file, "r");
    if (in == NULL) {
        LOG_RUN_ERR("failed to open old WORM file for read: %s, errno=%d", worm_file, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    out = fopen(new_file, "w");
    if (out == NULL) {
        LOG_RUN_ERR("failed to open new WORM file for write: %s, errno=%d", new_file, errno);
        (void)fclose(in);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    while ((nread = fread(buf, 1, sizeof(buf), in)) > 0) {
        nwrite = fwrite(buf, 1, nread, out);
        if (nwrite != nread) {
            LOG_RUN_ERR("write new WORM file failed: %s, errno=%d", new_file, errno);
            (void)fclose(in);
            (void)fclose(out);
            (void)remove(new_file);
            GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
            return CM_ERROR;
        }
    }

    if (ferror(in)) {
        LOG_RUN_ERR("read old WORM file failed: %s, errno=%d", worm_file, errno);
        (void)fclose(in);
        (void)fclose(out);
        (void)remove(new_file);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    if (fclose(in) != 0) {
        LOG_RUN_ERR("failed to close old WORM file: %s, errno=%d", worm_file, errno);
        (void)fclose(out);
        (void)remove(new_file);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    if (fclose(out) != 0) {
        LOG_RUN_ERR("failed to close new WORM file: %s, errno=%d", new_file, errno);
        (void)remove(new_file);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    if (chmod(new_file, GR_WORM_FILE_PERMISSION) != 0) {
        LOG_RUN_ERR("Failed to set permissions for new WORM file: %s, errno: %d", new_file, errno);
        (void)remove(new_file);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    if (rename(new_file, worm_file) != 0) {
        LOG_RUN_ERR("failed to rename new WORM file %s to %s, errno=%d", new_file, worm_file, errno);
        (void)remove(new_file);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    LOG_RUN_INF("successfully rebuilt WORM file: %s", worm_file);
    return CM_SUCCESS;
}

/* New primary takes over WORM files (memory & pfile). */
status_t gr_rebuild_worm_file(gr_config_t *inst_cfg)
{
    if (gr_rebuild_single_worm(inst_cfg, CM_TRUE) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (gr_rebuild_single_worm(inst_cfg, CM_FALSE) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void gr_set_config_first_last_item(config_t *config, config_item_t *item)
{
    config_item_t *prev_item = NULL;

    if (config->last_item == NULL) {
        config->first_item = item;
        config->last_item = item;
        return;
    }

    if (config->first_item == item) {
        config->first_item = item->next;
    } else if (item->next != NULL) {
        prev_item = config->first_item;
        while ((prev_item != NULL) && (prev_item->next != item)) {
            prev_item = prev_item->next;
        }
        if (prev_item != NULL) {
            prev_item->next = item->next;
        }
    }
    item->next = NULL;
    config->last_item->next = item;
    config->last_item = item;
}
static status_t gr_copy_worm_to_local_safe(const char *worm_file, const char *local_file)
{
    config_t worm_config = {0};
    config_t local_config = {0};
    config_item_t *base_items = NULL;
    config_item_t *worm_items = NULL;
    config_item_t *local_items = NULL;
    uint32 param_count = 0;
    errno_t rc;
    /* Snapshot worm values for sync params: index by param order */
    char worm_value_buf[GR_SYNC_PARAM_COUNT][CM_PARAM_BUFFER_SIZE] = {{0}};
    int32 err_code = 0;
    const char *err_msg = NULL;
    char name_buf[CM_PARAM_BUFFER_SIZE];
    text_t name_txt;
    const char *param_name = NULL;
    char *worm_value = NULL;
    char *local_value = NULL;
    config_item_t *item = NULL;
    
    LOG_RUN_INF("start copy params from worm to local, worm_file=%s, local_file=%s", worm_file, local_file);

    gr_get_param_items(&base_items, &param_count);
    worm_items = (config_item_t *)malloc(sizeof(config_item_t) * param_count);
    local_items = (config_item_t *)malloc(sizeof(config_item_t) * param_count);
    if (worm_items == NULL || local_items == NULL) {
        LOG_RUN_ERR("malloc for config items failed.");
        gr_free_config_items(&worm_config, worm_items);
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }

    rc = memcpy_s(worm_items, sizeof(config_item_t) * param_count,
        base_items, sizeof(config_item_t) * param_count);
    if (rc != EOK) {
        LOG_RUN_ERR("memcpy_s worm_items failed, rc=%d", rc);
        gr_free_config_items(&worm_config, worm_items);
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }
    rc = memcpy_s(local_items, sizeof(config_item_t) * param_count,
        base_items, sizeof(config_item_t) * param_count);
    if (rc != EOK) {
        LOG_RUN_ERR("memcpy_s local_items failed, rc=%d", rc);
        gr_free_config_items(&worm_config, worm_items);
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }

    for (uint32_t i = 0; i < param_count; i++) {
        worm_items[i].verify = NULL;
        worm_items[i].is_default = CM_TRUE;
        worm_items[i].value = NULL;
        worm_items[i].pfile_value = NULL;
        worm_items[i].runtime_value = NULL;
        worm_items[i].comment = NULL;

        local_items[i].verify = NULL;
        local_items[i].is_default = CM_TRUE;  /* 强制分配新内存，避免修改 g_gr_params 的内存 */
        local_items[i].value = NULL;
        local_items[i].pfile_value = NULL;
        local_items[i].runtime_value = NULL;
        local_items[i].comment = NULL;
    }

    cm_init_config(worm_items, param_count, &worm_config);
    worm_config.ignore = CM_TRUE;

    cm_init_config(local_items, param_count, &local_config);
    local_config.ignore = CM_TRUE;

    if (cm_read_config(worm_file, &worm_config) != CM_SUCCESS) {
        LOG_RUN_ERR("read worm file failed, file=%s, errno=%d, err=%s",
            worm_file, errno, strerror(errno));
        gr_free_config_items(&worm_config, worm_items);
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }

    for (uint32_t i = 0; i < GR_SYNC_PARAM_COUNT; i++) {
        param_name = gr_sync_param[i];
        worm_value = cm_get_config_value(&worm_config, param_name);
        if (worm_value != NULL) {
            rc = strncpy_s(worm_value_buf[i], CM_PARAM_BUFFER_SIZE, worm_value, CM_PARAM_BUFFER_SIZE - 1);
            if (rc != EOK) {
                LOG_RUN_ERR("copy worm value failed for %s, rc=%d", param_name, rc);
                gr_free_config_items(&worm_config, worm_items);
                gr_free_config_items(&local_config, local_items);
                return CM_ERROR;
            }
            LOG_RUN_INF("worm pfile[%u]: %s = %s", i, param_name, worm_value_buf[i]);
        } else {
            LOG_RUN_INF("worm pfile[%u]: %s not set (use default/ignored)", i, param_name);
        }
    }

    if (cm_read_config(local_file, &local_config) != CM_SUCCESS) {
        err_code = cm_get_error_code();
        err_msg = NULL;
        cm_get_error(&err_code, &err_msg);
        LOG_RUN_ERR("read local config failed, file=%s, errno=%d, err=%s, cm_err_code=%d, cm_err_msg=%s",
            local_file, errno, strerror(errno), err_code, err_msg == NULL ? "NULL" : err_msg);
        gr_free_config_items(&worm_config, worm_items);
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }

    for (uint32_t i = 0; i < GR_SYNC_PARAM_COUNT; i++) {
        param_name = gr_sync_param[i];
        local_value = cm_get_config_value(&local_config, param_name);
        LOG_RUN_INF("local[%u]: %s = %s", i, param_name, local_value ? local_value : "NULL");
    }

    for (uint32_t i = 0; i < GR_SYNC_PARAM_COUNT; i++) {
        param_name = gr_sync_param[i];
        worm_value = worm_value_buf[i][0] != '\0' ? worm_value_buf[i] : NULL;

        if (worm_value == NULL) {
            continue;
        }

        rc = strncpy_s(name_buf, CM_PARAM_BUFFER_SIZE, param_name, CM_PARAM_BUFFER_SIZE - 1);
        if (rc != EOK) {
            LOG_RUN_ERR("copy param name failed for %s, rc=%d", param_name, rc);
            gr_free_config_items(&worm_config, worm_items);
            gr_free_config_items(&local_config, local_items);
            return CM_ERROR;
        }
        cm_str2text(name_buf, &name_txt);
        item = cm_get_config_item(&local_config, &name_txt, CM_FALSE);
        if (item == NULL) {
            continue;
        }
        /* Only update pfile_value (file config), not value (memory config):
         * local_items and g_gr_params share pointers, changing value would touch runtime config.
         * Standby memory should be applied via restart/reload, not here.
         * pfile_value was allocated by cm_read_config(local_file, ...). */
        if (item->pfile_value == NULL) {
            item->pfile_value = (char *)malloc(CM_PARAM_BUFFER_SIZE);
            if (item->pfile_value == NULL) {
                LOG_RUN_ERR("alloc pfile_value failed for %s", param_name);
                gr_free_config_items(&worm_config, worm_items);
                gr_free_config_items(&local_config, local_items);
                return CM_ERROR;
            }
            item->pfile_value[0] = '\0';
            item->flag &= ~FLAG_INFILE;
            if (item != local_config.last_item) {
                gr_set_config_first_last_item(&local_config, item);
            }
        }
        rc = strncpy_s(item->pfile_value, CM_PARAM_BUFFER_SIZE, worm_value, CM_PARAM_BUFFER_SIZE - 1);
        if (rc != EOK) {
            LOG_RUN_ERR("strncpy_s to item->pfile_value failed for %s, rc=%d", param_name, rc);
            gr_free_config_items(&worm_config, worm_items);
            gr_free_config_items(&local_config, local_items);
            return CM_ERROR;
        }
        item->is_default = CM_FALSE;
        LOG_RUN_INF("updated pfile_value for %s = %s (memory value not changed)", param_name, worm_value);
    }

    if (cm_save_config(&local_config) != CM_SUCCESS) {
        LOG_RUN_ERR("save merged config failed, target=%s", local_config.file_name);
        gr_free_config_items(&worm_config, worm_items);
        gr_free_config_items(&local_config, local_items);
        return CM_ERROR;
    }

    gr_free_config_items(&worm_config, worm_items);
    gr_free_config_items(&local_config, local_items);
    return CM_SUCCESS;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */
