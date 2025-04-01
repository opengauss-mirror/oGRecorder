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
 * wr_diskgroup.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_diskgroup.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_api.h"
#include "wr_alloc_unit.h"
#include "wr_file.h"
#include "wr_malloc.h"
#include "cm_dlock.h"
#include "cm_disklock.h"
#include "cm_utils.h"
#include "wr_io_fence.h"
#include "wr_open_file.h"
#include "wr_diskgroup.h"

#ifndef WIN32
#include <sys/file.h>
#endif
#include "wr_meta_buf.h"
#include "wr_fs_aux.h"
#include "wr_syn_meta.h"
#include "wr_thv.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
#define WR_SIMUFILE_NAME "wr_vglock"
#define WR_FP_FREE (0)
#define WR_FP_INUSE (1)
typedef struct st_vglock_fp {
    uint32 state;
    char file_name[WR_MAX_FILE_LEN];
    FILE *fp;  // each process has itself fp
} vglock_fp_t;

vglock_fp_t g_fp_list[WR_MAX_OPEN_VG];
#endif

wr_vg_info_t *g_vgs_info = NULL;

bool32 g_is_wr_server = WR_FALSE;
static wr_rdwr_type_e g_is_wr_readwrite = WR_STATUS_NORMAL;
static uint32 g_master_instance_id = WR_INVALID_ID32;
static const char *const g_wr_lock_vg_file = "wr_vg.lck";
static int32 g_wr_lock_vg_fd = CM_INVALID_INT32;
static uint32 g_wr_recover_thread_id = 0;

// CAUTION: wr_admin manager command just like wr_create_vg,cannot call it,

wr_vg_info_t *wr_malloc_vg_info(void)
{
    if (g_vgs_info != NULL) {
        return g_vgs_info; /* reuse memory of g_vgs_info */
    }
    return (wr_vg_info_t *)cm_malloc(sizeof(wr_vg_info_t));
}

bool32 wr_is_server(void)
{
    return g_is_wr_server;
}

bool32 wr_is_readwrite(void)
{
    return g_is_wr_readwrite == WR_STATUS_READWRITE;
}

bool32 wr_is_readonly(void)
{
    return g_is_wr_readwrite == WR_STATUS_READONLY;
}

uint32 wr_get_master_id()
{
    return g_master_instance_id;
}

void wr_set_master_id(uint32 id)
{
    g_master_instance_id = id;
    LOG_RUN_INF("set master id is %u.", id);
}

void wr_set_server_flag(void)
{
    g_is_wr_server = WR_TRUE;
}

int32 wr_get_server_status_flag(void)
{
    return (int32)g_is_wr_readwrite;
}

void wr_set_server_status_flag(int32 wr_status)
{
    g_is_wr_readwrite = wr_status;
}

void wr_set_recover_thread_id(uint32 thread_id)
{
    g_wr_recover_thread_id = thread_id;
}

uint32 wr_get_recover_thread_id(void)
{
    return g_wr_recover_thread_id;
}

wr_get_instance_status_proc_t get_instance_status_proc = NULL;
void regist_get_instance_status_proc(wr_get_instance_status_proc_t proc)
{
    get_instance_status_proc = proc;
}
void wr_checksum_vg_ctrl(wr_vg_info_item_t *vg_item);

void vg_destroy_env(wr_vg_info_item_t *vg_item)
{
    cm_oamap_destroy(&vg_item->au_map);
}

status_t wr_read_vg_config_file(const char *file_name, char *buf, uint32 *buf_len, bool32 read_only)
{
    int32 file_fd;
    status_t status;
    uint32 mode = (read_only) ? (O_RDONLY | O_BINARY) : (O_CREAT | O_RDWR | O_BINARY);

    if (!cm_file_exist(file_name)) {
        WR_THROW_ERROR(ERR_WR_FILE_NOT_EXIST, file_name, "config");
        return CM_ERROR;
    }

    WR_RETURN_IF_ERROR(cm_open_file(file_name, mode, &file_fd));

    int64 size = cm_file_size(file_fd);
    bool32 result = (bool32)(size != -1);
    WR_RETURN_IF_FALSE3(result, cm_close_file(file_fd), WR_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno));

    result = (bool32)(size <= (int64)(*buf_len));
    WR_RETURN_IF_FALSE3(result, cm_close_file(file_fd), WR_THROW_ERROR(ERR_WR_CONFIG_FILE_OVERSIZED, file_name));

    result = (bool32)(cm_seek_file(file_fd, 0, SEEK_SET) == 0);
    WR_RETURN_IF_FALSE3(result, cm_close_file(file_fd), WR_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno));

    status = cm_read_file(file_fd, buf, (int32)size, (int32 *)buf_len);
    cm_close_file(file_fd);
    return status;
}

void wr_free_vg_info()
{
    LOG_RUN_INF("free g_vgs_info.");
    WR_FREE_POINT(g_vgs_info)
}

wr_vg_info_item_t *wr_find_vg_item(const char *vg_name)
{
    for (uint32_t i = 0; i < g_vgs_info->group_num; i++) {
        if (strcmp(g_vgs_info->volume_group[i].vg_name, vg_name) == 0) {
            return &g_vgs_info->volume_group[i];
        }
    }
    return NULL;
}

wr_vg_info_item_t *wr_find_vg_item_by_id(uint32 vg_id)
{
    if (vg_id > g_vgs_info->group_num) {
        return NULL;
    }
    return &g_vgs_info->volume_group[vg_id];
}

status_t wr_alloc_vg_item_redo_log_buf(wr_vg_info_item_t *vg_item)
{
    LOG_RUN_INF("Begin to alloc redo log buf of vg %s.", vg_item->vg_name);
    char *log_buf = (char *)cm_malloc_align(WR_ALIGN_SIZE, WR_VG_LOG_SPLIT_SIZE);
    if (log_buf == NULL) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_ALLOC_MEMORY, WR_VG_LOG_SPLIT_SIZE, "global log buffer"));
    }
    errno_t rc = memset_s(log_buf, WR_DISK_UNIT_SIZE, 0, WR_DISK_UNIT_SIZE);
    if (rc != EOK) {
        WR_RETURN_IFERR4(
            CM_ERROR, LOG_RUN_ERR("Memset failed."), WR_FREE_POINT(log_buf), CM_THROW_ERROR(ERR_SYSTEM_CALL, rc));
    }
    vg_item->log_file_ctrl.log_buf = log_buf;
    return CM_SUCCESS;
}

status_t wr_check_entry_path(char *entry_path1, char *entry_path2, bool32 *result)
{
    if (cm_str_equal_ins(entry_path1, entry_path2)) {
        *result = CM_TRUE;
        return CM_SUCCESS;
    }
    char real_path1[WR_MAX_VOLUME_PATH_LEN];
    char real_path2[WR_MAX_VOLUME_PATH_LEN];
    CM_RETURN_IFERR(realpath_file(entry_path1, real_path1, WR_MAX_VOLUME_PATH_LEN));
    CM_RETURN_IFERR(realpath_file(entry_path2, real_path2, WR_MAX_VOLUME_PATH_LEN));
    if (cm_str_equal_ins(real_path1, real_path2)) {
        *result = CM_TRUE;
        return CM_SUCCESS;
    }
    *result = CM_FALSE;
    return CM_SUCCESS;
}

status_t wr_check_dup_vg(wr_vg_info_t *config, uint32 vg_no, bool32 *result)
{
    char *last_vg_name = config->volume_group[vg_no - 1].vg_name;
    char *last_entry_path = config->volume_group[vg_no - 1].entry_path;

    for (uint32 i = 0; i < vg_no - 1; i++) {
        if (cm_str_equal_ins(last_vg_name, config->volume_group[i].vg_name)) {
            *result = CM_TRUE;
            return CM_SUCCESS;
        }
        CM_RETURN_IFERR(wr_check_entry_path(last_entry_path, config->volume_group[i].entry_path, result));
        if (*result) {
            return CM_SUCCESS;
        }
    }
    *result = CM_FALSE;
    return CM_SUCCESS;
}

// NOTE:called after load vg ctrl and recovery.
void wr_checksum_vg_ctrl(wr_vg_info_item_t *vg_item)
{
    LOG_RUN_INF("Begin to checksum vg:%s ctrl.", vg_item->vg_name);
    char *buf = vg_item->wr_ctrl->vg_data;
    uint32 checksum = wr_get_checksum(buf, WR_VG_DATA_SIZE);
    uint32 old_checksum = vg_item->wr_ctrl->vg_info.checksum;
    wr_check_checksum(checksum, old_checksum);

    buf = vg_item->wr_ctrl->root;
    checksum = wr_get_checksum(buf, WR_BLOCK_SIZE);
    wr_common_block_t *block = (wr_common_block_t *)buf;
    old_checksum = block->checksum;
    wr_check_checksum(checksum, old_checksum);
    LOG_RUN_INF("Succeed to checksum vg:%s ctrl.", vg_item->vg_name);
}

// NOTE:only called initializing.no check redo and recovery.
status_t wr_load_vg_ctrl(wr_vg_info_item_t *vg_item, bool32 is_lock)
{
    CM_ASSERT(vg_item != NULL);
    bool32 remote = CM_FALSE;
    wr_config_t *inst_cfg = wr_get_inst_cfg();

    if (vg_item->vg_name[0] == '\0' || vg_item->entry_path[0] == '\0') {
        LOG_RUN_ERR("Failed to load vg ctrl, input parameter is invalid.");
        return CM_ERROR;
    }
    LOG_RUN_INF("Begin to load vg %s ctrl.", vg_item->vg_name);
    status_t status;
    if (is_lock) {
        if (wr_lock_vg_storage_r(vg_item, vg_item->entry_path, inst_cfg) != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to lock vg:%s.", vg_item->entry_path);
            return CM_ERROR;
        }
    }
    status = wr_load_vg_ctrl_part(vg_item, 0, vg_item->wr_ctrl, (int32)sizeof(wr_ctrl_t), &remote);
    if (status != CM_SUCCESS) {
        if (is_lock) {
            (void)wr_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        }
        LOG_RUN_ERR("Failed to read volume %s.", vg_item->entry_path);
        return status;
    }
    if (is_lock) {
        if (wr_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    if (!WR_VG_IS_VALID(vg_item->wr_ctrl)) {
        WR_THROW_ERROR(ERR_WR_VG_CHECK_NOT_INIT);
        LOG_RUN_ERR("Invalid vg %s ctrl", vg_item->vg_name);
        return CM_ERROR;
    }

    date_t date = cm_timeval2date(vg_item->wr_ctrl->vg_info.create_time);
    time_t time = cm_date2time(date);
    char create_time[512];
    status = cm_time2str(time, "YYYY-MM-DD HH24:mi:ss", create_time, sizeof(create_time));
    LOG_RUN_INF("The vg:%s info, create time:%s.", vg_item->vg_name, create_time);

    return status;
}

status_t wr_load_vg_ctrl_part(wr_vg_info_item_t *vg_item, int64 offset, void *buf, int32 size, bool32 *remote)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(buf != NULL);
    // todo close volume?
    if (vg_item->volume_handle[0].handle == WR_INVALID_HANDLE) {
        if (wr_open_volume(vg_item->entry_path, NULL, WR_INSTANCE_OPEN_FLAG, &vg_item->volume_handle[0]) !=
            CM_SUCCESS) {
            LOG_RUN_ERR("Failed to open volume %s.", vg_item->entry_path);
            return CM_ERROR;
        }
    }
    LOG_DEBUG_INF(
        "Begin to read volume %s when load vg ctrl part, offset:%lld,size:%d.", vg_item->entry_path, offset, size);
    if (wr_read_volume_inst(vg_item, &vg_item->volume_handle[0], offset, buf, size, remote) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to read volume %s,offset:%lld,size:%d.", vg_item->entry_path, offset, size);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void wr_lock_vg_mem_x(wr_vg_info_item_t *vg_item)
{
    wr_latch_x(&vg_item->disk_latch);
}

void wr_lock_vg_mem_x2ix(wr_vg_info_item_t *vg_item)
{
    latch_statis_t *stat = NULL;
    wr_latch_x2ix(&vg_item->disk_latch, WR_DEFAULT_SESSIONID, stat);
}

void wr_lock_vg_mem_ix2x(wr_vg_info_item_t *vg_item)
{
    latch_statis_t *stat = NULL;
    wr_latch_ix2x(&vg_item->disk_latch, WR_DEFAULT_SESSIONID, stat);
}

void wr_lock_vg_mem_s(wr_vg_info_item_t *vg_item)
{
    wr_latch_s(&vg_item->disk_latch);
}

void wr_lock_vg_mem_degrade(wr_vg_info_item_t *vg_item)
{
    wr_latch_degrade(&vg_item->disk_latch, WR_DEFAULT_SESSIONID, NULL);
}

void wr_lock_vg_mem_s_force(wr_vg_info_item_t *vg_item)
{
    wr_latch_s2(&vg_item->disk_latch, WR_DEFAULT_SESSIONID, CM_TRUE, NULL);
}

void wr_unlock_vg_mem(wr_vg_info_item_t *vg_item)
{
    wr_unlatch(&vg_item->disk_latch);
}

static void wr_free_vglock_fp(const char *lock_file, FILE *fp)
{
    int32 i;
    for (i = 0; i < WR_MAX_OPEN_VG; i++) {
        if (g_fp_list[i].state == WR_FP_FREE) {
            continue;
        }
        if (g_fp_list[i].fp != fp) {
            continue;
        }
        if (strcmp(g_fp_list[i].file_name, lock_file) == 0) {
            g_fp_list[i].state = WR_FP_FREE;
            g_fp_list[i].fp = NULL;
            g_fp_list[i].file_name[0] = '\0';
        }
    }
}

static FILE *wr_get_vglock_fp(const char *lock_file, bool32 need_new)
{
    int32 i;
    int32 ifree = -1;
    for (i = 0; i < WR_MAX_OPEN_VG; i++) {
        if (g_fp_list[i].state == WR_FP_FREE) {
            ifree = (ifree == -1) ? i : ifree;
            continue;
        }
        if (strcmp(g_fp_list[i].file_name, lock_file) == 0) {
            return g_fp_list[i].fp;
        }
    }

    if (!need_new) {
        return NULL;
    }

    if (ifree == -1) {
        return NULL;
    }

    uint32 len = (uint32)strlen(lock_file);
    int32 ret = memcpy_sp(g_fp_list[ifree].file_name, WR_MAX_FILE_LEN, lock_file, len);
    WR_SECUREC_RETURN_IF_ERROR(ret, NULL);
    g_fp_list[ifree].file_name[len] = '\0';
    g_fp_list[ifree].fp = fopen(lock_file, "w");
    if (g_fp_list[ifree].fp == NULL) {
        char cmd[WR_MAX_CMD_LEN];
        ret = snprintf_s(cmd, WR_MAX_CMD_LEN, WR_MAX_CMD_LEN - 1, "touch %s", lock_file);
        WR_SECUREC_SS_RETURN_IF_ERROR(ret, NULL);
        (void)system(cmd);
        g_fp_list[ifree].fp = fopen(lock_file, "w");
    }

    if (g_fp_list[ifree].fp == NULL) {
        return NULL;
    }
    g_fp_list[ifree].state = WR_FP_INUSE;
    return g_fp_list[ifree].fp;
}

static status_t wr_pre_lockfile_name(const char *entry_path, char *lock_file, wr_config_t *inst_cfg)
{
    char *home = inst_cfg->params.disk_lock_file_path;
    char superblock[WR_MAX_FILE_LEN];
    text_t pname, sub;
    pname.len = (uint32)strlen(entry_path);
    pname.str = (char *)entry_path;
    if (!cm_fetch_rtext(&pname, '/', '\0', &sub)) {
        pname = sub;
    }

    int32 iret_snprintf;
    if (pname.len == 0) {
        iret_snprintf = snprintf_s(lock_file, WR_MAX_FILE_LEN, WR_MAX_FILE_LEN - 1, "%s/%s", home, WR_SIMUFILE_NAME);
        WR_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    } else {
        if (cm_text2str(&pname, superblock, WR_MAX_FILE_LEN) != CM_SUCCESS) {
            return CM_ERROR;
        }

        iret_snprintf = snprintf_s(
            lock_file, WR_MAX_FILE_LEN, WR_MAX_FILE_LEN - 1, "%s/%s_%s", home, WR_SIMUFILE_NAME, superblock);
        WR_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    }
    return CM_SUCCESS;
}

status_t wr_file_lock_vg(wr_config_t *inst_cfg, struct flock *lk)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    int iret_snprintf;

    iret_snprintf = snprintf_s(
        file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s", inst_cfg->home, g_wr_lock_vg_file);
    WR_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY, &g_wr_lock_vg_fd) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_fcntl(g_wr_lock_vg_fd, F_SETLK, lk, CM_WAIT_FOREVER) != CM_SUCCESS) {
        cm_close_file(g_wr_lock_vg_fd);
        g_wr_lock_vg_fd = CM_INVALID_INT32;
        CM_THROW_ERROR(ERR_LOCK_FILE, errno);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_file_lock_vg_w(wr_config_t *inst_cfg)
{
    struct flock lk;
    lk.l_type = F_WRLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = lk.l_len = 0;
    if (wr_file_lock_vg(inst_cfg, &lk) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to file write lock vg.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t wr_file_lock_vg_r(wr_config_t *inst_cfg)
{
    struct flock lk;
    lk.l_type = F_RDLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = lk.l_len = 0;
    if (wr_file_lock_vg(inst_cfg, &lk) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to file read lock vg.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void wr_file_unlock_vg(void)
{
    if (g_wr_lock_vg_fd != CM_INVALID_INT32) {
        (void)cm_unlock_fd(g_wr_lock_vg_fd);
        cm_close_file(g_wr_lock_vg_fd);
        g_wr_lock_vg_fd = CM_INVALID_INT32;
    }
}

status_t wr_lock_disk_vg(const char *entry_path, wr_config_t *inst_cfg)
{
    dlock_t lock;
    status_t status;

    status = cm_alloc_dlock(&lock, WR_CTRL_VG_LOCK_OFFSET, inst_cfg->params.inst_id);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to alloc lock.");
        return CM_ERROR;
    }

    // if get the timeout(ERR_SCSI_LOCK_OCCUPIED) error from scsi lock, we'll try lock vg again
    for (;;) {
        status = cm_init_dlock(&lock, WR_CTRL_VG_LOCK_OFFSET, inst_cfg->params.inst_id);
        WR_RETURN_IFERR3(status, cm_destory_dlock(&lock), LOG_DEBUG_ERR("Failed to init lock."));

        status = cm_disk_timed_lock_s(
            &lock, entry_path, WR_LOCK_VG_TIMEOUT, inst_cfg->params.lock_interval, inst_cfg->params.dlock_retry_count);
        if (status == CM_SUCCESS) {
            LOG_DEBUG_INF("Lock vg succ, entry path %s.", entry_path);
            cm_destory_dlock(&lock);
            return CM_SUCCESS;
        }
        if (status == CM_TIMEDOUT) {
            LOG_DEBUG_INF("Lock vg timeout, get current lock info, entry_path %s.", entry_path);
            // get old lock info from disk
            status_t ret = cm_get_dlock_info_s(&lock, entry_path);
            WR_RETURN_IFERR3(
                ret, cm_destory_dlock(&lock), LOG_DEBUG_ERR("Failed to get old lock info, entry path %s.", entry_path));

            // Get the status of the instance that owns the lock
            LOG_DEBUG_INF("The node that owns the lock is online, inst_id(disk) %lld, inst_id(lock) %lld.",
                LOCKR_INST_ID(lock), LOCKW_INST_ID(lock));
            if (wr_is_server()) {
                continue;
            }
        }
        LOG_DEBUG_ERR("Failed to lock %s, status %d.", entry_path, status);
        cm_destory_dlock(&lock);
        return status;
    }
}

status_t wr_dl_dealloc(unsigned int lock_id)
{
    int ret = cm_dl_dealloc(lock_id);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to dealloc lock %u, ret %d", lock_id, ret);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_lock_share_disk_vg(const char *entry_path, wr_config_t *inst_cfg)
{
    unsigned int lock_id;
    unsigned long long disk_inst_id;
    int ret;

    lock_id = cm_dl_alloc(entry_path, WR_VG_LOCK_SHARE_DISK_OFFSET, (unsigned long long)inst_cfg->params.inst_id);
    if (lock_id == CM_INVALID_LOCK_ID) {
        LOG_DEBUG_ERR("Failed to alloc lock.");
        return CM_ERROR;
    }

    for (;;) {
        ret = cm_dl_lock(lock_id, WR_LOCK_VG_TIMEOUT_MS);
        if (ret == CM_SUCCESS) {
            LOG_DEBUG_INF("Lock vg succ, entry path %s.", entry_path);
            WR_RETURN_IF_ERROR(wr_dl_dealloc(lock_id));
            return CM_SUCCESS;
        }
        if (ret == CM_DL_ERR_TIMEOUT) {
            LOG_DEBUG_INF("Lock vg timeout, get current lock info, entry_path %s.", entry_path);
            status_t status = cm_dl_getowner(lock_id, &disk_inst_id);
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to get old lock info, entry path %s.", entry_path);
                WR_RETURN_IF_ERROR(wr_dl_dealloc(lock_id));
                return status;
            }

            LOG_DEBUG_INF("The node that owns the lock is online, inst_id(disk) %lld, inst_id(lock) %lld.",
                disk_inst_id, inst_cfg->params.inst_id);
            if (wr_is_server()) {
                continue;
            }
        }
        LOG_DEBUG_ERR("Failed to lock %s, status %d.", entry_path, ret);
        WR_RETURN_IF_ERROR(wr_dl_dealloc(lock_id));
        return ret;
    }
}

status_t wr_lock_vg_storage_core(wr_vg_info_item_t *vg_item, const char *entry_path, wr_config_t *inst_cfg)
{
    LOG_DEBUG_INF("Lock vg storage, lock vg:%s.", entry_path);
    int32 wr_mode = wr_storage_mode(inst_cfg);
    if (wr_mode == WR_MODE_DISK) {
        char lock_file[WR_MAX_FILE_LEN];
        if (wr_pre_lockfile_name(entry_path, lock_file, inst_cfg) != CM_SUCCESS) {
            return CM_ERROR;
        }

        FILE *vglock_fp = wr_get_vglock_fp(lock_file, WR_TRUE);
        if (vglock_fp == NULL) {
            WR_THROW_ERROR(ERR_WR_VG_LOCK, entry_path);
            return CM_ERROR;
        }
        flock(vglock_fp->_fileno, LOCK_EX);  // use flock to exclusive
        LOG_DEBUG_INF("DISK MODE, lock vg:%s, lock file:%s.", entry_path, lock_file);
    } else if (wr_mode == WR_MODE_SHARE_DISK) {
        if (wr_lock_share_disk_vg(entry_path, inst_cfg) != CM_SUCCESS) {
            WR_THROW_ERROR(ERR_WR_VG_LOCK, entry_path);
            LOG_DEBUG_ERR("Failed to lock share disk vg, entry path %s.", entry_path);
            return CM_ERROR;
        }
    } else {
        /* in standby cluster, we do not need try to lock(scsi3) xlog vg, xlog vg is a read only disk */
        if (WR_STANDBY_CLUSTER_XLOG_VG(vg_item->id)) {
            return CM_SUCCESS;
        }
        if (wr_lock_disk_vg(entry_path, inst_cfg) != CM_SUCCESS) {
            WR_THROW_ERROR(ERR_WR_VG_LOCK, entry_path);
            LOG_DEBUG_ERR("Failed to lock vg, entry path %s.", entry_path);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t wr_lock_vg_storage_r(wr_vg_info_item_t *vg_item, const char *entry_path, wr_config_t *inst_cfg)
{
    if (wr_file_lock_vg_r(inst_cfg) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to file read lock vg.");
        return CM_ERROR;
    }
    if (wr_lock_vg_storage_core(vg_item, entry_path, inst_cfg) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to lock vg, entry path %s.", entry_path);
        wr_file_unlock_vg();
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t wr_lock_vg_storage_w(wr_vg_info_item_t *vg_item, const char *entry_path, wr_config_t *inst_cfg)
{
    if (wr_file_lock_vg_w(inst_cfg) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (wr_lock_vg_storage_core(vg_item, entry_path, inst_cfg) != CM_SUCCESS) {
        wr_file_unlock_vg();
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t wr_unlock_vg_raid(wr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id)
{
    dlock_t lock;
    status_t status = cm_alloc_dlock(&lock, WR_CTRL_VG_LOCK_OFFSET, inst_id);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to alloc dlock for %lld.", inst_id);
        return CM_ERROR;
    }
    status = cm_disk_unlock_s(&lock, entry_path);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to unlock %s the first time, inst id %llu, just try again.", entry_path, inst_id);
        status = cm_disk_unlock_s(&lock, entry_path);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to unlock %s the second time, inst id %llu.", entry_path, inst_id);
            cm_destory_dlock(&lock);
            return CM_ERROR;
        }
    }
    LOG_DEBUG_INF("unLock vg succ, entry path %s.", entry_path);
    cm_destory_dlock(&lock);
    return CM_SUCCESS;
}

status_t wr_unlock_vg_share_disk(wr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id)
{
    unsigned int lock_id;
    status_t status;

    lock_id = cm_dl_alloc(entry_path, WR_VG_LOCK_SHARE_DISK_OFFSET, (unsigned long long)inst_id);
    if (lock_id == CM_INVALID_LOCK_ID) {
        LOG_RUN_ERR("Failed to alloc %s, inst id %llu.", entry_path, inst_id);
        return CM_ERROR;
    }
    status = cm_dl_unlock(lock_id);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to unlock %s the first time, inst id %llu, just try again.", entry_path, inst_id);
        status = cm_dl_unlock(lock_id);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to unlock %s the second time, inst id %llu.", entry_path, inst_id);
            status = wr_dl_dealloc(lock_id);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Failed to dealloc %s, inst id %llu.", entry_path, inst_id);
            }
            return CM_ERROR;
        }
    }
    LOG_DEBUG_INF("unLock vg succ, entry path %s.", entry_path);
    status = wr_dl_dealloc(lock_id);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to dealloc %s, inst id %llu.", entry_path, inst_id);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_unlock_vg(int32 wr_mode, wr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id)
{
    if (wr_mode == WR_MODE_SHARE_DISK) {
        return wr_unlock_vg_share_disk(vg_item, entry_path, inst_id);
    } else {
        return wr_unlock_vg_raid(vg_item, entry_path, inst_id);
    }
}

status_t wr_unlock_vg_storage_core(wr_vg_info_item_t *vg_item, const char *entry_path, wr_config_t *inst_cfg)
{
    LOG_DEBUG_INF("Unlock vg storage, lock vg:%s.", entry_path);
    int32 wr_mode = wr_storage_mode(inst_cfg);
    if (wr_mode == WR_MODE_DISK) {
        char lock_file[WR_MAX_FILE_LEN];
        if (wr_pre_lockfile_name(entry_path, lock_file, inst_cfg) != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to get lock file %s.", entry_path);
            return CM_ERROR;
        }

        FILE *vglock_fp = wr_get_vglock_fp(lock_file, CM_FALSE);
        if (vglock_fp == NULL) {
            LOG_RUN_ERR("Failed to get vglock fp %s.", lock_file);
            return CM_ERROR;
        }

        flock(vglock_fp->_fileno, LOCK_UN);
        wr_free_vglock_fp(lock_file, vglock_fp);
        fclose(vglock_fp);
        LOG_DEBUG_INF("ulock vg:%s, lock file:%s.", entry_path, lock_file);
    } else {
        if (wr_unlock_vg(wr_mode, vg_item, entry_path, inst_cfg->params.inst_id) != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to unlock vg %s.", vg_item->vg_name);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t wr_unlock_vg_storage(wr_vg_info_item_t *vg_item, const char *entry_path, wr_config_t *inst_cfg)
{
    if (wr_unlock_vg_storage_core(vg_item, entry_path, inst_cfg) != CM_SUCCESS) {
        wr_file_unlock_vg();
        return CM_ERROR;
    }
    wr_file_unlock_vg();
    return CM_SUCCESS;
}

status_t wr_check_lock_remain_share_disk(
    wr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id, bool32 *is_remain)
{
    unsigned int lock_id;
    *is_remain = CM_TRUE;
    lock_id = cm_dl_alloc(entry_path, WR_VG_LOCK_SHARE_DISK_OFFSET, (unsigned long long)inst_id);
    if (lock_id == CM_INVALID_LOCK_ID) {
        LOG_DEBUG_ERR("Failed to alloc lock.");
        return CM_ERROR;
    }
    if (cm_dl_check_lock_remain(lock_id, (unsigned long long)inst_id, (unsigned int *)is_remain) != CM_SUCCESS) {
        (void)wr_dl_dealloc(lock_id);
        return CM_ERROR;
    }
    return wr_dl_dealloc(lock_id);
}

status_t wr_check_lock_remain_cluster_raid(
    wr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id, bool32 *is_remain)
{
    int32 fd = 0;
    dlock_t lock;
    *is_remain = CM_TRUE;
    status_t status = cm_alloc_dlock(&lock, WR_CTRL_VG_LOCK_OFFSET, inst_id);
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }
    fd = open(entry_path, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        cm_destory_dlock(&lock);
        return CM_ERROR;
    }
    status = cm_check_dlock_remain(&lock, fd, is_remain);
    if (status != CM_SUCCESS) {
        (void)close(fd);
        cm_destory_dlock(&lock);
        return CM_ERROR;
    }
    (void)close(fd);
    cm_destory_dlock(&lock);
    return CM_SUCCESS;
}
status_t wr_check_lock_remain_inner(
    int32 wr_mode, wr_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id, bool32 *is_remain)
{
    if (wr_mode == WR_MODE_SHARE_DISK) {
        return wr_check_lock_remain_share_disk(vg_item, entry_path, inst_id, is_remain);
    } else if (wr_mode == WR_MODE_CLUSTER_RAID) {
        return wr_check_lock_remain_cluster_raid(vg_item, entry_path, inst_id, is_remain);
    }
    LOG_DEBUG_ERR("Invalid wr mode %d when check lock remain.", wr_mode);
    return CM_ERROR;
}

status_t wr_write_ctrl_to_disk(wr_vg_info_item_t *vg_item, int64 offset, void *buf, uint32 size)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(buf != NULL);
    status_t status;

    if (vg_item->volume_handle[0].handle != WR_INVALID_HANDLE) {
        return wr_write_volume_inst(vg_item, &vg_item->volume_handle[0], offset, buf, size);
    }

    wr_volume_t volume;
    status = wr_open_volume(vg_item->entry_path, NULL, WR_INSTANCE_OPEN_FLAG, &volume);
    if (status != CM_SUCCESS) {
        return status;
    }
    status = wr_write_volume_inst(vg_item, &volume, offset, buf, size);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to read write file, offset:%lld, size:%u.", offset, size);
        return status;
    }

    vg_item->volume_handle[0] = volume;

    return CM_SUCCESS;
}

status_t wr_update_core_ctrl_disk(wr_vg_info_item_t *vg_item)
{
    status_t status;
    vg_item->wr_ctrl->core.version++;
    vg_item->wr_ctrl->core.checksum = wr_get_checksum(&vg_item->wr_ctrl->core, WR_CORE_CTRL_SIZE);
    LOG_DEBUG_INF(
        "[REDO]Try to update vg core:%s, version:%llu to disk.", vg_item->vg_name, vg_item->wr_ctrl->core.version);
    int64 offset = (int64)WR_CTRL_CORE_OFFSET;
    status = wr_write_ctrl_to_disk(vg_item, offset, &vg_item->wr_ctrl->core, WR_CORE_CTRL_SIZE);
    if (status == CM_SUCCESS) {
        // write to backup area
        status = wr_write_ctrl_to_disk(
            vg_item, (int64)WR_CTRL_BAK_CORE_OFFSET, &vg_item->wr_ctrl->core, WR_CORE_CTRL_SIZE);
        LOG_DEBUG_INF(
            "[REDO]End to update vg core:%s, version:%llu to disk.", vg_item->vg_name, vg_item->wr_ctrl->core.version);
    }
    return status;
}

status_t wr_update_volume_ctrl(wr_vg_info_item_t *vg_item)
{
    status_t status;
    vg_item->wr_ctrl->volume.version++;
    vg_item->wr_ctrl->volume.checksum = wr_get_checksum(&vg_item->wr_ctrl->volume, WR_VOLUME_CTRL_SIZE);
    status = wr_write_ctrl_to_disk(
        vg_item, (int64)WR_CTRL_VOLUME_OFFSET, &vg_item->wr_ctrl->volume, WR_VOLUME_CTRL_SIZE);
    if (status == CM_SUCCESS) {
        // write to backup area
        status = wr_write_ctrl_to_disk(
            vg_item, (int64)WR_CTRL_BAK_VOLUME_OFFSET, &vg_item->wr_ctrl->volume, WR_VOLUME_CTRL_SIZE);
    }
    return status;
}

status_t wr_update_redo_ctrl(wr_vg_info_item_t *vg_item, uint32 index, uint64 offset, uint64 lsn)
{
    status_t status;
    wr_redo_ctrl_t *redo_ctrl = &vg_item->wr_ctrl->redo_ctrl;
    redo_ctrl->redo_index = index;
    redo_ctrl->offset = offset;
    redo_ctrl->lsn = lsn;
    redo_ctrl->version++;
    redo_ctrl->checksum = wr_get_checksum(redo_ctrl, WR_DISK_UNIT_SIZE);
    status = wr_write_ctrl_to_disk(vg_item, (int64)WR_CTRL_REDO_OFFSET, redo_ctrl, WR_DISK_UNIT_SIZE);
    if (status == CM_SUCCESS) {
        // write to backup area
        status = wr_write_ctrl_to_disk(vg_item, (int64)WR_CTRL_BAK_REDO_OFFSET, redo_ctrl, WR_DISK_UNIT_SIZE);
    }
    return status;
}

status_t wr_update_volume_id_info(wr_vg_info_item_t *vg_item, uint32 id)
{
    WR_RETURN_IF_ERROR(wr_update_core_ctrl_disk(vg_item));
    WR_RETURN_IF_ERROR(wr_update_volume_ctrl(vg_item) != CM_SUCCESS);

    uint64 attr_offset = id * sizeof(wr_volume_attr_t);
    char *align_buf =
        (char *)vg_item->wr_ctrl->core.volume_attrs + (attr_offset / WR_DISK_UNIT_SIZE) * WR_DISK_UNIT_SIZE;
    int64 offset = align_buf - (char *)vg_item->wr_ctrl;
    if (wr_write_ctrl_to_disk(vg_item, offset, align_buf, WR_DISK_UNIT_SIZE) != CM_SUCCESS) {
        return CM_ERROR;
    }
    // write to backup area
    WR_RETURN_IF_ERROR(wr_write_ctrl_to_disk(vg_item, WR_CTRL_BAK_ADDR + offset, align_buf, WR_DISK_UNIT_SIZE));

    attr_offset = id * sizeof(wr_volume_def_t);
    align_buf = (char *)vg_item->wr_ctrl->volume.defs + (attr_offset / WR_DISK_UNIT_SIZE) * WR_DISK_UNIT_SIZE;
    offset = align_buf - (char *)vg_item->wr_ctrl;
    WR_RETURN_IF_ERROR(wr_write_ctrl_to_disk(vg_item, offset, align_buf, WR_DISK_UNIT_SIZE));
    // write to backup area
    return wr_write_ctrl_to_disk(vg_item, WR_CTRL_BAK_ADDR + offset, align_buf, WR_DISK_UNIT_SIZE);
}

status_t wr_write_volume_inst(
    wr_vg_info_item_t *vg_item, wr_volume_t *volume, int64 offset, const void *buf, uint32 size)
{
    void *temp_buf = (void *)buf;
    CM_ASSERT(offset % WR_DISK_UNIT_SIZE == 0);
    CM_ASSERT(size % WR_DISK_UNIT_SIZE == 0);
    if (((uint64)temp_buf) % WR_DISK_UNIT_SIZE != 0 && size <= WR_FILE_SPACE_BLOCK_SIZE) {
#ifndef WIN32
        char align_buf[WR_FILE_SPACE_BLOCK_SIZE] __attribute__((__aligned__(WR_DISK_UNIT_SIZE)));
#else
        char align_buf[WR_FILE_SPACE_BLOCK_SIZE];
#endif
        // some redo logs about free can not align. rp_redo_free_fs_block
        errno_t errcode = memcpy_s(align_buf, size, buf, size);
        securec_check_ret(errcode);
        return wr_write_volume(volume, offset, align_buf, (int32)size);
    }
    CM_ASSERT(((uint64)temp_buf) % WR_DISK_UNIT_SIZE == 0);
    return wr_write_volume(volume, offset, temp_buf, (int32)size);
}

uint32_t wr_find_free_volume_id(const wr_vg_info_item_t *vg_item)
{
    for (uint32_t i = 0; i < WR_MAX_VOLUMES; i++) {
        if (vg_item->wr_ctrl->volume.defs[i].flag == VOLUME_FREE) {
            return i;
        }
    }
    return CM_INVALID_ID32;
}

status_t wr_gen_volume_head(
    wr_volume_header_t *vol_head, wr_vg_info_item_t *vg_item, const char *volume_name, uint32 id)
{
    vol_head->vol_type.id = id;
    errno_t errcode = strcpy_s(vol_head->vol_type.entry_volume_name, WR_MAX_VOLUME_PATH_LEN, volume_name);
    WR_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
    vol_head->vol_type.type = WR_VOLUME_TYPE_NORMAL;
    vol_head->valid_flag = WR_CTRL_VALID_FLAG;
    errcode = strcpy_s(vol_head->vg_name, WR_MAX_NAME_LEN, vg_item->vg_name);
    WR_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
    wr_set_software_version((wr_vg_header_t *)vol_head, (uint32)WR_SOFTWARE_VERSION);
    (void)cm_gettimeofday(&vol_head->create_time);
    vol_head->checksum = wr_get_checksum((char *)vol_head, WR_VG_DATA_SIZE);
    return CM_SUCCESS;
}

status_t wr_cmp_volume_head(wr_vg_info_item_t *vg_item, const char *volume_name, uint32 id)
{
#ifndef WIN32
    char buf[WR_ALIGN_SIZE] __attribute__((__aligned__(WR_DISK_UNIT_SIZE)));
#else
    char buf[WR_ALIGN_SIZE];
#endif
    status_t status = CM_ERROR;
    wr_volume_header_t *vol_cmp_head = (wr_volume_header_t *)buf;
    do {
        WR_BREAK_IF_ERROR(wr_read_volume(&vg_item->volume_handle[id], 0, vol_cmp_head, (int32)WR_ALIGN_SIZE));
        if (vol_cmp_head->valid_flag == WR_CTRL_VALID_FLAG) {
            // cannot add a exists volume
            WR_THROW_ERROR(
                ERR_WR_VOLUME_ADD, volume_name, "please check volume is used in cluster, if not need to dd manually");
            break;
        }
        status = CM_SUCCESS;
    } while (0);
    return status;
}

status_t wr_add_volume_vg_ctrl(
    wr_ctrl_t *vg_ctrl, uint32 id, uint64 vol_size, const char *volume_name, volume_slot_e volume_flag)
{
    errno_t errcode = strcpy_s(vg_ctrl->volume.defs[id].name, WR_MAX_VOLUME_PATH_LEN, volume_name);
    WR_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
    vg_ctrl->volume.defs[id].flag = volume_flag;
    vg_ctrl->volume.defs[id].id = id;
    vg_ctrl->core.volume_attrs[id].id = id;
    vg_ctrl->core.volume_attrs[id].hwm = CM_CALC_ALIGN(WR_VOLUME_HEAD_SIZE, wr_get_vg_au_size(vg_ctrl));
    vg_ctrl->core.volume_attrs[id].size = vol_size;
    if (vol_size <= vg_ctrl->core.volume_attrs[id].hwm) {
        WR_THROW_ERROR(ERR_WR_VOLUME_ADD, volume_name, "volume size is too small");
        return CM_ERROR;
    }
    vg_ctrl->core.volume_attrs[id].free = vol_size - vg_ctrl->core.volume_attrs[id].hwm;
    LOG_RUN_INF("Add volume refresh core, old core version:%llu, volume version:%llu, volume def version:%llu.",
        vg_ctrl->core.version, vg_ctrl->volume.version, vg_ctrl->volume.defs[id].version);
    vg_ctrl->volume.defs[id].version++;
    vg_ctrl->core.volume_count++;
    vg_ctrl->core.version++;
    vg_ctrl->volume.version++;
    return CM_SUCCESS;
}

static status_t wr_add_volume_impl_generate_redo(
    wr_session_t *session, wr_vg_info_item_t *vg_item, const char *volume_name, uint32 id)
{
    wr_redo_volhead_t redo;
    wr_volume_header_t *vol_head = (wr_volume_header_t *)redo.head;

    CM_RETURN_IFERR(wr_cmp_volume_head(vg_item, volume_name, id));
    CM_RETURN_IFERR(wr_gen_volume_head(vol_head, vg_item, volume_name, id));

    int32 ret = snprintf_s(redo.name, WR_MAX_NAME_LEN, strlen(volume_name), "%s", volume_name);
    bool32 result = (bool32)(ret != -1);
    WR_RETURN_IF_FALSE2(result, WR_THROW_ERROR(ERR_SYSTEM_CALL, ret));
    wr_put_log(session, vg_item, WR_RT_UPDATE_VOLHEAD, &redo, sizeof(redo));
    return CM_SUCCESS;
}

static status_t wr_add_volume_record_log(wr_session_t *session, wr_vg_info_item_t *vg_item, uint32 id)
{
    wr_ctrl_t *vg_ctrl = vg_item->wr_ctrl;
    wr_redo_volop_t volop_redo;
    volop_redo.volume_count = vg_ctrl->core.volume_count;
    volop_redo.core_version = vg_ctrl->core.version;
    volop_redo.volume_version = vg_ctrl->volume.version;
    volop_redo.is_add = WR_TRUE;

    LOG_RUN_INF("Refresh core, old version:%llu, disk version:%llu.", vg_ctrl->core.version - 1, vg_ctrl->core.version);

    errno_t errcode =
        memcpy_sp(volop_redo.attr, WR_DISK_UNIT_SIZE, &vg_ctrl->core.volume_attrs[id], sizeof(wr_volume_attr_t));
    WR_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    errcode = memcpy_sp(volop_redo.def, WR_DISK_UNIT_SIZE, &vg_ctrl->volume.defs[id], sizeof(wr_volume_def_t));
    WR_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    wr_put_log(session, vg_item, WR_RT_ADD_OR_REMOVE_VOLUME, &volop_redo, sizeof(volop_redo));
    return CM_SUCCESS;
}

static status_t wr_add_volume_impl(
    wr_session_t *session, wr_vg_info_item_t *vg_item, const char *volume_name, volume_slot_e volume_flag)
{
    uint32 id = wr_find_free_volume_id(vg_item);
    bool32 result = (bool32)(id < WR_MAX_VOLUMES);
    WR_RETURN_IF_FALSE2(
        result, LOG_DEBUG_ERR("[VOL][ADV] Failed to add volume, exceed max volumes %d.", WR_MAX_VOLUMES));

    CM_RETURN_IFERR(wr_open_volume(volume_name, NULL, WR_INSTANCE_OPEN_FLAG, &vg_item->volume_handle[id]));
    status_t status = wr_add_volume_impl_generate_redo(session, vg_item, volume_name, id);
    uint64 vol_size = wr_get_volume_size(&vg_item->volume_handle[id]);
    wr_close_volume(&vg_item->volume_handle[id]);
    if (status != CM_SUCCESS) {
        return status;
    }

    result = (bool32)(vol_size != WR_INVALID_64);
    WR_RETURN_IF_FALSE2(
        result, LOG_DEBUG_ERR("[VOL][ADV] Failed to get volume size when add volume:%s.", volume_name));
    status = wr_add_volume_vg_ctrl(vg_item->wr_ctrl, id, vol_size, volume_name, volume_flag);
    if (status != CM_SUCCESS) {
        return status;
    }
    return wr_add_volume_record_log(session, vg_item, id);
}

uint32_t wr_find_volume(wr_vg_info_item_t *vg_item, const char *volume_name)
{
    for (uint32_t i = 0; i < WR_MAX_VOLUMES; i++) {
        if (vg_item->wr_ctrl->volume.defs[i].flag == VOLUME_FREE) {
            // not been used
            continue;
        }

        if (strcmp(vg_item->wr_ctrl->volume.defs[i].name, volume_name) == 0) {
            return i;
        }
    }

    return CM_INVALID_ID32;
}

status_t wr_add_volume_core(
    wr_session_t *session, wr_vg_info_item_t *vg_item, const char *volume_name, wr_config_t *inst_cfg)
{
    if (wr_refresh_vginfo(vg_item) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[VOL][ADV] %s refresh vginfo failed.", "wr_add_volume");
        return CM_ERROR;
    }
    if (wr_find_volume(vg_item, volume_name) != CM_INVALID_ID32) {
        WR_THROW_ERROR(ERR_WR_VOLUME_EXISTED, volume_name, vg_item->vg_name);
        return CM_ERROR;
    }
    if (wr_add_volume_impl(session, vg_item, volume_name, VOLUME_PREPARE) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (wr_process_redo_log(session, vg_item) != CM_SUCCESS) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
        (void)wr_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        LOG_RUN_ERR("[WR] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        wr_exit(1);
    }
    return CM_SUCCESS;
}

status_t wr_refresh_meta_info(wr_session_t *session)
{
    return CM_SUCCESS;
}

uint64 wr_get_vg_latch_shm_offset(wr_vg_info_item_t *vg_item)
{
    cm_shm_key_t key = ga_object_key(GA_INSTANCE_POOL, vg_item->objectid);
    sh_mem_p offset = cm_trans_shm_offset(key, vg_item->vg_latch);
    return offset;
}

// shoud lock in caller
status_t wr_load_volume_ctrl(wr_vg_info_item_t *vg_item, wr_volume_ctrl_t *volume_ctrl)
{
    return CM_SUCCESS;
}

status_t wr_check_refresh_core(wr_vg_info_item_t *vg_item)
{
    if (!WR_STANDBY_CLUSTER && wr_is_readwrite()) {
        WR_ASSERT_LOG(wr_need_exec_local(), "only masterid %u can be readwrite.", wr_get_master_id());
        return CM_SUCCESS;
    }
#ifndef WIN32
    char buf[WR_DISK_UNIT_SIZE] __attribute__((__aligned__(WR_DISK_UNIT_SIZE)));
#else
    char buf[WR_DISK_UNIT_SIZE];
#endif
    bool32 remote = CM_FALSE;
    uint64 core_version = vg_item->wr_ctrl->core.version;
    wr_fs_block_root_t *fs_root = (wr_fs_block_root_t *)vg_item->wr_ctrl->core.fs_block_root;
    uint64 fs_version = fs_root->version;
    wr_fs_aux_root_t *fs_aux_root = (wr_fs_aux_root_t *)vg_item->wr_ctrl->core.fs_aux_root;
    uint64 fs_aux_version = fs_aux_root->version;

    status_t status = wr_load_vg_ctrl_part(vg_item, (int64)WR_CTRL_CORE_OFFSET, buf, WR_DISK_UNIT_SIZE, &remote);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg core version %s.", vg_item->entry_path);
        return status;
    }

    wr_core_ctrl_t *new_core = (wr_core_ctrl_t *)buf;
    if (wr_compare_version(new_core->version, core_version)) {
        LOG_RUN_INF("Refresh core, old version:%llu, disk version:%llu.", core_version, new_core->version);
        status = wr_load_vg_ctrl_part(
            vg_item, (int64)WR_CTRL_CORE_OFFSET, &vg_item->wr_ctrl->core, (int32)WR_CORE_CTRL_SIZE, &remote);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to load vg core %s.", vg_item->entry_path);
            return status;
        }
    } else {
        fs_root = (wr_fs_block_root_t *)new_core->fs_block_root;
        fs_aux_root = (wr_fs_aux_root_t *)new_core->fs_aux_root;
        if (wr_compare_version(fs_root->version, fs_version) ||
            wr_compare_version(fs_aux_root->version, fs_aux_version)) {
            LOG_RUN_INF("Refresh core head, old version:%llu, disk version:%llu.", fs_version, fs_root->version);
            errno_t errcode = memcpy_s(&vg_item->wr_ctrl->core, WR_DISK_UNIT_SIZE, buf, WR_DISK_UNIT_SIZE);
            securec_check_ret(errcode);
        }
    }
    return CM_SUCCESS;
}

// NOTE:use in server.
status_t wr_check_volume(wr_vg_info_item_t *vg_item, uint32 volumeid)
{
    return CM_SUCCESS;
}

// first check volume is valid.
status_t wr_check_write_volume(wr_vg_info_item_t *vg_item, uint32 volumeid, int64 offset, void *buf, uint32 size)
{
    wr_volume_t *volume;
    WR_RETURN_IF_ERROR(wr_check_volume(vg_item, volumeid));
    volume = &vg_item->volume_handle[volumeid];
    return wr_write_volume_inst(vg_item, volume, offset, buf, size);
}

// first check volume is valid.
status_t wr_check_read_volume(
    wr_vg_info_item_t *vg_item, uint32 volumeid, int64 offset, void *buf, int32 size, bool32 *remote)
{
    wr_volume_t *volume;
    WR_RETURN_IF_ERROR(wr_check_volume(vg_item, volumeid));
    volume = &vg_item->volume_handle[volumeid];
    LOG_DEBUG_INF("Begin to read volume %s when check, offset:%lld,size:%d.", vg_item->entry_path, offset, size);
    return wr_read_volume_inst(vg_item, volume, offset, buf, size, remote);
}

wr_remote_read_proc_t remote_read_proc = NULL;
void regist_remote_read_proc(wr_remote_read_proc_t proc)
{
    remote_read_proc = proc;
}

static inline bool32 wr_need_load_remote(int size)
{
    return ((remote_read_proc != NULL) && (!wr_need_exec_local()) && (size <= (int32)WR_LOADDISK_BUFFER_SIZE));
}

bool32 wr_need_exec_local(void)
{
    wr_config_t *cfg = wr_get_inst_cfg();
    uint32 master_id = wr_get_master_id();
    uint32 curr_id = (uint32)(cfg->params.inst_id);
    return ((curr_id == master_id));
}

status_t wr_read_volume_inst(
    wr_vg_info_item_t *vg_item, wr_volume_t *volume, int64 offset, void *buf, int32 size, bool32 *remote_chksum)
{
    status_t status = CM_ERROR;
    CM_ASSERT(offset % WR_DISK_UNIT_SIZE == 0);
    CM_ASSERT(size % WR_DISK_UNIT_SIZE == 0);
    CM_ASSERT(((uint64)buf) % WR_DISK_UNIT_SIZE == 0);
    while (get_instance_status_proc != NULL && get_instance_status_proc() != WR_STATUS_RECOVERY &&
           wr_need_load_remote(size) == CM_TRUE && status != CM_SUCCESS) {
        if (size == (int32)sizeof(wr_ctrl_t)) {
            LOG_RUN_INF("Try to load wrctrl from remote.");
        }
        status = remote_read_proc(vg_item->vg_name, volume, offset, buf, size);
        if (status != CM_SUCCESS) {
            if (status == WR_READ4STANDBY_ERR || get_instance_status_proc() == WR_STATUS_PREPARE) {
                LOG_RUN_ERR("Failed to load disk(%s) data from the active node, result:%d", volume->name_p, status);
                return CM_ERROR;
            }
            LOG_RUN_WAR("Failed to load disk(%s) data from the active node, result:%d", volume->name_p, status);
            cm_sleep(WR_READ_REMOTE_INTERVAL);
            continue;
        }

        if (*remote_chksum == CM_TRUE) {
            if (wr_read_remote_checksum(buf, size) != CM_TRUE) {
                LOG_RUN_WAR("Failed to load disk(%s) data from the active node, checksum error", volume->name_p);
                status = CM_ERROR;
                continue;
            }
        }
        return status;
    }

    if (wr_is_server()) {
        uint32 recover_thread_id = wr_get_recover_thread_id();
        uint32 curr_thread_id = wr_get_current_thread_id();
        uint32 recover_status = get_instance_status_proc();
        if (recover_status != WR_STATUS_OPEN && recover_thread_id != curr_thread_id &&
            vg_item->status == WR_VG_STATUS_OPEN) {
            WR_THROW_ERROR(ERR_WR_RECOVER_CAUSE_BREAK);
            LOG_RUN_INF("Read volume inst break by recovery");
            return CM_ERROR;
        }
    }

    *remote_chksum = CM_FALSE;
    status = wr_read_volume(volume, offset, buf, size);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to load disk(%s) data, result:%d", volume->name_p, status);
        return status;
    }

    return CM_SUCCESS;
}

status_t wr_read_volume_4standby(const char *vg_name, uint32 volume_id, int64 offset, void *buf, uint32 size)
{
    wr_vg_info_item_t *vg_item = wr_find_vg_item(vg_name);
    if (vg_item == NULL) {
        LOG_RUN_ERR("Read volume for standby failed, find vg(%s) error.", vg_name);
        return CM_ERROR;
    }

    if (volume_id >= WR_MAX_VOLUMES) {
        LOG_RUN_ERR("Read volume for standby failed, vg(%s) volume id[%u] error.", vg_name, volume_id);
        return CM_ERROR;
    }

    wr_volume_t *volume = &vg_item->volume_handle[volume_id];
    if (volume->handle == WR_INVALID_HANDLE) {
        if (wr_open_volume(volume->name_p, NULL, WR_INSTANCE_OPEN_FLAG, volume) != CM_SUCCESS) {
            LOG_RUN_ERR("Read volume for standby failed, failed to open volume(%s).", volume->name_p);
            return CM_ERROR;
        }
    }

    uint64 volumesize = vg_item->wr_ctrl->core.volume_attrs[volume_id].size;
    if (((uint64)offset > volumesize) || ((uint64)size > (volumesize - (uint64)offset))) {
        LOG_RUN_ERR(
            "Read volume for standby failed, params err, vg(%s) voiume id[%u] offset[%llu] size[%u] volume size[%llu].",
            vg_name, volume_id, offset, size, volumesize);
        return CM_ERROR;
    }

    if (wr_read_volume(volume, offset, buf, (int32)size) != CM_SUCCESS) {
        LOG_RUN_ERR("Read volume for standby failed, failed to load disk(%s) data.", volume->name_p);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("load disk(%s) data for standby success.", volume->name_p);
    return CM_SUCCESS;
}

bool32 wr_meta_syn(wr_session_t *session, wr_bg_task_info_t *bg_task_info)
{
    bool32 finish = CM_TRUE;
    for (uint32_t i = bg_task_info->vg_id_beg; i < bg_task_info->vg_id_end; i++) {
        bool32 cur_finish = wr_syn_buffer_cache(session, &g_vgs_info->volume_group[i]);
        if (!cur_finish && !finish) {
            finish = CM_FALSE;
        }
    }
    return finish;
}

#ifdef __cplusplus
}
#endif
