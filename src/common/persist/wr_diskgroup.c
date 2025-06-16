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
    uint32_t state;
    char file_name[WR_MAX_FILE_LEN];
    FILE *fp;  // each process has itself fp
} vglock_fp_t;

vglock_fp_t g_fp_list[WR_MAX_OPEN_VG];
#endif

wr_vg_info_t *g_vgs_info = NULL;

bool32 g_is_wr_server = WR_FALSE;
static wr_rdwr_type_e g_is_wr_readwrite = WR_STATUS_NORMAL;
static uint32_t g_master_instance_id = WR_INVALID_ID32;
static const char *const g_wr_lock_vg_file = "wr_vg.lck";
static int32_t g_wr_lock_vg_fd = CM_INVALID_INT32;
static uint32_t g_wr_recover_thread_id = 0;

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

uint32_t wr_get_master_id()
{
    return g_master_instance_id;
}

void wr_set_master_id(uint32_t id)
{
    g_master_instance_id = id;
    LOG_RUN_INF("set master id is %u.", id);
}

void wr_set_server_flag(void)
{
    g_is_wr_server = WR_TRUE;
}

int32_t wr_get_server_status_flag(void)
{
    return (int32_t)g_is_wr_readwrite;
}

void wr_set_server_status_flag(int32_t wr_status)
{
    g_is_wr_readwrite = wr_status;
}

void wr_set_recover_thread_id(uint32_t thread_id)
{
    g_wr_recover_thread_id = thread_id;
}

uint32_t wr_get_recover_thread_id(void)
{
    return g_wr_recover_thread_id;
}

wr_get_instance_status_proc_t get_instance_status_proc = NULL;
void regist_get_instance_status_proc(wr_get_instance_status_proc_t proc)
{
    get_instance_status_proc = proc;
}

void vg_destroy_env(wr_vg_info_item_t *vg_item)
{
    cm_oamap_destroy(&vg_item->au_map);
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

wr_vg_info_item_t *wr_find_vg_item_by_id(uint32_t vg_id)
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

status_t wr_check_dup_vg(wr_vg_info_t *config, uint32_t vg_no, bool32 *result)
{
    char *last_vg_name = config->volume_group[vg_no - 1].vg_name;
    char *last_entry_path = config->volume_group[vg_no - 1].entry_path;

    for (uint32_t i = 0; i < vg_no - 1; i++) {
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

status_t wr_load_vg_ctrl_part(wr_vg_info_item_t *vg_item, int64 offset, void *buf, int32_t size, bool32 *remote)
{

    return CM_SUCCESS;
}

void wr_lock_vg_mem_x(wr_vg_info_item_t *vg_item)
{
    wr_latch_x(&vg_item->disk_latch);
}

void wr_lock_vg_mem_s(wr_vg_info_item_t *vg_item)
{
    wr_latch_s(&vg_item->disk_latch);
}

void wr_lock_vg_mem_s_force(wr_vg_info_item_t *vg_item)
{
    wr_latch_s2(&vg_item->disk_latch, WR_DEFAULT_SESSIONID, CM_TRUE, NULL);
}

void wr_unlock_vg_mem(wr_vg_info_item_t *vg_item)
{
    wr_unlatch(&vg_item->disk_latch);
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

status_t wr_dl_dealloc(unsigned int lock_id)
{
    int ret = cm_dl_dealloc(lock_id);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to dealloc lock %u, ret %d", lock_id, ret);
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
        LOG_RUN_ERR("Failed to alloc lock.");
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
                LOG_RUN_ERR("Failed to get old lock info, entry path %s.", entry_path);
                WR_RETURN_IF_ERROR(wr_dl_dealloc(lock_id));
                return status;
            }

            LOG_DEBUG_INF("The node that owns the lock is online, inst_id(disk) %lld, inst_id(lock) %lld.",
                disk_inst_id, inst_cfg->params.inst_id);
            if (wr_is_server()) {
                continue;
            }
        }
        LOG_RUN_ERR("Failed to lock %s, status %d.", entry_path, ret);
        WR_RETURN_IF_ERROR(wr_dl_dealloc(lock_id));
        return ret;
    }
}



status_t wr_write_volume_inst(
    wr_vg_info_item_t *vg_item, wr_volume_t *volume, int64 offset, const void *buf, uint32_t size)
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
        return wr_write_volume(volume, offset, align_buf, (int32_t)size);
    }
    CM_ASSERT(((uint64)temp_buf) % WR_DISK_UNIT_SIZE == 0);
    return wr_write_volume(volume, offset, temp_buf, (int32_t)size);
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
    wr_volume_header_t *vol_head, wr_vg_info_item_t *vg_item, const char *volume_name, uint32_t id)
{
    vol_head->vol_type.id = id;
    errno_t errcode = strcpy_s(vol_head->vol_type.entry_volume_name, WR_MAX_VOLUME_PATH_LEN, volume_name);
    WR_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
    vol_head->vol_type.type = WR_VOLUME_TYPE_NORMAL;
    vol_head->valid_flag = WR_CTRL_VALID_FLAG;
    errcode = strcpy_s(vol_head->vg_name, WR_MAX_NAME_LEN, vg_item->vg_name);
    WR_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
    wr_set_software_version((wr_vg_header_t *)vol_head, (uint32_t)WR_SOFTWARE_VERSION);
    (void)cm_gettimeofday(&vol_head->create_time);
    vol_head->checksum = wr_get_checksum((char *)vol_head, WR_VG_DATA_SIZE);
    return CM_SUCCESS;
}

status_t wr_cmp_volume_head(wr_vg_info_item_t *vg_item, const char *volume_name, uint32_t id)
{
#ifndef WIN32
    char buf[WR_ALIGN_SIZE] __attribute__((__aligned__(WR_DISK_UNIT_SIZE)));
#else
    char buf[WR_ALIGN_SIZE];
#endif
    status_t status = CM_ERROR;
    wr_volume_header_t *vol_cmp_head = (wr_volume_header_t *)buf;
    do {
        WR_BREAK_IF_ERROR(wr_read_volume(&vg_item->volume_handle[id], 0, vol_cmp_head, (int32_t)WR_ALIGN_SIZE));
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
    wr_ctrl_t *vg_ctrl, uint32_t id, uint64 vol_size, const char *volume_name, volume_slot_e volume_flag)
{
    return CM_SUCCESS;
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

// NOTE:use in server.
status_t wr_check_volume(wr_vg_info_item_t *vg_item, uint32_t volumeid)
{
    return CM_SUCCESS;
}

// first check volume is valid.
status_t wr_check_write_volume(wr_vg_info_item_t *vg_item, uint32_t volumeid, int64 offset, void *buf, uint32_t size)
{
    wr_volume_t *volume;
    WR_RETURN_IF_ERROR(wr_check_volume(vg_item, volumeid));
    volume = &vg_item->volume_handle[volumeid];
    return wr_write_volume_inst(vg_item, volume, offset, buf, size);
}

// first check volume is valid.
status_t wr_check_read_volume(
    wr_vg_info_item_t *vg_item, uint32_t volumeid, int64 offset, void *buf, int32_t size, bool32 *remote)
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
    return ((remote_read_proc != NULL) && (!wr_need_exec_local()) && (size <= (int32_t)WR_LOADDISK_BUFFER_SIZE));
}

bool32 wr_need_exec_local(void)
{
    wr_config_t *cfg = wr_get_inst_cfg();
    uint32_t master_id = wr_get_master_id();
    uint32_t curr_id = (uint32_t)(cfg->params.inst_id);
    return ((curr_id == master_id));
}

status_t wr_read_volume_inst(
    wr_vg_info_item_t *vg_item, wr_volume_t *volume, int64 offset, void *buf, int32_t size, bool32 *remote_chksum)
{
    status_t status = CM_ERROR;
    CM_ASSERT(offset % WR_DISK_UNIT_SIZE == 0);
    CM_ASSERT(size % WR_DISK_UNIT_SIZE == 0);
    CM_ASSERT(((uint64)buf) % WR_DISK_UNIT_SIZE == 0);
    while (get_instance_status_proc != NULL && get_instance_status_proc() != WR_STATUS_RECOVERY &&
           wr_need_load_remote(size) == CM_TRUE && status != CM_SUCCESS) {
        if (size == (int32_t)sizeof(wr_ctrl_t)) {
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
        uint32_t recover_thread_id = wr_get_recover_thread_id();
        uint32_t curr_thread_id = wr_get_current_thread_id();
        uint32_t recover_status = get_instance_status_proc();
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

status_t wr_read_volume_4standby(const char *vg_name, uint32_t volume_id, int64 offset, void *buf, uint32_t size)
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

    if (wr_read_volume(volume, offset, buf, (int32_t)size) != CM_SUCCESS) {
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
