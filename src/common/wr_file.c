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
#include "wr_alloc_unit.h"
#include "wr_io_fence.h"
#include "wr_malloc.h"
#include "wr_open_file.h"
#include "wr_redo.h"
#include "cm_system.h"
#include "wr_latch.h"
#include "wr_session.h"
#include "wr_fs_aux.h"
#include "wr_zero.h"
#include "wr_syn_meta.h"
#include "wr_thv.h"
#include "wr_filesystem.h"

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

static inline bool32 compare_auid(auid_t a, auid_t b)
{
    return ((a.volume == b.volume) && (a.au == b.au) && (a.block == b.block) && (a.item == b.item));
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

status_t wr_check_name(const char *name)
{
    if (name == NULL || strlen(name) == 0) {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, "[null]", ", name cannot be a null string.");
        return CM_ERROR;
    }

    return wr_check_name_is_valid(name, WR_MAX_NAME_LEN);
}

status_t wr_check_attr_flag(uint64 attrFlag)
{
    return CM_SUCCESS;
}

status_t wr_check_path(const char *path)
{
    if (path == NULL || strlen(path) == 0) {
        WR_RETURN_IFERR2(
            CM_ERROR, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, "[null]", ", path cannot be a null string."));
    }

    return wr_check_path_is_valid(path, WR_FILE_PATH_MAX_LENGTH);
}

status_t wr_check_volume_path(const char *path)
{
    if (path == NULL || strlen(path) == 0) {
        WR_RETURN_IFERR2(
            CM_ERROR, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, "[null]", ", path cannot be a null string."));
    }

    return wr_check_path_is_valid(path, WR_MAX_VOLUME_PATH_LEN);
}

status_t wr_check_device_path(const char *path)
{
    if (path == NULL || strlen(path) == 0) {
        WR_RETURN_IFERR2(
            CM_ERROR, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, "[null]", ", path cannot be a null string."));
    }

    return wr_check_path_is_valid(path + 1, (WR_FILE_PATH_MAX_LENGTH - 1));
}

status_t wr_check_path_both(const char *path)
{
    if (path == NULL || strlen(path) == 0) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, "[null]", "path cannot be a null string."));
    }

    if (path[0] == '+') {
        return wr_check_path_is_valid(path + 1, WR_FILE_PATH_MAX_LENGTH - 1);
    } else {
        return wr_check_path_is_valid(path, WR_FILE_PATH_MAX_LENGTH);
    }
}

status_t wr_get_name_from_path(const char *path, uint32_t *beg_pos, char *name)
{
    CM_ASSERT(path != NULL);
    CM_ASSERT(beg_pos != NULL);
    CM_ASSERT(name != NULL);
    uint32_t name_len = 0;
    size_t len = strlen(path);
    if (len == 0) {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, "[null]", "path cannot be a null string.");
        return CM_ERROR;
    }
    if (*beg_pos > len) {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, path, "begin pos is larger than string length.");
        return CM_ERROR;
    }
    if (path[*beg_pos] == '/' || (*beg_pos == 0 && path[*beg_pos] == '+')) {
        (*beg_pos)++;
        if (path[*beg_pos - 1] == '/') {
            while (path[*beg_pos] == '/') {
                (*beg_pos)++;
            }
        }
        while (path[*beg_pos] != '/' && path[*beg_pos] != 0) {
            name[name_len] = path[*beg_pos];
            if (wr_is_valid_name_char(name[name_len]) != CM_SUCCESS) {
                WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, path, ", name should be [0~9,a~z,A~Z,-,_,.]");
                return CM_ERROR;
            }
            (*beg_pos)++;
            name_len++;
            if (name_len >= WR_MAX_NAME_LEN) {
                char *err_msg = "name length should less than 64.";
                WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, (char *)path + *beg_pos, err_msg));
            }
        }
        name[name_len] = 0;
    } else if (path[*beg_pos] == 0) {
        name[0] = 0;
    } else {
        WR_RETURN_IFERR2(
            CM_ERROR, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, path, ", name should be [0~9,a~z,A~Z,-,_,.]"));
    }
    return CM_SUCCESS;
}

status_t wr_find_vg_by_dir(const char *dir_path, char *name, wr_vg_info_item_t **vg_item)
{
    status_t status;
    uint32_t beg_pos = 0;

    status = wr_get_name_from_path(dir_path, &beg_pos, name);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get name from path %s,%d.", dir_path, status);
        return status;
    }

    if (name[0] == 0) {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, dir_path, ", get vg name is NULL.");
        return CM_ERROR;
    }

    *vg_item = wr_find_vg_item(name);
    if (*vg_item == NULL) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_VG_NOT_EXIST, name));
    }

    return CM_SUCCESS;
}

void wr_lock_vg_mem_and_shm_x(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    wr_lock_vg_mem_x(vg_item);
    wr_enter_shm_x(session, vg_item);
}

void wr_lock_vg_mem_and_shm_s(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    wr_lock_vg_mem_s(vg_item);
    wr_enter_shm_s(session, vg_item, CM_FALSE, SPIN_WAIT_FOREVER);
}

void wr_lock_vg_mem_and_shm_s_force(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    wr_lock_vg_mem_s_force(vg_item);
    wr_enter_shm_s(session, vg_item, CM_TRUE, SPIN_WAIT_FOREVER);
}

void wr_unlock_vg_mem_and_shm(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    wr_leave_shm(session, vg_item);
    wr_unlock_vg_mem(vg_item);
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
                               "%s/%s", g_inst_cfg->data_dir, (dir_path));
    WR_SECUREC_SS_RETURN_IF_ERROR(err, CM_ERROR);


    if (lstat(path, &st) != 0) {
        LOG_DEBUG_ERR("failed to get stat for path %s, errno %d.\n", path, errno);
        return CM_ERROR;
    }

    if (S_ISREG(st.st_mode)) {
        *output_type = GFT_FILE;
    } else if (S_ISDIR(st.st_mode)) {
        *output_type = GFT_PATH;
    } else if (S_ISLNK(st.st_mode)) {
        *output_type = GFT_LINK;
    } else {
        LOG_DEBUG_ERR("file %s type is %o, not supported", path, st.st_mode);
        *output_type = -1;
        return CM_ERROR;
    }
    *result = true;

    return CM_SUCCESS;
}

status_t wr_check_dir(wr_session_t *session, const char *dir_path, gft_item_type_t type,
    wr_check_dir_output_t *output_info, bool32 is_throw_err)
{
    return CM_SUCCESS;
}

status_t wr_open_dir(wr_session_t *session, const char *dir_path, bool32 is_refresh, wr_find_node_t *find_info)
{
    return CM_SUCCESS;
}

void wr_close_dir(wr_session_t *session, char *vg_name, uint64 ftid)
{
    return;
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
                WR_BREAK_IFERR2(CM_ERROR, LOG_DEBUG_ERR("Failed to check item, errcode:%d.", status));
            }
        }
        status = CM_SUCCESS;
    } while (0);

    return status;
}

status_t wr_check_file(wr_vg_info_item_t *vg_item)
{
    status_t status = wr_check_refresh_ft(vg_item);
    WR_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("Failed to check and update file table %s.", vg_item->wr_ctrl->vg_info.vg_name));
    return CM_SUCCESS;
}

status_t wr_open_file_check_s(
    wr_session_t *session, const char *file, wr_vg_info_item_t **vg_item, gft_item_type_t type, gft_node_t **out_node)
{
    status_t status = wr_check_file(*vg_item);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to check file, errcode:%d.", cm_get_error_code()));
    wr_vg_info_item_t *file_vg_item = *vg_item;
    wr_check_dir_output_t output_info = {out_node, &file_vg_item, NULL, CM_FALSE};
    status = wr_check_dir(session, file, type, &output_info, CM_TRUE);
    WR_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("Failed to check dir when open file read, errcode:%d.", cm_get_error_code()));
    if (file_vg_item->id != (*vg_item)->id) {
        wr_unlock_vg_mem_and_shm(session, *vg_item);
        LOG_DEBUG_INF(
            "Unlock vg:%s and then lock vg:%s, session id:%u", (*vg_item)->vg_name, file_vg_item->vg_name, session->id);
        *vg_item = file_vg_item;
        wr_lock_vg_mem_and_shm_s(session, *vg_item);
    }
    return CM_SUCCESS;
}

status_t wr_open_file(wr_session_t *session, const char *file, int32_t flag, int64 *fd)
{
    status_t status;
    WR_LOG_DEBUG_OP("Begin to open file:%s, session id:%u.", file, session->id);
    status = wr_filesystem_open(file, flag, fd);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS]Failed to open file:%s.", file);
        return CM_ERROR;
    }
    WR_LOG_DEBUG_OP("Succeed to open file:%s, fd:%lld, session:%u.", file, *fd, session->id);
    return CM_SUCCESS;
}

status_t wr_close_file(wr_session_t *session, wr_vg_info_item_t *vg_item, uint64 ftid)
{
    status_t status =
        wr_delete_open_file_index(session, vg_item, ftid, session->cli_info.cli_pid, session->cli_info.start_time);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to delete open file index, ftid:%llu.", ftid));
    return CM_SUCCESS;
}

status_t wr_check_rm_file(
    wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t ftid, bool32 *should_rm_file, gft_node_t **file_node)
{
    return CM_SUCCESS;
}

void wr_init_bitmap_block(wr_ctrl_t *wr_ctrl, char *block, uint32_t block_id, auid_t auid)
{
    wr_fs_block_root_t *block_root = WR_GET_FS_BLOCK_ROOT(wr_ctrl);
    wr_fs_block_header *fs_block = (wr_fs_block_header *)block;
    if (memset_s(fs_block, WR_FILE_SPACE_BLOCK_SIZE, -1, WR_FILE_SPACE_BLOCK_SIZE) != EOK) {
        cm_panic(0);
    }
    fs_block->common.type = WR_BLOCK_TYPE_FS;
    fs_block->common.flags = WR_BLOCK_FLAG_FREE;
    fs_block->common.version = 0;
    fs_block->used_num = 0;
    fs_block->total_num = WR_FILE_SPACE_BLOCK_BITMAP_COUNT;
    fs_block->index = WR_FS_INDEX_INIT;
    fs_block->common.id.au = auid.au;
    fs_block->common.id.volume = auid.volume;
    fs_block->common.id.block = block_id;
    fs_block->common.id.item = 0;
    wr_set_auid(&fs_block->ftid, WR_BLOCK_ID_INIT);

    block_root->free.count++;
    wr_block_id_t first = block_root->free.first;
    block_root->free.first = fs_block->common.id;
    fs_block->next = first;

    bool32 cmp = wr_cmp_auid(block_root->free.last, WR_INVALID_64);
    if (cmp) {
        block_root->free.last = fs_block->common.id;
    }
    LOG_DEBUG_INF("[FS][FORMAT] Init bitmap block, free count:%llu, first:%s.", block_root->free.count,
        wr_display_metaid(first));
    LOG_DEBUG_INF("[FS][FORMAT] Fs block id:%s", wr_display_metaid(fs_block->common.id));
}

status_t wr_update_au_disk(
    wr_vg_info_item_t *vg_item, auid_t auid, ga_pool_id_e pool_id, uint32_t first, uint32_t count, uint32_t size)
{
    CM_ASSERT(vg_item != NULL);
    status_t status;
    char *buf;
    CM_ASSERT(vg_item->volume_handle[auid.volume].handle != WR_INVALID_HANDLE);
    int64 offset = wr_get_au_offset(vg_item, auid);
    int64 block_offset = offset;
    uint32_t obj_id = first;
    for (uint32_t i = 0; i < count; i++) {
        buf = wr_buffer_get_meta_addr(pool_id, obj_id);
        WR_ASSERT_LOG(buf != NULL, "buf is NULL when update au disk, auid:%s", wr_display_metaid(auid));
        wr_common_block_t *block = (wr_common_block_t *)buf;
        block->version++;
        block->checksum = wr_get_checksum(buf, size);
        LOG_DEBUG_INF(
            "wr_update_au_disk checksum:%u, %s, count:%u.", block->checksum, wr_display_metaid(block->id), i);

        block_offset = offset + i * size;
        status = wr_write_volume_inst(vg_item, &vg_item->volume_handle[auid.volume], block_offset, buf, size);
        if (status != CM_SUCCESS) {
            return status;
        }
        obj_id = ga_next_object(pool_id, obj_id);
    }
    return CM_SUCCESS;
}

status_t wr_format_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t auid)
{
    return CM_SUCCESS;
}

status_t wr_format_bitmap_node(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t auid)
{
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    status_t status;

    wr_fs_block_root_t *block_root = WR_GET_FS_BLOCK_ROOT(wr_ctrl);
    wr_fs_block_list_t bk_list = block_root->free;
    wr_fs_block_header *block;
    uint32_t block_num = (uint32_t)WR_GET_FS_BLOCK_NUM_IN_AU(wr_ctrl);
    ga_queue_t queue;
    status = ga_alloc_object_list(GA_16K_POOL, block_num, &queue);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[FS][FORMAT] Failed to alloc object list, block num is %u.", block_num));
    uint32_t obj_id = queue.first;
    ga_obj_id_t ga_obj_id;
    ga_obj_id.pool_id = GA_16K_POOL;
    for (uint32_t i = 0; i < block_num; i++) {
        block = (wr_fs_block_header *)wr_buffer_get_meta_addr(GA_16K_POOL, obj_id);
        CM_ASSERT(block != NULL);
        block->common.id = auid;
        block->common.id.block = i;
        block->common.id.item = 0;
        ga_obj_id.obj_id = obj_id;

        status =
            wr_register_buffer_cache(session, vg_item, block->common.id, ga_obj_id, (char *)block, WR_BLOCK_TYPE_FS);
        WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[FS][FORMAT] Failed to register block:%s, obj is %u.",
                                      wr_display_metaid(block->common.id), obj_id));

        wr_init_bitmap_block(wr_ctrl, (char *)block, i, auid);
        obj_id = ga_next_object(GA_16K_POOL, obj_id);
    }

    wr_redo_format_fs_t redo;
    redo.auid = auid;
    redo.count = block_num;
    redo.old_free_list = bk_list;
    wr_put_log(session, vg_item, WR_RT_FORMAT_AU_FILE_SPACE, &redo, sizeof(wr_redo_format_fs_t));

    return CM_SUCCESS;
}

status_t wr_refresh_root_ft_inner(wr_vg_info_item_t *vg_item)
{
    bool32 remote = CM_TRUE;
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    char *root = wr_ctrl->root;
    status_t status = wr_load_vg_ctrl_part(vg_item, (int64)WR_CTRL_ROOT_OFFSET, root, (int32_t)WR_BLOCK_SIZE, &remote);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to get the whole root."));
    if (remote == CM_FALSE) {
        uint32_t checksum = wr_get_checksum(root, WR_BLOCK_SIZE);
        wr_common_block_t *block = (wr_common_block_t *)root;
        wr_check_checksum(checksum, block->checksum);
    }
    return CM_SUCCESS;
}

status_t wr_refresh_root_ft(wr_vg_info_item_t *vg_item, bool32 check_version, bool32 active_refresh)
{
    if (!wr_is_server()) {
        return CM_SUCCESS;
    }
    if (!WR_STANDBY_CLUSTER && wr_is_readwrite() && !active_refresh) {
        WR_ASSERT_LOG(wr_need_exec_local(), "only masterid %u can be readwrite.", wr_get_master_id());
        return CM_SUCCESS;
    }
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    char *root = wr_ctrl->root;
    wr_root_ft_block_t *ft_block = (wr_root_ft_block_t *)(root);
    if (check_version) {
        uint64 version = ft_block->ft_block.common.version;
        uint64 disk_version;
        status_t status = wr_get_root_version(vg_item, &disk_version);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to get the root version.");
            return status;
        }

        if (wr_compare_version(disk_version, version)) {
            WR_LOG_DEBUG_OP(
                "The root version is changed, refresh it, version:%llu, new version:%llu.", version, disk_version);
            status = wr_refresh_root_ft_inner(vg_item);
            WR_RETURN_IF_ERROR(status);
        }
    }
    return CM_SUCCESS;
}

gft_node_t *wr_get_ft_node_by_ftid(
    wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t id, bool32 check_version, bool32 active_refresh)
{
    return NULL;
}

static void wr_init_ft_root_core(char *root, wr_root_ft_block_t *ft_block, gft_root_t *gft)
{
    wr_set_blockid(&ft_block->ft_block.next, WR_INVALID_64);
    wr_set_blockid(&gft->first, 0);
    wr_set_blockid(&gft->last, 0);

    gft->items.count = 0;
    *(uint64 *)(&gft->items.first) = WR_INVALID_64;
    *(uint64 *)(&gft->items.last) = WR_INVALID_64;
    gft->free_list.count = 0;
    *(uint64 *)(&gft->free_list.first) = WR_INVALID_64;
    *(uint64 *)(&gft->free_list.last) = WR_INVALID_64;
    // item_count is always 1
    uint32_t item_count = (WR_BLOCK_SIZE - sizeof(wr_root_ft_block_t)) / sizeof(gft_node_t);
    ft_block->ft_block.node_num = item_count;
    gft_node_t *first_free_node = (gft_node_t *)(root + sizeof(wr_root_ft_block_t));
    gft_node_t *node = NULL;

    // the first gft_node_t is used for vg name (like: `/`)
    for (uint32_t i = 1; i < item_count; i++) {
        node = first_free_node + i;
        wr_set_auid(&node->id, 0);
        node->id.block = 0;
        node->id.item = i;

        if (i == 1) {
            *(uint64 *)(&node->prev) = WR_INVALID_64;
            gft->free_list.first = node->id;
        } else {
            *(uint64 *)(&node->prev) = 0;
            node->prev.block = 0;
            node->prev.item = (uint16)i - 1;
        }

        if (i == item_count - 1) {
            *(uint64 *)(&node->next) = WR_INVALID_64;
            gft->free_list.last = node->id;
        } else {
            *(uint64 *)(&node->next) = 0;
            node->next.block = 0;
            node->next.item = (uint16)i + 1;
        }

        gft->free_list.count++;
    }
}

static void wr_init_first_node(wr_ctrl_t *wr_ctrl, gft_node_t *first_node)
{
    first_node->type = GFT_PATH;
    if (strcpy_s(first_node->name, WR_MAX_NAME_LEN, wr_ctrl->vg_info.vg_name) != EOK) {
        cm_panic(0);
    }
    first_node->create_time = cm_current_time();
    first_node->size = 0;
    first_node->written_size = 0;
    first_node->items.count = 0;
    wr_set_auid(&first_node->items.first, WR_INVALID_64);
    wr_set_auid(&first_node->items.last, WR_INVALID_64);
    wr_set_auid(&first_node->prev, WR_INVALID_64);
    wr_set_auid(&first_node->next, WR_INVALID_64);
    wr_set_auid(&first_node->id, 0);
    first_node->id.block = 0;
    first_node->id.item = 0;
}

void wr_init_ft_root(wr_ctrl_t *wr_ctrl, gft_node_t **out_node)
{
    CM_ASSERT(wr_ctrl != NULL);
    char *root = wr_ctrl->root;
    wr_root_ft_block_t *ft_block = (wr_root_ft_block_t *)(root);
    gft_root_t *gft = &ft_block->ft_root;
    wr_init_ft_root_core(root, ft_block, gft);

    gft_node_t *first_node = (gft_node_t *)(root + sizeof(wr_root_ft_block_t));
    wr_init_first_node(wr_ctrl, first_node);

    gft->items.count = 1;
    gft->items.first = first_node->id;
    gft->items.last = first_node->id;
    if (out_node) {
        *out_node = first_node;
    }
    return;
}

status_t wr_update_ft_root(wr_vg_info_item_t *vg_item)
{
    status_t status;
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    wr_root_ft_block_t *block = WR_GET_ROOT_BLOCK(wr_ctrl);
    block->ft_block.common.version++;
    block->ft_block.common.checksum = wr_get_checksum(block, WR_BLOCK_SIZE);
    CM_ASSERT(vg_item->volume_handle[0].handle != WR_INVALID_HANDLE);
    WR_LOG_DEBUG_OP("Update node table root, version:%llu, checksum:%u.", block->ft_block.common.version,
        block->ft_block.common.checksum);
    status = wr_write_volume_inst(
        vg_item, &vg_item->volume_handle[0], (int64)WR_CTRL_ROOT_OFFSET, wr_ctrl->root, WR_BLOCK_SIZE);
    if (status == CM_SUCCESS) {
        // write to backup area
        status = wr_write_volume_inst(
            vg_item, &vg_item->volume_handle[0], (int64)WR_CTRL_BAK_ROOT_OFFSET, wr_ctrl->root, WR_BLOCK_SIZE);
    }
    return status;
}

status_t wr_get_root_version(wr_vg_info_item_t *vg_item, uint64 *version)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(version != NULL);

#ifndef WIN32
    char temp[WR_DISK_UNIT_SIZE] __attribute__((__aligned__(WR_DISK_UNIT_SIZE)));
#else
    char temp[WR_DISK_UNIT_SIZE];
#endif
    bool32 remote = CM_FALSE;
    status_t status = wr_load_vg_ctrl_part(vg_item, (int64)WR_CTRL_ROOT_OFFSET, temp, WR_DISK_UNIT_SIZE, &remote);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg core version %s.", vg_item->entry_path);
        return status;
    }
    *version = ((wr_common_block_t *)temp)->version;
    return CM_SUCCESS;
}

status_t wr_check_refresh_ft(wr_vg_info_item_t *vg_item)
{
    if (!wr_is_server()) {
        return CM_SUCCESS;
    }
    if (!WR_STANDBY_CLUSTER && wr_is_readwrite()) {
        WR_ASSERT_LOG(wr_need_exec_local(), "only masterid %u can be readwrite.", wr_get_master_id());
        return CM_SUCCESS;
    }
    uint64 disk_version;
    bool32 remote = CM_FALSE;
    status_t status = wr_get_root_version(vg_item, &disk_version);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to get root version %s.", vg_item->entry_path));

    wr_root_ft_block_t *ft_block_m = WR_GET_ROOT_BLOCK(vg_item->wr_ctrl);
    if (wr_compare_version(disk_version, ft_block_m->ft_block.common.version)) {
        status = wr_load_vg_ctrl_part(
            vg_item, (int64)WR_CTRL_ROOT_OFFSET, vg_item->wr_ctrl->root, (int32_t)WR_BLOCK_SIZE, &remote);
        WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to load vg core part %s.", vg_item->entry_path));
    }
    WR_LOG_DEBUG_OP(
        "wr_check_refresh_ft version:%llu, disk version:%llu.", ft_block_m->ft_block.common.version, disk_version);
    return CM_SUCCESS;
}

status_t wr_update_ft_block_disk(wr_vg_info_item_t *vg_item, wr_ft_block_t *block, ftid_t id)
{
    return CM_SUCCESS;
}

static status_t wr_get_block_entry(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_config_t *inst_cfg,
    uint64 fid, ftid_t ftid, gft_node_t **node_out, wr_fs_block_t **entry_out)
{
    return CM_SUCCESS;
}

status_t wr_extend_from_offset(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, wr_node_data_t *node_data)
{
    return CM_SUCCESS;
}

static status_t wr_extend_with_updt_written_size(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, wr_node_data_t *node_data)
{
    return CM_SUCCESS;
}

status_t wr_extend(wr_session_t *session, wr_node_data_t *node_data)
{
    return CM_SUCCESS;
}

status_t wr_do_fallocate(wr_session_t *session, wr_node_data_t *node_data)
{
    status_t status;
    if (node_data->size < 0) {
        WR_THROW_ERROR(ERR_WR_FILE_INVALID_SIZE, node_data->offset, node_data->size);
        LOG_DEBUG_ERR("Invalid fallocate offset:%lld, size:%lld.", node_data->offset, node_data->size);
        return CM_ERROR;
    }

    if (node_data->mode != 0) {
        WR_RETURN_IFERR3(CM_ERROR, LOG_DEBUG_ERR("Failed to check mode,vg id %d.", node_data->mode),
            WR_THROW_ERROR(ERR_WR_INVALID_ID, "fallocate mode", (uint64)node_data->mode));
    }

    wr_vg_info_item_t *vg_item = wr_find_vg_item_by_id(node_data->vgid);
    if (vg_item == NULL) {
        WR_RETURN_IFERR3(CM_ERROR, LOG_DEBUG_ERR("Failed to find vg, vg id:%u.", node_data->vgid),
            WR_THROW_ERROR(ERR_WR_INVALID_ID, "vg id", (uint64)node_data->vgid));
    }
    node_data->vg_name = (char *)vg_item->vg_name;

    wr_lock_vg_mem_and_shm_x(session, vg_item);
    gft_node_t *node = wr_get_ft_node_by_ftid(session, vg_item, node_data->ftid, CM_TRUE, CM_FALSE);
    if (node == NULL) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
        WR_RETURN_IFERR2(
            CM_ERROR, LOG_DEBUG_ERR("Failed to find ftid, ftid:%s.", wr_display_metaid(node_data->ftid)));
    }

    status = wr_extend_with_updt_written_size(session, vg_item, node, node_data);
    wr_unlock_vg_mem_and_shm(session, vg_item);

    return status;
}

/* validate params, lock VG and process recovery for truncate */
static status_t wr_prepare_truncate(wr_session_t *session, wr_vg_info_item_t *vg_item, int64 length)
{
    wr_lock_vg_mem_and_shm_x(session, vg_item);

    status_t status = wr_check_file(vg_item);
    if (status != CM_SUCCESS) {
        WR_RETURN_IFERR3(CM_ERROR, wr_unlock_vg_mem_and_shm(session, vg_item),
            LOG_DEBUG_ERR("Failed to check file,errcode:%d.", cm_get_error_code()));
    }
    return CM_SUCCESS;
}

static void wr_truncate_set_size(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, int64 length)
{
    uint64 old_size = (uint64)node->size;
    uint64 align_length = CM_CALC_ALIGN((uint64)length, wr_get_vg_au_size(vg_item->wr_ctrl));
    (void)cm_atomic_set(&node->size, (int64)align_length);
    node->written_size = (uint64)length < node->written_size ? (uint64)length : node->written_size;
    node->min_inited_size = (uint64)align_length < node->min_inited_size ? (uint64)align_length : node->min_inited_size;
    wr_redo_set_file_size_t redo_size;
    redo_size.ftid = node->id;
    redo_size.size = (uint64)node->size;
    redo_size.oldsize = old_size;
    wr_put_log(session, vg_item, WR_RT_SET_FILE_SIZE, &redo_size, sizeof(redo_size));
}

status_t truncate_to_extend(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, int64 size)
{
    wr_node_data_t node_data;
    node_data.fid = node->fid;
    node_data.ftid = node->id;
    node_data.vgid = vg_item->id;
    node_data.vg_name = (char *)vg_item->vg_name;
    node_data.offset = 0;
    node_data.size = size;

    return wr_extend_with_updt_written_size(session, vg_item, node, &node_data);
}

void wr_set_node_flag(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, bool32 is_set, uint32_t flags)
{
    wr_redo_set_file_flag_t file_flag;
    file_flag.ftid = node->id;
    file_flag.old_flags = node->flags;

    if (is_set) {
        node->flags |= flags;
    } else {
        node->flags &= ~flags;
    }
    file_flag.flags = node->flags;
    if (wr_need_exec_local()) {
        wr_put_log(session, vg_item, WR_RT_SET_NODE_FLAG, &file_flag, sizeof(wr_redo_set_file_flag_t));
        LOG_DEBUG_INF("Successfully put the set flag redo log flags:%u, curr flags:%u, node:%s, name %s", flags,
            node->flags, wr_display_metaid(node->id), node->name);
    } else {
        LOG_DEBUG_INF("Dont put the set flag redo log flags:%u, curr flags:%u, node:%s, name %s", flags, node->flags,
            wr_display_metaid(node->id), node->name);
    }
}

void wr_validate_fs_meta(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node)
{

}

wr_invalidate_other_nodes_proc_t invalidate_other_nodes_proc = NULL;
wr_broadcast_check_file_open_proc_t broadcast_check_file_open_proc = NULL;

status_t wr_invalidate_other_nodes_proc(
    wr_vg_info_item_t *vg_item, char *meta_info, uint32_t meta_info_size, bool32 *cmd_ack)
{
    return CM_SUCCESS;
}

void regist_invalidate_other_nodes_proc(wr_invalidate_other_nodes_proc_t proc)
{
    invalidate_other_nodes_proc = proc;
}

void regist_broadcast_check_file_open_proc(wr_broadcast_check_file_open_proc_t proc)
{
    broadcast_check_file_open_proc = proc;
}

status_t wr_invalidate_fs_meta(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node)
{
    return CM_SUCCESS;
}

status_t wr_truncate_small_init_tail(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node)
{
    if (!WR_IS_FILE_INNER_INITED(node->flags)) {
        LOG_DEBUG_INF("normal file:%s fid:%llu not bitmap type, skip extend fs aux", node->name, node->fid);
        return CM_SUCCESS;
    }
    if ((uint64)node->size == node->written_size) {
        LOG_DEBUG_INF("No need to init tail to zero for file:%s, fid:%llu, ftid:%s, size:%llu, written_size:%llu",
            node->name, node->fid, wr_display_metaid(node->id), (uint64)node->size, node->written_size);
        return CM_SUCCESS;
    }
    return wr_try_write_zero_one_au("truncate small", session, vg_item, node, (int64)node->written_size);
}

static status_t wr_truncate_to_recycle(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, wr_fs_block_t *entry_block, int64 length)
{
    return CM_SUCCESS;
}

status_t wr_truncate_inner(wr_session_t *session, uint64 fid, ftid_t ftid, int64 length, wr_vg_info_item_t *vg_item)
{
    CM_RETURN_IFERR(wr_prepare_truncate(session, vg_item, length));

    // update props on FT, generate new FT node in recycle with props, check v3 usage on truncate
    status_t status = CM_SUCCESS;
    gft_node_t *node = NULL;
    wr_fs_block_t *entry_block = NULL;
    wr_config_t *inst_cfg = wr_get_inst_cfg();

    uint64 au_size = wr_get_vg_au_size(vg_item->wr_ctrl);
    uint64 align_length = CM_CALC_ALIGN((uint64)length, au_size);
    CM_RETURN_IFERR(wr_get_block_entry(session, vg_item, inst_cfg, fid, ftid, &node, &entry_block));

    uint64 written_size = (uint64)length;
    if ((written_size == node->written_size) && (align_length == (uint64)node->size)) {
        LOG_DEBUG_INF("No truncate file:%s, size:%llu, written_size:%llu", node->name, node->size, node->written_size);
        wr_unlock_vg_mem_and_shm(session, vg_item);
        return CM_SUCCESS;
    }

    // need to truncate to bigger
    if (written_size > node->written_size) {
        /* to extend the file */
        LOG_DEBUG_INF("start truncate to extend");
        status = truncate_to_extend(session, vg_item, node, length);
        wr_unlock_vg_mem_and_shm(session, vg_item);
        return status;
    }

    wr_block_ctrl_t *block_ctrl = wr_get_block_ctrl_by_node(node);
    wr_init_wr_fs_block_cache_info(&block_ctrl->fs_block_cache_info);

    // need to truncate to smaller
    if (wr_invalidate_fs_meta(session, vg_item, node) != CM_SUCCESS) {
        LOG_RUN_ERR("[WR] Invalid file:%s in vg:%s fail.", node->name, vg_item->vg_name);
        wr_unlock_vg_mem_and_shm(session, vg_item);
        return CM_ERROR;
    }

    /*
     * Key idea: what to check when determining that we've reached EOF during R/W? we must make sure no out-of-bound
     * R/W on truncated file. Answer is the second file space block id at the truncate point should be invalid64.
     * More importantly, truncated space must be recycled for re-use, meaning the metadata in .recycle must be
     * generated accordingly, associated with the file space block(s) taken from the truncated file.
     */

    uint64 align_origin_length = CM_CALC_ALIGN((uint64)node->size, au_size);
    bool32 need_recycle = (align_length < align_origin_length);
    LOG_DEBUG_INF("To truncate %s from %lld(aligned %llu) to %lld(aligned %llu), a recycle file is %s needed.",
        node->name, node->size, align_origin_length, length, align_length, (need_recycle ? "" : "not"));
    if (need_recycle) {
        if (wr_truncate_to_recycle(session, vg_item, node, entry_block, length) != CM_SUCCESS) {
            wr_validate_fs_meta(session, vg_item, node);
            wr_unlock_vg_mem_and_shm(session, vg_item);
            return CM_ERROR;
        }
    }
    wr_truncate_set_size(session, vg_item, node, length);

    if (wr_truncate_small_init_tail(session, vg_item, node) != CM_SUCCESS) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("[WR] ABORT INFO:truncate small init tail failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        wr_exit_error();
    }

    /* Truncating file space block completed. */
    if (wr_process_redo_log(session, vg_item) != CM_SUCCESS) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("[WR] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        wr_exit_error();
    }

    // update the file ver for entry block
    wr_set_fs_block_file_ver(node, entry_block);

    // re-valid the file after the truncate has been done
    wr_validate_fs_meta(session, vg_item, node);

    // release resources
    wr_unlock_vg_mem_and_shm(session, vg_item);
    LOG_DEBUG_INF(
        "Succeed to truncate file:%s, size:%llu, written_size:%llu", node->name, node->size, node->written_size);
    return CM_SUCCESS;
}

status_t wr_truncate(wr_session_t *session, uint64 fid, ftid_t ftid, int64 length, char *vg_name)
{
    wr_vg_info_item_t *vg_item = wr_find_vg_item(vg_name);
    if (vg_item == NULL) {
        WR_RETURN_IFERR3(CM_ERROR, LOG_DEBUG_ERR("Failed to find vg with name %s.", vg_name),
            WR_THROW_ERROR(ERR_WR_VG_NOT_EXIST, vg_name));
    }

    return wr_truncate_inner(session, fid, ftid, length, vg_item);
}

// return is true means need to retry again
bool32 wr_try_revalidate_file(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node)
{
    LOG_DEBUG_INF("Refresh file:%llu found node:%s is invalid, need refresh from primary.", node->fid,
        wr_display_metaid(node->id));

    if (wr_need_exec_local()) {
        wr_validate_fs_meta(session, vg_item, node);
    } else {

    }
    return CM_FALSE;
}

status_t wr_refresh_file(wr_session_t *session, uint64 fid, ftid_t ftid, char *vg_name, int64 offset)
{
    return CM_SUCCESS;
}

status_t wr_check_rename_path(wr_session_t *session, const char *src_path, const char *dst_path, text_t *dst_name)
{
    text_t src_dir;
    text_t src_name;
    cm_str2text((char *)src_path, &src_name);
    if (!cm_fetch_rtext(&src_name, '/', '\0', &src_dir)) {
        WR_RETURN_IFERR3(CM_ERROR, LOG_DEBUG_ERR("not a complete absolute path name(%s %s)", T2S(&src_dir), src_path),
            WR_THROW_ERROR(ERR_WR_FILE_RENAME, "can not change path."));
    }

    text_t dst_dir;
    cm_str2text((char *)dst_path, dst_name);
    if (!cm_fetch_rtext(dst_name, '/', '\0', &dst_dir)) {
        WR_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("not a complete absolute path name(%s %s)", T2S(&dst_dir), dst_path));
    }

    if (cm_text_equal(&src_dir, &dst_dir) == CM_FALSE) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FILE_RENAME, "can not change path."));
    }
    return CM_SUCCESS;
}

status_t wr_check_open_file_remote(wr_session_t *session, const char *vg_name, uint64 ftid, bool32 *is_open)
{
    *is_open = CM_FALSE;

    WR_LOG_DEBUG_OP("[WR-MES-CB]Begin to check file-open %llu.", ftid);
    wr_vg_info_item_t *vg_item = wr_find_vg_item(vg_name);
    if (vg_item == NULL) {
        WR_RETURN_IFERR3(
            CM_ERROR, WR_THROW_ERROR(ERR_WR_VG_NOT_EXIST, vg_name), LOG_DEBUG_ERR("Failed to find vg, %s.", vg_name));
    }

    status_t status = wr_check_open_file(session, vg_item, ftid, is_open);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to check open file, vg:%s, ftid:%llu.", vg_name, ftid));
    return CM_SUCCESS;
}

status_t wr_update_file_written_size(
    wr_session_t *session, uint32_t vg_id, int64 offset, int64 size, wr_block_id_t ftid, uint64 fid)
{
    status_t status = CM_SUCCESS;
    wr_vg_info_item_t *vg_item = wr_find_vg_item_by_id(vg_id);
    if (!vg_item) {
        WR_RETURN_IFERR3(CM_ERROR, LOG_DEBUG_ERR("Failed to find vg,vg id %u.", vg_id),
            WR_THROW_ERROR(ERR_WR_INVALID_ID, "vg id", (uint64)vg_id));
    }

    // when be primary, reload all the block meta by wr_refresh_buffer_cache
    uint64 written_size = (uint64)(offset + size);

    gft_node_t *node = NULL;
    wr_lock_vg_mem_and_shm_s(session, vg_item);

    LOG_DEBUG_INF("Begin to update file:%s fid:%llu, node size:%llu, written_size:%llu, min_inited_size:%llu with."
                  "offset :%lld, size:%lld",
        node->name, node->fid, node->size, node->written_size, node->min_inited_size, offset, size);

    if (node->written_size >= written_size && node->min_inited_size >= written_size) {
        LOG_DEBUG_INF("Skip to update file:%s fid:%llu, node size:%llu, written_size:%llu, min_inited_size:%llu with."
                      "offset :%lld, size:%lld",
            node->name, node->fid, node->size, node->written_size, node->min_inited_size, offset, size);
        wr_unlock_vg_mem_and_shm(session, vg_item);
        return CM_SUCCESS;
    }

    wr_ft_block_t *cur_block = wr_get_ft_by_node(node);

    bool32 has_updt_min_written_size = CM_FALSE;
    bool32 has_updt_written_size = CM_FALSE;

    // prevent changeed by other task
    wr_latch_x_node(session, node, NULL);
    if (WR_IS_FILE_INNER_INITED(node->flags) && (uint64)offset <= node->min_inited_size &&
        (written_size > node->min_inited_size)) {
        node->min_inited_size = written_size;
        has_updt_min_written_size = CM_TRUE;
    }

    if (node->written_size < written_size) {
        // when both truncate to 0 and update to written)size reach primary form diff node, may truncat process at first
        uint64 written_size_real = written_size > (uint64)node->size ? (uint64)node->size : written_size;
        node->written_size = node->written_size > written_size_real ? node->written_size : written_size_real;

        has_updt_written_size = CM_TRUE;
    }

    if (has_updt_min_written_size || has_updt_written_size) {
        status = wr_update_ft_block_disk(vg_item, cur_block, node->id);
        if (status != CM_SUCCESS) {
            wr_unlatch_node(node);
            wr_unlock_vg_mem_and_shm(session, vg_item);
            WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Fail to update written_size:%llu of file:%s, node size:%llu.",
                                          node->written_size, node->name, node->size));
        }
    }

    LOG_DEBUG_INF("End to update file:%s fid:%llu, node size:%llu, written_size:%llu, min_inited_size:%llu with."
                  "offset :%lld, size:%lld",
        node->name, node->fid, node->size, node->written_size, node->min_inited_size, offset, size);

    wr_unlatch_node(node);
    wr_unlock_vg_mem_and_shm(session, vg_item);

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

gft_node_t *wr_get_next_node(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node)
{
    if (wr_cmp_blockid(node->next, CM_INVALID_ID64)) {
        return NULL;
    }
    return wr_get_ft_node_by_ftid(session, vg_item, node->next, CM_TRUE, CM_FALSE);
}

bool32 wr_is_last_tree_node(gft_node_t *node)
{
    return (node->type != GFT_PATH || node->items.count == 0);
}

status_t wr_block_data_oper(char *op_desc, bool32 is_write, wr_vg_info_item_t *vg_item, wr_block_id_t block_id,
    uint64 offset, char *data_buf, int32_t size)
{
    status_t status;
    wr_volume_t volume = vg_item->volume_handle[block_id.volume];
    if (volume.handle == WR_INVALID_HANDLE) {
        status = wr_open_volume(
            vg_item->wr_ctrl->volume.defs[block_id.volume].name, NULL, WR_INSTANCE_OPEN_FLAG, &volume);
        WR_RETURN_IFERR2(
            status, LOG_DEBUG_ERR("open volume %s failed.", vg_item->wr_ctrl->volume.defs[block_id.volume].name));
        vg_item->volume_handle[block_id.volume] = volume;
    }

    int64 vol_offset = wr_get_au_offset(vg_item, block_id) + (uint32_t)offset;
    if (is_write) {
        status = wr_write_volume(&volume, vol_offset, data_buf, size);
    } else {
        status = wr_read_volume(&volume, vol_offset, data_buf, size);
    }
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR(
            "%s volume failed, volume:%s, vol_offset:%lld, buf_size:%d", op_desc, volume.name, vol_offset, size);
        return CM_ERROR;
    }
    WR_LOG_DEBUG_OP("%s data, volume:%s, vol_offset:%lld, auid:%llu, buf_size:%d", op_desc, volume.name, vol_offset,
        WR_ID_TO_U64(block_id), size);
    return CM_SUCCESS;
}

status_t wr_data_oper(char *op_desc, bool32 is_write, wr_vg_info_item_t *vg_item, auid_t auid, uint32_t au_offset,
    char *data_buf, int32_t size)
{
    uint32_t au_size = (uint32_t)wr_get_vg_au_size(vg_item->wr_ctrl);
    if (au_offset >= au_size || (au_offset + (uint32_t)size) > au_size || ((uint64)data_buf % WR_DISK_UNIT_SIZE) != 0) {
        LOG_RUN_ERR("%s data para error", op_desc);
        return CM_ERROR;
    }

    return wr_block_data_oper(op_desc, is_write, vg_item, auid, au_offset, data_buf, size);
}

status_t wr_write_zero2au(char *op_desc, wr_vg_info_item_t *vg_item, uint64 fid, auid_t auid, uint32_t au_offset)
{
    char *zero_buf = wr_get_zero_buf();
    uint32_t zero_buf_len = wr_get_zero_buf_len();
    LOG_DEBUG_INF("Try to write zero for fid:%llu to auid:%s au_offset:%u.", fid, wr_display_metaid(auid), au_offset);
    uint64 au_size = wr_get_vg_au_size(vg_item->wr_ctrl);
    do {
        int32_t write_size = (int32_t)((au_size - au_offset) < zero_buf_len ? (au_size - au_offset) : zero_buf_len);
        status_t ret = wr_data_oper(op_desc, CM_TRUE, vg_item, auid, au_offset, zero_buf, write_size);
        if (ret != CM_SUCCESS) {
            return ret;
        }
        au_offset += (uint32_t)write_size;
    } while (au_offset < au_size);
    return CM_SUCCESS;
}

status_t wr_try_write_zero_one_au(
    char *desc, wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, int64 offset)
{
    return CM_SUCCESS;
}

void wr_alarm_check_vg_usage(wr_session_t *session)
{
    return;
}