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

static status_t wr_check_name_is_valid(const char *name, uint32 path_max_size)
{
    if (strlen(name) >= path_max_size) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, name, ", name is too long"));
    }
    if (cm_str_equal(name, WR_DIR_PARENT) || cm_str_equal(name, WR_DIR_SELF)) {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, name, ", cannot be '..' or '.'");
        return CM_ERROR;
    }

    for (uint32 i = 0; i < strlen(name); i++) {
        status_t status = wr_is_valid_name_char(name[i]);
        WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, name, ", name should be [0~9,a~z,A~Z,-,_,.]"));
    }
    return CM_SUCCESS;
}

static status_t wr_check_path_is_valid(const char *path, uint32 path_max_size)
{
    if (strlen(path) >= path_max_size) {
        WR_THROW_ERROR(ERR_WR_FILE_PATH_ILL, path, ", path is too long\n");
        return CM_ERROR;
    }

    for (uint32 i = 0; i < strlen(path); i++) {
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

void wr_lock_vg_mem_s_and_shm_x(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    wr_lock_vg_mem_s(vg_item);
    wr_enter_shm_x(session, vg_item);
}

void wr_lock_vg_mem_and_shm_x(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    wr_lock_vg_mem_x(vg_item);
    wr_enter_shm_x(session, vg_item);
}

void wr_lock_vg_mem_and_shm_x2ix(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    wr_lock_shm_meta_x2ix(session, vg_item->vg_latch);
    wr_lock_vg_mem_x2ix(vg_item);
}

void wr_lock_vg_mem_and_shm_ix2x(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    wr_lock_vg_mem_ix2x(vg_item);
    wr_lock_shm_meta_ix2x(session, vg_item->vg_latch);
}

void wr_lock_vg_mem_and_shm_degrade(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    wr_lock_vg_mem_degrade(vg_item);
    wr_lock_shm_meta_degrade(session, vg_item->vg_latch);
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

void wr_lock_vg_mem_and_shm_ex_s(wr_session_t *session, char *vg_name)
{
    wr_vg_info_item_t *vg_item = wr_find_vg_item(vg_name);
    if (vg_item != NULL) {
        wr_lock_vg_mem_and_shm_s_force(session, vg_item);
    }
}

void wr_unlock_vg_mem_and_shm_ex(wr_session_t *session, char *vg_name)
{
    wr_vg_info_item_t *vg_item = wr_find_vg_item(vg_name);
    if (vg_item != NULL) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
    }
}

static status_t wr_exist_item_core(
    wr_session_t *session, const char *dir_path, bool32 *result, gft_item_type_t *output_type)
{
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

int64 wr_get_fs_block_offset(wr_vg_info_item_t *vg_item, wr_block_id_t blockid)
{
    return wr_get_block_offset(vg_item, WR_FILE_SPACE_BLOCK_SIZE, blockid.block, blockid.au);
}

void wr_init_fs_block_head(wr_fs_block_t *fs_block)
{
    CM_ASSERT(fs_block != NULL);
    wr_set_blockid(&fs_block->head.next, CM_INVALID_ID64);
    fs_block->head.used_num = 0;
    wr_set_blockid(&fs_block->bitmap[0], CM_INVALID_ID64);
}

status_t wr_alloc_fs_block_inter(wr_session_t *session, wr_vg_info_item_t *vg_item, bool32 check_version,
    char **block, wr_alloc_fs_block_info_t *info)
{
    return CM_SUCCESS;
}

status_t wr_alloc_fs_block(
    wr_session_t *session, wr_vg_info_item_t *vg_item, char **block, wr_alloc_fs_block_info_t *info)
{
    return CM_SUCCESS;
}

status_t wr_exist_item(wr_session_t *session, const char *item, bool32 *result, gft_item_type_t *output_type)
{
    CM_ASSERT(item != NULL);
    status_t status;
    *result = CM_FALSE;
    wr_vg_info_item_t *vg_item = NULL;
    char name[WR_MAX_NAME_LEN];
    CM_RETURN_IFERR(wr_find_vg_by_dir(item, name, &vg_item));
    wr_lock_vg_mem_and_shm_s(session, vg_item);

    status = CM_ERROR;
    do {
        WR_BREAK_IF_ERROR(wr_check_file(vg_item));
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

    wr_unlock_vg_mem_and_shm(session, vg_item);
    return status;
}

static void wr_get_dir_path(char *dir_path, uint32 buf_size, const char *full_path)
{
    char *p = NULL;
    size_t path_len = strlen(full_path);
    errno_t ret = strncpy_s(dir_path, buf_size, full_path, path_len);
    if (ret != EOK) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, (ret));
        return;
    }
    p = strrchr(dir_path, '/');
    if (p == NULL) {
        return;
    }
    *p = '\0';
}

static uint32_t wr_get_last_delimiter(const char *path, char delimiter)
{
    uint32_t len = (uint32_t)strlen(path);
    for (uint32_t i = len - 1; i > 0; i--) {
        if (path[i] == delimiter) {
            return i;
        }
    }
    return len;
}

static status_t wr_check_node_delete(gft_node_t *node)
{
    if ((node->flags & WR_FT_NODE_FLAG_DEL) == 0) {
        return CM_SUCCESS;
    }
    WR_THROW_ERROR(ERR_WR_FILE_NOT_EXIST, node->name, "wr");
    LOG_DEBUG_ERR("The file node:%s is deleted", node->name);
    return CM_ERROR;
}

gft_node_t *wr_get_gft_node_by_path(
    wr_session_t *session, wr_vg_info_item_t *vg_item, const char *path, wr_vg_info_item_t **dir_vg_item)
{
    gft_node_t *parent_node = NULL;
    gft_node_t *node = NULL;
    status_t status = CM_ERROR;
    char name[WR_MAX_NAME_LEN];
    char dir_path[WR_FILE_PATH_MAX_LENGTH];
    do {
        WR_BREAK_IF_ERROR(wr_check_file(vg_item));
        wr_get_dir_path(dir_path, WR_FILE_PATH_MAX_LENGTH, path);
        *dir_vg_item = vg_item;
        wr_check_dir_output_t output_info = {&parent_node, dir_vg_item, NULL, CM_FALSE};
        status = wr_check_dir(session, dir_path, GFT_PATH, &output_info, CM_TRUE);
        WR_BREAK_IF_ERROR(status);
        uint32_t pos = wr_get_last_delimiter(path, '/');
        status = wr_get_name_from_path(path, &pos, name);
        WR_BREAK_IF_ERROR(status);
        if (name[0] == 0) {
            LOG_DEBUG_INF("get root node ftid");
            return parent_node;
        }
        node = wr_find_ft_node(session, *dir_vg_item, parent_node, name, CM_TRUE);
        if (node == NULL) {
            status = CM_ERROR;
            WR_BREAK_IFERR3(
                status, WR_THROW_ERROR(ERR_WR_FILE_NOT_EXIST, name, path), LOG_DEBUG_ERR("path:%s not exist", path));
        }
        WR_BREAK_IF_ERROR(wr_check_node_delete(node));
        LOG_DEBUG_INF("Success to get ft_node:%s by path:%s", wr_display_metaid(node->id), path);
        status = CM_SUCCESS;
    } while (0);
    if (status == CM_SUCCESS) {
        return node;
    }
    return NULL;
}

status_t wr_get_ftid_by_path(wr_session_t *session, const char *path, ftid_t *ftid, wr_vg_info_item_t **dir_vg_item)
{
    CM_ASSERT(path != NULL);
    wr_vg_info_item_t *vg_item = NULL;
    char name[WR_MAX_NAME_LEN];
    CM_RETURN_IFERR(wr_find_vg_by_dir(path, name, &vg_item));
    wr_lock_vg_mem_and_shm_s(session, vg_item);
    status_t status = CM_ERROR;
    gft_node_t *node = wr_get_gft_node_by_path(session, vg_item, path, dir_vg_item);
    if (node != NULL) {
        *ftid = node->id;
        LOG_DEBUG_INF("Success to get ftid:%s by path:%s", wr_display_metaid(*ftid), path);
        status = CM_SUCCESS;
    }
    wr_unlock_vg_mem_and_shm(session, vg_item);
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

static status_t wr_open_file_find_block_and_insert_index(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *out_node)
{
    status_t status;
    if (wr_cmp_blockid(out_node->entry, CM_INVALID_ID64)) {
        LOG_RUN_ERR("Failed to open fs block,errcode:%d.", cm_get_error_code());
        WR_THROW_ERROR(ERR_WR_INVALID_ID, "node entry", WR_ID_TO_U64(out_node->entry));
        return ERR_WR_INVALID_ID;
    }
    // check the entry and load
    char *entry_block =
        wr_find_block_in_shm(session, vg_item, out_node->entry, WR_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
    if (entry_block == NULL) {
        WR_RETURN_IFERR2(
            CM_ERROR, LOG_DEBUG_ERR("Failed to find block:%s in cache", wr_display_metaid(out_node->entry)));
    }

    status = wr_insert_open_file_index(
        session, vg_item, WR_ID_TO_U64(out_node->id), session->cli_info.cli_pid, session->cli_info.start_time);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to insert open file index."));
    return CM_SUCCESS;
}

static status_t wr_open_file_core(
    wr_session_t *session, const char *path, uint32 type, gft_node_t **out_node, wr_find_node_t *find_info)
{
    CM_ASSERT(path != NULL);
    wr_vg_info_item_t *vg_item = NULL;
    errno_t errno;
    char name[WR_MAX_NAME_LEN];
    CM_RETURN_IFERR(wr_find_vg_by_dir(path, name, &vg_item));
    wr_lock_vg_mem_and_shm_s(session, vg_item);

    status_t status = wr_open_file_check_s(session, path, &vg_item, type, out_node);
    WR_RETURN_IFERR2(status, wr_unlock_vg_mem_and_shm(session, vg_item));
    if (*out_node == NULL) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
        cm_panic(0);
    }

    if (((*out_node)->flags & WR_FT_NODE_FLAG_DEL) && ((*out_node)->type == GFT_FILE)) {
        WR_RETURN_IFERR3(CM_ERROR, WR_THROW_ERROR(ERR_WR_FILE_NOT_EXIST, path, "wr"),
            wr_unlock_vg_mem_and_shm(session, vg_item));
    }

    status = wr_open_file_find_block_and_insert_index(session, vg_item, *out_node);
    WR_RETURN_IFERR3(status, wr_rollback_mem_update(session, vg_item), wr_unlock_vg_mem_and_shm(session, vg_item));

    find_info->ftid = (*out_node)->id;
    errno = strncpy_sp(find_info->vg_name, WR_MAX_NAME_LEN, vg_item->vg_name, WR_MAX_NAME_LEN - 1);
    bool32 result = (bool32)(errno == EOK);
    WR_RETURN_IF_FALSE3(
        result, wr_rollback_mem_update(session, vg_item), wr_unlock_vg_mem_and_shm(session, vg_item));
    status = wr_process_redo_log(session, vg_item);

    if (status != CM_SUCCESS) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("[WR] ABORT INFO : redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        wr_exit(1);
    }
    wr_unlock_vg_mem_and_shm(session, vg_item);
    return CM_SUCCESS;
}

status_t wr_open_file(wr_session_t *session, const char *file, int32_t flag, wr_find_node_t *find_info)
{
    WR_LOG_DEBUG_OP("Begin to open file:%s, session id:%u.", file, session->id);
    gft_node_t *out_node = NULL;
    CM_RETURN_IFERR(wr_open_file_core(session, file, GFT_FILE, &out_node, find_info));
    uint64 fid = out_node->fid;
    WR_LOG_DEBUG_OP("Succeed to open file:%s, fid:%llu, ftid:%s, session:%u.", file, fid,
        wr_display_metaid(out_node->id), session->id);
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

static void wr_init_ft_node(
    wr_ft_block_t *ft_block, gft_node_t *first_node, gft_root_t *gft, uint32_t block_id, auid_t auid)
{
    gft_node_t *node;
    for (uint32 i = 0; i < ft_block->node_num; i++) {
        node = &first_node[i];
        if (i != 0) {
            node->prev = auid;
            node->prev.block = block_id;
            node->prev.item = (uint16)i - 1;
        }
        node->id = auid;
        node->id.block = block_id;
        node->id.item = i;
        wr_set_auid(&node->parent, WR_BLOCK_ID_INIT);

        if (i == ft_block->node_num - 1) {
            gft->free_list.last = auid;
            gft->free_list.last.block = block_id;
            gft->free_list.last.item = i;
            wr_set_auid(&node->next, WR_INVALID_64);
        } else {
            node->next = auid;
            node->next.block = block_id;
            node->next.item = (uint16)i + 1;
        }
    }
}

status_t wr_init_ft_block(
    wr_session_t *session, wr_vg_info_item_t *vg_item, char *block, uint32_t block_id, auid_t auid)
{
    char *root = vg_item->wr_ctrl->root;
    gft_root_t *gft = &((wr_root_ft_block_t *)(root))->ft_root;

    wr_ft_block_t *ft_block = (wr_ft_block_t *)block;
    ft_block->node_num = (WR_BLOCK_SIZE - sizeof(wr_ft_block_t)) / sizeof(gft_node_t);
    ft_block->common.id = auid;
    ft_block->common.id.block = block_id;
    ft_block->common.type = WR_BLOCK_TYPE_FT;
    ft_block->common.flags = WR_BLOCK_FLAG_FREE;

    gft_node_t *first_node = (gft_node_t *)(block + sizeof(wr_ft_block_t));
    gft_node_t *node;
    gft_node_t *last_node = NULL;
    if (ft_block->node_num > 0) {
        node = &first_node[0];
        node->prev = gft->free_list.last;
        bool32 cmp = wr_cmp_auid(gft->free_list.last, WR_INVALID_64);
        if (!cmp) {
            last_node = wr_get_ft_node_by_ftid(session, vg_item, gft->free_list.last, CM_FALSE, CM_FALSE);
            if (last_node == NULL) {
                LOG_DEBUG_ERR(
                    "[FT][FORMAT] Failed to get file table node:%s.", wr_display_metaid(gft->free_list.last));
                return CM_ERROR;
            }

            last_node->next = auid;
            last_node->next.block = block_id;
            last_node->next.item = 0;
        }
    }
    wr_init_ft_node(ft_block, first_node, gft, block_id, auid);
    gft->free_list.count = gft->free_list.count + ft_block->node_num;
    if (wr_cmp_auid(gft->free_list.first, WR_INVALID_64)) {
        gft->free_list.first = auid;
        gft->free_list.first.block = block_id;
        gft->free_list.first.item = 0;
    }
    WR_LOG_DEBUG_OP("[FT][FORMAT] wr_init_ft_block blockid:%s.", wr_display_metaid(ft_block->common.id));
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
    wr_vg_info_item_t *vg_item, auid_t auid, ga_pool_id_e pool_id, uint32 first, uint32 count, uint32 size)
{
    CM_ASSERT(vg_item != NULL);
    status_t status;
    char *buf;
    CM_ASSERT(vg_item->volume_handle[auid.volume].handle != WR_INVALID_HANDLE);
    int64_t offset = wr_get_au_offset(vg_item, auid);
    int64_t block_offset = offset;
    uint32 obj_id = first;
    for (uint32 i = 0; i < count; i++) {
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

status_t wr_format_ft_node_core(
    wr_session_t *session, wr_vg_info_item_t *vg_item, ga_queue_t queue, auid_t auid, gft_root_t *gft)
{
    status_t status = CM_SUCCESS;
    uint32 rollback_count = 0;
    uint32 block_num = (uint32)WR_GET_FT_BLOCK_NUM_IN_AU(vg_item->wr_ctrl);
    uint32 obj_id = queue.first;
    ga_obj_id_t ga_obj_id = {.pool_id = GA_8K_POOL, .obj_id = 0};
    gft_list_t bk_list = gft->free_list;
    wr_ft_block_t *block = (wr_ft_block_t *)wr_get_ft_block_by_ftid(session, vg_item, gft->last);
    CM_ASSERT(block != NULL);
    block->next = auid;
    for (uint32 i = 0; i < block_num; i++) {
        block = (wr_ft_block_t *)wr_buffer_get_meta_addr(GA_8K_POOL, obj_id);
        errno_t err = memset_sp((char *)block, WR_BLOCK_SIZE, 0, WR_BLOCK_SIZE);
        cm_panic(err == EOK);
        block->common.id = auid;
        block->common.id.block = i;
        if (i != block_num - 1) {
            block->next = auid;
            block->next.block = i + 1;
        } else {
            wr_set_blockid(&block->next, CM_INVALID_ID64);
        }
        gft->last = block->common.id;

        ga_obj_id.obj_id = obj_id;
        do {
            status = wr_register_buffer_cache(
                session, vg_item, block->common.id, ga_obj_id, (char *)block, WR_BLOCK_TYPE_FT);
            if (status != CM_SUCCESS) {
                rollback_count = i;
                WR_BREAK_IFERR2(status,
                    LOG_DEBUG_ERR("[FT][FORMAT] Failed to register block:%s.", wr_display_metaid(block->common.id)));
            }

            status = wr_init_ft_block(session, vg_item, (char *)block, i, auid);
            if (status != CM_SUCCESS) {
                rollback_count = i + 1;
                WR_BREAK_IFERR2(status,
                    LOG_DEBUG_ERR("[FT][FORMAT] Failed to initialize block:%s.", wr_display_metaid(block->common.id)));
            }
        } while (0);
        if (status != CM_SUCCESS) {
            for (uint32 j = 0; j < rollback_count; ++j) {
                wr_block_id_t block_id = auid;
                block_id.block = j;
                wr_unregister_buffer_cache(session, vg_item, block_id);
            }
            ga_free_object_list(GA_8K_POOL, &queue);
            gft->free_list = bk_list;  // rollback free_list
            LOG_DEBUG_ERR("[FT][FORMAT] Rollback the format ft node when fail, i:%u.", i);
            return status;
        }

        obj_id = ga_next_object(GA_8K_POOL, obj_id);
    }
    return CM_SUCCESS;
}

status_t wr_format_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t auid)
{
    CM_ASSERT(vg_item != NULL);
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    char *root = wr_ctrl->root;
    wr_root_ft_block_t *ft_block = (wr_root_ft_block_t *)(root);
    gft_root_t *gft = &ft_block->ft_root;
    status_t status = CM_SUCCESS;

    gft_list_t bk_list = gft->free_list;
    uint32 block_num = (uint32)WR_GET_FT_BLOCK_NUM_IN_AU(wr_ctrl);
    ga_queue_t queue;
    status = ga_alloc_object_list(GA_8K_POOL, block_num, &queue);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[FT][FORMAT] Failed to alloc object list, block_num:%u.", block_num));

    wr_block_id_t old_last = gft->last;
    status = wr_format_ft_node_core(session, vg_item, queue, auid, gft);
    if (status != CM_SUCCESS) {
        return status;
    }

    wr_redo_format_ft_t redo;
    redo.auid = auid;
    redo.obj_id = queue.first;
    redo.count = block_num;
    redo.old_last_block = old_last;
    redo.old_free_list = bk_list;
    wr_put_log(session, vg_item, WR_RT_FORMAT_AU_FILE_TABLE, &redo, sizeof(wr_redo_format_ft_t));
    return CM_SUCCESS;
}

status_t wr_format_bitmap_node(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t auid)
{
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    status_t status;

    wr_fs_block_root_t *block_root = WR_GET_FS_BLOCK_ROOT(wr_ctrl);
    wr_fs_block_list_t bk_list = block_root->free;
    wr_fs_block_header *block;
    uint32 block_num = (uint32)WR_GET_FS_BLOCK_NUM_IN_AU(wr_ctrl);
    ga_queue_t queue;
    status = ga_alloc_object_list(GA_16K_POOL, block_num, &queue);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[FS][FORMAT] Failed to alloc object list, block num is %u.", block_num));
    uint32 obj_id = queue.first;
    ga_obj_id_t ga_obj_id;
    ga_obj_id.pool_id = GA_16K_POOL;
    for (uint32 i = 0; i < block_num; i++) {
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

static void format_ft_block_when_create_vg(
    wr_vg_info_item_t *vg_item, gft_list_t *plist, wr_ft_block_t *block, uint32 index, auid_t auid)
{
    uint32 blk_count = (uint32)WR_GET_FT_BLOCK_NUM_IN_AU(vg_item->wr_ctrl);
    uint32 item_count = (WR_BLOCK_SIZE - sizeof(wr_ft_block_t)) / sizeof(gft_node_t);
    gft_node_t *node = NULL;

    block->common.type = WR_BLOCK_TYPE_FT;
    block->common.flags = WR_BLOCK_FLAG_FREE;
    block->node_num = item_count;

    for (uint32 j = 0; j < item_count; j++) {
        node = (gft_node_t *)((char *)block + sizeof(wr_ft_block_t) + sizeof(gft_node_t) * j);
        node->id = auid;
        node->id.block = index;
        node->id.item = j;
        wr_set_auid(&node->parent, WR_BLOCK_ID_INIT);

        // set the prev ftid_t
        if (j == 0) {
            if (index == 0) {
                *(uint64 *)(&node->prev) = WR_INVALID_64;
            } else {
                // the prev ft block
                node->prev = auid;
                node->prev.block = index - 1;
                node->prev.item = item_count - 1;
            }
        } else {
            // the same ft block
            node->prev = auid;
            node->prev.block = index;
            node->prev.item = j - 1;
        }

        // set the next ftid_t
        if (j == item_count - 1) {
            if (index == blk_count - 1) {
                *(uint64 *)(&node->next) = WR_INVALID_64;
            } else {
                // the next ft block
                node->next = auid;
                node->next.block = index + 1;
                node->next.item = 0;
            }
        } else {
            // the same ft block
            node->next = auid;
            node->next.block = index;
            node->next.item = j + 1;
        }

        // add to gft node free list
        if (*(uint64 *)(&plist->first) == WR_INVALID_64) {
            plist->first = node->id;
        }
        plist->last = node->id;
        plist->count++;
    }
}

/*
 * NOTE: this function is used only in creating vg.
 * you can't use block memory cache and must flush block to disk manually.
 */
static status_t format_ft_au_when_create_vg(wr_vg_info_item_t *vg_item, auid_t auid)
{
    LOG_DEBUG_INF("[FT][FORMAT] Begin to format ft au when create vg.");
    status_t status;
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    uint64 au_size = wr_get_vg_au_size(wr_ctrl);
    char *au_buf = (char *)cm_malloc_align(WR_DISK_UNIT_SIZE, (uint32)au_size);
    if (au_buf == NULL) {
        WR_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("[FT][FORMAT] Failed to alloc %d memory", (int32)au_size));
    }
    int64 offset;
    wr_ft_block_t *block = NULL;
    errno_t err = memset_sp(au_buf, au_size, 0, au_size);
    if (err != EOK) {
        free(au_buf);
        LOG_DEBUG_ERR("[FT][FORMAT] Failed to memset:%d", err);
        return CM_ERROR;
    }

    uint32 blk_count = (uint32)WR_GET_FT_BLOCK_NUM_IN_AU(wr_ctrl);

    gft_list_t new_list;
    new_list.count = 0;
    *(uint64 *)&new_list.first = WR_INVALID_64;
    *(uint64 *)&new_list.last = WR_INVALID_64;

    for (uint32 i = 0; i < blk_count; i++) {
        block = (wr_ft_block_t *)(au_buf + (i * WR_BLOCK_SIZE));
        block->common.id = auid;
        block->common.id.block = i;

        // set ft block next
        if (i == blk_count - 1) {
            *(uint64 *)(&block->next) = WR_INVALID_64;
        } else {
            block->next = auid;
            block->next.block = i + 1;
        }
        format_ft_block_when_create_vg(vg_item, &new_list, block, i, auid);
        block->common.version++;
        block->common.checksum = wr_get_checksum(block, WR_BLOCK_SIZE);
    }

    wr_root_ft_block_t *root_ft = WR_GET_ROOT_BLOCK(wr_ctrl);
    gft_root_t *root_gft = &root_ft->ft_root;
    root_ft->ft_block.next = ((wr_ft_block_t *)au_buf)->common.id;                       // first block
    root_gft->last = ((wr_ft_block_t *)(au_buf + au_size - WR_BLOCK_SIZE))->common.id;  // last block

    // link the gft_node and free_list
    root_gft->free_list = new_list;
    // flush ft block to disk manually
    block = (wr_ft_block_t *)(au_buf);
    offset = wr_get_ft_block_offset(vg_item, block->common.id);
    status = wr_check_write_volume(vg_item, block->common.id.volume, offset, au_buf, (uint32)au_size);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("[FT][FORMAT] Failed to check write volume.");
        free(au_buf);
        return status;
    }
    status = wr_update_ft_root(vg_item);
    free(au_buf);
    return status;
}

status_t wr_alloc_ft_au(wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t *id)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(id != NULL);
    status_t status;

    status = wr_alloc_au(session, vg_item, id);
    WR_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("[FT][ALLOC] Failed allocate au for file table from vg:%s.", vg_item->vg_name));

    wr_au_root_t *au_root = WR_GET_AU_ROOT(vg_item->wr_ctrl);
    if (au_root->free_root == WR_INVALID_64) {
        /* when we are creating vg, .recycle directory hasn't been initialized yet! */
        status = format_ft_au_when_create_vg(vg_item, *(auid_t *)id);
    } else {
        CM_ASSERT(session != NULL);
        status = wr_format_ft_node(session, vg_item, *id);
    }

    WR_RETURN_IFERR2(status,
        LOG_DEBUG_ERR("[FT][ALLOC] Failed format ft au:%s from vg:%s.", wr_display_metaid(*id), vg_item->vg_name));
    LOG_DEBUG_INF("[FT][ALLOC] Succeed to allocate ft au:%s from vg:%s.", wr_display_metaid(*id), vg_item->vg_name);
    return status;
}

static void wr_init_alloc_ft_node(gft_root_t *gft, gft_node_t *node, uint32 flags, gft_node_t *parent_node)
{
    node->create_time = cm_current_time();
    node->update_time = node->create_time;
    (void)cm_atomic_set(&node->size, 0);
    node->written_size = 0;
    node->min_inited_size = 0;
    node->prev = parent_node->items.last;
    node->fid = gft->fid++;
    node->flags = flags;
#ifdef WR_DEFAULT_FILE_FLAG_INNER_INITED
    if (node->type == GFT_FILE) {
        node->flags |= WR_FT_NODE_FLAG_INNER_INITED;
    }
#endif
    node->parent = parent_node->id;
    wr_set_auid(&node->next, CM_INVALID_ID64);

    wr_block_ctrl_t *block_ctrl = wr_get_block_ctrl_by_node(node);
    if (node->type == GFT_FILE && block_ctrl != NULL) {
        wr_init_wr_fs_block_cache_info(&block_ctrl->fs_block_cache_info);
    }
}

void wr_set_ft_node(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node,
    gft_root_t *gft, gft_node_t *prev_node)
{
    wr_redo_alloc_ft_node_t redo_node;
    redo_node.node[WR_REDO_ALLOC_FT_NODE_SELF_INDEX] = *node;
    if (prev_node != NULL) {
        redo_node.node[WR_REDO_ALLOC_FT_NODE_PREV_INDEX] = *prev_node;
    } else {
        wr_set_auid(&redo_node.node[WR_REDO_ALLOC_FT_NODE_PREV_INDEX].id, WR_INVALID_64);
    }
    redo_node.node[WR_REDO_ALLOC_FT_NODE_PARENT_INDEX] = *parent_node;

    redo_node.ft_root = *gft;
    wr_put_log(session, vg_item, WR_RT_ALLOC_FILE_TABLE_NODE, &redo_node, sizeof(wr_redo_alloc_ft_node_t));
    char *prev_name;
    if (prev_node) {
        prev_name = prev_node->name;
    } else {
        prev_name = "NULL";
    }
    WR_LOG_DEBUG_OP("[FT] Alloc ft node, type:%u, name:%s, prev name:%s, %s, free count:%u.", node->type, node->name,
        prev_name, wr_display_metaid(node->id), gft->free_list.count);
}

void wr_ft_node_link_list(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *parent_node, ftid_t id,
    gft_node_t *node, gft_root_t *gft)
{
    gft_node_t *prev_node = NULL;
    bool32 cmp = wr_cmp_auid(parent_node->items.last, CM_INVALID_ID64);
    if (!cmp) {
        /*
         * when current thread modify prev_node's next pointer,
         * another thread may be modify prev_node's size by extend space
         * so here we need file lock to avoid concurrency scenario.
         */
        prev_node = wr_get_ft_node_by_ftid(session, vg_item, parent_node->items.last, CM_TRUE, CM_FALSE);
        if (prev_node != NULL) {
            prev_node->next = id;
        }
    }

    parent_node->items.count++;
    parent_node->items.last = id;
    cmp = wr_cmp_auid(parent_node->items.first, CM_INVALID_ID64);
    if (cmp) {
        parent_node->items.first = id;
    }

    wr_set_ft_node(session, vg_item, parent_node, node, gft, prev_node);
}

/*
 * NOTE: this function is called only in creating vg.
 * because there is no block buffer for use, you can't call wr_find_block_in_mem
 * or ga_alloc_object_list, redo log etc. You must flush buffer to disk manually.
 */
status_t wr_alloc_ft_node_when_create_vg(
    wr_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, gft_item_type_t type, uint32 flags)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(parent_node != NULL);
    CM_ASSERT(name != NULL);
    /* parent_node must be the root directory */
    CM_ASSERT(parent_node->id.au == 0 && parent_node->id.block == 0 && parent_node->id.item == 0);

    status_t status;
    ftid_t id;
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    char *root = wr_ctrl->root;
    wr_root_ft_block_t *ft_block = (wr_root_ft_block_t *)(root);
    gft_root_t *gft = &ft_block->ft_root;
    if (gft->free_list.count == 0) {
        status = wr_alloc_ft_au(NULL, vg_item, &id);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("[FT][ALLOC] Failed to allocate au when allocating file table node.");
            return status;
        }
        LOG_RUN_INF("[FT][ALLOC] Succeed to allocate au:%s when allocating file table node.", wr_display_metaid(id));
    }

    id = gft->free_list.first;
    char *buf = (char *)cm_malloc_align(WR_DISK_UNIT_SIZE, WR_BLOCK_SIZE);
    if (buf == NULL) {
        LOG_RUN_ERR("[FT][ALLOC] Failed to allocate buf.");
        return CM_ERROR;
    }

    /* read ft block from disk, because there's no cache in hands */
    wr_block_id_t block_id = id;
    block_id.item = 0;
    int64 offset = wr_get_block_offset(vg_item, WR_BLOCK_SIZE, block_id.block, block_id.au);
    if (wr_get_block_from_disk(vg_item, block_id, buf, offset, WR_BLOCK_SIZE, CM_TRUE) != CM_SUCCESS) {
        WR_FREE_POINT(buf);
        LOG_RUN_ERR("[FT][ALLOC] Failed to load ft block %s.", wr_display_metaid(block_id));
        return CM_ERROR;
    }
    gft_node_t *node = (gft_node_t *)(buf + sizeof(wr_ft_block_t) + sizeof(gft_node_t) * id.item);
    gft->free_list.first = node->next;
    bool32 cmp = wr_cmp_auid(gft->free_list.first, CM_INVALID_ID64);
    if (cmp) {
        gft->free_list.last = gft->free_list.first;
    }
    gft->free_list.count--;
    node->type = type;
    node->parent = parent_node->id;
    if (type == GFT_PATH) {
        node->items.count = 0;
        wr_set_auid(&node->items.first, CM_INVALID_ID64);
        wr_set_auid(&node->items.last, CM_INVALID_ID64);
    } else {
        /* file or link */
        wr_set_blockid(&node->entry, CM_INVALID_ID64);
    }
    if (strcpy_s(node->name, sizeof(node->name), name) != EOK) {
        cm_panic(0);
    }
    wr_init_alloc_ft_node(gft, node, flags, parent_node);
    parent_node->items.first = node->id;
    parent_node->items.last = node->id;
    parent_node->items.count = 1;
    ((wr_ft_block_t *)buf)->common.flags = WR_BLOCK_FLAG_USED;
    do {
        /* flush ft block to disk manually */
        status = wr_update_ft_block_disk(vg_item, (wr_ft_block_t *)buf, id);
        WR_BREAK_IF_ERROR(status);
        status = wr_update_ft_root(vg_item);  // parent_node must be root directory like `+data`
    } while (0);
    if (status == CM_SUCCESS) {
        LOG_RUN_INF("Succeed to create recycle file, node id is %s.", wr_display_metaid(node->id));
    }
    WR_FREE_POINT(buf);
    return status;
}

status_t wr_alloc_ft_au_when_no_free(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_root_t *gft, bool32 *check_version)
{
    if (gft->free_list.count == 0) {
        LOG_DEBUG_INF("[FT][ALLOC] There is no free au, begin to allocate au in vg:%s", vg_item->vg_name);
        ftid_t id;
        status_t status = wr_alloc_ft_au(session, vg_item, &id);
        WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("[FT][ALLOC] Failed to allocate au when allocating file table node."));
        *check_version = CM_FALSE;
        WR_LOG_DEBUG_OP(
            "[FT][ALLOC] Succeed to allocate au:%s when allocating file table node, ", wr_display_metaid(id));
    }
    return CM_SUCCESS;
}

static void wr_get_prev_and_next_node(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *parent_node,
    gft_node_t *node, gft_block_info_t *prev_info, gft_block_info_t *next_info)
{
    node->update_time = cm_current_time();
    if (*(uint64 *)(&parent_node->items.first) == *(uint64 *)(&node->id)) {
        parent_node->items.first = node->next;
        bool32 cmp = wr_cmp_blockid(parent_node->items.first, CM_INVALID_ID64);
        if (cmp) {
            CM_ASSERT(parent_node->items.count == 1);
            parent_node->items.last = parent_node->items.first;
        } else {
            next_info->ft_node = wr_get_ft_node_by_ftid(session, vg_item, parent_node->items.first, CM_TRUE, CM_FALSE);
            CM_ASSERT(next_info->ft_node != NULL);
            wr_set_blockid(&next_info->ft_node->prev, CM_INVALID_ID64);
        }
    } else if (*(uint64 *)(&parent_node->items.last) == *(uint64 *)(&node->id)) {
        parent_node->items.last = node->prev;
        prev_info->ft_node = wr_get_ft_node_by_ftid(session, vg_item, parent_node->items.last, CM_TRUE, CM_FALSE);
        CM_ASSERT(prev_info->ft_node != NULL);
        wr_set_blockid(&prev_info->ft_node->next, CM_INVALID_ID64);
    } else {
        prev_info->ft_node = wr_get_ft_node_by_ftid(session, vg_item, node->prev, CM_TRUE, CM_FALSE);
        CM_ASSERT(prev_info->ft_node != NULL);
        prev_info->ft_node->next = node->next;
        next_info->ft_node = wr_get_ft_node_by_ftid(session, vg_item, node->next, CM_TRUE, CM_FALSE);
        CM_ASSERT(next_info->ft_node != NULL);
        next_info->ft_node->prev = node->prev;
    }
    parent_node->items.count--;
}

void wr_free_ft_node_inner(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node, bool32 real_del)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(parent_node != NULL);
    CM_ASSERT(node != NULL);
    gft_block_info_t prev_info = {0};
    gft_block_info_t next_info = {0};
    node->update_time = cm_current_time();
    wr_get_prev_and_next_node(session, vg_item, parent_node, node, &prev_info, &next_info);

    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    char *root = wr_ctrl->root;
    wr_root_ft_block_t *ft_block = (wr_root_ft_block_t *)(root);
    gft_root_t *gft = &ft_block->ft_root;
    if (real_del) {
        wr_ft_block_t *block = wr_get_ft_by_node(node);
        block->common.flags = WR_BLOCK_FLAG_FREE;
        node->next = gft->free_list.first;
        wr_set_blockid(&node->parent, WR_BLOCK_ID_INIT);
        wr_set_blockid(&node->prev, WR_INVALID_64);
        wr_set_blockid(&node->entry, WR_INVALID_64);
        gft->free_list.first = node->id;
        gft->free_list.count++;
    }

    wr_redo_free_ft_node_t redo_node;
    redo_node.node[WR_REDO_FREE_FT_NODE_PARENT_INDEX] = *parent_node;
    if (prev_info.ft_node != NULL) {
        redo_node.node[WR_REDO_FREE_FT_NODE_PREV_INDEX] = *prev_info.ft_node;
        WR_LOG_DEBUG_OP("Free ft node, prev_node name:%s, prev_node id:%s.", prev_info.ft_node->name,
            wr_display_metaid(prev_info.ft_node->id));
    } else {
        wr_set_auid(&redo_node.node[WR_REDO_FREE_FT_NODE_PREV_INDEX].id, CM_INVALID_ID64);
    }
    if (next_info.ft_node != NULL) {
        redo_node.node[WR_REDO_FREE_FT_NODE_NEXT_INDEX] = *next_info.ft_node;
        WR_LOG_DEBUG_OP("Free ft node, next_node name:%s, next_node id:%s.", next_info.ft_node->name,
            wr_display_metaid(next_info.ft_node->id));
    } else {
        wr_set_auid(&redo_node.node[WR_REDO_FREE_FT_NODE_NEXT_INDEX].id, CM_INVALID_ID64);
    }
    redo_node.node[WR_REDO_FREE_FT_NODE_SELF_INDEX] = *node;
    redo_node.ft_root = *gft;
    wr_put_log(session, vg_item, WR_RT_FREE_FILE_TABLE_NODE, &redo_node, sizeof(wr_redo_free_ft_node_t));
    WR_LOG_DEBUG_OP("[FT][FREE] Free ft node, name:%s, %s, free count:%u, real delete:%u", node->name,
        wr_display_metaid(node->id), gft->free_list.count, real_del);
}

// remove ftn from parent
void wr_free_ft_node(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node, bool32 real_del)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(parent_node != NULL);
    CM_ASSERT(node != NULL);
    wr_free_ft_node_inner(session, vg_item, parent_node, node, real_del);
}

gft_node_t *wr_find_ft_node_core(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, bool32 skip_del)
{
    bool32 check_version = wr_is_server();
    ftid_t id = parent_node->items.first;

    for (uint32 i = 0; i < parent_node->items.count; i++) {
        if (wr_cmp_blockid(id, CM_INVALID_ID64)) {
            // may be find uncommitted node when standby
            LOG_DEBUG_ERR("Get invalid id in parent name:%s, %s, count:%u, when find node name:%s, index:%u.",
                parent_node->name, wr_display_metaid(parent_node->id), parent_node->items.count, name, i);
            return NULL;
        }
        gft_node_t *node = wr_get_ft_node_by_ftid(session, vg_item, id, check_version, CM_FALSE);
        if (node == NULL) {
            LOG_DEBUG_ERR(
                "Can not get node:%s, File name %s type:%u.", wr_display_metaid(id), name, parent_node->type);
            return NULL;
        }
        if (skip_del && (node->flags & WR_FT_NODE_FLAG_DEL)) {
            id = node->next;
            LOG_DEBUG_INF("Skip del the node, next node:%s", wr_display_metaid(id));
            continue;
        }
        if (strcmp(node->name, name) == 0) {
            return node;
        }

        id = node->next;
    }
    return NULL;
}

gft_node_t *wr_find_ft_node(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, bool8 skip_del)
{
    CM_ASSERT(name != NULL);
    ftid_t id;
    if (parent_node == NULL) {
        memset_s(&id, sizeof(id), 0, sizeof(id));
        return wr_get_ft_node_by_ftid(session, vg_item, id, wr_is_server(), CM_FALSE);
    }

    if (parent_node->type != GFT_PATH) {
        LOG_DEBUG_ERR("File name %s, its parent's type:%u is invalid.", name, parent_node->type);
        return NULL;
    }

    if (parent_node->items.count == 0) {
        LOG_DEBUG_INF("File name %s, its parent's sub item count:%u.", name, parent_node->items.count);
        return NULL;
    }
    timeval_t begin_tv;
    wr_begin_stat(&begin_tv);
    gft_node_t *node = wr_find_ft_node_core(session, vg_item, parent_node, name, skip_del);
    wr_session_end_stat(session, &begin_tv, WR_FIND_FT_ON_SERVER);
    if (node != NULL) {
        return node;
    }

    LOG_DEBUG_INF("File name %s, its parent's sub item count:%u.", name, parent_node->items.count);
    return NULL;
}

status_t wr_refresh_root_ft_inner(wr_vg_info_item_t *vg_item)
{
    bool32 remote = CM_TRUE;
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    char *root = wr_ctrl->root;
    status_t status = wr_load_vg_ctrl_part(vg_item, (int64)WR_CTRL_ROOT_OFFSET, root, (int32)WR_BLOCK_SIZE, &remote);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to get the whole root."));
    if (remote == CM_FALSE) {
        uint32 checksum = wr_get_checksum(root, WR_BLOCK_SIZE);
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
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    if (is_ft_root_block(id)) {
        char *root = wr_ctrl->root;
        wr_root_ft_block_t *ft_block = (wr_root_ft_block_t *)(root);
        if (wr_refresh_root_ft(vg_item, check_version, active_refresh) != CM_SUCCESS) {
            return NULL;
        }

        if (id.item < ft_block->ft_block.node_num) {
            return (gft_node_t *)((root + sizeof(wr_root_ft_block_t)) + id.item * sizeof(gft_node_t));
        }
    } else {
        wr_block_id_t block_id = id;
        block_id.item = 0;
        wr_ft_block_t *ft_block = (wr_ft_block_t *)wr_find_block_in_shm(
            session, vg_item, block_id, WR_BLOCK_TYPE_FT, check_version, NULL, active_refresh);
        if (ft_block == NULL) {
            LOG_DEBUG_ERR("Failed to find block:%s in mem.", wr_display_metaid(block_id));
            return NULL;
        }

        if (ft_block->node_num <= id.item) {
            LOG_DEBUG_ERR("The block is wrong, node_num:%u, item:%u.", ft_block->node_num, (uint32)id.item);
            return NULL;
        }

        gft_node_t *node = (gft_node_t *)(((char *)ft_block + sizeof(wr_ft_block_t)) + id.item * sizeof(gft_node_t));
        if (!wr_is_server() || wr_is_ft_block_valid(node, ft_block)) {
            return node;
        }

        LOG_DEBUG_INF("block:%llu fid:%llu, file ver:%llu is not same as node:%llu, fid:%llu, file ver:%llu",
            WR_ID_TO_U64(block_id), wr_get_ft_block_fid(ft_block), wr_get_ft_block_file_ver(ft_block),
            WR_ID_TO_U64(node->id), node->fid, node->file_ver);
        wr_set_ft_block_file_ver(node, ft_block);
        LOG_DEBUG_INF("block:%llu fid:%llu, file ver:%llu setted with node:%llu, fid:%llu, file ver:%llu",
            WR_ID_TO_U64(block_id), wr_get_ft_block_fid(ft_block), wr_get_ft_block_file_ver(ft_block),
            WR_ID_TO_U64(node->id), node->fid, node->file_ver);
        return node;
    }
    return NULL;
}

gft_node_t *wr_get_ft_node_by_ftid_no_refresh(wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t id)
{
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    if (is_ft_root_block(id)) {
        char *root = wr_ctrl->root;
        wr_root_ft_block_t *ft_block = (wr_root_ft_block_t *)(root);
        if (id.item < ft_block->ft_block.node_num) {
            return (gft_node_t *)((root + sizeof(wr_root_ft_block_t)) + id.item * sizeof(gft_node_t));
        }
    } else {
        wr_block_id_t block_id = id;
        block_id.item = 0;
        wr_ft_block_t *block = (wr_ft_block_t *)wr_find_block_in_shm_no_refresh(session, vg_item, block_id, NULL);
        if (block == NULL) {
            LOG_DEBUG_ERR("Failed to find block:%s in mem.", wr_display_metaid(block_id));
            return NULL;
        }

        if (block->node_num <= id.item) {
            LOG_DEBUG_ERR("The block is wrong, node_num:%u, item:%u.", block->node_num, (uint32)id.item);
            return NULL;
        }

        return (gft_node_t *)(((char *)block + sizeof(wr_ft_block_t)) + id.item * sizeof(gft_node_t));
    }
    return NULL;
}

gft_node_t *wr_get_ft_node_by_ftid_from_disk_and_refresh_shm(
    wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t id)
{
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    if (is_ft_root_block(id)) {
        char *root = wr_ctrl->root;
        wr_root_ft_block_t *ft_block = (wr_root_ft_block_t *)(root);
        if (wr_refresh_root_ft_inner(vg_item) != CM_SUCCESS) {
            return NULL;
        }
        if (id.item < ft_block->ft_block.node_num) {
            return (gft_node_t *)((root + sizeof(wr_root_ft_block_t)) + id.item * sizeof(gft_node_t));
        }
    } else {
        wr_block_id_t block_id = id;
        block_id.item = 0;
        wr_ft_block_t *ft_block = (wr_ft_block_t *)wr_find_block_from_disk_and_refresh_shm(
            session, vg_item, block_id, WR_BLOCK_TYPE_FT, NULL);
        if (ft_block == NULL) {
            LOG_DEBUG_ERR("Failed to find block:%s from disk and refresh shm.", wr_display_metaid(block_id));
            return NULL;
        }
        if (ft_block->node_num <= id.item) {
            LOG_DEBUG_ERR("Wrong block, node_num:%u, item:%u.", ft_block->node_num, (uint32)id.item);
            return NULL;
        }
        gft_node_t *node = (gft_node_t *)(((char *)ft_block + sizeof(wr_ft_block_t)) + id.item * sizeof(gft_node_t));
        if (!wr_is_server() || wr_is_ft_block_valid(node, ft_block)) {
            return node;
        }
        LOG_DEBUG_INF("block:%llu, fid:%llu, file ver:%llu is not same as node:%llu, fid:%llu, file ver:%llu",
            WR_ID_TO_U64(block_id), wr_get_ft_block_fid(ft_block), wr_get_ft_block_file_ver(ft_block),
            WR_ID_TO_U64(node->id), node->fid, node->file_ver);
        wr_set_ft_block_file_ver(node, ft_block);
        LOG_DEBUG_INF("block:%llu, fid:%llu, file ver:%llu setted with node:%llu, fid:%llu, file ver:%llu",
            WR_ID_TO_U64(block_id), wr_get_ft_block_fid(ft_block), wr_get_ft_block_file_ver(ft_block),
            WR_ID_TO_U64(node->id), node->fid, node->file_ver);
        return node;
    }
    return NULL;
}

char *wr_get_ft_block_by_ftid(wr_session_t *session, wr_vg_info_item_t *vg_item, ftid_t id)
{
    wr_ctrl_t *wr_ctrl = vg_item->wr_ctrl;
    if (is_ft_root_block(id)) {
        char *root = wr_ctrl->root;
        // NOTE:when recover just return root, must not be load from disk.Because format ft node is logic recovery,
        // its gft info only use redo log info.
        if (vg_item->status == WR_VG_STATUS_RECOVERY) {
            return root;
        }

        if (wr_refresh_root_ft(vg_item, CM_TRUE, CM_FALSE) != CM_SUCCESS) {
            return NULL;
        }
        return root;
    }
    return wr_find_block_in_shm(session, vg_item, id, WR_BLOCK_TYPE_FT, CM_TRUE, NULL, CM_FALSE);
}

static void wr_init_ft_root_core(char *root, wr_root_ft_block_t *ft_block, gft_root_t *gft)
{
    wr_set_blockid(&ft_block->ft_block.next, WR_INVALID_64);
    wr_set_blockid(&gft->first, 0);
    wr_set_blockid(&gft->last, 0);

    gft->items.count = 0;
    *(uint64_t *)(&gft->items.first) = WR_INVALID_64;
    *(uint64_t *)(&gft->items.last) = WR_INVALID_64;
    gft->free_list.count = 0;
    *(uint64 *)(&gft->free_list.first) = WR_INVALID_64;
    *(uint64 *)(&gft->free_list.last) = WR_INVALID_64;
    // item_count is always 1
    uint32 item_count = (WR_BLOCK_SIZE - sizeof(wr_root_ft_block_t)) / sizeof(gft_node_t);
    ft_block->ft_block.node_num = item_count;
    gft_node_t *first_free_node = (gft_node_t *)(root + sizeof(wr_root_ft_block_t));
    gft_node_t *node = NULL;

    // the first gft_node_t is used for vg name (like: `/`)
    for (uint32 i = 1; i < item_count; i++) {
        node = first_free_node + i;
        wr_set_auid(&node->id, 0);
        node->id.block = 0;
        node->id.item = i;

        if (i == 1) {
            *(uint64_t *)(&node->prev) = WR_INVALID_64;
            gft->free_list.first = node->id;
        } else {
            *(uint64_t *)(&node->prev) = 0;
            node->prev.block = 0;
            node->prev.item = (uint16)i - 1;
        }

        if (i == item_count - 1) {
            *(uint64_t *)(&node->next) = WR_INVALID_64;
            gft->free_list.last = node->id;
        } else {
            *(uint64_t *)(&node->next) = 0;
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

status_t wr_check_refresh_fs_block(
    wr_vg_info_item_t *vg_item, wr_block_id_t blockid, char *block, bool32 *is_changed)
{
    if (!WR_STANDBY_CLUSTER && wr_is_readwrite()) {
        WR_ASSERT_LOG(wr_need_exec_local(), "only masterid %u can be readwrite.", wr_get_master_id());
        return CM_SUCCESS;
    }
    status_t status = wr_check_refresh_core(vg_item);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to check and refresh core, %s.", vg_item->entry_path));

    return wr_check_block_version(vg_item, blockid, WR_BLOCK_TYPE_FS, block, is_changed, CM_FALSE);
}

// refresh file table
status_t wr_refresh_ft(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    if (!WR_STANDBY_CLUSTER && wr_is_readwrite()) {
        WR_ASSERT_LOG(wr_need_exec_local(), "only masterid %u can be readwrite.", wr_get_master_id());
        return CM_SUCCESS;
    }
    bool32 remote = CM_FALSE;
    status_t status = wr_load_vg_ctrl_part(
        vg_item, (int64)WR_CTRL_ROOT_OFFSET, vg_item->wr_ctrl->root, (int32)WR_BLOCK_SIZE, &remote);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to load vg core part %s.", vg_item->entry_path));

    uint64 count = 0;
    char *root = vg_item->wr_ctrl->root;
    wr_root_ft_block_t *ft_block = (wr_root_ft_block_t *)(root);
    wr_block_id_t block_id = ft_block->ft_block.next;
    bool32 cmp = wr_cmp_blockid(block_id, CM_INVALID_ID64);
    while (!cmp) {
        ft_block = (wr_root_ft_block_t *)wr_get_ft_block_by_ftid(session, vg_item, block_id);
        if (ft_block) {
            block_id = ft_block->ft_block.next;
            cmp = wr_cmp_blockid(block_id, CM_INVALID_ID64);
        } else {
            WR_RETURN_IFERR2(
                CM_ERROR, LOG_DEBUG_ERR("Failed to get file table block when refresh ft %s.", vg_item->entry_path));
        }
        count++;
    }
    WR_LOG_DEBUG_OP("Succeed to refresh ft %s, count:%llu.", vg_item->entry_path, count);
    return CM_SUCCESS;
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
            vg_item, (int64)WR_CTRL_ROOT_OFFSET, vg_item->wr_ctrl->root, (int32)WR_BLOCK_SIZE, &remote);
        WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to load vg core part %s.", vg_item->entry_path));
    }
    WR_LOG_DEBUG_OP(
        "wr_check_refresh_ft version:%llu, disk version:%llu.", ft_block_m->ft_block.common.version, disk_version);
    return CM_SUCCESS;
}

status_t wr_update_ft_block_disk(wr_vg_info_item_t *vg_item, wr_ft_block_t *block, ftid_t id)
{
    uint32 volume_id = (uint32)id.volume;
    int64 offset = wr_get_ft_block_offset(vg_item, id);

    block->common.version++;
    block->common.checksum = wr_get_checksum(block, WR_BLOCK_SIZE);
    CM_ASSERT(vg_item->volume_handle[volume_id].handle != WR_INVALID_HANDLE);
    return wr_check_write_volume(vg_item, volume_id, offset, block, WR_BLOCK_SIZE);
}

int64 wr_get_ft_block_offset(wr_vg_info_item_t *vg_item, ftid_t id)
{
    if ((id.au) == 0) {
        return (int64)WR_CTRL_ROOT_OFFSET;
    }
    return wr_get_block_offset(vg_item, WR_BLOCK_SIZE, id.block, id.au);
}

status_t wr_update_fs_bitmap_block_disk(
    wr_vg_info_item_t *item, wr_fs_block_t *block, uint32 size, bool32 had_checksum)
{
    CM_ASSERT(item != NULL);
    CM_ASSERT(block != NULL);
    uint32 volume_id = (uint32)block->head.common.id.volume;
    int64 offset = wr_get_fs_block_offset(item, block->head.common.id);

    if (!had_checksum) {
        block->head.common.version++;
        block->head.common.checksum = wr_get_checksum(block, WR_FILE_SPACE_BLOCK_SIZE);
    }

    WR_LOG_DEBUG_OP("[FS] update_fs_bitmap_block_disk checksum:%u, fsid:%s, version:%llu, size:%u.",
        block->head.common.checksum, wr_display_metaid(block->head.common.id), block->head.common.version, size);

    CM_ASSERT(item->volume_handle[volume_id].handle != WR_INVALID_HANDLE);
    status_t status = wr_check_write_volume(item, volume_id, offset, block, size);
    if (status != CM_SUCCESS) {
        return status;
    }
    return CM_SUCCESS;
}

static status_t wr_get_block_entry(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_config_t *inst_cfg,
    uint64 fid, ftid_t ftid, gft_node_t **node_out, wr_fs_block_t **entry_out)
{
    return CM_SUCCESS;
}

status_t wr_get_fs_block_info_by_offset(
    int64 offset, uint64 au_size, uint32 *block_count, uint32 *block_au_count, uint32 *au_offset)
{
    WR_ASSERT_LOG(au_size != 0, "The au size cannot be zero.");

    // two level bitmap, ~2k block ids per entry FSB
    uint64 au_count = WR_FILE_SPACE_BLOCK_BITMAP_COUNT;  // 2043 2nd FSBs
    uint64 block_len = au_count * au_size;                // [4G, 128G] per 2nd-level FSB, with AU range [2MB, 64MB]
    int64 temp = (offset / (int64)block_len);
    if (temp > (int64)au_count) {  // Total [8T, 256T] per file, to be verified
        LOG_DEBUG_ERR(
            "Invalid offset, offset:%lld, real block count:%lld, max block count:%llu.", offset, temp, au_count);
        return CM_ERROR;
    }
    *block_count = (uint32)(temp);                              // index of secondary FSB(id) in entry FSB's bitmap
    int64 block_offset = offset % (int64)block_len;             // offset within FSB
    *block_au_count = (uint32)(block_offset / (int64)au_size);  // index of AU within FSB
    if (au_offset != NULL) {
        *au_offset = (uint32)(block_offset % (int64)au_size);  // offset within AU
    }

    return CM_SUCCESS;
}
status_t wr_alloc_fs_aux_batch_prepare(wr_session_t *session, wr_vg_info_item_t *vg_item, uint32 batch_count)
{
    return CM_SUCCESS;
}

status_t wr_extend_fs_aux_batch_inner(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t batch_first,
    gft_node_t *node, uint32 block_au_count, uint32 batch_count, wr_fs_block_t *second_block,
    uint64 old_aux_root_free_count)
{
    return CM_SUCCESS;
}

status_t wr_extend_fs_aux_batch(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t batch_first,
    gft_node_t *node, uint32 block_au_count, uint32 batch_count, wr_fs_block_t *second_block)
{
    return CM_SUCCESS;
}

status_t wr_extend_fs_aux(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node,
    wr_block_id_t second_fs_block_id, wr_alloc_fs_block_info_t *info, auid_t *data_auid)
{
    return CM_SUCCESS;
}

status_t wr_extend_fs_batch(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t batch_first,
    uint32 block_au_count, uint32 batch_count, wr_fs_block_t *second_block)
{
    return CM_SUCCESS;
}

status_t wr_extend_batch_inner(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, uint64 align_beg,
    uint64 align_end, bool32 *finish)
{
    return CM_SUCCESS;
}

status_t wr_extend_batch(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, wr_node_data_t *node_data, bool32 *finish)
{
    return CM_SUCCESS;
}

status_t wr_extend_inner(wr_session_t *session, wr_node_data_t *node_data)
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
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, bool32 is_set, uint32 flags)
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
    wr_vg_info_item_t *vg_item, char *meta_info, uint32 meta_info_size, bool32 *cmd_ack)
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
        wr_exit(1);
    }

    /* Truncating file space block completed. */
    if (wr_process_redo_log(session, vg_item) != CM_SUCCESS) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("[WR] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        wr_exit(1);
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

void wr_init_root_fs_block(wr_ctrl_t *wr_ctrl)
{
    CM_ASSERT(wr_ctrl != NULL);
    wr_fs_block_root_t *block_root = WR_GET_FS_BLOCK_ROOT(wr_ctrl);
    block_root->version = 0;
    block_root->free.count = 0;
    wr_set_auid(&block_root->free.first, CM_INVALID_ID64);
    wr_set_auid(&block_root->free.last, CM_INVALID_ID64);
}

status_t wr_refresh_volume(wr_session_t *session, const char *name_str, uint32 vgid, uint32 volumeid)
{
    return CM_SUCCESS;
}

status_t wr_refresh_vginfo(wr_vg_info_item_t *vg_item)
{
    return CM_SUCCESS;
}

status_t wr_load_fs_block_by_blockid(
    wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t blockid, int32 size)
{
    char *block = wr_find_block_in_shm(session, vg_item, blockid, WR_BLOCK_TYPE_FS, CM_FALSE, NULL, CM_FALSE);
    CM_ASSERT(block != NULL);
    int64 offset = wr_get_fs_block_offset(vg_item, blockid);
    status_t status = wr_get_block_from_disk(vg_item, blockid, block, offset, size, CM_TRUE);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to get block %s.", vg_item->entry_path));

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

status_t wr_refresh_ft_block(wr_session_t *session, char *vg_name, uint32 vgid, wr_block_id_t blockid)
{
    return CM_SUCCESS;
}

status_t wr_update_file_written_size(
    wr_session_t *session, uint32 vg_id, int64 offset, int64 size, wr_block_id_t ftid, uint64 fid)
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
    uint32 sid = 0;
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
    uint64 offset, char *data_buf, int32 size)
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

    int64 vol_offset = wr_get_au_offset(vg_item, block_id) + (uint32)offset;
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

status_t wr_data_oper(char *op_desc, bool32 is_write, wr_vg_info_item_t *vg_item, auid_t auid, uint32 au_offset,
    char *data_buf, int32 size)
{
    uint32 au_size = (uint32)wr_get_vg_au_size(vg_item->wr_ctrl);
    if (au_offset >= au_size || (au_offset + (uint32)size) > au_size || ((uint64)data_buf % WR_DISK_UNIT_SIZE) != 0) {
        LOG_RUN_ERR("%s data para error", op_desc);
        return CM_ERROR;
    }

    return wr_block_data_oper(op_desc, is_write, vg_item, auid, au_offset, data_buf, size);
}

status_t wr_write_zero2au(char *op_desc, wr_vg_info_item_t *vg_item, uint64 fid, auid_t auid, uint32 au_offset)
{
    char *zero_buf = wr_get_zero_buf();
    uint32 zero_buf_len = wr_get_zero_buf_len();
    LOG_DEBUG_INF("Try to write zero for fid:%llu to auid:%s au_offset:%u.", fid, wr_display_metaid(auid), au_offset);
    uint64 au_size = wr_get_vg_au_size(vg_item->wr_ctrl);
    do {
        int32 write_size = (int32)((au_size - au_offset) < zero_buf_len ? (au_size - au_offset) : zero_buf_len);
        status_t ret = wr_data_oper(op_desc, CM_TRUE, vg_item, auid, au_offset, zero_buf, write_size);
        if (ret != CM_SUCCESS) {
            return ret;
        }
        au_offset += (uint32)write_size;
    } while (au_offset < au_size);
    return CM_SUCCESS;
}

status_t wr_try_write_zero_one_au(
    char *desc, wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, int64 offset)
{
    return CM_SUCCESS;
}

status_t wr_calculate_vg_usage(wr_session_t *session, wr_vg_info_item_t *vg_item, uint32 *usage)
{
    return CM_SUCCESS;
}

void wr_alarm_check_vg_usage(wr_session_t *session)
{
    return;
}