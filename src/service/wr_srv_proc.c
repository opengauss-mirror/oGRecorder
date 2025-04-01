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
 * wr_srv_proc.c
 *
 *
 * IDENTIFICATION
 *    src/service/wr_srv_proc.c
 *
 * -------------------------------------------------------------------------
 */
#include "wr_errno.h"
#include "wr_redo.h"
#include "wr_open_file.h"
#include "wr_file.h"
#include "wr_mes.h"
#include "wr_srv_proc.h"
#include "wr_instance.h"
#include "wr_thv.h"
#include "wr_filesystem.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t wr_check_two_path_in_same_vg(const char *path1, const char *path2, char *vg_name)
{
    uint32 beg_pos1 = 0;
    uint32 beg_pos2 = 0;
    char vg_name1[WR_MAX_NAME_LEN] = {0};

    status_t ret = wr_get_name_from_path(path1, &beg_pos1, vg_name1);
    WR_RETURN_IFERR2(ret, LOG_DEBUG_ERR("Failed to get name from path %s,%d.", path1, ret));

    ret = wr_get_name_from_path(path2, &beg_pos2, vg_name);
    WR_RETURN_IFERR2(ret, LOG_DEBUG_ERR("Failed to get name from path %s,%d.", path2, ret));

    if ((beg_pos1 != beg_pos2) || (cm_strcmpni(vg_name1, vg_name, strlen(vg_name1)) != 0)) {
        WR_THROW_ERROR(ERR_WR_FILE_RENAME_DIFF_VG, vg_name1, vg_name);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t wr_rename_file_check(
    wr_session_t *session, const char *src, const char *dst, wr_vg_info_item_t **vg_item, gft_node_t **out_node)
{
    status_t status = wr_check_file(*vg_item);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to check file,errcode:%d.", cm_get_error_code()));

    wr_check_dir_output_t output_info = {out_node, NULL, NULL, CM_TRUE};
    wr_vg_info_item_t *file_vg_item = *vg_item;
    output_info.item = &file_vg_item;
    status = wr_check_dir(session, src, GFT_FILE, &output_info, CM_TRUE);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to check dir,errcode:%d.", cm_get_error_code()));

    gft_node_t *out_node_tmp = NULL;
    wr_check_dir_output_t output_info_tmp = {&out_node_tmp, NULL, NULL, CM_TRUE};
    if (wr_check_dir(session, dst, GFT_FILE, &output_info_tmp, CM_TRUE) != CM_SUCCESS) {
        int32 errcode = cm_get_error_code();
        if (errcode != ERR_WR_FILE_NOT_EXIST) {
            return CM_ERROR;
        }
        cm_reset_error();
    } else {
        WR_THROW_ERROR(ERR_WR_FILE_RENAME_EXIST, "cannot rename a existed file.");
        return CM_ERROR;
    }

    if (file_vg_item->id != (*vg_item)->id) {
        wr_unlock_vg_mem_and_shm(session, *vg_item);
        *vg_item = file_vg_item;
        wr_lock_vg_mem_and_shm_x(session, *vg_item);
    }
    return CM_SUCCESS;
}

status_t wr_rename_file_put_redo_log(wr_session_t *session, gft_node_t *out_node, const char *dst_name,
    wr_vg_info_item_t *vg_item, wr_config_t *inst_cfg)
{
    wr_redo_rename_t redo;
    redo.node = *out_node;
    errno_t err = snprintf_s(redo.name, WR_MAX_NAME_LEN, strlen(dst_name), "%s", dst_name);
    bool32 result = (bool32)(err != -1);
    WR_RETURN_IF_FALSE2(result, WR_THROW_ERROR(ERR_SYSTEM_CALL, err));

    err = snprintf_s(redo.old_name, WR_MAX_NAME_LEN, strlen(out_node->name), "%s", out_node->name);
    result = (bool32)(err != -1);
    WR_RETURN_IF_FALSE2(result, WR_THROW_ERROR(ERR_SYSTEM_CALL, err));

    err = snprintf_s(out_node->name, WR_MAX_NAME_LEN, strlen(dst_name), "%s", dst_name);
    result = (bool32)(err != -1);
    WR_RETURN_IF_FALSE2(result, WR_THROW_ERROR(ERR_SYSTEM_CALL, err));

    wr_put_log(session, vg_item, WR_RT_RENAME_FILE, &redo, sizeof(redo));

    if (wr_process_redo_log(session, vg_item) != CM_SUCCESS) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("[WR] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        wr_exit(1);
    }
    return CM_SUCCESS;
}

status_t wr_rename_file_check_path_and_name(
    wr_session_t *session, const char *src_path, const char *dst_path, char *vg_name, char *dst_name)
{
    CM_RETURN_IFERR(wr_check_two_path_in_same_vg(src_path, dst_path, vg_name));
    text_t dst_name_text;
    CM_RETURN_IFERR(wr_check_rename_path(session, src_path, dst_path, &dst_name_text));
    CM_RETURN_IFERR(cm_text2str(&dst_name_text, dst_name, WR_MAX_NAME_LEN));
    status_t status = wr_check_name(dst_name);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("The name %s is invalid.", dst_path));

    return CM_SUCCESS;
}

status_t wr_check_vg_ft_dir(wr_session_t *session, wr_vg_info_item_t **vg_item, const char *path,
    gft_item_type_t type, gft_node_t **node, gft_node_t **parent_node)
{
    CM_RETURN_IFERR(wr_check_file(*vg_item));

    wr_vg_info_item_t *tmp_vg_item = *vg_item;
    wr_check_dir_output_t output_info = {node, &tmp_vg_item, parent_node, CM_TRUE};
    status_t status = wr_check_dir(session, path, type, &output_info, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check dir, errcode: %d.", status);
        return status;
    }
    if (tmp_vg_item->id != (*vg_item)->id) {
        wr_unlock_vg_mem_and_shm(session, *vg_item);
        *vg_item = tmp_vg_item;
        wr_lock_vg_mem_and_shm_x(session, *vg_item);
    }
    return CM_SUCCESS;
}

static bool32 wr_has_children_nodes(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node)
{
    if (node->items.count == 0) {
        return CM_FALSE;
    }
    gft_node_t *sub_node = wr_get_ft_node_by_ftid(session, vg_item, node->items.first, CM_TRUE, CM_FALSE);
    while (sub_node != NULL) {
        if ((sub_node->flags & WR_FT_NODE_FLAG_DEL) == 0) {
            return CM_TRUE;
        }
        if (wr_cmp_auid(sub_node->next, WR_INVALID_ID64)) {
            break;
        }
        sub_node = wr_get_ft_node_by_ftid(session, vg_item, sub_node->next, CM_TRUE, CM_FALSE);
    }
    return CM_FALSE;
}

static inline status_t wr_mark_delete_flag_core(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node)
{
    wr_set_node_flag(session, vg_item, node, CM_TRUE, WR_FT_NODE_FLAG_DEL);
    LOG_DEBUG_INF("File : %s successfully marked for deletion", node->name);
    return CM_SUCCESS;
}

static status_t wr_mark_delete_flag_r(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node)
{
    if ((node->flags & WR_FT_NODE_FLAG_SYSTEM) != 0) {
        WR_THROW_ERROR(ERR_WR_FILE_REMOVE_SYSTEM, node->name);
        LOG_DEBUG_ERR("Failed to rm dir %s, can not rm system dir.", node->name);
        return CM_ERROR;
    }
    if (!wr_is_last_tree_node(node)) {
        gft_node_t *sub_node = wr_get_ft_node_by_ftid(session, vg_item, node->items.first, CM_TRUE, CM_FALSE);
        while (sub_node != NULL) {
            if ((sub_node->flags & WR_FT_NODE_FLAG_DEL) == 0) {
                CM_RETURN_IFERR(wr_mark_delete_flag_r(session, vg_item, sub_node));
            }
            sub_node = wr_get_next_node(session, vg_item, sub_node);
        }
    }
    if ((node->flags & WR_FT_NODE_FLAG_DEL) != 0) {
        LOG_DEBUG_INF("File: %s has been marked for deletion, nothing need to do.", node->name);
        return CM_SUCCESS;
    }
    return wr_mark_delete_flag_core(session, vg_item, node);
}

static status_t wr_mark_delete_flag(
    wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node, const char *dir_name, bool recursive)
{
    LOG_DEBUG_INF(
        "Mark delete flag for file or dir %s, fid:%llu, ftid: %s.", dir_name, node->fid, wr_display_metaid(node->id));
    if ((node->flags & WR_FT_NODE_FLAG_DEL) != 0) {
        LOG_DEBUG_INF("File: %s has been marked for deletion, nothing need to do.", node->name);
        return CM_SUCCESS;
    }
    bool32 has_sub_file = CM_FALSE;
    status_t status = CM_ERROR;
    if (node->type == GFT_PATH) {
        has_sub_file = wr_has_children_nodes(session, vg_item, node);
    }

    if (has_sub_file) {
        if (!recursive) {
            WR_THROW_ERROR_EX(ERR_WR_DIR_REMOVE_NOT_EMPTY, "Failed to rm dir %s, which has sub node.", dir_name);
            return CM_ERROR;
        }
        status = wr_mark_delete_flag_r(session, vg_item, node);
    } else {
        return wr_mark_delete_flag_core(session, vg_item, node);
    }
    return status;
}

static status_t wr_rm_dir_file_inner(wr_session_t *session, wr_vg_info_item_t **vg_item, gft_node_t **node,
    const char *dir_name, gft_item_type_t type, bool32 recursive)
{
    gft_node_t *parent_node = NULL;
    status_t status = wr_check_vg_ft_dir(session, vg_item, dir_name, type, node, &parent_node);
    WR_RETURN_IF_ERROR(status);
    if (((*node)->flags & WR_FT_NODE_FLAG_SYSTEM) != 0) {
        WR_THROW_ERROR(ERR_WR_FILE_REMOVE_SYSTEM, dir_name);
        LOG_DEBUG_ERR("Failed to rm dir %s, can not rm system dir.", dir_name);
        return CM_ERROR;
    }

    return wr_mark_delete_flag(session, *vg_item, *node, dir_name, recursive);
}

static status_t wr_rm_dir_file(wr_session_t *session, const char *dir_name, gft_item_type_t type, bool32 recursive)
{
    CM_ASSERT(dir_name != NULL);

    gft_node_t *node = NULL;
    char name[WR_MAX_NAME_LEN];
    wr_vg_info_item_t *vg_item = NULL;
    CM_RETURN_IFERR(wr_find_vg_by_dir(dir_name, name, &vg_item));

    wr_lock_vg_mem_and_shm_x(session, vg_item);
    wr_init_vg_cache_node_info(vg_item);
    status_t status = wr_rm_dir_file_inner(session, &vg_item, &node, dir_name, type, recursive);
    if (status != CM_SUCCESS) {
        wr_rollback_mem_update(session, vg_item);
        wr_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("Failed to remove dir or file, name : %s.", dir_name);
        return status;
    }

    if (wr_process_redo_log(session, vg_item) != CM_SUCCESS) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("[WR] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        wr_exit(1);
    }

    LOG_RUN_INF("Succeed to rm dir or file:%s in vg:%s.", dir_name, vg_item->vg_name);
    wr_unlock_vg_mem_and_shm(session, vg_item);
    return CM_SUCCESS;
}

static status_t wr_rm_dir_file_in_rename(
    wr_session_t *session, wr_vg_info_item_t **vg_item, const char *dir_name, gft_item_type_t type, bool32 recursive)
{
    CM_ASSERT(dir_name != NULL);
    gft_node_t *node = NULL;

    status_t status = wr_rm_dir_file_inner(session, vg_item, &node, dir_name, type, recursive);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to remove dir or file, name : %s.", dir_name);
        return status;
    }
    LOG_RUN_INF("Succeed to rm dir or file:%s in vg:%s in rename.", dir_name, (*vg_item)->vg_name);
    return CM_SUCCESS;
}

static status_t wr_rename_file_inner(wr_session_t *session, wr_vg_info_item_t **vg_item, wr_config_t *inst_cfg,
    const char *src, const char *dst, const char *dst_name)
{
    gft_node_t *out_node = NULL;
    status_t ret = wr_rename_file_check(session, src, dst, vg_item, &out_node);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    return wr_rename_file_put_redo_log(session, out_node, dst_name, *vg_item, inst_cfg);
}

status_t wr_rename_file(wr_session_t *session, const char *src, const char *dst)
{
    char vg_name[WR_MAX_NAME_LEN];
    char dst_name[WR_MAX_NAME_LEN];
    CM_RETURN_IFERR(wr_rename_file_check_path_and_name(session, src, dst, vg_name, dst_name));
    wr_vg_info_item_t *vg_item = wr_find_vg_item(vg_name);
    if (vg_item == NULL) {
        WR_THROW_ERROR(ERR_WR_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }
    if (cm_str_equal(src, dst)) {
        WR_THROW_ERROR(ERR_WR_FILE_RENAME, "src name is the same as dst.");
        return CM_ERROR;
    }
    wr_config_t *inst_cfg = wr_get_inst_cfg();
    wr_lock_vg_mem_and_shm_x(session, vg_item);
    status_t ret = wr_rename_file_inner(session, &vg_item, inst_cfg, src, dst, dst_name);
    if (ret == CM_SUCCESS) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
        return ret;
    }
    wr_init_vg_cache_node_info(vg_item);

    // error_handle: rollback memory
    wr_rollback_mem_update(session, vg_item);
    int32 err_code = cm_get_error_code();
    if (err_code != ERR_WR_FILE_RENAME_EXIST) {
        wr_unlock_vg_mem_and_shm(session, vg_item);
        return ret;
    }

    cm_reset_error();
    ret = wr_rm_dir_file_in_rename(session, &vg_item, dst, GFT_FILE, CM_FALSE);
    if (ret != CM_SUCCESS) {
        wr_rollback_mem_update(session, vg_item);
        wr_unlock_vg_mem_and_shm(session, vg_item);
        return ret;
    }
    wr_init_vg_cache_node_info(vg_item);

    ret = wr_rename_file_inner(session, &vg_item, inst_cfg, src, dst, dst_name);
    if (ret != CM_SUCCESS) {
        wr_rollback_mem_update(session, vg_item);
    }
    wr_init_vg_cache_node_info(vg_item);

    wr_unlock_vg_mem_and_shm(session, vg_item);
    return ret;
}

status_t wr_remove_dir(wr_session_t *session, const char *dir, bool32 recursive)
{
    return wr_rm_dir_file(session, dir, GFT_PATH, recursive);
}

status_t wr_remove_file(wr_session_t *session, const char *file)
{
    return wr_rm_dir_file(session, file, GFT_FILE, CM_FALSE);
}

status_t wr_make_dir(wr_session_t *session, const char *dir_name)
{
    char path[WR_FILE_PATH_MAX_LENGTH];
    snprintf(path, WR_FILE_PATH_MAX_LENGTH, "%s/%s", g_inst_cfg->data_dir, dir_name);
    return wr_filesystem_mkdir(path, 0777);
}

status_t wr_create_file(wr_session_t *session, const char *parent, const char *name, int32 flag)
{
    char path[WR_FILE_PATH_MAX_LENGTH];
    snprintf(path, WR_FILE_PATH_MAX_LENGTH, "%s/%s/%s", g_inst_cfg->data_dir, parent, name);
    return wr_filesystem_touch(path);
}

void wr_clean_open_files_in_vg(wr_session_t *session, wr_vg_info_item_t *vg_item, uint64 pid)
{
    wr_open_file_info_t *open_file = NULL;
    wr_latch_x2(&vg_item->open_file_latch, session->id);
    bilist_node_t *curr_node = cm_bilist_head(&vg_item->open_file_list);
    bilist_node_t *next_node = NULL;
    while (curr_node != NULL) {
        next_node = curr_node->next;
        open_file = BILIST_NODE_OF(wr_open_file_info_t, curr_node, link);
        if (open_file->pid == pid) {
            wr_free_open_file_node(curr_node, &vg_item->open_file_list);
        }
        curr_node = next_node;
    }
    wr_unlatch(&vg_item->open_file_latch);
}

#ifdef __cplusplus
}
#endif
