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

status_t wr_check_vg_ft_dir(wr_session_t *session, wr_vg_info_item_t **vg_item, const char *path,
    gft_item_type_t type, gft_node_t **node, gft_node_t **parent_node)
{
    return CM_SUCCESS;
}

status_t wr_rename_file(wr_session_t *session, const char *src, const char *dst)
{
    return CM_SUCCESS;
}

status_t wr_make_dir(wr_session_t *session, const char *dir_name)
{
    return wr_filesystem_mkdir(dir_name, 0777);
}

status_t wr_create_file(wr_session_t *session, const char *parent, const char *name, int32_t flag)
{
    char path[WR_FILE_PATH_MAX_LENGTH];
    snprintf(path, WR_FILE_PATH_MAX_LENGTH, "%s/%s", parent, name);
    return wr_filesystem_touch(path);
}

#ifdef __cplusplus
}
#endif
