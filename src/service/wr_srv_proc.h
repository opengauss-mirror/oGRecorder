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
 * wr_srv_proc.h
 *
 *
 * IDENTIFICATION
 *    src/service/wr_srv_proc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __WR_SRV_PROC_H__
#define __WR_SRV_PROC_H__

#include <stdbool.h>
#include "wr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_REMOVE_DIR_NEED_NODE_NUM 2

status_t wr_rename_file(wr_session_t *session, const char *src, const char *dst);
// only rm empty dir
status_t wr_remove_dir(wr_session_t *session, const char *dir, bool32 recursive);
status_t wr_remove_file(wr_session_t *session, const char *file);
status_t wr_remove_link(wr_session_t *session, const char *file);
status_t wr_remove_dir_file_by_node(wr_session_t *session, wr_vg_info_item_t *vg_item, gft_node_t *node);
void wr_clean_open_files_in_vg(wr_session_t *session, wr_vg_info_item_t *vg_item, uint64 pid);
#ifdef __cplusplus
}
#endif

#endif
