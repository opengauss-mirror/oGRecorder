/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * wr_defs_print.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_defs_print.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_DEFS_PRINT_H__
#define __WR_DEFS_PRINT_H__

#include "wr_diskgroup.h"
#include "wr_alloc_unit.h"
#include "wr_meta_buf.h"
#include "wr_file.h"
#include "wr_session.h"
#include "wr_fs_aux.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_SECOND_PRINT_LEVEL 2
extern uint8 g_print_level;
void printf_auid(const auid_t *first);
void printf_wr_fs_block_list(wr_fs_block_list_t *free);
void printf_wr_fs_aux_root(wr_fs_aux_root_t *root);
void printf_wr_au_root(wr_au_root_t *au_root);
void printf_wr_fs_block_root(wr_fs_block_root_t *root);
void printf_wr_volume_attr(const wr_volume_attr_t *volume_attrs);
void wr_printf_core_ctrl_base(wr_core_ctrl_t *core_ctrl);
void printf_gft_root(gft_root_t *ft_root);
void printf_gft_node(gft_node_t *gft_node, const char *tab);
void printf_gft_list(gft_list_t *items);
#ifdef __cplusplus
}
#endif

#endif
