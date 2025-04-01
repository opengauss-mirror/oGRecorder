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
 * wr_volume.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_volume.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_VOLUME_H__
#define __WR_VOLUME_H__

#include "wr_defs.h"
#include "cm_date.h"
#include "wr_file_def.h"

#ifdef __cplusplus
extern "C" {
#endif
extern uint64 g_log_offset;
status_t wr_open_volume(const char *name, const char *code, int flags, wr_volume_t *volume);
void wr_close_volume(wr_volume_t *volume);
status_t wr_read_volume(wr_volume_t *volume, int64 offset, void *buf, int32 size);
status_t wr_write_volume(wr_volume_t *volume, int64 offset, const void *buf, int32 size);
uint64 wr_get_volume_size(wr_volume_t *volume);

status_t wr_open_simple_volume(const char *name, int flags, wr_simple_volume_t *volume);
void wr_close_simple_volume(wr_simple_volume_t *simple_volume);

#ifdef __cplusplus
}
#endif

#endif
