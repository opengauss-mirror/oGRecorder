/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * gr_au.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/gr_au.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_au.h"

auid_t gr_invalid_auid = {.volume = 0x3ff, .au = 0x3ffffffff, .block = 0x1ffff, .item = 0x7};
auid_t gr_set_inited_mask = {.volume = 0, .au = 0, .block = 0, .item = 0x1};
auid_t gr_unset_inited_mask = {.volume = 0x3ff, .au = 0x3ffffffff, .block = 0x1ffff, .item = 0};

#define GR_DISPLAY_SIZE 75

#ifdef WIN32
__declspec(thread) char g_display_buf[GR_DISPLAY_SIZE];
#else
__thread char g_display_buf[GR_DISPLAY_SIZE];
#endif

