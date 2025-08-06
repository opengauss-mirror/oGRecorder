/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * gr_zero.h
 *
 *
 * IDENTIFICATION
 *    src/common/gr_zero.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_ZERO_H
#define __GR_ZERO_H

#include "gr_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t gr_init_zero_buf();
void gr_uninit_zero_buf();

#ifdef __cplusplus
}
#endif

#endif