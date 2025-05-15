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
 * wr_fault_injection.h
 * the ways to perform fault injection:
 * compile DEBUG, which registers all FI triggers at cfg para SS_FI_
 *
 * -------------------------------------------------------------------------
 */
#ifndef WR_FAULT_INJECTION_H
#define WR_FAULT_INJECTION_H

#include "ddes_fault_injection.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_FI_MAX_PROBABILTY (uint32_t)100

typedef enum en_wr_fi_point_name {
    WR_FI_ENTRY_BEGIN = 4000,
    WR_FI_MES_PROC_ENTER = WR_FI_ENTRY_BEGIN,
    WR_FI_ENTRY_END = 6000,
} wr_fi_point_name_e;

#ifdef __cplusplus
}
#endif

#endif  // WR_FAULT_INJECTION_H