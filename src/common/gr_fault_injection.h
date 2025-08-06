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
 * gr_fault_injection.h
 * the ways to perform fault injection:
 * compile DEBUG, which registers all FI triggers at cfg para SS_FI_
 *
 * -------------------------------------------------------------------------
 */
#ifndef GR_FAULT_INJECTION_H
#define GR_FAULT_INJECTION_H

#include "ddes_fault_injection.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GR_FI_MAX_PROBABILTY (uint32_t)100

typedef enum en_gr_fi_point_name {
    GR_FI_ENTRY_BEGIN = 4000,
    GR_FI_MES_PROC_ENTER = GR_FI_ENTRY_BEGIN,
    GR_FI_ENTRY_END = 6000,
} gr_fi_point_name_e;

#ifdef __cplusplus
}
#endif

#endif  // GR_FAULT_INJECTION_H