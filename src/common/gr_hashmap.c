/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
 * cm_hashmap.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_hashmap.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_error.h"
#include "cm_hash.h"
#include "cm_log.h"
#include "gr_errno.h"
#include "gr_malloc.h"
#include "gr_hashmap.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define HASH_MASK 0x3fffffff

#ifdef __cplusplus
}
#endif /* __cplusplus */
