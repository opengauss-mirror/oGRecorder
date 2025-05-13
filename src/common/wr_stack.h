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
 * wr_stack.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_stack.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __WR_STACK_H_
#define __WR_STACK_H_

#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_MAX_STACK_DEPTH 32
typedef struct tagknl_stack {
    uint32_t depth;
    uint32_t buff_pos;
    uint32_t indicator[WR_MAX_STACK_DEPTH];
    uint32_t size;
    uint32_t reserve;
    char *buff;
} wr_stack;

char *wr_get_stack_pos(wr_stack *stack, uint32_t depth);
void wr_pop_ex(wr_stack *stack, uint32_t depth);

#ifdef __cplusplus
}
#endif

#endif
