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
 * wr_stack.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_stack.c
 *
 * -------------------------------------------------------------------------
 */
#include "wr_stack.h"
#include "cm_log.h"
#include "cm_debug.h"
#include "wr_defs.h"
#include "wr_log.h"

char *wr_get_stack_pos(wr_stack *stack, uint32_t depth)
{
    CM_ASSERT(stack != NULL);

    if (stack->depth < depth) {
        return NULL;
    }

    return (stack->buff + stack->indicator[depth]);
}

void wr_pop_ex(wr_stack *stack, uint32_t depth)
{
    CM_ASSERT(stack != NULL);

    if (depth >= WR_MAX_STACK_DEPTH) {
        LOG_DEBUG_ERR("pop vg_item stack depth is out of bound");
        return;
    }

    stack->depth = depth;
    stack->buff_pos = stack->indicator[depth];
}
