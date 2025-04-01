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
 * wrcmd.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/wrcmd.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WRCMD_H__
#define __WRCMD_H__

#include "wr_defs.h"
#include "wr_interaction.h"

int32 execute_help_cmd(int argc, char **argv, uint32_t *idx, bool8 *go_ahead);

status_t execute_cmd(int argc, char **argv, uint32 idx);

void clean_cmd();

#endif