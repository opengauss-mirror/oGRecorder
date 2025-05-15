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
 * wr_interaction.h
 *
 *
 * IDENTIFICATION
 *    src/common_api/wr_interaction.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_INTERACTION_H__
#define __WR_INTERACTION_H__

#include <stdio.h>
#include "wr_errno.h"
#include "wr_file_def.h"
#include "wr_protocol.h"
#include "wr_api.h"
#include "wr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_wr_conn wr_conn_t;
int wr_get_pack_err(wr_conn_t *conn, wr_packet_t *pack);
void wr_cli_get_err(wr_packet_t *pack, int32_t *errcode, char **errmsg);

#ifdef __cplusplus
}
#endif

#endif  // __WR_INTERACTION_H__
