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
 * gr_interaction.h
 *
 *
 * IDENTIFICATION
 *    src/common_api/gr_interaction.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_INTERACTION_H__
#define __GR_INTERACTION_H__

#include <stdio.h>
#include "gr_errno.h"
#include "gr_file_def.h"
#include "gr_protocol.h"
#include "gr_api.h"
#include "gr_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_gr_conn gr_conn_t;
int gr_get_pack_err(gr_conn_t *conn, gr_packet_t *pack);
void gr_cli_get_err(gr_packet_t *pack, int32_t *errcode, char **errmsg);

#ifdef __cplusplus
}
#endif

#endif  // __GR_INTERACTION_H__
