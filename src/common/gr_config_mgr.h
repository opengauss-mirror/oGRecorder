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
 * gr_config_mgr.h
 *
 * IDENTIFICATION
 *    src/common/gr_config_mgr.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_CONFIG_MGR_H__
#define __GR_CONFIG_MGR_H__

#include "gr_param.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Lightweight configuration access wrapper.
 *
 * Goals:
 * - Provide a unified entry to access g_inst_cfg; if we need to support hot-reload,
 *   multi-instance or read/write locks later, we only need to change the implementation
 *   here without touching most callers;
 * - The current implementation is a very lightweight inline wrapper and does not
 *   change existing behavior.
 */

/* Get the current instance configuration (usable by both server and client) */
static inline gr_config_t *gr_cfg_get_inst(void)
{
    return gr_get_g_inst_cfg();
}

/* Get the current instance configuration for the server process (server-side only) */
static inline gr_config_t *gr_cfg_get_server_inst(void)
{
    return g_inst_cfg;
}

#ifdef __cplusplus
}
#endif

#endif /* __GR_CONFIG_MGR_H__ */

