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
 * gr_param_sync.h
 *
 *
 * IDENTIFICATION
 *    src/params/gr_param_sync.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_PARAM_SYNC_H__
#define __GR_PARAM_SYNC_H__

#include "cm_types.h"
#include "gr_param.h"
#include "cm_config.h"
#include "cm_thread.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern const char *gr_sync_param[];      /**< list of synchronizable parameters */
extern const char *gr_reserve_param[];   /**< list of reserved parameters to keep locally */

typedef struct st_gr_config_sync_context {
    thread_t broadcast_thread;        /**< broadcast thread handle */
    volatile bool8 broadcast_thread_running;  /**< broadcast thread state */
    cm_event_t broadcast_event;       /**< broadcast event */
    thread_lock_t lock;               /**< sync lock */
} gr_config_sync_context_t;

extern gr_config_sync_context_t g_config_sync_ctx;

void gr_param_broadcast_thread(thread_t *thread);
bool32 gr_is_sync_param(const char *name);
status_t gr_init_config_worm();
status_t gr_init_config_sync_context(void);
status_t gr_write_config_to_worm(gr_config_t *inst_cfg);
status_t gr_trigger_param_broadcast(void);
status_t gr_apply_cfg_to_memory(gr_config_t *inst_cfg, bool8 is_worm, bool8 is_memory);
status_t gr_standby_node_worm_write(gr_config_t *inst_cfg);
status_t gr_rebuild_worm_file(gr_config_t *inst_cfg);
status_t gr_delete_worm_file(gr_config_t *inst_cfg);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __GR_PARAM_SYNC_H__ */
