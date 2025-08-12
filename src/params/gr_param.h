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
 * gr_param.h
 *
 *
 * IDENTIFICATION
 *    src/params/gr_param.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_PARAM_H__
#define __GR_PARAM_H__

#include "gr_defs.h"
#include "gr_log.h"
#include "cm_config.h"
#include "cs_pipe.h"
#include "mes_metadata.h"
#include "mes_interface.h"
#include "ssl_metadata.h"
#include "gr_errno.h"
#include "gr_api.h"
#include "gr_nodes_list.h"
#ifdef __cplusplus
extern "C" {
#endif

#define GR_MIN_MES_WORK_THREAD_COUNT (2)
#define GR_MAX_MES_WORK_THREAD_COUNT (64)
// for most time, standby nodes rerad meta from primary
#define GR_WORK_THREAD_LOAD_DATA_PERCENT 0.5

#define GR_MES_MAX_WAIT_TIMEOUT 30000  // 30s
#define GR_MES_MIN_WAIT_TIMEOUT 500    // 500ms

#define GR_MIN_RECV_MSG_BUFF_SIZE (uint64) SIZE_M(9)
#define GR_MAX_RECV_MSG_BUFF_SIZE (uint64) SIZE_G(1)

typedef enum en_gr_mode {
    GR_MODE_UNKNOWN = 0,
    GR_MODE_CLUSTER_RAID = 1,  // MULTI DATANODE's RAID
    GR_MODE_SHARE_DISK = 2,    // SHARE DISK LOCK
    GR_MODE_DISK = 3           // A DATANODE's DISK
} gr_mode_e;

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
#define GR_RECYLE_META_RANGE_MAX 10000U
#endif

typedef struct st_gr_recycle_meta_pos {
    uint32_t hwm;  // trigger to recycle, the unit is 0.01%
    uint32_t lwm;  // mark to end recycle, the unit is 0.01%
} gr_recycle_meta_pos_t;

typedef struct st_gr_params {
    char *root_name;  // root volume name
    int64 inst_id;
    char disk_lock_file_path[GR_UNIX_PATH_MAX];
    char data_file_path[GR_UNIX_PATH_MAX];
    int32_t gr_mode;
    uint32_t cfg_session_num;
    int32_t lock_interval;
    uint32_t dlock_retry_count;

    uint64 mes_pool_size;
    gr_nodes_list_t nodes_list;
    gr_listen_addr_t listen_addr;  // listen addr
    uint32_t channel_num;
    uint32_t work_thread_cnt;
    cs_pipe_type_t pipe_type;
    bool32 elapsed_switch;
    uint32_t shm_key;
    uint32_t ssl_detect_day;
    bool32 mes_with_ip;
    bool32 ip_white_list_on;
    uint32_t iothread_count;
    uint32_t workthread_count;
    uint32_t xlog_vg_id;
    bool32 blackbox_detail_on;
    uint32_t mes_wait_timeout;
    bool32 enable_core_state_collect;
    uint32_t delay_clean_interval;
    gr_recycle_meta_pos_t recyle_meta_pos;
    uint32_t space_usage_hwm;
    uint32_t space_usage_lwm;
} gr_params_t;

typedef struct st_gr_config {
    char home[GR_MAX_PATH_BUFFER_SIZE];
    char data_dir[GR_MAX_PATH_BUFFER_SIZE];
    config_t config;
    config_t ssl_ser_config;
    gr_params_t params;
} gr_config_t;
extern gr_config_t *g_inst_cfg;
gr_config_t *gr_get_g_inst_cfg();

#define GR_UNIX_DOMAIN_SOCKET_NAME ".gr_unix_d_socket"
#define GR_MAX_SSL_PERIOD_DETECTION 180
#define GR_MIN_SSL_PERIOD_DETECTION 1

status_t gr_load_config(gr_config_t *inst_cfg);
status_t gr_set_cfg_dir(const char *home, gr_config_t *inst_cfg);
status_t gr_load_ser_ssl_config(gr_config_t *inst_cfg);
status_t gr_load_cli_ssl();

static inline int32_t gr_storage_mode(gr_config_t *inst_cfg)
{
    return inst_cfg->params.gr_mode;
}

static inline char *gr_get_cfg_dir(gr_config_t *inst_cfg)
{
    return inst_cfg->home;
}

/*
 * @brief set ssl relevant param
 * @[in] param name(SSL_CA、SSL_KEY、SSL_PWD_PLAINTEXT、SSL_CERT).
 * @[in] param value--ssl cert or ssl key
 * @* @return CM_SUCCESS - success;otherwise: failed
 */
status_t gr_set_ssl_param(const char *param_name, const char *param_value);

/*
 * @brief get ssl relevant param
 * @[in] param name(SSL_CA、SSL_KEY、SSL_PWD_PLAINTEXT、SSL_CERT).
 * @[in]size--ssl cert or ssl key size
 * @[out]param value--ssl cert or ssl key
 * @* @return CM_SUCCESS - success;otherwise: failed
 */
inline status_t gr_get_ssl_param(const char *param_name, char *param_value, uint32_t size)
{
    if (param_name == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "the ssl param name should not be null.");
        return CM_ERROR;
    }
    return mes_get_md_param_by_name(param_name, param_value, size);
}
void gr_ssl_ca_cert_expire(void);

status_t gr_set_cfg_param(char *name, char *value, char *scope);
status_t gr_get_cfg_param(const char *name, char **value);
status_t gr_load_delay_clean_interval_core(char *value, gr_config_t *inst_cfg);
status_t gr_set_cert_param(const char *param_name, const char *param_value);

#ifdef __cplusplus
}
#endif

#endif
