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
 * wr_param.h
 *
 *
 * IDENTIFICATION
 *    src/params/wr_param.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_PARAM_H__
#define __WR_PARAM_H__

#include "wr_defs.h"
#include "wr_log.h"
#include "cm_config.h"
#include "cs_pipe.h"
#include "mes_metadata.h"
#include "mes_interface.h"
#include "ssl_metadata.h"
#include "wr_errno.h"
#include "wr_api.h"
#include "wr_nodes_list.h"
#ifdef __cplusplus
extern "C" {
#endif

#define WR_MIN_WORK_THREAD_COUNT (2)
#define WR_MAX_WORK_THREAD_COUNT (64)
// for most time, standby nodes rerad meta from primary
#define WR_WORK_THREAD_LOAD_DATA_PERCENT 0.5

#define WR_MES_MAX_WAIT_TIMEOUT 30000  // 30s
#define WR_MES_MIN_WAIT_TIMEOUT 500    // 500ms

#define WR_MIN_RECV_MSG_BUFF_SIZE (uint64) SIZE_M(9)
#define WR_MAX_RECV_MSG_BUFF_SIZE (uint64) SIZE_G(1)

typedef enum en_wr_mode {
    WR_MODE_UNKNOWN = 0,
    WR_MODE_CLUSTER_RAID = 1,  // MULTI DATANODE's RAID
    WR_MODE_SHARE_DISK = 2,    // SHARE DISK LOCK
    WR_MODE_DISK = 3           // A DATANODE's DISK
} wr_mode_e;

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
#define WR_RECYLE_META_RANGE_MAX 10000U
#endif

typedef struct st_wr_recycle_meta_pos {
    uint32_t hwm;  // trigger to recycle, the unit is 0.01%
    uint32_t lwm;  // mark to end recycle, the unit is 0.01%
} wr_recycle_meta_pos_t;

typedef struct st_wr_params {
    char *root_name;  // root volume name
    int64 inst_id;
    char disk_lock_file_path[WR_UNIX_PATH_MAX];
    char data_file_path[WR_UNIX_PATH_MAX];
    int32_t wr_mode;
    uint32_t cfg_session_num;
    int32_t lock_interval;
    uint32_t dlock_retry_count;

    uint64 mes_pool_size;
    wr_nodes_list_t nodes_list;
    wr_listen_addr_t listen_addr;  // listen addr
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
    wr_recycle_meta_pos_t recyle_meta_pos;
    uint32_t space_usage_hwm;
    uint32_t space_usage_lwm;
} wr_params_t;

typedef struct st_wr_config {
    char home[WR_MAX_PATH_BUFFER_SIZE];
    char data_dir[WR_MAX_PATH_BUFFER_SIZE];
    config_t config;
    config_t ssl_ser_config;
    wr_params_t params;
} wr_config_t;
extern wr_config_t *g_inst_cfg;
wr_config_t *wr_get_g_inst_cfg();

#define WR_UNIX_DOMAIN_SOCKET_NAME ".wr_unix_d_socket"
#define WR_MAX_SSL_PERIOD_DETECTION 180
#define WR_MIN_SSL_PERIOD_DETECTION 1

status_t wr_load_config(wr_config_t *inst_cfg);
status_t wr_set_cfg_dir(const char *home, wr_config_t *inst_cfg);
status_t wr_load_ser_ssl_config(wr_config_t *inst_cfg);
status_t wr_load_cli_ssl();

static inline int32_t wr_storage_mode(wr_config_t *inst_cfg)
{
    return inst_cfg->params.wr_mode;
}

static inline char *wr_get_cfg_dir(wr_config_t *inst_cfg)
{
    return inst_cfg->home;
}

/*
 * @brief set ssl relevant param
 * @[in] param name(SSL_CA、SSL_KEY、SSL_PWD_PLAINTEXT、SSL_CERT).
 * @[in] param value--ssl cert or ssl key
 * @* @return CM_SUCCESS - success;otherwise: failed
 */
status_t wr_set_ssl_param(const char *param_name, const char *param_value);

/*
 * @brief get ssl relevant param
 * @[in] param name(SSL_CA、SSL_KEY、SSL_PWD_PLAINTEXT、SSL_CERT).
 * @[in]size--ssl cert or ssl key size
 * @[out]param value--ssl cert or ssl key
 * @* @return CM_SUCCESS - success;otherwise: failed
 */
inline status_t wr_get_ssl_param(const char *param_name, char *param_value, uint32_t size)
{
    if (param_name == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "the ssl param name should not be null.");
        return CM_ERROR;
    }
    return mes_get_md_param_by_name(param_name, param_value, size);
}
void wr_ssl_ca_cert_expire(void);

status_t wr_set_cfg_param(char *name, char *value, char *scope);
status_t wr_get_cfg_param(const char *name, char **value);
status_t wr_load_delay_clean_interval_core(char *value, wr_config_t *inst_cfg);
status_t wr_set_cert_param(const char *param_name, const char *param_value);

#ifdef __cplusplus
}
#endif

#endif
