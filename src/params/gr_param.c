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
 * gr_param.c
 *
 *
 * IDENTIFICATION
 *    src/params/gr_param.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_errno.h"
#include "cm_num.h"
#include "cm_ip.h"
#include "cm_encrypt.h"
#include "cm_utils.h"
#include "gr_malloc.h"
#include "gr_param_verify.h"
#include "gr_fault_injection.h"
#include "gr_diskgroup.h"
#include "gr_param.h"
#include "gr_diskgroup.h"

#ifdef __cplusplus
extern "C" {
#endif

gr_config_t *g_inst_cfg = NULL;
static gr_config_t g_inst_cfg_inner = {0};
gr_config_t *gr_get_g_inst_cfg()
{
    return &g_inst_cfg_inner;
}

config_t cli_ssl_cfg;

static config_item_t g_gr_ssl_params[] = {
    {"SER_SSL_CA", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 25, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"SER_SSL_KEY", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 26, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"SER_SSL_CERT", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 28, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"SER_SSL_CRL", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 28, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"CLI_SSL_CA", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 25, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"CLI_SSL_KEY", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 26, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"CLI_SSL_CERT", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 28, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"CLI_SSL_CRL", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 28, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
};

static config_item_t g_gr_params[] = {
    // ==================== Basic Configuration ====================
    {"INST_ID", CM_TRUE, ATTR_READONLY, "0", NULL, NULL, "-", "[0,64)", "GS_TYPE_INTEGER",
        NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"LISTEN_ADDR", CM_TRUE, ATTR_READONLY, "127.0.0.1:1622", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 1, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"DATA_FILE_PATH", CM_TRUE, ATTR_READONLY, "/tmp", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 2, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"GR_CM_SO_NAME", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 3, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"SHM_KEY", CM_TRUE, ATTR_READONLY, "1", NULL, NULL, "-", "[1,64]", "GS_TYPE_INTEGER",
        NULL, 4, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},

    // ==================== Logging Configuration ====================
    {"LOG_HOME", CM_TRUE, CM_TRUE, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 5, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"LOG_LEVEL", CM_TRUE, ATTR_NONE, "519", NULL, NULL, "-", "[0,4087]", "GS_TYPE_INTEGER",
        NULL, 6, EFFECT_IMMEDIATELY, CFG_INS, gr_verify_log_level, gr_notify_log_level, NULL, NULL},
    {"LOG_BACKUP_FILE_COUNT", CM_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[0,128]", "GS_TYPE_INTEGER",
        NULL, 7, EFFECT_REBOOT, CFG_INS, gr_verify_log_backup_file_count, gr_notify_log_backup_file_count, NULL, NULL},
    {"LOG_MAX_FILE_SIZE", CM_TRUE, ATTR_NONE, "256M", NULL, NULL, "-", "[1M,4G]", "GS_TYPE_INTEGER",
        NULL, 8, EFFECT_REBOOT, CFG_INS, gr_verify_log_file_size, gr_notify_log_file_size, NULL, NULL},
    {"LOG_COMPRESSED", CM_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "[FALSE,TRUE]", "GS_TYPE_BOOLEAN",
        NULL, 9, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"LOG_FILE_PERMISSIONS", CM_TRUE, ATTR_READONLY, "600", NULL, NULL, "-", "[600-777]", "GS_TYPE_INTEGER",
        NULL, 10, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"LOG_PATH_PERMISSIONS", CM_TRUE, ATTR_READONLY, "700", NULL, NULL, "-", "[700-777]", "GS_TYPE_INTEGER",
        NULL, 11, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"LOG_ALARM_HOME", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 12, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},

    // ==================== Audit Configuration ====================
    {"AUDIT_LEVEL", CM_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[0,255]", "GS_TYPE_INTEGER",
        NULL, 13, EFFECT_IMMEDIATELY, CFG_INS, gr_verify_audit_level, gr_notify_audit_level, NULL, NULL},
    {"AUDIT_BACKUP_FILE_COUNT", CM_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[0,128]", "GS_TYPE_INTEGER",
        NULL, 14, EFFECT_REBOOT, CFG_INS, gr_verify_audit_backup_file_count, gr_notify_audit_backup_file_count, NULL, NULL},
    {"AUDIT_MAX_FILE_SIZE", CM_TRUE, ATTR_NONE, "256M", NULL, NULL, "-", "[1M,4G]", "GS_TYPE_INTEGER",
        NULL, 15, EFFECT_REBOOT, CFG_INS, gr_verify_audit_file_size, gr_notify_audit_file_size, NULL, NULL},

    // ==================== SSL Security Configuration ====================
    {"SSL_CA", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 16, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"SSL_KEY", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 17, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"SSL_CERT", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 18, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"SSL_CRL", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 19, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"SSL_CIPHER", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 20, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"SSL_PWD_CIPHERTEXT", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 21, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"SSL_CERT_NOTIFY_TIME", CM_TRUE, ATTR_READONLY, "30", NULL, NULL, "-", "[7,180]", "GS_TYPE_INTEGER",
        NULL, 22, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"SSL_PERIOD_DETECTION", CM_TRUE, ATTR_READONLY, "7", NULL, NULL, "-", "[1,180]", "GS_TYPE_INTEGER",
        NULL, 23, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},

    // ==================== Network and Cluster Configuration ====================
    {"GR_NODES_LIST", CM_TRUE, ATTR_NONE, "0:127.0.0.1:1611", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 24, EFFECT_IMMEDIATELY, CFG_INS, gr_verify_nodes_list, gr_notify_gr_nodes_list, NULL, NULL},
    {"INTERCONNECT_TYPE", CM_TRUE, ATTR_READONLY, "TCP", NULL, NULL, "-", "TCP,RDMA", "GS_TYPE_VARCHAR",
        NULL, 25, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"INTERCONNECT_CHANNEL_NUM", CM_TRUE, ATTR_READONLY, "2", NULL, NULL, "-", "[1,32]", "GS_TYPE_INTEGER",
        NULL, 26, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"MES_WITH_IP", CM_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "GS_TYPE_BOOLEAN",
        NULL, 27, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"IP_WHITE_LIST", CM_TRUE, ATTR_NONE, "127.0.0.1", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR",
        NULL, 28, EFFECT_IMMEDIATELY, CFG_INS, NULL, NULL, NULL, NULL},

    // ==================== Performance and Thread Configuration ====================
    {"MAX_SESSION_NUMS", CM_TRUE, ATTR_READONLY, "8192", NULL, NULL, "-", "[16,16320]", "GS_TYPE_INTEGER",
        NULL, 29, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"IO_THREADS", CM_TRUE, ATTR_READONLY, "2", NULL, NULL, "-", "[1,8]", "GS_TYPE_INTEGER",
        NULL, 30, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"WORK_THREADS", CM_TRUE, ATTR_READONLY, "16", NULL, NULL, "-", "[16,128]", "GS_TYPE_INTEGER",
        NULL, 31, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"MES_WORK_THREAD_COUNT", CM_TRUE, ATTR_READONLY, "8", NULL, NULL, "-", "[2,64]", "GS_TYPE_INTEGER",
        NULL, 32, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},

    // ==================== Message and Memory Configuration ====================
    {"RECV_MSG_POOL_SIZE", CM_TRUE, ATTR_READONLY, "48M", NULL, NULL, "-", "[9M,1G]", "GS_TYPE_INTEGER",
        NULL, 34, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"MES_WAIT_TIMEOUT", CM_TRUE, ATTR_NONE, "10000", NULL, NULL, "-", "[500,30000]", "GS_TYPE_INTEGER",
        NULL, 35, EFFECT_IMMEDIATELY, CFG_INS, gr_verify_mes_wait_timeout, gr_notify_mes_wait_timeout, NULL, NULL},
    {"MES_ELAPSED_SWITCH", CM_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "GS_TYPE_BOOLEAN",
        NULL, 36, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"DELAY_CLEAN_INTERVAL", CM_TRUE, ATTR_NONE, "5", NULL, NULL, "-", "[5,1000000]", "GS_TYPE_INTEGER",
        NULL, 37, EFFECT_IMMEDIATELY, CFG_INS, gr_verify_delay_clean_interval, gr_notify_delay_clean_interval, NULL, NULL},
};

static const char *g_gr_config_file = (const char *)"gr_inst.ini";
static const char *g_gr_ser_config_file = (const char *)"gr_ser_inst.ini";
static const char *g_gr_cli_config_file = (const char *)"gr_cli_inst.ini";
#define GR_PARAM_COUNT (sizeof(g_gr_params) / sizeof(config_item_t))
#define GR_CERT_PARAM_COUNT (sizeof(g_gr_ssl_params) / sizeof(config_item_t))

static status_t gr_load_threadpool_cfg(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "IO_THREADS");
    int32_t count = 0;
    status_t status = cm_str2int(value, &count);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "IO_THREADS"));

    if (count < GR_MIN_IOTHREADS_CFG || count > GR_MAX_IOTHREADS_CFG) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "IO_THREADS");
        return CM_ERROR;
    }
    inst_cfg->params.iothread_count = (uint32_t)count;

    value = cm_get_config_value(&inst_cfg->config, "WORK_THREADS");
    status = cm_str2int(value, &count);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "WORK_THREADS"));
    if (count < GR_MIN_WORKTHREADS_CFG || count > GR_MAX_WORKTHREADS_CFG) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "WORK_THREADS");
        return CM_ERROR;
    }
    inst_cfg->params.workthread_count = (uint32_t)count;

    return CM_SUCCESS;
}

static status_t gr_load_session_cfg(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MAX_SESSION_NUMS");
    int32_t sessions;
    status_t status = cm_str2int(value, &sessions);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "MAX_SESSION_NUMS"));

    if (sessions < GR_MIN_SESSIONID_CFG || sessions > GR_MAX_SESSIONS) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "MAX_SESSION_NUMS"));
    }

    inst_cfg->params.cfg_session_num = (uint32_t)sessions;
    return CM_SUCCESS;
}

static status_t gr_load_mes_pool_size(gr_config_t *inst_cfg)
{
    int64 mes_pool_size;
    char *value = cm_get_config_value(&inst_cfg->config, "RECV_MSG_POOL_SIZE");
    status_t status = cm_str2size(value, &mes_pool_size);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "RECV_MSG_POOL_SIZE"));

    inst_cfg->params.mes_pool_size = (uint64)mes_pool_size;
    if ((inst_cfg->params.mes_pool_size < GR_MIN_RECV_MSG_BUFF_SIZE) ||
        (inst_cfg->params.mes_pool_size > GR_MAX_RECV_MSG_BUFF_SIZE)) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "RECV_MSG_POOL_SIZE"));
    }
    LOG_RUN_INF("Cluster Raid mode, mes_pool_size = %lld.", mes_pool_size);
    return CM_SUCCESS;
}

static status_t gr_load_mes_url(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "GR_NODES_LIST");
    return gr_extract_nodes_list(value, &inst_cfg->params.nodes_list);
}

static status_t gr_load_mes_conn_type(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "INTERCONNECT_TYPE");
    if (cm_str_equal_ins(value, "TCP")) {
        inst_cfg->params.pipe_type = CS_TYPE_TCP;
    } else if (cm_str_equal_ins(value, "RDMA")) {
        inst_cfg->params.pipe_type = CS_TYPE_RDMA;
    } else {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "INTERCONNECT_TYPE"));
    }
    LOG_RUN_INF("Cluster Raid mode, pipe type = %u.", inst_cfg->params.pipe_type);
    return CM_SUCCESS;
}

static status_t gr_load_mes_channel_num(gr_config_t *inst_cfg)
{
    uint32_t channel_num;
    char *value = cm_get_config_value(&inst_cfg->config, "INTERCONNECT_CHANNEL_NUM");
    status_t status = cm_str2uint32(value, &channel_num);
    GR_RETURN_IFERR2(
        status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid parameter value of 'INTERCONNECT_CHANNEL_NUM'"));

    if (channel_num < CM_MES_MIN_CHANNEL_NUM || channel_num > CM_MES_MAX_CHANNEL_NUM) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "INTERCONNECT_CHANNEL_NUM"));
    }

    inst_cfg->params.channel_num = channel_num;
    LOG_RUN_INF("Cluster Raid mode, channel_num = %u.", inst_cfg->params.channel_num);
    return CM_SUCCESS;
}

static status_t gr_load_mes_work_thread_cnt(gr_config_t *inst_cfg)
{
    uint32_t work_thread_cnt;
    char *value = cm_get_config_value(&inst_cfg->config, "MES_WORK_THREAD_COUNT");
    status_t status = cm_str2uint32(value, &work_thread_cnt);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid parameter value of 'MES_WORK_THREAD_COUNT'"));

    if (work_thread_cnt < GR_MIN_MES_WORK_THREAD_COUNT || work_thread_cnt > GR_MAX_MES_WORK_THREAD_COUNT) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "MES_WORK_THREAD_COUNT"));
    }

    inst_cfg->params.work_thread_cnt = work_thread_cnt;
    LOG_RUN_INF("Cluster Raid mode, work_thread_cnt = %u.", inst_cfg->params.work_thread_cnt);
    return CM_SUCCESS;
}

static status_t gr_load_mes_elapsed_switch(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MES_ELAPSED_SWITCH");
    if (cm_str_equal_ins(value, "TRUE")) {
        inst_cfg->params.elapsed_switch = CM_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        inst_cfg->params.elapsed_switch = CM_FALSE;
    } else {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "MES_ELAPSED_SWITCH"));
    }

    LOG_RUN_INF("Cluster Raid mode, elapsed_switch = %u.", inst_cfg->params.elapsed_switch);
    return CM_SUCCESS;
}

static status_t gr_load_random_file(uchar *value, int32_t value_len)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    char dir_name[CM_FILE_NAME_BUFFER_SIZE];
    int32_t handle;
    int32_t file_size;
    PRTS_RETURN_IFERR(snprintf_s(
        dir_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/gr_protect", g_inst_cfg->home));
    if (!cm_dir_exist(dir_name)) {
        GR_THROW_ERROR(ERR_GR_FILE_NOT_EXIST, "gr_protect", g_inst_cfg->home);
        return CM_ERROR;
    }
    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/gr_protect/%s",
        g_inst_cfg->home, GR_FKEY_FILENAME));
    GR_RETURN_IF_ERROR(cs_ssl_verify_file_stat(file_name));
    GR_RETURN_IF_ERROR(cm_open_file_ex(file_name, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &handle));
    status_t ret = cm_read_file(handle, value, value_len, &file_size);
    cm_close_file(handle);
    GR_RETURN_IF_ERROR(ret);
    if (file_size < RANDOM_LEN + 1) {
        LOG_RUN_ERR("Random component file %s is invalid, size is %d.", file_name, file_size);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t gr_load_data_file_path(gr_config_t *inst_cfg)
{
    int32 ret;
    char *value = cm_get_config_value(&inst_cfg->config, "DATA_FILE_PATH");
    status_t status = gr_verify_lock_file_path(value);
    GR_RETURN_IFERR2(
        status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "failed to load params, invalid DATA_FILE_PATH"));
    ret = snprintf_s(inst_cfg->params.data_file_path, GR_UNIX_PATH_MAX, GR_UNIX_PATH_MAX - 1, "%s", value);
    if (ret == -1) {
        GR_RETURN_IFERR2(
            CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "failed to load params, invalid DATA_FILE_PATH"));
    }

    return CM_SUCCESS;
}

int32_t gr_decrypt_pwd_cb(const char *cipher_text, uint32_t cipher_len, char *plain_text, uint32_t plain_len)
{
    if (cipher_text == NULL) {
        GR_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_RUN_ERR("[GR] failed to decrypt SSL cipher: cipher is NULL"));
    }
    if (cipher_len == 0 || cipher_len >= GR_PARAM_BUFFER_SIZE) {
        GR_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_RUN_ERR("[GR] failed to decrypt SSL cipher: cipher size [%u] is invalid.", cipher_len));
    }
    if (plain_text == NULL) {
        GR_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_RUN_ERR("[GR] failed to decrypt SSL cipher: plain is NULL"));
    }
    if (plain_len < CM_PASSWD_MAX_LEN) {
        GR_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_RUN_ERR("[GR] failed to decrypt SSL cipher: plain len [%u] is invalid.", plain_len));
    }
    cipher_t cipher;
    if (cm_base64_decode(cipher_text, cipher_len, (uchar *)&cipher, (uint32_t)(sizeof(cipher_t) + 1)) == 0) {
        GR_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_RUN_ERR("[GR] failed to decode SSL cipher."));
    }
    if (cipher.cipher_len > 0) {
        status_t status = gr_load_random_file(cipher.rand, (int32_t)sizeof(cipher.rand));
        GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_VALUE_ERROR, "[GR] load random component failed."));
        status = cm_decrypt_pwd(&cipher, (uchar *)plain_text, &plain_len);
        GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_VALUE_ERROR, "[GR] failed to decrypt ssl pwd."));
    } else {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT");
        LOG_RUN_ERR("[GR] failed to decrypt ssl pwd for the cipher len is invalid.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_load_mes_ssl(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "SSL_CA");
    status_t status = gr_set_ssl_param("SSL_CA", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SSL_CA"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_KEY");
    status = gr_set_ssl_param("SSL_KEY", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SSL_KEY"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CRL");
    status = gr_set_ssl_param("SSL_CRL", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SSL_CRL"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CERT");
    status = gr_set_ssl_param("SSL_CERT", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SSL_CERT"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CIPHER");
    status = gr_set_ssl_param("SSL_CIPHER", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SSL_CIPHER"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CERT_NOTIFY_TIME");
    status = gr_set_ssl_param("SSL_CERT_NOTIFY_TIME", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SSL_CERT_NOTIFY_TIME"));
    uint32_t alert_value;
    status = cm_str2uint32(value, &alert_value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SSL_CERT_NOTIFY_TIME"));
    value = cm_get_config_value(&inst_cfg->config, "SSL_PERIOD_DETECTION");
    status = cm_str2uint32(value, &inst_cfg->params.ssl_detect_day);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SSL_PERIOD_DETECTION"));
    if (inst_cfg->params.ssl_detect_day > GR_MAX_SSL_PERIOD_DETECTION ||
        inst_cfg->params.ssl_detect_day < GR_MIN_SSL_PERIOD_DETECTION) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SSL_PERIOD_DETECTION");
        return CM_ERROR;
    }
    if (inst_cfg->params.ssl_detect_day > alert_value) {
        GR_THROW_ERROR_EX(ERR_GR_INVALID_PARAM,
            "SSL disabled: the value of SSL_PERIOD_DETECTION which is %u is "
            "bigger than the value of SSL_CERT_NOTIFY_TIME which is %u.",
            inst_cfg->params.ssl_detect_day, alert_value);
        return CM_ERROR;
    }
    value = cm_get_config_value(&inst_cfg->config, "SSL_PWD_CIPHERTEXT");
    status = gr_set_ssl_param("SSL_PWD_CIPHERTEXT", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"));

    if (!CM_IS_EMPTY_STR(value)) {
        return mes_register_decrypt_pwd(gr_decrypt_pwd_cb);
    }
    return CM_SUCCESS;
}

static status_t gr_load_mes_wait_timeout(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MES_WAIT_TIMEOUT");
    int32_t timeout = 0;
    status_t status = cm_str2int(value, &timeout);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "MES_WAIT_TIMEOUT"));
    if (timeout < GR_MES_MIN_WAIT_TIMEOUT || timeout > GR_MES_MAX_WAIT_TIMEOUT) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "MES_WAIT_TIMEOUT");
        return CM_ERROR;
    }
    inst_cfg->params.mes_wait_timeout = (uint32_t)timeout;
    return CM_SUCCESS;
}

static status_t gr_load_mes_params(gr_config_t *inst_cfg)
{
    CM_RETURN_IFERR(gr_load_mes_url(inst_cfg));
    CM_RETURN_IFERR(gr_load_mes_conn_type(inst_cfg));
    CM_RETURN_IFERR(gr_load_mes_channel_num(inst_cfg));
    CM_RETURN_IFERR(gr_load_mes_work_thread_cnt(inst_cfg));
    CM_RETURN_IFERR(gr_load_mes_pool_size(inst_cfg));
    CM_RETURN_IFERR(gr_load_mes_elapsed_switch(inst_cfg));
    CM_RETURN_IFERR(gr_load_mes_ssl(inst_cfg));
    CM_RETURN_IFERR(gr_load_mes_wait_timeout(inst_cfg));
    return CM_SUCCESS;
}

static status_t gr_load_listen_addr(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "LISTEN_ADDR");
    if (value == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "LISTEN_ADDR is not set");
        return CM_ERROR;
    }

    char buffer[GR_MAX_PATH_BUFFER_SIZE];
    strncpy(buffer, value, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *colon_pos = strchr(buffer, ':');
    if (colon_pos == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "LISTEN_ADDR format is invalid, expected IP:Port");
        return CM_ERROR;
    }

    *colon_pos = '\0';
    char *ip = buffer;
    char *port_str = colon_pos + 1;

    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "Port number is invalid");
        return CM_ERROR;
    }

    strncpy(inst_cfg->params.listen_addr.host, ip, sizeof(inst_cfg->params.listen_addr.host) - 1);
    inst_cfg->params.listen_addr.host[sizeof(inst_cfg->params.listen_addr.host) - 1] = '\0';
    inst_cfg->params.listen_addr.port = port;

    return CM_SUCCESS;
}

status_t gr_set_cfg_dir(const char *home, gr_config_t *inst_cfg)
{
    char home_realpath[GR_MAX_PATH_BUFFER_SIZE];
    bool8 is_home_empty = (home == NULL || home[0] == '\0');
    if (is_home_empty) {
        const char *home_env = getenv(GR_ENV_HOME);
        if (home_env == NULL || home_env[0] == '\0') {
            GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid cfg dir"));
        }
        uint32_t len = (uint32_t)strlen(home_env);
        if (len >= GR_MAX_PATH_BUFFER_SIZE) {
            GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid cfg dir len"));
        }
        status_t status = realpath_file(home_env, home_realpath, GR_MAX_PATH_BUFFER_SIZE);
        GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid cfg dir"));

    } else {
        uint32_t len = (uint32_t)strlen(home);
        if (len >= GR_MAX_PATH_BUFFER_SIZE) {
            GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "invalid cfg dir");
            return CM_ERROR;
        }
    }
    int32_t iret_snprintf = snprintf_s(inst_cfg->home, GR_MAX_PATH_BUFFER_SIZE, GR_MAX_PATH_BUFFER_SIZE - 1, "%s",
        is_home_empty ? home_realpath : home);
    GR_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);

    g_inst_cfg = inst_cfg;
    return CM_SUCCESS;
}

static status_t gr_load_instance_id(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "INST_ID");
    status_t status = cm_str2bigint(value, &inst_cfg->params.inst_id);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "the value of 'INST_ID' is invalid"));

    if (inst_cfg->params.inst_id < GR_MIN_INST_ID || inst_cfg->params.inst_id >= GR_MAX_INST_ID) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "the value of 'INST_ID' is invalid"));
    }

    LOG_RUN_INF("The instanceid is %lld.", inst_cfg->params.inst_id);
    return CM_SUCCESS;
}

// 白名单IP地址结构
#define GR_MAX_WHITE_LIST_COUNT 64
#define GR_MAX_IP_RANGE_LEN 32

typedef struct st_ip_whitelist_entry {
    char ip_addr[CM_MAX_IP_LEN];
    char subnet_mask[CM_MAX_IP_LEN];
    bool32 is_range;
    struct sockaddr_storage sock_addr;
    struct sockaddr_storage mask_addr;
} ip_whitelist_entry_t;

typedef struct st_ip_whitelist {
    ip_whitelist_entry_t entries[GR_MAX_WHITE_LIST_COUNT];
    uint32 count;
} ip_whitelist_t;

static ip_whitelist_t g_ip_whitelist = {0};

// 解析IP范围 (支持: 192.168.1.100, 192.168.1.0/24, 192.168.1.*)
static status_t parse_ip_range(const char *ip_str, ip_whitelist_entry_t *entry)
{
    char temp_str[CM_MAX_IP_LEN];
    char *slash_pos, *star_pos;
    
    if (strlen(ip_str) >= CM_MAX_IP_LEN) {
        return CM_ERROR;
    }
    
    strcpy_s(temp_str, CM_MAX_IP_LEN, ip_str);
    
    // 检查通配符格式 (192.168.1.* 或 192.168.*.*)  
    star_pos = strchr(temp_str, '*');
    if (star_pos != NULL) {
        // 将*替换为0，并根据*的位置确定掩码
        char *dot_count = temp_str;
        int dots = 0;
        while (*dot_count) {
            if (*dot_count == '.') dots++;
            dot_count++;
        }
        
        // 替换*为0来构建网络地址
        char network_ip[CM_MAX_IP_LEN];
        strcpy_s(network_ip, CM_MAX_IP_LEN, temp_str);
        char *p = network_ip;
        while (*p) {
            if (*p == '*') *p = '0';
            p++;
        }
        
        strcpy_s(entry->ip_addr, CM_MAX_IP_LEN, network_ip);
        
        // 根据*的位置生成掩码
        if (strstr(temp_str, "*.*.*") != NULL) {
            // a.*.*.*  -> /8
            strcpy_s(entry->subnet_mask, CM_MAX_IP_LEN, "255.0.0.0");
        } else if (strstr(temp_str, "*.* ") != NULL || strstr(temp_str, "*.*") == (temp_str + strlen(temp_str) - 3)) {
            // a.b.*.*  -> /16
            strcpy_s(entry->subnet_mask, CM_MAX_IP_LEN, "255.255.0.0");
        } else if (strstr(temp_str, "*") != NULL) {
            // a.b.c.*  -> /24
            strcpy_s(entry->subnet_mask, CM_MAX_IP_LEN, "255.255.255.0");
        }
        
        entry->is_range = CM_TRUE;
        return CM_SUCCESS;
    }
    
    // 检查CIDR格式 (192.168.1.0/24)
    slash_pos = strchr(temp_str, '/');
    if (slash_pos != NULL) {
        *slash_pos = '\0';
        strcpy_s(entry->ip_addr, CM_MAX_IP_LEN, temp_str);
        
        int prefix_len = atoi(slash_pos + 1);
        if (prefix_len <= 0 || prefix_len > 32) {
            return CM_ERROR;
        }
        
        // 生成子网掩码
        uint32 mask = 0xFFFFFFFF << (32 - prefix_len);
        snprintf_s(entry->subnet_mask, CM_MAX_IP_LEN, CM_MAX_IP_LEN - 1, 
                  "%d.%d.%d.%d", 
                  (mask >> 24) & 0xFF, 
                  (mask >> 16) & 0xFF, 
                  (mask >> 8) & 0xFF, 
                  mask & 0xFF);
        entry->is_range = CM_TRUE;
        return CM_SUCCESS;
    }
    
    // 单个IP地址
    strcpy_s(entry->ip_addr, CM_MAX_IP_LEN, temp_str);
    entry->is_range = CM_FALSE;
    return CM_SUCCESS;
}

// 检查IPv4地址是否在白名单中
static bool32 is_ip_in_whitelist(const char *client_ip)
{
    struct sockaddr_in client_addr;
    if (inet_pton(AF_INET, client_ip, &client_addr.sin_addr) != 1) {
        LOG_RUN_WAR("[GR_WHITELIST] Invalid IPv4 address format: %s", client_ip);
        return CM_FALSE;
    }
    
    for (uint32 i = 0; i < g_ip_whitelist.count; i++) {
        ip_whitelist_entry_t *entry = &g_ip_whitelist.entries[i];
        
        if (!entry->is_range) {
            if (strcmp(client_ip, entry->ip_addr) == 0) {
                LOG_DEBUG_INF("[GR_WHITELIST] IP %s matched exact entry: %s", 
                             client_ip, entry->ip_addr);
                return CM_TRUE;
            }
        } else {
            struct sockaddr_in entry_addr, mask_addr;
            if (inet_pton(AF_INET, entry->ip_addr, &entry_addr.sin_addr) == 1 &&
                inet_pton(AF_INET, entry->subnet_mask, &mask_addr.sin_addr) == 1) {
                
                uint32 client_ip_int = ntohl(client_addr.sin_addr.s_addr);
                uint32 entry_ip_int = ntohl(entry_addr.sin_addr.s_addr);
                uint32 mask_int = ntohl(mask_addr.sin_addr.s_addr);
                
                if ((client_ip_int & mask_int) == (entry_ip_int & mask_int)) {
                    LOG_DEBUG_INF("[GR_WHITELIST] IP %s matched range entry: %s/%s", 
                                 client_ip, entry->ip_addr, entry->subnet_mask);
                    return CM_TRUE;
                }
            }
        }
    }
    
    LOG_DEBUG_INF("[GR_WHITELIST] IP %s not found in whitelist", client_ip);
    return CM_FALSE;
}

// 加载白名单IP地址列表
static status_t gr_load_ip_white_list_addrs(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "IP_WHITE_LIST");
    
    g_ip_whitelist.count = 0;
    
    char temp_value[1024];
    strcpy_s(temp_value, sizeof(temp_value), value);
    
    char *token = strtok(temp_value, ",;");
    while (token != NULL && g_ip_whitelist.count < GR_MAX_WHITE_LIST_COUNT) {
        // 去除前后空格
        while (*token == ' ' || *token == '\t') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) *end-- = '\0';
        
        if (strlen(token) > 0) {
            if (parse_ip_range(token, &g_ip_whitelist.entries[g_ip_whitelist.count]) == CM_SUCCESS) {
                g_ip_whitelist.count++;
            } else {
                LOG_RUN_WAR("Invalid IP address in whitelist: %s", token);
            }
        }
        
        token = strtok(NULL, ",;");
    }
    
    LOG_RUN_INF("Loaded %u IP addresses into whitelist", g_ip_whitelist.count);
    
    return CM_SUCCESS;
}

bool32 gr_check_ip_whitelist(const char *client_ip)
{
    return is_ip_in_whitelist(client_ip);
}

static status_t gr_load_mes_with_ip(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MES_WITH_IP");
    if (cm_str_equal_ins(value, "TRUE")) {
        inst_cfg->params.mes_with_ip = CM_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        inst_cfg->params.mes_with_ip = CM_FALSE;
    } else {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "MES_WITH_IP"));
    }
    LOG_DEBUG_INF("MES_WITH_IP status: %u. (0: off, 1: on)", inst_cfg->params.mes_with_ip);
    return CM_SUCCESS;
}

static status_t gr_load_shm_key(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "SHM_KEY");
    // 单个机器上最多允许(1<<GR_MAX_SHM_KEY_BITS)这么多个用户并发使用wr的范围的ipc key，这样是为了防止重叠
    // key组成为: (((基础_SHM_KEY << GR_MAX_SHM_KEY_BITS)      + inst_id) << 16) | 实际的业务id，
    // 实际的业务id具体范围现在分为[1,2][3,18],[19,20496]
    status_t status = cm_str2uint32(value, &inst_cfg->params.shm_key);
    GR_RETURN_IFERR2(status, LOG_RUN_ERR("invalid parameter value of 'SHM_KEY', value:%s.", value));

    if (inst_cfg->params.shm_key < GR_MIN_SHM_KEY || inst_cfg->params.shm_key > GR_MAX_SHM_KEY) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "the value of 'SHM_KEY' is invalid"));
    }
    LOG_RUN_INF("SHM_KEY is %u.", inst_cfg->params.shm_key);
    return CM_SUCCESS;
}

status_t gr_load_delay_clean_interval_core(char *value, gr_config_t *inst_cfg)
{
    uint32_t delay_clean_interval;

    status_t status = cm_str2uint32(value, &delay_clean_interval);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "DELAY_CLEAN_INTERVAL"));

    if (delay_clean_interval < GR_MIN_DELAY_CLEAN_INTERVAL || delay_clean_interval > GR_MAX_DELAY_CLEAN_INTERVAL) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "DELAY_CLEAN_INTERVAL"));
    }
    inst_cfg->params.delay_clean_interval = delay_clean_interval;
    LOG_RUN_INF("DELAY_CLEAN_INTERVAL = %u.", inst_cfg->params.delay_clean_interval);
    return CM_SUCCESS;
}

static status_t gr_load_delay_clean_interval(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "DELAY_CLEAN_INTERVAL");
    return gr_load_delay_clean_interval_core(value, inst_cfg);
}

status_t gr_load_ser_ssl_params(gr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->ssl_ser_config, "SER_SSL_CA");
    status_t status = gr_set_cert_param("SER_SSL_CA", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SER_SSL_CA"));

    value = cm_get_config_value(&inst_cfg->ssl_ser_config, "SER_SSL_KEY");
    status = gr_set_cert_param("SER_SSL_KEY", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SER_SSL_KEY"));

    value = cm_get_config_value(&inst_cfg->ssl_ser_config, "SER_SSL_CERT");
    status = gr_set_cert_param("SER_SSL_CERT", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SER_SSL_CERT"));

    value = cm_get_config_value(&inst_cfg->ssl_ser_config, "SER_SSL_CRL");
    status = gr_set_cert_param("SER_SSL_CRL", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "SER_SSL_CRL"));

    return CM_SUCCESS;
}

status_t gr_load_ser_ssl_config(gr_config_t *inst_cfg)
{
    char file_name[GR_FILE_NAME_BUFFER_SIZE];
    errno_t ret = snprintf_s(file_name, GR_FILE_NAME_BUFFER_SIZE, GR_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        inst_cfg->home, g_gr_ser_config_file);
    if (ret == -1) {
        GR_RETURN_IFERR2(
            CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "failed to load ser params, invalid ser config file path"));
    }

    status_t status = 
        cm_load_config(g_gr_ssl_params, GR_CERT_PARAM_COUNT, file_name, &inst_cfg->ssl_ser_config, CM_FALSE);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "failed to load seri config"));
    CM_RETURN_IFERR(gr_load_ser_ssl_params(inst_cfg));
    return CM_SUCCESS;
}

status_t gr_load_cli_ssl_params()
{
    char *value = cm_get_config_value(&cli_ssl_cfg, "CLI_SSL_CA");
    status_t status = gr_set_cert_param("CLI_SSL_CA", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "CLI_SSL_CA"));

    value = cm_get_config_value(&cli_ssl_cfg, "CLI_SSL_KEY");
    status = gr_set_cert_param("CLI_SSL_KEY", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "CLI_SSL_KEY"));

    value = cm_get_config_value(&cli_ssl_cfg, "CLI_SSL_CERT");
    status = gr_set_cert_param("CLI_SSL_CERT", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "CLI_SSL_CERT"));

    value = cm_get_config_value(&cli_ssl_cfg, "CLI_SSL_CRL");
    status = gr_set_cert_param("CLI_SSL_CRL", value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "CLI_SSL_CRL"));

    return CM_SUCCESS;
}

status_t gr_load_cli_ssl(gr_config_t *inst_cfg)
{
    char file_name[GR_FILE_NAME_BUFFER_SIZE];
    errno_t ret = snprintf_s(file_name, GR_FILE_NAME_BUFFER_SIZE, GR_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        inst_cfg->home, g_gr_cli_config_file);
    if (ret == -1) {
        GR_RETURN_IFERR2(
            CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "failed to load cli params, invalid cli config file path"));
    }

    status_t status =
        cm_load_config(g_gr_ssl_params, GR_CERT_PARAM_COUNT, file_name, &cli_ssl_cfg, CM_FALSE);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "failed to load cli config"));
    CM_RETURN_IFERR(gr_load_cli_ssl_params());
    return CM_SUCCESS;
}

status_t gr_load_config(gr_config_t *inst_cfg)
{
    char file_name[GR_FILE_NAME_BUFFER_SIZE];
    errno_t ret = memset_sp(&inst_cfg->params, sizeof(gr_params_t), 0, sizeof(gr_params_t));
    if (ret != EOK) {
        return CM_ERROR;
    }

    // get config info
    ret = snprintf_s(file_name, GR_FILE_NAME_BUFFER_SIZE, GR_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s", inst_cfg->home,
        g_gr_config_file);
    if (ret == -1) {
        GR_RETURN_IFERR2(
            CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "failed to load params, invalid config file path"));
    }

    status_t status = cm_load_config(g_gr_params, GR_PARAM_COUNT, file_name, &inst_cfg->config, CM_FALSE);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "failed to load config"));
    if (gr_is_server()) {
        status = gr_init_loggers(inst_cfg, gr_get_instance_log_def(), gr_get_instance_log_def_count(), "grserver");
        GR_RETURN_IFERR2(status, (void)printf("%s\nGR init loggers failed!\n", cm_get_errormsg(cm_get_error_code())));
        log_param_t *log_param = cm_log_param_instance();
        log_param->log_instance_starting = CM_TRUE;
    }
    CM_RETURN_IFERR(gr_load_instance_id(inst_cfg));
    CM_RETURN_IFERR(gr_load_session_cfg(inst_cfg));
    CM_RETURN_IFERR(gr_load_mes_params(inst_cfg));
    CM_RETURN_IFERR(gr_load_shm_key(inst_cfg));
    CM_RETURN_IFERR(gr_load_mes_with_ip(inst_cfg));
    CM_RETURN_IFERR(gr_load_ip_white_list_addrs(inst_cfg));
    CM_RETURN_IFERR(gr_load_threadpool_cfg(inst_cfg));
    CM_RETURN_IFERR(gr_load_listen_addr(inst_cfg));
    CM_RETURN_IFERR(gr_load_delay_clean_interval(inst_cfg));
    CM_RETURN_IFERR(gr_load_data_file_path(inst_cfg));
    return CM_SUCCESS;
}

status_t gr_set_ssl_param(const char *param_name, const char *param_value)
{
    if (param_name == NULL) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "the ssl param name should not be null."));
    }
    if ((cm_str_equal(param_name, "SSL_PWD_PLAINTEXT") || cm_str_equal(param_name, "SSL_PWD_CIPHERTEXT")) &&
        strlen(param_value) != 0) {
        LOG_RUN_INF("gr set ssl param, param_name=%s param_value=%s", param_name, "***");
    } else {
        LOG_RUN_INF("gr set ssl param, param_name=%s param_value=%s", param_name, param_value);
    }
    cbb_param_t param_type;
    param_value_t out_value;
    CM_RETURN_IFERR(mes_chk_md_param(param_name, param_value, &param_type, &out_value));
    status_t status = mes_set_md_param(param_type, &out_value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, param_name));
    return CM_SUCCESS;
}

void gr_ssl_ca_cert_expire(void)
{
    if ((g_timer()->systime / SECONDS_PER_DAY) % g_inst_cfg->params.ssl_detect_day == 0) {
        (void)mes_chk_ssl_cert_expire();
    }
}

static status_t gr_set_cfg_param_core(text_t *text, char *value, gr_def_t *def)
{
    bool32 force = CM_TRUE;
    config_item_t *item = cm_get_config_item(&g_inst_cfg->config, text, CM_TRUE);
    if (item == NULL || item->attr != ATTR_NONE) {
        GR_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, def->name));
    }

    if ((item->verify) && (item->verify((void *)value, (void *)def) != CM_SUCCESS)) {
        return CM_ERROR;
    }

    if (def->scope != CONFIG_SCOPE_DISK) {
        if (item->notify && item->notify(NULL, (void *)item, def->value)) {
            return CM_ERROR;
        }
    } else {
        if (item->notify_pfile && item->notify_pfile(NULL, (void *)item, def->value)) {
            return CM_ERROR;
        }
    }

    if (item->attr & ATTR_READONLY) {
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
        force = CM_TRUE;
#else
        force = CM_FALSE;  // can not alter parameter whose attr is readonly  for release
#endif
    }
    if (cm_alter_config(&g_inst_cfg->config, def->name, def->value, def->scope, force) != CM_SUCCESS) {
        return CM_ERROR;
    }
    LOG_RUN_INF("parameter %s has been changed successfully, new value is %s", def->name, value);
    return CM_SUCCESS;
}

static latch_t g_gr_set_cfg_latch = {0, 0, 0, 0, 0};
status_t gr_set_cfg_param(char *name, char *value, char *scope)
{
    CM_ASSERT(name != NULL);
    CM_ASSERT(value != NULL);
    CM_ASSERT(scope != NULL);

    // 1. parse name
    gr_def_t def;
    text_t text = {.str = name, .len = (uint32_t)strlen(name)};
    if (text.len == 0) {
        GR_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, text.str));
    }
    cm_trim_text(&text);
    cm_text_upper(&text);
    CM_RETURN_IFERR(cm_text2str(&text, def.name, CM_PARAM_BUFFER_SIZE));

    // 2. parse scope
    if (strcmp(scope, "memory") == 0) {
        def.scope = CONFIG_SCOPE_MEMORY;
    } else if (strcmp(scope, "pfile") == 0) {
        def.scope = CONFIG_SCOPE_DISK;
    } else {
        def.scope = CONFIG_SCOPE_BOTH;
    }
    gr_latch_x(&g_gr_set_cfg_latch);
    status_t status = gr_set_cfg_param_core(&text, value, &def);
    gr_unlatch(&g_gr_set_cfg_latch);
    return status;
}

status_t gr_get_cfg_param(const char *name, char **value)
{
    CM_ASSERT(name != NULL);
    gr_def_t def;
    text_t text = {.str = (char *)name, .len = (uint32_t)strlen(name)};
    if (text.len == 0) {
        GR_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, text.str));
    }

    cm_trim_text(&text);
    cm_text_upper(&text);
    CM_RETURN_IFERR(cm_text2str(&text, def.name, CM_NAME_BUFFER_SIZE));

    *value = cm_get_config_value(&g_inst_cfg->config, def.name);
    if (*value == NULL) {
        CM_THROW_ERROR(ERR_INVALID_VALUE, name);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t gr_set_cert_param(const char *param_name, const char *param_value)
{
    if (param_name == NULL) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "the ssl param name should not be null."));
    }
    LOG_RUN_INF("gr set ssl param, param_name=%s param_value=%s", param_name, param_value);
    cert_param_t param_type;
    cert_param_value_t out_value;
    CM_RETURN_IFERR(ssl_chk_md_param(param_name, param_value, &param_type, &out_value));
    status_t status = ssl_set_md_param(param_type, &out_value);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, param_name));
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
