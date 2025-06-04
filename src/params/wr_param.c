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
 * wr_param.c
 *
 *
 * IDENTIFICATION
 *    src/params/wr_param.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_errno.h"
#include "cm_num.h"
#include "cm_ip.h"
#include "cm_encrypt.h"
#include "cm_utils.h"
#include "wr_malloc.h"
#include "wr_param_verify.h"
#include "wr_fault_injection.h"
#include "wr_diskgroup.h"
#include "wr_param.h"
#include "wr_diskgroup.h"

#ifdef __cplusplus
extern "C" {
#endif

wr_config_t *g_inst_cfg = NULL;
static wr_config_t g_inst_cfg_inner = {0};
wr_config_t *wr_get_g_inst_cfg()
{
    return &g_inst_cfg_inner;
}

config_t cli_ssl_cfg;

static config_item_t g_wr_ssl_params[] = {
    {"SER_SSL_CA", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 25, EFFECT_REBOOT, CFG_INS,
        NULL, NULL, NULL, NULL},
    {"SER_SSL_KEY", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 26, EFFECT_REBOOT, CFG_INS,
        NULL, NULL, NULL, NULL},
    {"SER_SSL_CERT", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 28, EFFECT_REBOOT, CFG_INS,
        NULL, NULL, NULL, NULL},
    {"CLI_SSL_CA", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 25, EFFECT_REBOOT, CFG_INS,
        NULL, NULL, NULL, NULL},
    {"CLI_SSL_KEY", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 26, EFFECT_REBOOT, CFG_INS,
        NULL, NULL, NULL, NULL},
    {"CLI_SSL_CERT", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 28, EFFECT_REBOOT, CFG_INS,
        NULL, NULL, NULL, NULL},
};

static config_item_t g_wr_params[] = {
    {"SSL_CERT_NOTIFY_TIME", CM_TRUE, ATTR_READONLY, "30", NULL, NULL, "-", "[7,180]", "GS_TYPE_INTEGER", NULL, 0,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"WR_CM_SO_NAME", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 1, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"LOG_HOME", CM_TRUE, CM_TRUE, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 3, EFFECT_REBOOT, CFG_INS, NULL,
        NULL, NULL, NULL},
    {"_LOG_BACKUP_FILE_COUNT", CM_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[0,128]", "GS_TYPE_INTEGER", NULL, 4,
        EFFECT_REBOOT, CFG_INS, wr_verify_log_backup_file_count, wr_notify_log_backup_file_count, NULL, NULL},
    {"_LOG_MAX_FILE_SIZE", CM_TRUE, ATTR_NONE, "256M", NULL, NULL, "-", "[1M,4G]", "GS_TYPE_INTEGER", NULL, 5,
        EFFECT_REBOOT, CFG_INS, wr_verify_log_file_size, wr_notify_log_file_size, NULL, NULL},
    {"INST_ID", CM_TRUE, ATTR_READONLY, "0", NULL, NULL, "-", "[0,64)", "GS_TYPE_INTEGER", NULL, 6, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"_LOG_LEVEL", CM_TRUE, ATTR_NONE, "519", NULL, NULL, "-", "[0,4087]", "GS_TYPE_INTEGER", NULL, 8,
        EFFECT_IMMEDIATELY, CFG_INS, wr_verify_log_level, wr_notify_log_level, NULL, NULL},
    {"MAX_SESSION_NUMS", CM_TRUE, ATTR_READONLY, "8192", NULL, NULL, "-", "[16,16320]", "GS_TYPE_INTEGER", NULL, 9,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"_AUDIT_BACKUP_FILE_COUNT", CM_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[0,128]", "GS_TYPE_INTEGER", NULL, 12,
        EFFECT_REBOOT, CFG_INS, wr_verify_audit_backup_file_count, wr_notify_audit_backup_file_count, NULL, NULL},
    {"_AUDIT_MAX_FILE_SIZE", CM_TRUE, ATTR_NONE, "256M", NULL, NULL, "-", "[1M,4G]", "GS_TYPE_INTEGER", NULL, 13,
        EFFECT_REBOOT, CFG_INS, wr_verify_audit_file_size, wr_notify_audit_file_size, NULL, NULL},
    {"_LOG_FILE_PERMISSIONS", CM_TRUE, ATTR_READONLY, "600", NULL, NULL, "-", "[600-777]", "GS_TYPE_INTEGER", NULL, 14,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"_LOG_PATH_PERMISSIONS", CM_TRUE, ATTR_READONLY, "700", NULL, NULL, "-", "[700-777]", "GS_TYPE_INTEGER", NULL, 15,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"SSL_PWD_CIPHERTEXT", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 16, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"_SHM_KEY", CM_TRUE, ATTR_READONLY, "1", NULL, NULL, "-", "[1,64]", "GS_TYPE_INTEGER", NULL, 17, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"WR_NODES_LIST", CM_TRUE, ATTR_NONE, "0:127.0.0.1:1611", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 18,
        EFFECT_IMMEDIATELY, CFG_INS, wr_verify_nodes_list, wr_notify_wr_nodes_list, NULL, NULL},
    {"INTERCONNECT_TYPE", CM_TRUE, ATTR_READONLY, "TCP", NULL, NULL, "-", "TCP,RDMA", "GS_TYPE_VARCHAR", NULL, 19,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"INTERCONNECT_CHANNEL_NUM", CM_TRUE, ATTR_READONLY, "2", NULL, NULL, "-", "[1,32]", "GS_TYPE_INTEGER", NULL, 20,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"WORK_THREAD_COUNT", CM_TRUE, ATTR_READONLY, "8", NULL, NULL, "-", "[2,64]", "GS_TYPE_INTEGER", NULL, 21,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"RECV_MSG_POOL_SIZE", CM_TRUE, ATTR_READONLY, "48M", NULL, NULL, "-", "[9M,1G]", "GS_TYPE_INTEGER", NULL, 22,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"MES_ELAPSED_SWITCH", CM_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "GS_TYPE_BOOLEAN", NULL, 23,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"SSL_CA", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 25, EFFECT_REBOOT, CFG_INS,
        NULL, NULL, NULL, NULL},
    {"SSL_KEY", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 26, EFFECT_REBOOT, CFG_INS,
        NULL, NULL, NULL, NULL},
    {"SSL_CRL", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 27, EFFECT_REBOOT, CFG_INS,
        NULL, NULL, NULL, NULL},
    {"SSL_CERT", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 28, EFFECT_REBOOT, CFG_INS,
        NULL, NULL, NULL, NULL},
    {"SSL_CIPHER", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 29, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"POOL_NAMES", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 30, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"IMAGE_NAMES", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 31, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"_AUDIT_LEVEL", CM_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[0,255]", "GS_TYPE_INTEGER", NULL, 34,
        EFFECT_IMMEDIATELY, CFG_INS, wr_verify_audit_level, wr_notify_audit_level, NULL, NULL},
    {"SSL_PERIOD_DETECTION", CM_TRUE, ATTR_READONLY, "7", NULL, NULL, "-", "[1,180]", "GS_TYPE_INTEGER", NULL, 35,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"MES_WITH_IP", CM_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "GS_TYPE_BOOLEAN", NULL, 36,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"IP_WHITE_LIST_ON", CM_TRUE, ATTR_READONLY, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "GS_TYPE_BOOLEAN", NULL, 37,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"IO_THREADS", CM_TRUE, ATTR_READONLY, "2", NULL, NULL, "-", "[1,8]", "GS_TYPE_INTEGER", NULL, 38, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"WORK_THREADS", CM_TRUE, ATTR_READONLY, "16", NULL, NULL, "-", "[16,128]", "GS_TYPE_INTEGER", NULL, 39,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"_BLACKBOX_DETAIL_ON", CM_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "GS_TYPE_BOOLEAN", NULL, 40,
        EFFECT_IMMEDIATELY, CFG_INS, wr_verify_blackbox_detail_on, wr_notify_blackbox_detail_on, NULL, NULL},
    {"MES_WAIT_TIMEOUT", CM_TRUE, ATTR_NONE, "10000", NULL, NULL, "-", "[500,30000]", "GS_TYPE_INTEGER", NULL, 43,
        EFFECT_IMMEDIATELY, CFG_INS, wr_verify_mes_wait_timeout, wr_notify_mes_wait_timeout, NULL, NULL},
    {"_ENABLE_CORE_STATE_COLLECT", CM_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "[FALSE,TRUE]", "GS_TYPE_BOOLEAN",
        NULL, 44, EFFECT_IMMEDIATELY, CFG_INS, wr_verify_enable_core_state_collect,
        wr_notify_enable_core_state_collect, NULL, NULL},
    {"DELAY_CLEAN_INTERVAL", CM_TRUE, ATTR_NONE, "5", NULL, NULL, "-", "[5,1000000]", "GS_TYPE_INTEGER", NULL, 45,
        EFFECT_IMMEDIATELY, CFG_INS, wr_verify_delay_clean_interval, wr_notify_delay_clean_interval, NULL, NULL},
    {"LOG_COMPRESSED", CM_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "[FALSE,TRUE]", "GS_TYPE_BOOLEAN", NULL, 56,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"LOG_ALARM_HOME", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 59, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"LISTEN_ADDR", CM_TRUE, ATTR_READONLY, "127.0.0.1:1622", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 62, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"DATA_FILE_PATH", CM_TRUE, ATTR_READONLY, "/tmp", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 24,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
};

static const char *g_wr_config_file = (const char *)"wr_inst.ini";
static const char *g_wr_ser_config_file = (const char *)"wr_ser_inst.ini";
static const char *g_wr_cli_config_file = (const char *)"wr_cli_inst.ini";
#define WR_PARAM_COUNT (sizeof(g_wr_params) / sizeof(config_item_t))
#define WR_CERT_PARAM_COUNT (sizeof(g_wr_ssl_params) / sizeof(config_item_t))

static status_t wr_load_threadpool_cfg(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "IO_THREADS");
    int32_t count = 0;
    status_t status = cm_str2int(value, &count);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "IO_THREADS"));

    if (count < WR_MIN_IOTHREADS_CFG || count > WR_MAX_IOTHREADS_CFG) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "IO_THREADS");
        return CM_ERROR;
    }
    inst_cfg->params.iothread_count = (uint32_t)count;

    value = cm_get_config_value(&inst_cfg->config, "WORK_THREADS");
    status = cm_str2int(value, &count);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "WORK_THREADS"));
    if (count < WR_MIN_WORKTHREADS_CFG || count > WR_MAX_WORKTHREADS_CFG) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "WORK_THREADS");
        return CM_ERROR;
    }
    inst_cfg->params.workthread_count = (uint32_t)count;

    return CM_SUCCESS;
}

static status_t wr_load_session_cfg(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MAX_SESSION_NUMS");
    int32_t sessions;
    status_t status = cm_str2int(value, &sessions);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "MAX_SESSION_NUMS"));

    if (sessions < WR_MIN_SESSIONID_CFG || sessions > WR_MAX_SESSIONS) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "MAX_SESSION_NUMS"));
    }

    inst_cfg->params.cfg_session_num = (uint32_t)sessions;
    return CM_SUCCESS;
}

static status_t wr_load_mes_pool_size(wr_config_t *inst_cfg)
{
    int64 mes_pool_size;
    char *value = cm_get_config_value(&inst_cfg->config, "RECV_MSG_POOL_SIZE");
    status_t status = cm_str2size(value, &mes_pool_size);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "RECV_MSG_POOL_SIZE"));

    inst_cfg->params.mes_pool_size = (uint64)mes_pool_size;
    if ((inst_cfg->params.mes_pool_size < WR_MIN_RECV_MSG_BUFF_SIZE) ||
        (inst_cfg->params.mes_pool_size > WR_MAX_RECV_MSG_BUFF_SIZE)) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "RECV_MSG_POOL_SIZE"));
    }
    LOG_RUN_INF("Cluster Raid mode, mes_pool_size = %lld.", mes_pool_size);
    return CM_SUCCESS;
}

static status_t wr_load_mes_url(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "WR_NODES_LIST");
    return wr_extract_nodes_list(value, &inst_cfg->params.nodes_list);
}

static status_t wr_load_mes_conn_type(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "INTERCONNECT_TYPE");
    if (cm_str_equal_ins(value, "TCP")) {
        inst_cfg->params.pipe_type = CS_TYPE_TCP;
    } else if (cm_str_equal_ins(value, "RDMA")) {
        inst_cfg->params.pipe_type = CS_TYPE_RDMA;
    } else {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "INTERCONNECT_TYPE"));
    }
    LOG_RUN_INF("Cluster Raid mode, pipe type = %u.", inst_cfg->params.pipe_type);
    return CM_SUCCESS;
}

static status_t wr_load_mes_channel_num(wr_config_t *inst_cfg)
{
    uint32_t channel_num;
    char *value = cm_get_config_value(&inst_cfg->config, "INTERCONNECT_CHANNEL_NUM");
    status_t status = cm_str2uint32(value, &channel_num);
    WR_RETURN_IFERR2(
        status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid parameter value of 'INTERCONNECT_CHANNEL_NUM'"));

    if (channel_num < CM_MES_MIN_CHANNEL_NUM || channel_num > CM_MES_MAX_CHANNEL_NUM) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "INTERCONNECT_CHANNEL_NUM"));
    }

    inst_cfg->params.channel_num = channel_num;
    LOG_RUN_INF("Cluster Raid mode, channel_num = %u.", inst_cfg->params.channel_num);
    return CM_SUCCESS;
}

static status_t wr_load_mes_work_thread_cnt(wr_config_t *inst_cfg)
{
    uint32_t work_thread_cnt;
    char *value = cm_get_config_value(&inst_cfg->config, "WORK_THREAD_COUNT");
    status_t status = cm_str2uint32(value, &work_thread_cnt);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid parameter value of 'WORK_THREAD_COUNT'"));

    if (work_thread_cnt < WR_MIN_WORK_THREAD_COUNT || work_thread_cnt > WR_MAX_WORK_THREAD_COUNT) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "WORK_THREAD_COUNT"));
    }

    inst_cfg->params.work_thread_cnt = work_thread_cnt;
    LOG_RUN_INF("Cluster Raid mode, work_thread_cnt = %u.", inst_cfg->params.work_thread_cnt);
    return CM_SUCCESS;
}

static status_t wr_load_mes_elapsed_switch(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MES_ELAPSED_SWITCH");
    if (cm_str_equal_ins(value, "TRUE")) {
        inst_cfg->params.elapsed_switch = CM_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        inst_cfg->params.elapsed_switch = CM_FALSE;
    } else {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "MES_ELAPSED_SWITCH"));
    }

    LOG_RUN_INF("Cluster Raid mode, elapsed_switch = %u.", inst_cfg->params.elapsed_switch);
    return CM_SUCCESS;
}

static status_t wr_load_random_file(uchar *value, int32_t value_len)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    char dir_name[CM_FILE_NAME_BUFFER_SIZE];
    int32_t handle;
    int32_t file_size;
    PRTS_RETURN_IFERR(snprintf_s(
        dir_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/wr_protect", g_inst_cfg->home));
    if (!cm_dir_exist(dir_name)) {
        WR_THROW_ERROR(ERR_WR_FILE_NOT_EXIST, "wr_protect", g_inst_cfg->home);
        return CM_ERROR;
    }
    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/wr_protect/%s",
        g_inst_cfg->home, WR_FKEY_FILENAME));
    WR_RETURN_IF_ERROR(cs_ssl_verify_file_stat(file_name));
    WR_RETURN_IF_ERROR(cm_open_file_ex(file_name, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &handle));
    status_t ret = cm_read_file(handle, value, value_len, &file_size);
    cm_close_file(handle);
    WR_RETURN_IF_ERROR(ret);
    if (file_size < RANDOM_LEN + 1) {
        LOG_DEBUG_ERR("Random component file %s is invalid, size is %d.", file_name, file_size);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t wr_load_data_file_path(wr_config_t *inst_cfg)
{
    int32 ret;
    char *value = cm_get_config_value(&inst_cfg->config, "DATA_FILE_PATH");
    status_t status = wr_verify_lock_file_path(value);
    WR_RETURN_IFERR2(
        status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "failed to load params, invalid DATA_FILE_PATH"));
    ret = snprintf_s(inst_cfg->params.data_file_path, WR_UNIX_PATH_MAX, WR_UNIX_PATH_MAX - 1, "%s", value);
    if (ret == -1) {
        WR_RETURN_IFERR2(
            CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "failed to load params, invalid DATA_FILE_PATH"));
    }

    return CM_SUCCESS;
}

int32_t wr_decrypt_pwd_cb(const char *cipher_text, uint32_t cipher_len, char *plain_text, uint32_t plain_len)
{
    if (cipher_text == NULL) {
        WR_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_DEBUG_ERR("[WR] failed to decrypt SSL cipher: cipher is NULL"));
    }
    if (cipher_len == 0 || cipher_len >= WR_PARAM_BUFFER_SIZE) {
        WR_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_DEBUG_ERR("[WR] failed to decrypt SSL cipher: cipher size [%u] is invalid.", cipher_len));
    }
    if (plain_text == NULL) {
        WR_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_DEBUG_ERR("[WR] failed to decrypt SSL cipher: plain is NULL"));
    }
    if (plain_len < CM_PASSWD_MAX_LEN) {
        WR_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_DEBUG_ERR("[WR] failed to decrypt SSL cipher: plain len [%u] is invalid.", plain_len));
    }
    cipher_t cipher;
    if (cm_base64_decode(cipher_text, cipher_len, (uchar *)&cipher, (uint32_t)(sizeof(cipher_t) + 1)) == 0) {
        WR_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_DEBUG_ERR("[WR] failed to decode SSL cipher."));
    }
    if (cipher.cipher_len > 0) {
        status_t status = wr_load_random_file(cipher.rand, (int32_t)sizeof(cipher.rand));
        WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_VALUE_ERROR, "[WR] load random component failed."));
        status = cm_decrypt_pwd(&cipher, (uchar *)plain_text, &plain_len);
        WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_VALUE_ERROR, "[WR] failed to decrypt ssl pwd."));
    } else {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT");
        LOG_DEBUG_ERR("[WR] failed to decrypt ssl pwd for the cipher len is invalid.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_load_mes_ssl(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "SSL_CA");
    status_t status = wr_set_ssl_param("SSL_CA", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SSL_CA"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_KEY");
    status = wr_set_ssl_param("SSL_KEY", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SSL_KEY"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CRL");
    status = wr_set_ssl_param("SSL_CRL", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SSL_CRL"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CERT");
    status = wr_set_ssl_param("SSL_CERT", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SSL_CERT"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CIPHER");
    status = wr_set_ssl_param("SSL_CIPHER", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SSL_CIPHER"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CERT_NOTIFY_TIME");
    status = wr_set_ssl_param("SSL_CERT_NOTIFY_TIME", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SSL_CERT_NOTIFY_TIME"));
    uint32_t alert_value;
    status = cm_str2uint32(value, &alert_value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SSL_CERT_NOTIFY_TIME"));
    value = cm_get_config_value(&inst_cfg->config, "SSL_PERIOD_DETECTION");
    status = cm_str2uint32(value, &inst_cfg->params.ssl_detect_day);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SSL_PERIOD_DETECTION"));
    if (inst_cfg->params.ssl_detect_day > WR_MAX_SSL_PERIOD_DETECTION ||
        inst_cfg->params.ssl_detect_day < WR_MIN_SSL_PERIOD_DETECTION) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SSL_PERIOD_DETECTION");
        return CM_ERROR;
    }
    if (inst_cfg->params.ssl_detect_day > alert_value) {
        WR_THROW_ERROR_EX(ERR_WR_INVALID_PARAM,
            "SSL disabled: the value of SSL_PERIOD_DETECTION which is %u is "
            "bigger than the value of SSL_CERT_NOTIFY_TIME which is %u.",
            inst_cfg->params.ssl_detect_day, alert_value);
        return CM_ERROR;
    }
    value = cm_get_config_value(&inst_cfg->config, "SSL_PWD_CIPHERTEXT");
    status = wr_set_ssl_param("SSL_PWD_CIPHERTEXT", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"));

    if (!CM_IS_EMPTY_STR(value)) {
        return mes_register_decrypt_pwd(wr_decrypt_pwd_cb);
    }
    return CM_SUCCESS;
}

static status_t wr_load_mes_wait_timeout(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MES_WAIT_TIMEOUT");
    int32_t timeout = 0;
    status_t status = cm_str2int(value, &timeout);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "MES_WAIT_TIMEOUT"));
    if (timeout < WR_MES_MIN_WAIT_TIMEOUT || timeout > WR_MES_MAX_WAIT_TIMEOUT) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "MES_WAIT_TIMEOUT");
        return CM_ERROR;
    }
    inst_cfg->params.mes_wait_timeout = (uint32_t)timeout;
    return CM_SUCCESS;
}

static status_t wr_load_mes_params(wr_config_t *inst_cfg)
{
    CM_RETURN_IFERR(wr_load_mes_url(inst_cfg));
    CM_RETURN_IFERR(wr_load_mes_conn_type(inst_cfg));
    CM_RETURN_IFERR(wr_load_mes_channel_num(inst_cfg));
    CM_RETURN_IFERR(wr_load_mes_work_thread_cnt(inst_cfg));
    CM_RETURN_IFERR(wr_load_mes_pool_size(inst_cfg));
    CM_RETURN_IFERR(wr_load_mes_elapsed_switch(inst_cfg));
    CM_RETURN_IFERR(wr_load_mes_ssl(inst_cfg));
    CM_RETURN_IFERR(wr_load_mes_wait_timeout(inst_cfg));
    return CM_SUCCESS;
}

static status_t wr_load_listen_addr(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "LISTEN_ADDR");
    if (value == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "LISTEN_ADDR is not set");
        return CM_ERROR;
    }

    char buffer[256];
    strncpy(buffer, value, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *colon_pos = strchr(buffer, ':');
    if (colon_pos == NULL) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "LISTEN_ADDR format is invalid, expected IP:Port");
        return CM_ERROR;
    }

    *colon_pos = '\0';
    char *ip = buffer;
    char *port_str = colon_pos + 1;

    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "Port number is invalid");
        return CM_ERROR;
    }

    strncpy(inst_cfg->params.listen_addr.host, ip, sizeof(inst_cfg->params.listen_addr.host) - 1);
    inst_cfg->params.listen_addr.host[sizeof(inst_cfg->params.listen_addr.host) - 1] = '\0';
    inst_cfg->params.listen_addr.port = port;

    return CM_SUCCESS;
}

status_t wr_set_cfg_dir(const char *home, wr_config_t *inst_cfg)
{
    char home_realpath[WR_MAX_PATH_BUFFER_SIZE];
    bool8 is_home_empty = (home == NULL || home[0] == '\0');
    if (is_home_empty) {
        const char *home_env = getenv(WR_ENV_HOME);
        if (home_env == NULL || home_env[0] == '\0') {
            WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid cfg dir"));
        }
        uint32_t len = (uint32_t)strlen(home_env);
        if (len >= WR_MAX_PATH_BUFFER_SIZE) {
            WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid cfg dir len"));
        }
        status_t status = realpath_file(home_env, home_realpath, WR_MAX_PATH_BUFFER_SIZE);
        WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid cfg dir"));

    } else {
        uint32_t len = (uint32_t)strlen(home);
        if (len >= WR_MAX_PATH_BUFFER_SIZE) {
            WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "invalid cfg dir");
            return CM_ERROR;
        }
    }
    int32_t iret_snprintf = snprintf_s(inst_cfg->home, WR_MAX_PATH_BUFFER_SIZE, WR_MAX_PATH_BUFFER_SIZE - 1, "%s",
        is_home_empty ? home_realpath : home);
    WR_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);

    g_inst_cfg = inst_cfg;
    return CM_SUCCESS;
}

static status_t wr_load_instance_id(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "INST_ID");
    status_t status = cm_str2bigint(value, &inst_cfg->params.inst_id);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "the value of 'INST_ID' is invalid"));

    if (inst_cfg->params.inst_id < WR_MIN_INST_ID || inst_cfg->params.inst_id >= WR_MAX_INST_ID) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "the value of 'INST_ID' is invalid"));
    }

    LOG_RUN_INF("The instanceid is %lld.", inst_cfg->params.inst_id);
    return CM_SUCCESS;
}

static status_t wr_load_ip_white_list(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "IP_WHITE_LIST_ON");
    if (cm_str_equal_ins(value, "TRUE")) {
        inst_cfg->params.ip_white_list_on = CM_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        inst_cfg->params.ip_white_list_on = CM_FALSE;
    } else {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "value of IP_WHITE_LIST_ON is invalid"));
    }
    LOG_DEBUG_INF("IP_WHITE_LIST status: %u. (0: off, 1: on)", inst_cfg->params.ip_white_list_on);
    return CM_SUCCESS;
}

static status_t wr_load_mes_with_ip(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MES_WITH_IP");
    if (cm_str_equal_ins(value, "TRUE")) {
        inst_cfg->params.mes_with_ip = CM_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        inst_cfg->params.mes_with_ip = CM_FALSE;
    } else {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "MES_WITH_IP"));
    }
    LOG_DEBUG_INF("MES_WITH_IP status: %u. (0: off, 1: on)", inst_cfg->params.mes_with_ip);
    return CM_SUCCESS;
}

static status_t wr_load_shm_key(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "_SHM_KEY");
    // 单个机器上最多允许(1<<WR_MAX_SHM_KEY_BITS)这么多个用户并发使用wr的范围的ipc key，这样是为了防止重叠
    // key组成为: (((基础_SHM_KEY << WR_MAX_SHM_KEY_BITS)      + inst_id) << 16) | 实际的业务id，
    // 实际的业务id具体范围现在分为[1,2][3,18],[19,20496]
    status_t status = cm_str2uint32(value, &inst_cfg->params.shm_key);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("invalid parameter value of '_SHM_KEY', value:%s.", value));

    if (inst_cfg->params.shm_key < WR_MIN_SHM_KEY || inst_cfg->params.shm_key > WR_MAX_SHM_KEY) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "the value of '_SHM_KEY' is invalid"));
    }
    LOG_RUN_INF("_SHM_KEY is %u.", inst_cfg->params.shm_key);
    return CM_SUCCESS;
}

static status_t wr_load_blackbox_detail_on(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "_BLACKBOX_DETAIL_ON");
    return wr_load_blackbox_detail_on_inner(value, inst_cfg);
}

static status_t wr_load_enable_core_state_collect(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "_ENABLE_CORE_STATE_COLLECT");
    return wr_load_enable_core_state_collect_inner(value, inst_cfg);
}

status_t wr_load_delay_clean_interval_core(char *value, wr_config_t *inst_cfg)
{
    uint32_t delay_clean_interval;

    status_t status = cm_str2uint32(value, &delay_clean_interval);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "DELAY_CLEAN_INTERVAL"));

    if (delay_clean_interval < WR_MIN_DELAY_CLEAN_INTERVAL || delay_clean_interval > WR_MAX_DELAY_CLEAN_INTERVAL) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "DELAY_CLEAN_INTERVAL"));
    }
    inst_cfg->params.delay_clean_interval = delay_clean_interval;
    LOG_RUN_INF("DELAY_CLEAN_INTERVAL = %u.", inst_cfg->params.delay_clean_interval);
    return CM_SUCCESS;
}

static status_t wr_load_delay_clean_interval(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "DELAY_CLEAN_INTERVAL");
    return wr_load_delay_clean_interval_core(value, inst_cfg);
}

status_t wr_load_ser_ssl_params(wr_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->ssl_ser_config, "SER_SSL_CA");
    status_t status = wr_set_cert_param("SER_SSL_CA", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SER_SSL_CA"));

    value = cm_get_config_value(&inst_cfg->ssl_ser_config, "SER_SSL_KEY");
    status = wr_set_cert_param("SER_SSL_KEY", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SER_SSL_KEY"));

    value = cm_get_config_value(&inst_cfg->ssl_ser_config, "SER_SSL_CERT");
    status = wr_set_cert_param("SER_SSL_CERT", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "SER_SSL_CERT"));

    return CM_SUCCESS;
}

status_t wr_load_ser_ssl_config(wr_config_t *inst_cfg)
{
    char file_name[WR_FILE_NAME_BUFFER_SIZE];
    errno_t ret = snprintf_s(file_name, WR_FILE_NAME_BUFFER_SIZE, WR_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        inst_cfg->home, g_wr_ser_config_file);
    if (ret == -1) {
        WR_RETURN_IFERR2(
            CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "failed to load ser params, invalid ser config file path"));
    }

    status_t status = 
        cm_load_config(g_wr_ssl_params, WR_CERT_PARAM_COUNT, file_name, &inst_cfg->ssl_ser_config, CM_FALSE);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "failed to load seri config"));
    CM_RETURN_IFERR(wr_load_ser_ssl_params(inst_cfg));
    return CM_SUCCESS;
}

status_t wr_load_cli_ssl_params()
{
    char *value = cm_get_config_value(&cli_ssl_cfg, "CLI_SSL_CA");
    status_t status = wr_set_cert_param("CLI_SSL_CA", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "CLI_SSL_CA"));

    value = cm_get_config_value(&cli_ssl_cfg, "CLI_SSL_KEY");
    status = wr_set_cert_param("CLI_SSL_KEY", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "CLI_SSL_KEY"));

    value = cm_get_config_value(&cli_ssl_cfg, "CLI_SSL_CERT");
    status = wr_set_cert_param("CLI_SSL_CERT", value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "CLI_SSL_CERT"));

    return CM_SUCCESS;
}

status_t wr_load_cli_ssl()
{
    char file_name[WR_FILE_NAME_BUFFER_SIZE];
    char *path = getenv(WR_ENV_HOME);
    errno_t ret = snprintf_s(file_name, WR_FILE_NAME_BUFFER_SIZE, WR_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        path, g_wr_cli_config_file);
    if (ret == -1) {
        WR_RETURN_IFERR2(
            CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "failed to load cli params, invalid cli config file path"));
    }

    status_t status =
        cm_load_config(g_wr_ssl_params, WR_CERT_PARAM_COUNT, file_name, &cli_ssl_cfg, CM_FALSE);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "failed to load cli config"));
    CM_RETURN_IFERR(wr_load_cli_ssl_params());
    return CM_SUCCESS;
}

status_t wr_load_config(wr_config_t *inst_cfg)
{
    char file_name[WR_FILE_NAME_BUFFER_SIZE];
    errno_t ret = memset_sp(&inst_cfg->params, sizeof(wr_params_t), 0, sizeof(wr_params_t));
    if (ret != EOK) {
        return CM_ERROR;
    }

    // get config info
    ret = snprintf_s(file_name, WR_FILE_NAME_BUFFER_SIZE, WR_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s", inst_cfg->home,
        g_wr_config_file);
    if (ret == -1) {
        WR_RETURN_IFERR2(
            CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "failed to load params, invalid config file path"));
    }

    status_t status = cm_load_config(g_wr_params, WR_PARAM_COUNT, file_name, &inst_cfg->config, CM_FALSE);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "failed to load config"));
    if (wr_is_server()) {
        status = wr_init_loggers(inst_cfg, wr_get_instance_log_def(), wr_get_instance_log_def_count(), "wrserver");
        WR_RETURN_IFERR2(status, (void)printf("%s\nWR init loggers failed!\n", cm_get_errormsg(cm_get_error_code())));
        log_param_t *log_param = cm_log_param_instance();
        log_param->log_instance_starting = CM_TRUE;
    }
    CM_RETURN_IFERR(wr_load_instance_id(inst_cfg));
    CM_RETURN_IFERR(wr_load_session_cfg(inst_cfg));
    CM_RETURN_IFERR(wr_load_mes_params(inst_cfg));
    CM_RETURN_IFERR(wr_load_shm_key(inst_cfg));
    CM_RETURN_IFERR(wr_load_mes_with_ip(inst_cfg));
    CM_RETURN_IFERR(wr_load_ip_white_list(inst_cfg));
    CM_RETURN_IFERR(wr_load_threadpool_cfg(inst_cfg));
    CM_RETURN_IFERR(wr_load_blackbox_detail_on(inst_cfg));
    CM_RETURN_IFERR(wr_load_listen_addr(inst_cfg));
    CM_RETURN_IFERR(wr_load_enable_core_state_collect(inst_cfg));
    CM_RETURN_IFERR(wr_load_delay_clean_interval(inst_cfg));
    CM_RETURN_IFERR(wr_load_data_file_path(inst_cfg));
    return CM_SUCCESS;
}

status_t wr_set_ssl_param(const char *param_name, const char *param_value)
{
    if (param_name == NULL) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "the ssl param name should not be null."));
    }
    if ((cm_str_equal(param_name, "SSL_PWD_PLAINTEXT") || cm_str_equal(param_name, "SSL_PWD_CIPHERTEXT")) &&
        strlen(param_value) != 0) {
        LOG_RUN_INF("wr set ssl param, param_name=%s param_value=%s", param_name, "***");
    } else {
        LOG_RUN_INF("wr set ssl param, param_name=%s param_value=%s", param_name, param_value);
    }
    cbb_param_t param_type;
    param_value_t out_value;
    CM_RETURN_IFERR(mes_chk_md_param(param_name, param_value, &param_type, &out_value));
    status_t status = mes_set_md_param(param_type, &out_value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, param_name));
    return CM_SUCCESS;
}

void wr_ssl_ca_cert_expire(void)
{
    if ((g_timer()->systime / SECONDS_PER_DAY) % g_inst_cfg->params.ssl_detect_day == 0) {
        (void)mes_chk_ssl_cert_expire();
    }
}

static status_t wr_set_cfg_param_core(text_t *text, char *value, wr_def_t *def)
{
    bool32 force = CM_TRUE;
    config_item_t *item = cm_get_config_item(&g_inst_cfg->config, text, CM_TRUE);
    if (item == NULL || item->attr != ATTR_NONE) {
        WR_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, def->name));
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

static latch_t g_wr_set_cfg_latch = {0, 0, 0, 0, 0};
status_t wr_set_cfg_param(char *name, char *value, char *scope)
{
    CM_ASSERT(name != NULL);
    CM_ASSERT(value != NULL);
    CM_ASSERT(scope != NULL);

    // 1. parse name
    wr_def_t def;
    text_t text = {.str = name, .len = (uint32_t)strlen(name)};
    if (text.len == 0) {
        WR_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, text.str));
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
    wr_latch_x(&g_wr_set_cfg_latch);
    status_t status = wr_set_cfg_param_core(&text, value, &def);
    wr_unlatch(&g_wr_set_cfg_latch);
    return status;
}

status_t wr_get_cfg_param(const char *name, char **value)
{
    CM_ASSERT(name != NULL);
    wr_def_t def;
    text_t text = {.str = (char *)name, .len = (uint32_t)strlen(name)};
    if (text.len == 0) {
        WR_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, text.str));
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

status_t wr_set_cert_param(const char *param_name, const char *param_value)
{
    if (param_name == NULL) {
        WR_RETURN_IFERR2(CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "the ssl param name should not be null."));
    }
    LOG_RUN_INF("wr set ssl param, param_name=%s param_value=%s", param_name, param_value);
    cert_param_t param_type;
    cert_param_value_t out_value;
    CM_RETURN_IFERR(ssl_chk_md_param(param_name, param_value, &param_type, &out_value));
    status_t status = ssl_set_md_param(param_type, &out_value);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, param_name));
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
