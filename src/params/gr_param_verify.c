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
 * gr_param_verify.c
 *
 *
 * IDENTIFICATION
 *    src/params/gr_param_verify.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_num.h"
#include "cm_utils.h"
#include "gr_defs.h"
#include "gr_errno.h"
#include "gr_param.h"
#include "gr_log.h"
#include "gr_fault_injection.h"
#include "gr_param_verify.h"
#include <pthread.h>

// keep in sync with definitions in gr_param.c
#define GR_MAX_WHITE_LIST_COUNT 64

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

// externs from gr_param.c
extern void trim_whitespace(char *str);
extern status_t parse_ip_range(const char *ip_str, ip_whitelist_entry_t *entry);
extern ip_whitelist_t g_ip_whitelist;
extern pthread_rwlock_t g_ip_whitelist_lock;

#ifdef __cplusplus
extern "C" {
#endif

status_t gr_verify_log_level(void *lex, void *def)
{
    char *value = (char *)lex;
    uint32_t num;
    text_t text = {.str = value, .len = (uint32_t)strlen(value)};
    cm_trim_text(&text);
    status_t status = cm_text2uint32(&text, &num);
    GR_RETURN_IFERR2(status, CM_THROW_ERROR(ERR_INVALID_PARAM, "LOG_LEVEL"));

    if (num > GR_MAX_LOG_LEVEL) {
        GR_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "LOG_LEVEL"));
    }

    int32_t iret_snprintf =
        snprintf_s(((gr_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT32, num);
    GR_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t gr_notify_log_level(void *se, void *item, char *value)
{
    CM_RETURN_IFERR(cm_str2uint32(value, (uint32_t *)&cm_log_param_instance()->log_level));
    return CM_SUCCESS;
}


status_t gr_verify_lock_file_path(char *path)
{
    char input_path_buffer[GR_UNIX_PATH_MAX];
    char *input_path = NULL;
    uint32_t len;
    len = (uint32_t)strlen(path);
    if (len == 0 || len >= GR_UNIX_PATH_MAX) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_INVALID_FILE_NAME, path, GR_UNIX_PATH_MAX));
    }

    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_INVALID_DIR, path));
    }

    input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path, GR_UNIX_PATH_MAX, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= CM_SINGLE_QUOTE_LEN;
    }

    if (len == 0 || input_path[0] == ' ') {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_INVALID_DIR, path));
    }

    input_path[len] = '\0';
    if (cm_check_exist_special_char(input_path, len)) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_INVALID_DIR, input_path));
    }

    char buffer_path[GR_UNIX_PATH_MAX];
    CM_RETURN_IFERR(realpath_file(input_path, buffer_path, GR_UNIX_PATH_MAX));
    if (!cm_dir_exist(input_path) || (access(buffer_path, W_OK | R_OK) != 0)) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_INVALID_DIR, input_path));
    }
    return CM_SUCCESS;
}

status_t gr_verify_log_file_dir_name(char *path)
{
    char input_path_buffer[CM_MAX_LOG_HOME_LEN];
    char *input_path = NULL;
    uint32_t len;
    len = (uint32_t)strlen(path);
    if (len == 0 || len >= CM_MAX_LOG_HOME_LEN) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_INVALID_FILE_NAME, path, CM_MAX_LOG_HOME_LEN));
    }

    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_INVALID_DIR, path));
    }

    input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path, CM_MAX_LOG_HOME_LEN, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= CM_SINGLE_QUOTE_LEN;
    }

    if (len == 0 || input_path[0] == ' ') {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_INVALID_DIR, path));
    }

    input_path[len] = '\0';
    if (cm_check_exist_special_char(input_path, len)) {
        GR_RETURN_IFERR2(CM_ERROR, GR_THROW_ERROR(ERR_INVALID_DIR, input_path));
    }
    return CM_SUCCESS;
}

status_t gr_verify_log_file_real_path(char *path)
{
    char real_path[CM_MAX_LOG_HOME_LEN] = {0};
    CM_RETURN_IFERR(realpath_file(path, real_path, CM_MAX_LOG_HOME_LEN));
    if (!cm_dir_exist(path) && cm_create_dir_ex(path) != CM_SUCCESS) {
        GR_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_DIR, path));
    }
    if (access(path, W_OK | R_OK) != 0) {
        GR_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_DIR, path));
    }
    return CM_SUCCESS;
}

status_t gr_verify_log_backup_file_count(void *lex, void *def)
{
    char *value = (char *)lex;
    uint32_t num;
    text_t text = {.str = value, .len = (uint32_t)strlen(value)};
    cm_trim_text(&text);
    status_t status = cm_text2uint32(&text, &num);
    GR_RETURN_IFERR2(status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "LOG_FILE_COUNT"));
#ifdef OPENGAUSS
    if (num > CM_MAX_LOG_FILE_COUNT_LARGER) {
#else
    if (num > CM_MAX_LOG_FILE_COUNT) {
#endif
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "LOG_FILE_COUNT");
        return CM_ERROR;
    }

    int32_t iret_snprintf =
        snprintf_s(((gr_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT32, num);
    GR_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t gr_notify_log_backup_file_count(void *se, void *item, char *value)
{
    CM_RETURN_IFERR(cm_str2uint32(value, (uint32_t *)&cm_log_param_instance()->log_backup_file_count));
    return CM_SUCCESS;
}

status_t gr_verify_ip_white_list(void *lex, void *def)
{
    const char *value = (const char *)lex;
    if (value == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "IP_WHITE_LIST is NULL");
        return CM_ERROR;
    }

    size_t len = strlen(value);
    if (len >= CM_PARAM_BUFFER_SIZE) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "IP_WHITE_LIST length too large");
        return CM_ERROR;
    }

    // 只做长度校验和拷贝，具体 IP 语法在解析阶段由 parse_ip_range 再次校验
    securec_check_ret(strcpy_sp(((gr_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, value));
    return CM_SUCCESS;
}

status_t gr_notify_ip_white_list(void *se, void *item, char *value)
{
    (void)se;
    (void)item;

    if (value == NULL) {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "IP_WHITE_LIST is NULL");
        return CM_ERROR;
    }

    // 直接基于新的字符串 value 重建 g_ip_whitelist
    pthread_rwlock_wrlock(&g_ip_whitelist_lock);
    g_ip_whitelist.count = 0;

    char temp_value[1024];
    securec_check_ret(strcpy_s(temp_value, sizeof(temp_value), value));

    char *token = strtok(temp_value, ",;");
    while (token != NULL && g_ip_whitelist.count < GR_MAX_WHITE_LIST_COUNT) {
        trim_whitespace(token);

        if (strlen(token) > 0) {
            if (parse_ip_range(token, &g_ip_whitelist.entries[g_ip_whitelist.count]) == CM_SUCCESS) {
                g_ip_whitelist.count++;
            } else {
                LOG_RUN_WAR("Invalid IP address in whitelist (dynamic): %s", token);
            }
        }

        token = strtok(NULL, ",;");
    }

    LOG_RUN_INF("Dynamically loaded %u IP addresses into whitelist", g_ip_whitelist.count);
    pthread_rwlock_unlock(&g_ip_whitelist_lock);
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif