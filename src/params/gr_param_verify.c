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
#include "gr_fault_injection.h"
#include "gr_param_verify.h"

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

    if (num > MAX_LOG_LEVEL) {
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

#ifdef __cplusplus
}
#endif