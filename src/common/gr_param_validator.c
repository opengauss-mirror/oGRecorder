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
 * -------------------------------------------------------------------------
 *
 * gr_param_validator.c
 *
 * IDENTIFICATION
 *    src/common/gr_param_validator.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_param_validator.h"
#include "gr_error_handler.h"
#include "gr_log.h"
#include <string.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

static bool32 is_letter(char c)
{
    return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
}

static bool32 is_number(char c)
{
    return (c >= '0' && c <= '9');
}

bool32 gr_is_valid_name_char(char c)
{
    return (is_number(c) || is_letter(c) || c == '_' || c == '.' || c == '-') ? CM_TRUE : CM_FALSE;
}

bool32 gr_is_valid_path_char(char c)
{
    return (c == '/' || gr_is_valid_name_char(c)) ? CM_TRUE : CM_FALSE;
}

status_t gr_validate_string(const char *str, size_t max_len, const char *param_name)
{
    if (str == NULL) {
        GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "%s is NULL", param_name);
    }
    
    if (str[0] == '\0') {
        GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "%s is empty", param_name);
    }
    
    if (max_len > 0) {
        size_t len = strlen(str);
        if (len >= max_len) {
            GR_PARAM_ERROR_RETURN(ERR_GR_STRING_TOO_LONG, "%s is too long: %zu (max: %zu)", param_name, len, max_len - 1);
        }
    }
    
    return CM_SUCCESS;
}

status_t gr_validate_file_name(const char *name)
{
    GR_RETURN_IF_ERROR(gr_validate_string(name, GR_MAX_NAME_LEN, "file name"));
    
    // Check for invalid characters
    const char *invalid_chars = "\\:*?\"<>|";
    if (strpbrk(name, invalid_chars) != NULL) {
        GR_PARAM_ERROR_RETURN(ERR_GR_FILE_PATH_ILL, "file name contains invalid characters: %s", name);
    }
    
    // Check each character
    for (const char *p = name; *p != '\0'; p++) {
        if (!gr_is_valid_name_char(*p)) {
            GR_PARAM_ERROR_RETURN(ERR_GR_FILE_PATH_ILL, "file name contains invalid character: '%c'", *p);
        }
    }
    
    return CM_SUCCESS;
}

status_t gr_validate_path(const char *path, size_t max_len)
{
    GR_RETURN_IF_ERROR(gr_validate_string(path, max_len, "path"));
    
    // Check path length
    size_t len = strlen(path);
    if (len >= max_len) {
        GR_PARAM_ERROR_RETURN(ERR_GR_STRING_TOO_LONG, "path is too long: %zu (max: %zu)", len, max_len - 1);
    }
    
    return CM_SUCCESS;
}

status_t gr_validate_pointer(const void *ptr, const char *param_name)
{
    if (ptr == NULL) {
        GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "%s pointer is NULL", param_name);
    }
    return CM_SUCCESS;
}

status_t gr_validate_size(int64 size, int64 max_size, const char *param_name)
{
    if (size < 0) {
        GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "%s is negative: %lld", param_name, size);
    }
    
    if (max_size > 0 && size > max_size) {
        GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "%s exceeds maximum: %lld (max: %lld)", param_name, size, max_size);
    }
    
    return CM_SUCCESS;
}

status_t gr_validate_ip(const char *ip)
{
    GR_RETURN_IF_ERROR(gr_validate_string(ip, 0, "IP address"));
    
    // Simple IP validation (can be enhanced)
    int dots = 0;
    int digits = 0;
    
    for (const char *p = ip; *p != '\0'; p++) {
        if (*p == '.') {
            if (digits == 0 || digits > 3) {
                GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "Invalid IP address format: %s", ip);
            }
            dots++;
            digits = 0;
        } else if (isdigit((unsigned char)*p)) {
            digits++;
            if (digits > 3) {
                GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "Invalid IP address format: %s", ip);
            }
        } else {
            GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "Invalid IP address format: %s", ip);
        }
    }
    
    if (dots != 3 || digits == 0 || digits > 3) {
        GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "Invalid IP address format: %s", ip);
    }
    
    return CM_SUCCESS;
}

status_t gr_validate_port(uint32_t port)
{
    if (port == 0 || port > 65535) {
        GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "Invalid port number: %u (valid range: 1-65535)", port);
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
