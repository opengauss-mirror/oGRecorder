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
 * gr_path_utils.c
 *
 * IDENTIFICATION
 *    src/common/gr_path_utils.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_path_utils.h"
#include "gr_param.h"
#include "gr_error_handler.h"
#include "gr_log.h"
#include "gr_config_mgr.h"
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *gr_get_base_path(void)
{
    gr_config_t *cfg = gr_cfg_get_inst();
    if (cfg == NULL || cfg->params.data_file_path == NULL) {
        return NULL;
    }
    return cfg->params.data_file_path;
}

status_t gr_build_path(char *buf, size_t buf_size, const char *base_path, const char *name)
{
    if (buf == NULL || buf_size == 0) {
        return CM_ERROR;
    }
    
    if (base_path == NULL || name == NULL) {
        if (buf != NULL && buf_size > 0) {
            buf[0] = '\0';
        }
        return CM_ERROR;
    }
    
    // Trim trailing slashes from base_path
    size_t base_len = strlen(base_path);
    while (base_len > 0 && base_path[base_len - 1] == '/') {
        base_len--;
    }
    
    // Trim leading slashes from name
    const char *name_start = name;
    while (*name_start == '/') {
        name_start++;
    }
    
    // Build path: base_path/name
    int ret = snprintf_s(buf, buf_size, buf_size - 1, "%.*s/%s", (int)base_len, base_path, name_start);
    if (ret < 0 || ret >= (int)buf_size) {
        LOG_RUN_ERR("[PATH] gr_build_path snprintf_s failed or truncated: %d (buffer size: %zu)", ret, buf_size);
        if (buf_size > 0 && buf != NULL) {
            buf[0] = '\0';
        }
        return CM_ERROR;
    }
    
    return CM_SUCCESS;
}

status_t gr_normalize_path(char *path, size_t path_size)
{
    if (path == NULL || path_size == 0) {
        return CM_ERROR;
    }
    
    // Remove redundant slashes (keep single slash)
    char *dst = path;
    const char *src = path;
    bool prev_slash = false;
    
    while (*src != '\0' && (size_t)(dst - path) < path_size - 1) {
        if (*src == '/') {
            if (!prev_slash) {
                *dst++ = '/';
                prev_slash = true;
            }
        } else {
            *dst++ = *src;
            prev_slash = false;
        }
        src++;
    }
    *dst = '\0';
    
    return CM_SUCCESS;
}

bool32 gr_is_valid_path(const char *path, size_t max_len)
{
    if (path == NULL || path[0] == '\0') {
        return CM_FALSE;
    }
    
    size_t len = strlen(path);
    if (len >= max_len) {
        return CM_FALSE;
    }
    
    return CM_TRUE;
}

void gr_get_fs_path(const char *name, char *buf, size_t buf_size)
{
    if (name == NULL || buf == NULL || buf_size == 0) {
        if (buf != NULL && buf_size > 0) {
            buf[0] = '\0';
        }
        return;
    }
    
    const char *base_path = gr_get_base_path();
    if (base_path == NULL) {
        LOG_RUN_ERR("[PATH] gr_get_fs_path: base path is NULL");
        if (buf_size > 0 && buf != NULL) {
            buf[0] = '\0';
        }
        return;
    }
    
    if (gr_build_path(buf, buf_size, base_path, name) != CM_SUCCESS) {
        if (buf_size > 0 && buf != NULL) {
            buf[0] = '\0';
        }
    }
}

#ifdef __cplusplus
}
#endif
