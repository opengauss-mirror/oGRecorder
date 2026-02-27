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
 * gr_path_utils.h
 *
 * IDENTIFICATION
 *    src/common/gr_path_utils.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_PATH_UTILS_H__
#define __GR_PATH_UTILS_H__

#include "cm_defs.h"
#include "gr_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build full path from base path and name
 * Automatically handles path separators and prevents double slashes
 * 
 * @param buf Output buffer for the full path
 * @param buf_size Size of the output buffer
 * @param base_path Base path (e.g., data file path)
 * @param name File or directory name
 * @return CM_SUCCESS on success, CM_ERROR on failure
 */
status_t gr_build_path(char *buf, size_t buf_size, const char *base_path, const char *name);

/**
 * Get filesystem base path (cached)
 * Returns the data file path from configuration
 * 
 * @return Base path string, or NULL if not configured
 */
const char *gr_get_base_path(void);

/**
 * Normalize path by removing redundant separators and resolving relative paths
 * 
 * @param path Path to normalize (modified in place)
 * @param path_size Size of the path buffer
 * @return CM_SUCCESS on success, CM_ERROR on failure
 */
status_t gr_normalize_path(char *path, size_t path_size);

/**
 * Check if path is valid (not empty, not too long)
 * 
 * @param path Path to check
 * @param max_len Maximum allowed length
 * @return CM_TRUE if valid, CM_FALSE otherwise
 */
bool32 gr_is_valid_path(const char *path, size_t max_len);

/**
 * Get filesystem path for a given name (wrapper for backward compatibility)
 * This function uses gr_build_path internally
 * 
 * @param name File or directory name
 * @param buf Output buffer
 * @param buf_size Size of output buffer
 */
void gr_get_fs_path(const char *name, char *buf, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif /* __GR_PATH_UTILS_H__ */
