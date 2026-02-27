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
 * gr_error_handler.h
 *
 * IDENTIFICATION
 *    src/common/gr_error_handler.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_ERROR_HANDLER_H__
#define __GR_ERROR_HANDLER_H__

#include "cm_error.h"
#include "gr_errno.h"
#include "gr_log.h"
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Error category for better error classification
 */
typedef enum {
    GR_ERR_CATEGORY_SYSTEM,      // System call errors (errno-based)
    GR_ERR_CATEGORY_PARAM,       // Parameter validation errors
    GR_ERR_CATEGORY_RESOURCE,    // Resource errors (memory, file, etc.)
    GR_ERR_CATEGORY_NETWORK,     // Network errors
    GR_ERR_CATEGORY_FILESYSTEM,  // Filesystem errors
    GR_ERR_CATEGORY_CONFIG,       // Configuration errors
    GR_ERR_CATEGORY_SESSION,     // Session management errors
    GR_ERR_CATEGORY_PROTOCOL     // Protocol errors
} gr_err_category_t;

/**
 * Unified error handling macro with category
 * Usage: GR_ERROR_HANDLE(GR_ERR_CATEGORY_FILESYSTEM, ERR_GR_FILE_SYSTEM_ERROR, "Failed to open file: %s", path);
 *
 * IMPORTANT:
 * - We MUST use GR_THROW_ERROR_EX here, so that the user-provided format string
 *   (format) is passed into cm_set_error. If we called GR_THROW_ERROR (which
 *   uses g_gr_error_desc[code] as the format string), the number and types of
 *   variadic arguments might not match the default error description, leading
 *   to undefined behaviour (e.g. vsnprintf reading wrong arguments and causing
 *   a crash).
 */
#define GR_ERROR_HANDLE(category, code, format, ...) \
    do { \
        LOG_RUN_ERR("[%s] " format, gr_err_category_name(category), ##__VA_ARGS__); \
        GR_THROW_ERROR_EX(code, format, ##__VA_ARGS__); \
    } while(0)

/**
 * Unified error handling with return
 * Usage: GR_ERROR_RETURN(GR_ERR_CATEGORY_FILESYSTEM, ERR_GR_FILE_SYSTEM_ERROR, CM_ERROR, "Failed to open file: %s", path);
 */
#define GR_ERROR_RETURN(category, code, ret_val, format, ...) \
    do { \
        GR_ERROR_HANDLE(category, code, format, ##__VA_ARGS__); \
        return (ret_val); \
    } while(0)

/**
 * Check condition and return error if false
 * Usage: GR_CHECK_RETURN(ptr != NULL, GR_ERR_CATEGORY_PARAM, ERR_GR_INVALID_PARAM, CM_ERROR, "Pointer is NULL");
 */
#define GR_CHECK_RETURN(condition, category, code, ret_val, format, ...) \
    do { \
        if (SECUREC_UNLIKELY(!(condition))) { \
            GR_ERROR_RETURN(category, code, ret_val, format, ##__VA_ARGS__); \
        } \
    } while(0)

/**
 * Check NULL pointer and return error
 * Usage: GR_CHECK_NULL_RETURN(ptr, GR_ERR_CATEGORY_PARAM, ERR_GR_INVALID_PARAM, CM_ERROR, "Pointer is NULL");
 */
#define GR_CHECK_NULL_RETURN(ptr, category, code, ret_val, format, ...) \
    GR_CHECK_RETURN((ptr) != NULL, category, code, ret_val, format, ##__VA_ARGS__)

/**
 * Filesystem-specific error handling macros
 */
#define GR_FS_ERROR_RETURN(code, format, ...) \
    GR_ERROR_RETURN(GR_ERR_CATEGORY_FILESYSTEM, code, CM_ERROR, format, ##__VA_ARGS__)

#define GR_FS_CHECK_RETURN(condition, code, format, ...) \
    GR_CHECK_RETURN(condition, GR_ERR_CATEGORY_FILESYSTEM, code, CM_ERROR, format, ##__VA_ARGS__)

#define GR_FS_CHECK_NULL_RETURN(ptr, code, format, ...) \
    GR_CHECK_NULL_RETURN(ptr, GR_ERR_CATEGORY_FILESYSTEM, code, CM_ERROR, format, ##__VA_ARGS__)

/**
 * Parameter validation error handling macros
 */
#define GR_PARAM_ERROR_RETURN(code, format, ...) \
    GR_ERROR_RETURN(GR_ERR_CATEGORY_PARAM, code, CM_ERROR, format, ##__VA_ARGS__)

#define GR_PARAM_CHECK_RETURN(condition, code, format, ...) \
    GR_CHECK_RETURN(condition, GR_ERR_CATEGORY_PARAM, code, CM_ERROR, format, ##__VA_ARGS__)

/**
 * System call error handling with errno
 * Usage: GR_SYS_ERROR_RETURN("Failed to open file: %s", path);
 */
#define GR_SYS_ERROR_RETURN(format, ...) \
    do { \
        int _errno_save = errno; \
        LOG_RUN_ERR("[SYSTEM] " format ", errno: %d (%s)", ##__VA_ARGS__, _errno_save, strerror(_errno_save)); \
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR); \
        return CM_ERROR; \
    } while(0)

/**
 * Function call error check and return
 * Usage: GR_CALL_RETURN(func(), "Function call failed");
 */
#define GR_CALL_RETURN(func_call, format, ...) \
    do { \
        status_t _ret = (func_call); \
        if (SECUREC_UNLIKELY(_ret != CM_SUCCESS)) { \
            LOG_RUN_ERR(format ", status: %d", ##__VA_ARGS__, _ret); \
            return _ret; \
        } \
    } while(0)

/**
 * Get error category name for logging
 */
const char *gr_err_category_name(gr_err_category_t category);

#ifdef __cplusplus
}
#endif

#endif /* __GR_ERROR_HANDLER_H__ */
