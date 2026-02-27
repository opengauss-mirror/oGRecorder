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
 * gr_param_validator.h
 *
 * IDENTIFICATION
 *    src/common/gr_param_validator.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_PARAM_VALIDATOR_H__
#define __GR_PARAM_VALIDATOR_H__

#include "cm_defs.h"
#include "gr_defs.h"
#include "gr_errno.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Validate string parameter (not NULL and not empty)
 * 
 * @param str String to validate
 * @param max_len Maximum allowed length (0 means no limit)
 * @param param_name Parameter name for error message
 * @return CM_SUCCESS if valid, CM_ERROR otherwise
 */
status_t gr_validate_string(const char *str, size_t max_len, const char *param_name);

/**
 * Validate file name (valid characters only)
 * Allowed characters: [0-9a-zA-Z_-.]
 * 
 * @param name File name to validate
 * @return CM_SUCCESS if valid, CM_ERROR otherwise
 */
status_t gr_validate_file_name(const char *name);

/**
 * Validate directory path
 * 
 * @param path Path to validate
 * @param max_len Maximum allowed length
 * @return CM_SUCCESS if valid, CM_ERROR otherwise
 */
status_t gr_validate_path(const char *path, size_t max_len);

/**
 * Validate pointer parameter (not NULL)
 * 
 * @param ptr Pointer to validate
 * @param param_name Parameter name for error message
 * @return CM_SUCCESS if valid, CM_ERROR otherwise
 */
status_t gr_validate_pointer(const void *ptr, const char *param_name);

/**
 * Validate size parameter (non-negative and within range)
 * 
 * @param size Size to validate
 * @param max_size Maximum allowed size
 * @param param_name Parameter name for error message
 * @return CM_SUCCESS if valid, CM_ERROR otherwise
 */
status_t gr_validate_size(int64 size, int64 max_size, const char *param_name);

/**
 * Validate IP address format
 * 
 * @param ip IP address string
 * @return CM_SUCCESS if valid, CM_ERROR otherwise
 */
status_t gr_validate_ip(const char *ip);

/**
 * Validate port number (1-65535)
 * 
 * @param port Port number
 * @return CM_SUCCESS if valid, CM_ERROR otherwise
 */
status_t gr_validate_port(uint32_t port);

/**
 * Check if character is valid for file name
 * 
 * @param c Character to check
 * @return CM_TRUE if valid, CM_FALSE otherwise
 */
bool32 gr_is_valid_name_char(char c);

/**
 * Check if character is valid for path
 * 
 * @param c Character to check
 * @return CM_TRUE if valid, CM_FALSE otherwise
 */
bool32 gr_is_valid_path_char(char c);

#ifdef __cplusplus
}
#endif

#endif /* __GR_PARAM_VALIDATOR_H__ */
