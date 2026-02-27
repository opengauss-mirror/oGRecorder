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
 * gr_error_handler.c
 *
 * IDENTIFICATION
 *    src/common/gr_error_handler.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_error_handler.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *gr_err_category_name(gr_err_category_t category)
{
    switch (category) {
        case GR_ERR_CATEGORY_SYSTEM:
            return "SYSTEM";
        case GR_ERR_CATEGORY_PARAM:
            return "PARAM";
        case GR_ERR_CATEGORY_RESOURCE:
            return "RESOURCE";
        case GR_ERR_CATEGORY_NETWORK:
            return "NETWORK";
        case GR_ERR_CATEGORY_FILESYSTEM:
            return "FS";
        case GR_ERR_CATEGORY_CONFIG:
            return "CONFIG";
        case GR_ERR_CATEGORY_SESSION:
            return "SESSION";
        case GR_ERR_CATEGORY_PROTOCOL:
            return "PROTOCOL";
        default:
            return "UNKNOWN";
    }
}

#ifdef __cplusplus
}
#endif
