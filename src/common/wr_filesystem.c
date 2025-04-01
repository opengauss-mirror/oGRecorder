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
 * wr_volume.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_filesystem.c
 *
 * -------------------------------------------------------------------------
 */
#include "wr_filesystem.h"
#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif  // !WIN32
#include "wr_file.h"
#include "wr_thv.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t wr_filesystem_mkdir(const char *name, mode_t mode)
{
    if (mkdir(name, mode) != 0) {
        LOG_RUN_ERR("[FS]Failed to mkdir %s.", name);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_rmdir(const char *name)
{
    if (rmdir(name) != 0) {
        LOG_RUN_ERR("[FS]Failed to rmdir %s.", name);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_touch(const char *name)
{
    FILE *file = fopen(name, "w");
    if (file) {
        fclose(file);
    } else {
        LOG_RUN_ERR("[FS]Failed to touch %s.", name);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_rm(const char *name)
{
    if (unlink(name) != 0) {
        LOG_RUN_ERR("[FS]Failed to rm %s.", name);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
