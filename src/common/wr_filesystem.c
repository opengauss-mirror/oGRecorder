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
#include <stdint.h>
#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif  // !WIN32
#include "wr_file.h"
#include "wr_thv.h"
#include "wr_param.h"

#ifdef __cplusplus
extern "C" {
#endif

errno_t iret_snprintf = 0;

#define WR_FS_GET_PATH(name) ({ \
    char _path[WR_FILE_PATH_MAX_LENGTH]; \
    iret_snprintf = snprintf_s(_path, WR_FILE_PATH_MAX_LENGTH, WR_FILE_PATH_MAX_LENGTH - 1, \
                               "%s/%s", g_inst_cfg->data_dir, (name)); \
    WR_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR); \
    _path; \
})

status_t wr_filesystem_mkdir(const char *name, mode_t mode) {
    if (access(WR_FS_GET_PATH(name), F_OK) == 0) {
        LOG_RUN_ERR("[FS] Directory already exists: %s", name);
        WR_THROW_ERROR(ERR_WR_DIR_CREATE_DUPLICATED, name);
        return CM_ERROR;
    }

    if (mkdir(WR_FS_GET_PATH(name), mode) != 0) {
        LOG_RUN_ERR("[FS] Failed to create directory: %s", name);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_rmdir(const char *name, uint64_t flag) {
    if (flag != 0) {
        DIR *dir = opendir(WR_FS_GET_PATH(name));
        if (!dir) {
            LOG_RUN_ERR("[FS] Failed to open directory: %s", name);
            WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
            return CM_ERROR;
        }

        struct dirent *entry;
        char path[WR_FILE_PATH_MAX_LENGTH];

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            snprintf(path, sizeof(path), "%s/%s", WR_FS_GET_PATH(name), entry->d_name);
            if (unlink(path) != 0) {
                LOG_RUN_ERR("[FS] Failed to remove file: %s", path);
                WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
                closedir(dir);
                return CM_ERROR;
            }
        }

        closedir(dir);
    }

    if (rmdir(WR_FS_GET_PATH(name)) != 0) {
        LOG_RUN_ERR("[FS] Failed to remove directory: %s", name);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t wr_filesystem_touch(const char *name) {
    if (access(WR_FS_GET_PATH(name), F_OK) == 0) {
        LOG_RUN_ERR("[FS] File already exists: %s", name);
        WR_THROW_ERROR(ERR_WR_DIR_CREATE_DUPLICATED, name);
        return CM_ERROR;
    }

    FILE *file = fopen(WR_FS_GET_PATH(name), "w");
    if (!file) {
        LOG_RUN_ERR("[FS] Failed to create file: %s", name);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    (void)fclose(file);
    return CM_SUCCESS;
}

status_t wr_filesystem_rm(const char *name) {
    if (unlink(WR_FS_GET_PATH(name)) != 0) {
        LOG_RUN_ERR("[FS] Failed to remove file: %s", name);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int64_t wr_filesystem_pwrite(int64_t handle, int64_t offset, int64_t size, const char *buf) {
    int64_t res = pwrite(handle, buf, size, offset);
    if (res == -1) {
        LOG_RUN_ERR("[FS] Failed to write to handle: %ld, offset: %ld, size: %ld", handle, offset, size);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return res;
}

int64_t wr_filesystem_pread(int64_t handle, int64_t offset, int64_t size, char *buf) {
    int64_t res = pread(handle, buf, size, offset);
    if (res == -1) {
        LOG_RUN_ERR("[FS] Failed to read from handle: %ld, offset: %ld, size: %ld", handle, offset, size);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return res;
}

status_t wr_filesystem_query_file_num(const char *vfs_name, uint32_t *file_num) {
    if (!vfs_name || !file_num) {
        LOG_RUN_ERR("[FS] Invalid parameters: vfs_name or file_num is NULL");
    }

    DIR *dir = opendir(WR_FS_GET_PATH(vfs_name));
    if (!dir) {
        LOG_RUN_ERR("[FS] Failed to open directory: %s", vfs_name);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    struct dirent *entry;
    *file_num = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            (*file_num)++;
        }
    }

    (void)closedir(dir);
    return CM_SUCCESS;
}

status_t wr_filesystem_get_file_end_position(const char *file_path, off_t *end_position) {
    if (!file_path || !end_position) {
        LOG_RUN_ERR("[FS] Invalid parameters: file_path or end_position is NULL");
    }

    struct stat file_stat;
    if (stat(WR_FS_GET_PATH(file_path), &file_stat) != 0) {
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        LOG_RUN_ERR("[FS] Failed to stat file: %s", file_path);
        return CM_ERROR;
    }

    *end_position = file_stat.st_size;
    return CM_SUCCESS;
}

status_t wr_filesystem_open(const char *file_path, int flag, int64_t *fd) {
    *fd = open(WR_FS_GET_PATH(file_path), flag, 0);
    if (*fd == -1) {
        LOG_RUN_ERR("[FS] Failed to open file: %s", file_path);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_close(int fd) {
    if (close(fd) == -1) {
        LOG_RUN_ERR("[FS] Failed to close file descriptor: %d", fd);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_truncate(int64_t fd, int64_t length) {
    if (ftruncate(fd, length) == -1) {
        LOG_RUN_ERR("[FS] Failed to truncate file: %ld, length: %ld", fd, length);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_stat(const char *name, int64_t *offset, int64_t *size) {
    struct stat file_stat;
    if (stat(WR_FS_GET_PATH(name), &file_stat) != 0) {
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        LOG_RUN_ERR("[FS] Failed to stat file: %s", name);
        return CM_ERROR;
    }
    *offset = file_stat.st_size;
    *size = file_stat.st_size;
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
