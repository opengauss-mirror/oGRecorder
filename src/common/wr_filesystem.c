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
#include <time.h>
#include <utime.h>
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
                               "%s/%s", g_inst_cfg->params.data_file_path, (name)); \
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

status_t wr_filesystem_rmdir(const char *name, uint64 flag) {
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


#define WR_LOCK_MODE 0400
#define WR_APPEND_MODE 0600
status_t wr_filesystem_append(const char *name) {
    off_t end_position;
    if (wr_filesystem_get_file_end_position(name, &end_position) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to get file %s size.", name);
        return CM_ERROR;
    }
    // when file is null can be changed to append mode from lock mode or expired mode
    if ((access(WR_FS_GET_PATH(name), W_OK) == -1) && (end_position == 0)) {
        LOG_RUN_INF("File %s can enter into append mode.", name);
        if (chmod(WR_FS_GET_PATH(name), WR_APPEND_MODE) != CM_SUCCESS) {
            return CM_ERROR;
        }
        return CM_SUCCESS;
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
    if (chmod(WR_FS_GET_PATH(name), WR_LOCK_MODE) != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] File %d enter lock mode failed", WR_LOCK_MODE);
        return CM_ERROR;
    }
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

int64 wr_filesystem_pwrite(int64 handle, int64 offset, int64 size, const char *buf) {
    int64 res = pwrite(handle, buf, size, offset);
    if (res == -1) {
        LOG_RUN_ERR("[FS] Failed to write to handle: %lld, offset: %lld, size: %lld", handle, offset, size);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return res;
}

int64 wr_filesystem_pread(int64 handle, int64 offset, int64 size, char *buf) {
    int64 res = pread(handle, buf, size, offset);
    if (res == -1) {
        LOG_RUN_ERR("[FS] Failed to read from handle: %lld, offset: %lld, size: %lld", handle, offset, size);
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

status_t wr_filesystem_open(const char *file_path, int flag, int64 *fd) {
    if (wr_filesystem_append(file_path) != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] Failed to change file %s to append mode", file_path);
        return CM_ERROR;
    }
    *fd = open(WR_FS_GET_PATH(file_path), flag | O_APPEND, 0);
    if (*fd == -1) {
        LOG_RUN_ERR("[FS] Failed to open file: %s", file_path);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_lock(int fd, int need_lock)
{
    if (need_lock == 0) {
        return CM_SUCCESS;
    }
    LOG_RUN_INF("[FS] current file need to enter lock mode");
    if (fchmod(fd, WR_LOCK_MODE) == CM_ERROR) {
        LOG_RUN_ERR("[FS] Failed to change current file to lock mode.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_close(int fd, int need_lock) {
    if (wr_filesystem_lock(fd, need_lock) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to change file to be lock_mode");
        return CM_ERROR;
    }
    if (close(fd) == -1) {
        LOG_RUN_ERR("[FS] Failed to close file descriptor: %d", fd);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_truncate(int64 fd, int64 length) {
    if (ftruncate(fd, length) == -1) {
        LOG_RUN_ERR("[FS] Failed to truncate file: %lld, length: %lld", fd, length);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_mode(char *file_path, time_t file_atime, wr_file_status_t *mode) {
    int w_mode = access(file_path, W_OK);
    time_t systime;
    if (wr_filesystem_get_systime(&systime) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to get worm system time.");
        return CM_ERROR;
    }
    if (w_mode == -1 && systime > file_atime) {
        *mode = WR_FILE_LOCK;
    } else if (w_mode == 0 && systime > file_atime) {
        *mode = WR_FILE_APPEND;
    } else if (systime <= file_atime) {
        *mode = WR_FILE_EXPIRED;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_stat(const char *name, int64 *offset, int64 *size, wr_file_status_t *mode, time_t *atime) {
    struct stat file_stat;
    char *file_path = WR_FS_GET_PATH(name);
    if (stat(file_path, &file_stat) != 0) {
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        LOG_RUN_ERR("[FS] Failed to stat file: %s", name);
        return CM_ERROR;
    }
    *offset = file_stat.st_size;
    *size = file_stat.st_size;
    *atime = file_stat.st_atime;
    status_t status = wr_filesystem_mode(file_path, file_stat.st_atime, mode);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to get file %s mode", name);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_postpone(const char *file_path, const char *time)
{
    status_t status;
    struct tm time_info;
    strptime(time, "%Y-%m-%d %H:%M:%S", &time_info);
    time_t new_time = mktime(&time_info);
    struct utimbuf new_utimes = {new_time, new_time};
    status = utime(WR_FS_GET_PATH(file_path), &new_utimes);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] Failed to extend file %s expired time", file_path);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_get_systime(time_t *sys_time)
{
    const char *test_time = "test_time";
    FILE *file = fopen(WR_FS_GET_PATH(test_time), "w");
    if (!file) {
        LOG_RUN_ERR("[FS] Failed to create file: %s", test_time);
        return CM_ERROR;
    }
    struct stat buf;
    if (stat(WR_FS_GET_PATH(test_time), &buf) != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] Failed to get file %s time", test_time);
        fclose(file);
        return CM_ERROR;
    }
    *sys_time = buf.st_mtime;
    fclose(file);
    unlink(WR_FS_GET_PATH(test_time));
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
