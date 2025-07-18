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
#include <pthread.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

static void wr_get_fs_path(const char *name, char *buf, size_t buf_size)
{
    int ret = snprintf(buf, buf_size, "%s/%s", g_inst_cfg->params.data_file_path, name);
    if (ret < 0 || (size_t)ret >= buf_size) {
        LOG_RUN_ERR("[FS] wr_get_fs_path snprintf failed or truncated: %d", ret);
        if (buf_size > 0) {
            buf[0] = '\0';
        }
    }
}

typedef struct wr_dir_map_item {
    uint64_t handle;
    DIR *dir;
    struct wr_dir_map_item *next;
} wr_dir_map_item_t;

/* handle-DIR map */
static wr_dir_map_item_t *g_dir_map_head = NULL;
static pthread_mutex_t g_dir_map_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_next_dir_handle = 1;

uint64_t wr_dir_map_insert(DIR *dir) {
    pthread_mutex_lock(&g_dir_map_lock);
    uint64_t handle = g_next_dir_handle++;
    wr_dir_map_item_t *item = malloc(sizeof(wr_dir_map_item_t));
    item->handle = handle;
    item->dir = dir;
    item->next = g_dir_map_head;
    g_dir_map_head = item;
    pthread_mutex_unlock(&g_dir_map_lock);
    return handle;
}

DIR *wr_dir_map_get(uint64_t handle) {
    pthread_mutex_lock(&g_dir_map_lock);
    wr_dir_map_item_t *item = g_dir_map_head;
    while (item) {
        if (item->handle == handle) {
            pthread_mutex_unlock(&g_dir_map_lock);
            return item->dir;
        }
        item = item->next;
    }
    pthread_mutex_unlock(&g_dir_map_lock);
    return NULL;
}

void wr_dir_map_remove(uint64_t handle) {
    pthread_mutex_lock(&g_dir_map_lock);
    wr_dir_map_item_t **pp = &g_dir_map_head;
    while (*pp) {
        if ((*pp)->handle == handle) {
            wr_dir_map_item_t *to_free = *pp;
            *pp = to_free->next;
            free(to_free);
            break;
        }
        pp = &((*pp)->next);
    }
    pthread_mutex_unlock(&g_dir_map_lock);
}

status_t wr_filesystem_mkdir(const char *name, mode_t mode) {
    char path[WR_FILE_PATH_MAX_LENGTH];
    wr_get_fs_path(name, path, sizeof(path));
    if (access(path, F_OK) == 0) {
        LOG_RUN_ERR("[FS] Directory already exists: %s", name);
        WR_THROW_ERROR(ERR_WR_DIR_CREATE_DUPLICATED, name);
        return CM_ERROR;
    }

    if (mkdir(path, mode) != 0) {
        LOG_RUN_ERR("[FS] Failed to create directory: %s", name);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_rmdir(const char *name, uint64 flag) {
    char path[WR_FILE_PATH_MAX_LENGTH];
    wr_get_fs_path(name, path, sizeof(path));
    if (flag != 0) {
        DIR *dir = opendir(path);
        if (!dir) {
            LOG_RUN_ERR("[FS] Failed to open directory: %s", name);
            WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
            return CM_ERROR;
        }

        struct dirent *entry;
        char subpath[WR_FILE_PATH_MAX_LENGTH];

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            int ret = snprintf_s(subpath, WR_FILE_PATH_MAX_LENGTH, WR_FILE_PATH_MAX_LENGTH - 1,
                                 "%s/%s", path, entry->d_name);
            if (ret == -1) {
                WR_THROW_ERROR(ERR_SYSTEM_CALL, ret);
                return CM_ERROR;
            }
            if (unlink(subpath) != 0) {
                LOG_RUN_ERR("[FS] Failed to remove file: %s", subpath);
                WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
                closedir(dir);
                return CM_ERROR;
            }
        }

        closedir(dir);
    }

    if (rmdir(path) != 0) {
        LOG_RUN_ERR("[FS] Failed to remove directory: %s", name);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t wr_filesystem_opendir(const char *name, uint64_t *out_handle)
{
    if (!name || !out_handle) {
        LOG_RUN_ERR("[FS] Invalid parameters: name or out_handle is NULL");
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    char path[WR_FILE_PATH_MAX_LENGTH];
    wr_get_fs_path(name, path, sizeof(path));
    DIR *dir = opendir(path);
    if (!dir) {
        LOG_RUN_ERR("[FS] Failed to open directory: %s", name);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    LOG_RUN_INF("[FS] Successfully opened directory: %s", name);
    *out_handle = wr_dir_map_insert(dir);
    return CM_SUCCESS;
}

status_t wr_filesystem_closedir(uint64_t handle)
{
    DIR *dir = wr_dir_map_get(handle);
    if (!dir) {
        LOG_RUN_ERR("[FS] Invalid directory handle: %lu", handle);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    if (closedir(dir) != 0) {
        LOG_RUN_ERR("[FS] Failed to close directory");
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    wr_dir_map_remove(handle);
    LOG_RUN_INF("[FS] Successfully closed directory");
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
    char path[WR_FILE_PATH_MAX_LENGTH];
    wr_get_fs_path(name, path, sizeof(path));
    // when file is null can be changed to append mode from lock mode or expired mode
    if ((access(path, W_OK) == -1) && (end_position == 0)) {
        LOG_RUN_INF("File %s can enter into append mode.", name);
        if (chmod(path, WR_APPEND_MODE) != CM_SUCCESS) {
            return CM_ERROR;
        }
        return CM_SUCCESS;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_touch(const char *name) {
    char path[WR_FILE_PATH_MAX_LENGTH];
    wr_get_fs_path(name, path, sizeof(path));
    if (access(path, F_OK) == 0) {
        LOG_RUN_ERR("[FS] File already exists: %s", name);
        WR_THROW_ERROR(ERR_WR_DIR_CREATE_DUPLICATED, name);
        return CM_ERROR;
    }

    FILE *file = fopen(path, "w");
    if (!file) {
        LOG_RUN_ERR("[FS] Failed to create file: %s", name);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    (void)fclose(file);
    if (chmod(path, WR_LOCK_MODE) != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] File %d enter lock mode failed", WR_LOCK_MODE);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_rm(const char *name) {
    char path[WR_FILE_PATH_MAX_LENGTH];
    wr_get_fs_path(name, path, sizeof(path));
    if (unlink(path) != 0) {
        LOG_RUN_ERR("[FS] Failed to remove file: %s", name);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_pwrite(int handle, int64 offset, int64 size, const char *buf, int64 *rel_size) {
    if (rel_size == NULL) {
        LOG_RUN_ERR("[FS] Invalid rel_size pointer for write operation");
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM);
        return CM_ERROR;
    }
    *rel_size = pwrite(handle, buf, size, offset);
    if (*rel_size == -1) {
        LOG_RUN_ERR("[FS] Failed to write to handle: %d, offset: %lld, size: %lld", handle, offset, size);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_pread(int handle, int64 offset, int64 size, char *buf, int64 *rel_size) {
    if (rel_size == NULL) {
        LOG_RUN_ERR("[FS] Invalid rel_size pointer for read operation");
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM);
        return CM_ERROR;
    }
    *rel_size = pread(handle, buf, size, offset);
    if (*rel_size == -1) {
        LOG_RUN_ERR("[FS] Failed to read from handle: %d, offset: %lld, size: %lld", handle, offset, size);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_query_file_num(uint64_t handle, uint32_t *file_num) {
    if (!file_num) {
        LOG_RUN_ERR("[FS] Invalid parameters: file_num is NULL");
        return CM_ERROR;
    }
    DIR *dir = wr_dir_map_get(handle);
    if (!dir) {
        LOG_RUN_ERR("[FS] Invalid directory handle: %lu", handle);
        return CM_ERROR;
    }
    struct dirent *entry;
    *file_num = 0;
    rewinddir(dir);
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            (*file_num)++;
        }
    }
    rewinddir(dir);
    return CM_SUCCESS;
}

status_t wr_filesystem_query_file_info(uint64_t handle, wr_file_item_t *file_items, uint32_t max_files, uint32_t *file_count, bool is_continue) {
    if (!file_items || !file_count) {
        LOG_RUN_ERR("[FS] Invalid parameters: file_items or file_count is NULL");
        return CM_ERROR;
    }
    DIR *dir = wr_dir_map_get(handle);
    if (!dir) {
        LOG_RUN_ERR("[FS] Invalid directory handle: %lu", handle);
        return CM_ERROR;
    }
    if (!is_continue) {
        rewinddir(dir);
    }
    struct dirent *entry;
    *file_count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            wr_file_item_t *current_item = &file_items[*file_count];
            strncpy(current_item->name, entry->d_name, WR_MAX_NAME_LEN - 1);
            current_item->name[WR_MAX_NAME_LEN - 1] = '\0';
            (*file_count)++;
            if (*file_count >= max_files) {
                break;
            }
        }
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_get_file_end_position(const char *file_path, off_t *end_position) {
    if (!file_path || !end_position) {
        LOG_RUN_ERR("[FS] Invalid parameters: file_path or end_position is NULL");
    }
    char path[WR_FILE_PATH_MAX_LENGTH];
    wr_get_fs_path(file_path, path, sizeof(path));
    struct stat file_stat;
    if (stat(path, &file_stat) != 0) {
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        LOG_RUN_ERR("[FS] Failed to stat file: %s", file_path);
        return CM_ERROR;
    }

    *end_position = file_stat.st_size;
    return CM_SUCCESS;
}

status_t wr_filesystem_open(const char *file_path, int flag, int *fd) {
    if (wr_filesystem_append(file_path) != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] Failed to change file %s to append mode", file_path);
        return CM_ERROR;
    }
    char path[WR_FILE_PATH_MAX_LENGTH];
    wr_get_fs_path(file_path, path, sizeof(path));
    *fd = open(path, flag | O_APPEND, 0);
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
    struct stat fd_stat;
    if (fstat(fd, &fd_stat) == -1) {
        LOG_RUN_ERR("failed to get stat for file %d", fd);
        return CM_ERROR;
    }
    if ((fd_stat.st_mode & S_IWUSR) == 0) {
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

status_t wr_filesystem_truncate(int fd, int64 length) {
    if (ftruncate(fd, length) == -1) {
        LOG_RUN_ERR("[FS] Failed to truncate file: %d, length: %lld", fd, length);
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_mode(char *file_path, time_t file_atime, wr_file_status_t *mode) {
    int w_mode = access(file_path, W_OK);
    time_t systime = time(NULL);
    if (systime == ((time_t)-1)) {
        LOG_RUN_ERR("Failed to get system time.");
        return CM_ERROR;
    }
    if (w_mode == 0 && systime >= file_atime) {
        *mode = WR_FILE_INIT;
    } else if (w_mode == -1 && systime < file_atime) {
        *mode = WR_FILE_LOCK;
    } else if (w_mode == 0 && systime < file_atime) {
        *mode = WR_FILE_APPEND;
    } else if (w_mode == -1 && systime >= file_atime) {
        *mode = WR_FILE_EXPIRED;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_stat(const char *name, int64 *offset, int64 *size, wr_file_status_t *mode, time_t *atime) {
    char path[WR_FILE_PATH_MAX_LENGTH];
    wr_get_fs_path(name, path, sizeof(path));
    struct stat file_stat;
    if (stat(path, &file_stat) != 0) {
        WR_THROW_ERROR(ERR_WR_FILE_SYSTEM_ERROR);
        LOG_RUN_ERR("[FS] Failed to stat file: %s", name);
        return CM_ERROR;
    }
    *offset = file_stat.st_size;
    *size = file_stat.st_size;
    *atime = file_stat.st_atime;
    status_t status = wr_filesystem_mode(path, file_stat.st_atime, mode);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to get file %s mode", name);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_check_postpone_time(const char *file_name, time_t new_time)
{
    int64 offset;
    int64 size;
    time_t atime;
    wr_file_status_t mode;
    if (wr_filesystem_stat(file_name, &offset, &size, &mode, &atime) != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] Failed to get current file %s expire time.", file_name);
        return CM_ERROR;
    }

    if (atime >= new_time) {
        LOG_RUN_ERR("[FS] new expire time should be later than current expire time, file %s current expire time is: %s",
            file_name, ctime(&atime));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t wr_filesystem_postpone(const char *file_path, const char *time)
{
    char path[WR_FILE_PATH_MAX_LENGTH];
    wr_get_fs_path(file_path, path, sizeof(path));
    status_t status;
    struct tm time_info;
    strptime(time, "%Y-%m-%d %H:%M:%S", &time_info);
    time_t new_time = mktime(&time_info);
    if (wr_filesystem_check_postpone_time(file_path, new_time) != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] Failed to change file %s expired time", file_path);
        return CM_ERROR;
    }

    struct utimbuf new_utimes = {new_time, new_time};
    status = utime(path, &new_utimes);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] Failed to extend file %s expired time", file_path);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif