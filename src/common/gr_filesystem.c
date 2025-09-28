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
 * gr_volume.c
 *
 *
 * IDENTIFICATION
 *    src/common/gr_filesystem.c
 *
 * -------------------------------------------------------------------------
 */
#include "gr_filesystem.h"
#include <stdint.h>
#include <time.h>
#include <utime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#endif  // !WIN32
#include "gr_file.h"
#include "gr_thv.h"
#include "gr_param.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

static void gr_get_fs_path(const char *name, char *buf, size_t buf_size)
{
    int ret = snprintf(buf, buf_size, "%s/%s", g_inst_cfg->params.data_file_path, name);
    if (ret < 0 || (size_t)ret >= buf_size) {
        LOG_RUN_ERR("[FS] gr_get_fs_path snprintf failed or truncated: %d", ret);
        if (buf_size > 0) {
            buf[0] = '\0';
        }
    }
}

typedef struct gr_dir_map_item {
    uint64_t handle;
    DIR *dir;
    struct gr_dir_map_item *next;
} gr_dir_map_item_t;

/* handle-DIR map */
static gr_dir_map_item_t *g_dir_map_head = NULL;
static pthread_mutex_t g_dir_map_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_next_dir_handle = 1;

uint64_t gr_dir_map_insert(DIR *dir) {
    pthread_mutex_lock(&g_dir_map_lock);
    uint64_t handle = g_next_dir_handle++;
    gr_dir_map_item_t *item = malloc(sizeof(gr_dir_map_item_t));
    item->handle = handle;
    item->dir = dir;
    item->next = g_dir_map_head;
    g_dir_map_head = item;
    pthread_mutex_unlock(&g_dir_map_lock);
    return handle;
}

DIR *gr_dir_map_get(uint64_t handle) {
    pthread_mutex_lock(&g_dir_map_lock);
    gr_dir_map_item_t *item = g_dir_map_head;
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

void gr_dir_map_remove(uint64_t handle) {
    pthread_mutex_lock(&g_dir_map_lock);
    gr_dir_map_item_t **pp = &g_dir_map_head;
    while (*pp) {
        if ((*pp)->handle == handle) {
            gr_dir_map_item_t *to_free = *pp;
            *pp = to_free->next;
            free(to_free);
            break;
        }
        pp = &((*pp)->next);
    }
    pthread_mutex_unlock(&g_dir_map_lock);
}

status_t gr_filesystem_mkdir(const char *name, mode_t mode) {
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    if (access(path, F_OK) == 0) {
        LOG_RUN_ERR("[FS] Directory already exists: %s", name);
        GR_THROW_ERROR(ERR_GR_DIR_CREATE_DUPLICATED, name);
        return CM_ERROR;
    }

    if (mkdir(path, mode) != 0) {
        LOG_RUN_ERR("[FS] Failed to create directory: %s, errno: %d", name, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_rmdir(const char *name, uint64_t flag) {
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    if (flag != 0) {
        DIR *dir = opendir(path);
        if (!dir) {
            LOG_RUN_ERR("[FS] Failed to open directory: %s, errno: %d", name, errno);
            GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
            return CM_ERROR;
        }

        struct dirent *entry;
        char subpath[GR_FILE_PATH_MAX_LENGTH];

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            int ret = snprintf_s(subpath, GR_FILE_PATH_MAX_LENGTH, GR_FILE_PATH_MAX_LENGTH - 1,
                                 "%s/%s", path, entry->d_name);
            if (ret == -1) {
                GR_THROW_ERROR(ERR_SYSTEM_CALL, ret);
                return CM_ERROR;
            }
            if (unlink(subpath) != 0) {
                LOG_RUN_ERR("[FS] Failed to remove file: %s, errno: %d", subpath, errno);
                GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
                closedir(dir);
                return CM_ERROR;
            }
        }

        closedir(dir);
    }

    if (rmdir(path) != 0) {
        LOG_RUN_ERR("[FS] Failed to remove directory: %s, errno: %d", name, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t gr_filesystem_opendir(const char *name, uint64_t *out_handle)
{
    if (!name || !out_handle) {
        LOG_RUN_ERR("[FS] Invalid parameters: name or out_handle is NULL");
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    DIR *dir = opendir(path);
    if (!dir) {
        LOG_RUN_ERR("[FS] Failed to open directory: %s, errno: %d", name, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    LOG_RUN_INF("[FS] Successfully opened directory: %s", name);
    *out_handle = gr_dir_map_insert(dir);
    return CM_SUCCESS;
}

status_t gr_filesystem_closedir(uint64_t handle)
{
    DIR *dir = gr_dir_map_get(handle);
    if (!dir) {
        LOG_RUN_ERR("[FS] Invalid directory handle: %lu", handle);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    if (closedir(dir) != 0) {
        LOG_RUN_ERR("[FS] Failed to close directory, errno: %d", errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    gr_dir_map_remove(handle);
    LOG_RUN_INF("[FS] Successfully closed directory");
    return CM_SUCCESS;
}

#define GR_LOCK_MODE 0400
#define GR_APPEND_MODE 0600
status_t gr_filesystem_append(const char *name) {
    off_t end_position;
    if (gr_filesystem_get_file_end_position(name, &end_position) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to get file %s size, errno: %d", name, errno);
        return CM_ERROR;
    }
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    // when file is null can be changed to append mode from lock mode or expired mode
    if ((access(path, W_OK) == -1) && (end_position == 0)) {
        LOG_RUN_INF("File %s can enter into append mode.", name);
        if (chmod(path, GR_APPEND_MODE) != CM_SUCCESS) {
            LOG_RUN_ERR("[FS] Failed to change file %s to append mode, errno: %d", name, errno);
            return CM_ERROR;
        }
        return CM_SUCCESS;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_touch(const char *name) {
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    if (access(path, F_OK) == 0) {
        LOG_RUN_ERR("[FS] File already exists: %s, errno: %d", name, errno);
        GR_THROW_ERROR(ERR_GR_DIR_CREATE_DUPLICATED, name);
        return CM_ERROR;
    }

    FILE *file = fopen(path, "w");
    if (!file) {
        LOG_RUN_ERR("[FS] Failed to create file: %s, errno: %d", name, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    (void)fclose(file);
    if (chmod(path, GR_LOCK_MODE) != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] File %s enter lock mode failed, errno: %d", name, errno);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_rm(const char *name) {
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    if (unlink(path) != 0) {
        LOG_RUN_ERR("[FS] Failed to remove file: %s, errno: %d", name, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_pwrite(int handle, int64 offset, int64 size, const char *buf, int64 *rel_size) {
    if (rel_size == NULL) {
        LOG_RUN_ERR("[FS] Invalid rel_size pointer for write operation");
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM);
        return CM_ERROR;
    }
    *rel_size = pwrite(handle, buf, size, offset);
    if (*rel_size == -1) {
        LOG_RUN_ERR("[FS] Failed to write to handle: %d, offset: %lld, size: %lld, errno: %d", handle, offset, size, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    } else if (*rel_size != size) {
        LOG_RUN_WAR("[FS] Failed to write to handle: %d, offset: %lld, size: %lld, errno: %d", handle, offset, size, errno);
    }   
    return CM_SUCCESS;
}

status_t gr_filesystem_pread(int handle, int64 offset, int64 size, char *buf, int64 *rel_size) {
    if (rel_size == NULL) {
        LOG_RUN_ERR("[FS] Invalid rel_size pointer for read operation");
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM);
        return CM_ERROR;
    }
    *rel_size = pread(handle, buf, size, offset);
    if (*rel_size == -1) {
        LOG_RUN_ERR("[FS] Failed to read from handle: %d, offset: %lld, size: %lld, errno: %d", handle, offset, size, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_query_file_num(uint64_t handle, uint32_t *file_num) {
    if (!file_num) {
        LOG_RUN_ERR("[FS] Invalid parameters: file_num is NULL");
        return CM_ERROR;
    }
    DIR *dir = gr_dir_map_get(handle);
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

status_t gr_filesystem_query_file_info(uint64_t handle, gr_file_item_t *file_items, uint32_t max_files, uint32_t *file_count, bool is_continue) {
    if (!file_items || !file_count) {
        LOG_RUN_ERR("[FS] Invalid parameters: file_items or file_count is NULL");
        return CM_ERROR;
    }
    DIR *dir = gr_dir_map_get(handle);
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
            gr_file_item_t *current_item = &file_items[*file_count];
            strncpy(current_item->name, entry->d_name, GR_MAX_NAME_LEN - 1);
            current_item->name[GR_MAX_NAME_LEN - 1] = '\0';
            (*file_count)++;
            if (*file_count >= max_files) {
                break;
            }
        }
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_get_file_end_position(const char *file_path, off_t *end_position) {
    if (!file_path || !end_position) {
        LOG_RUN_ERR("[FS] Invalid parameters: file_path or end_position is NULL");
    }
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(file_path, path, sizeof(path));
    struct stat file_stat;
    if (stat(path, &file_stat) != 0) {
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        LOG_RUN_ERR("[FS] Failed to stat file: %s, errno: %d", file_path, errno);
        return CM_ERROR;
    }

    *end_position = file_stat.st_size;
    return CM_SUCCESS;
}

status_t gr_filesystem_open(const char *file_path, int flag, int *fd) {
    if (gr_filesystem_append(file_path) != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] Failed to change file %s to append mode, errno: %d", file_path, errno);
        return CM_ERROR;
    }
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(file_path, path, sizeof(path));
    *fd = open(path, flag | O_APPEND, 0);
    if (*fd == -1) {
        LOG_RUN_ERR("[FS] Failed to open file: %s, errno: %d", file_path, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_lock(int fd)
{
    struct stat fd_stat;
    if (fstat(fd, &fd_stat) == -1) {
        LOG_RUN_ERR("failed to get stat for file %d, errno: %d", fd, errno);
        return CM_ERROR;
    }
    if ((fd_stat.st_mode & S_IWUSR) == 0) {
        return CM_SUCCESS;
    }
    LOG_RUN_INF("[FS] current file need to enter lock mode");
    if (fchmod(fd, GR_LOCK_MODE) == CM_ERROR) {
        LOG_RUN_ERR("[FS] Failed to change current file to lock mode, errno: %d", errno);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_close(int fd, bool32 need_lock) {
    if (need_lock && gr_filesystem_lock(fd) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to change file to be lock_mode, errno: %d", errno);
        return CM_ERROR;
    }
    if (close(fd) == -1) {
        LOG_RUN_ERR("[FS] Failed to close file descriptor: %d, errno: %d", fd, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_truncate(int fd, int64 length) {
    if (ftruncate(fd, length) == -1) {
        LOG_RUN_ERR("[FS] Failed to truncate file: %d, length: %lld, errno: %d", fd, length, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_mode(char *file_path, time_t file_atime, gr_file_status_t *mode) {
    int w_mode = access(file_path, W_OK);
    time_t systime = time(NULL);
    if (systime == ((time_t)-1)) {
        LOG_RUN_ERR("Failed to get system time, errno: %d", errno);
        return CM_ERROR;
    }
    if (w_mode == 0 && systime >= file_atime) {
        *mode = GR_FILE_INIT;
    } else if (w_mode == -1 && systime < file_atime) {
        *mode = GR_FILE_LOCK;
    } else if (w_mode == 0 && systime < file_atime) {
        *mode = GR_FILE_APPEND;
    } else if (w_mode == -1 && systime >= file_atime) {
        *mode = GR_FILE_EXPIRED;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_stat(const char *name, int64 *offset, int64 *size, gr_file_status_t *mode, time_t *atime) {
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    struct stat file_stat;
    if (stat(path, &file_stat) != 0) {
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        LOG_RUN_ERR("[FS] Failed to stat file: %s, errno: %d", name, errno);
        return CM_ERROR;
    }
    *offset = file_stat.st_size;
    *size = file_stat.st_size;
    *atime = file_stat.st_atime;
    status_t status = gr_filesystem_mode(path, file_stat.st_atime, mode);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to get file %s mode, errno: %d", name, errno);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_check_postpone_time(const char *file_name, time_t new_time)
{
    int64 offset;
    int64 size;
    time_t atime;
    gr_file_status_t mode;
    if (gr_filesystem_stat(file_name, &offset, &size, &mode, &atime) != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] Failed to get current file %s expire time, errno: %d", file_name, errno);
        return CM_ERROR;
    }

    if (atime >= new_time) {
        LOG_RUN_ERR("[FS] new expire time should be later than current expire time, file %s current expire time is: %s",
            file_name, ctime(&atime));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_postpone(const char *file_path, const char *time)
{
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(file_path, path, sizeof(path));
    status_t status;
    struct tm time_info;
    strptime(time, "%Y-%m-%d %H:%M:%S", &time_info);
    time_t new_time = mktime(&time_info);

    struct stat file_stat;
    if (stat(path, &file_stat) != 0) {
        LOG_RUN_ERR("[FS] Failed to get file %s stat, errno: %d", file_path, errno);
        return CM_ERROR;
    }

    if (file_stat.st_atime >= new_time) {
        LOG_RUN_ERR("[FS] new expire time should be later than current expire time, file %s current expire time is: %s",
            file_path, ctime(&file_stat.st_atime));
        GR_THROW_ERROR(ERR_GR_FILE_INVALID_EXPIRE_TIME);
        return CM_ERROR;
    }

    struct utimbuf new_utimes = {new_time, file_stat.st_mtime};
    status = utime(path, &new_utimes);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] Failed to extend file %s expired time, errno: %d", file_path, errno);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif