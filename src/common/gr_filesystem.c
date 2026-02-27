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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include "gr_file.h"
#include "gr_thv.h"
#include "gr_param.h"
#include "gr_session.h"
#include "gr_file_def.h"
#include <pthread.h>
#include <stdio.h>
#include "cm_defs.h"
#include "cm_error.h"
#include "cm_hash.h"
#include "gr_error_handler.h"
#include "gr_path_utils.h"
#include "gr_param_validator.h"

#ifdef __cplusplus
extern "C" {
#endif

// Use unified error handling and path utilities from gr_error_handler.h and gr_path_utils.h

typedef struct gr_dir_map_item {
    hash_node_t node;
    uint64_t handle;
    DIR *dir;
    pthread_mutex_t lock;  // Per-handle lock to protect concurrent access to DIR*
} gr_dir_map_item_t;

#define MAX_DIR_HANDLE_COUNT 10000  // Maximum number of directory handles
#define DIR_MAP_LOCK_TIMEOUT_MS 500
#define DIR_MAP_BUCKET_COUNT 256

/* handle-DIR map using CBB hash table */
static hash_map_t g_dir_map;
static hash_funcs_t g_dir_map_funcs;
static pthread_mutex_t g_dir_map_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_next_dir_handle = 1;
static uint64_t g_freed_handles[MAX_DIR_HANDLE_COUNT];
static uint32_t g_freed_handle_count = 0;
static bool g_dir_map_initialized = false;

// Hash function for uint64_t keys using CBB hash
static uint32 gr_dir_map_hash_func(void *key) {
    uint64_t handle = *(uint64_t*)key;
    return cm_hash_uint32_shard((uint32)(handle ^ (handle >> 32)));
}

// Compare function for uint64_t keys
static bool32 gr_dir_map_compare_func(void *key1, void *key2) {
    uint64_t handle1 = *(uint64_t*)key1;
    uint64_t handle2 = *(uint64_t*)key2;
    return (handle1 == handle2) ? CM_TRUE : CM_FALSE;
}

// Key extraction function
static void* gr_dir_map_key_func(hash_node_t *node) {
    gr_dir_map_item_t *item = (gr_dir_map_item_t*)node;
    return &item->handle;
}

// Allocator functions for CBB hash map
static status_t gr_dir_map_alloc(void *ctx, uint32 size, void **buf) {
    (void)ctx; // unused
    *buf = malloc(size);
    return (*buf != NULL) ? CM_SUCCESS : CM_ERROR;
}

static void gr_dir_map_free(void *ctx, void *buf) {
    (void)ctx; // unused
    free(buf);
}

// Initialize directory map
static int gr_dir_map_init(void) {
    if (g_dir_map_initialized) {
        return 0;
    }
    
    // Initialize hash functions
    g_dir_map_funcs.f_key = gr_dir_map_key_func;
    g_dir_map_funcs.f_equal = gr_dir_map_compare_func;
    g_dir_map_funcs.f_hash = gr_dir_map_hash_func;
    
    // Initialize hash map using CBB allocator
    cm_allocator_t alloc = {0};
    alloc.f_alloc = gr_dir_map_alloc;
    alloc.f_free = gr_dir_map_free;
    alloc.mem_ctx = NULL;
    
    if (cm_hmap_init(&g_dir_map, &alloc, DIR_MAP_BUCKET_COUNT) != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] Failed to initialize directory map");
        return -1;
    }
    
    g_dir_map_initialized = true;
    return 0;
}

// Cleanup directory map
void gr_dir_map_cleanup(void) {
    if (!g_dir_map_initialized) {
        return;
    }
    
    pthread_mutex_lock(&g_dir_map_lock);
    
    // Free all items using CBB hash iteration
    hash_node_t *curr = NULL;
    cm_hmap_begin(&g_dir_map, &curr);
    while (curr) {
        gr_dir_map_item_t *item = (gr_dir_map_item_t*)curr;
        hash_node_t *next = curr;
        cm_hmap_next(&g_dir_map, &g_dir_map_funcs, &next);
        
        if (item->dir) {
            closedir(item->dir);
        }
        pthread_mutex_destroy(&item->lock);  // Destroy per-handle lock
        free(item);
        curr = next;
    }
    
    // Free hash buckets
    if (g_dir_map.buckets) {
        free(g_dir_map.buckets);
        g_dir_map.buckets = NULL;
    }
    
    g_dir_map_initialized = false;
    pthread_mutex_unlock(&g_dir_map_lock);
}

uint64_t gr_dir_map_insert(DIR *dir) {
    if (dir == NULL) {
        return 0;
    }
    
    pthread_mutex_lock(&g_dir_map_lock);
    
    // Initialize map if not already done
    if (!g_dir_map_initialized) {
        if (gr_dir_map_init() != 0) {
            pthread_mutex_unlock(&g_dir_map_lock);
            return 0;
        }
    }
    
    uint64_t handle = 0;
    
    // Prefer to reuse freed handles first
    if (g_freed_handle_count > 0) {
        handle = g_freed_handles[--g_freed_handle_count];
    } else {
        // If there are no reusable handles, allocate a new one
        if (g_next_dir_handle >= MAX_DIR_HANDLE_COUNT) {
            pthread_mutex_unlock(&g_dir_map_lock);
            LOG_RUN_ERR("[FS] Directory handle limit exceeded: %lu (max: %d)", g_next_dir_handle, MAX_DIR_HANDLE_COUNT);
            return 0;
        }
        handle = g_next_dir_handle++;
    }
    
    gr_dir_map_item_t *item = calloc(1, sizeof(gr_dir_map_item_t));
    if (item == NULL) {
        // If allocation fails, put the handle back into the reuse pool
        if (g_freed_handle_count < MAX_DIR_HANDLE_COUNT) {
            g_freed_handles[g_freed_handle_count++] = handle;
        }
        pthread_mutex_unlock(&g_dir_map_lock);
        LOG_RUN_ERR("[FS] Failed to allocate memory for directory map item");
        return 0;
    }
    
    item->handle = handle;
    item->dir = dir;
    pthread_mutex_init(&item->lock, NULL);  // Initialize per-handle lock
    
    // Insert into CBB hash map
    if (cm_hmap_insert(&g_dir_map, &g_dir_map_funcs, (hash_node_t*)item) != CM_TRUE) {
        pthread_mutex_destroy(&item->lock);
        free(item);
        // If insertion fails, put the handle back into the reuse pool
        if (g_freed_handle_count < MAX_DIR_HANDLE_COUNT) {
            g_freed_handles[g_freed_handle_count++] = handle;
        }
        pthread_mutex_unlock(&g_dir_map_lock);
        LOG_RUN_ERR("[FS] Failed to insert directory map item");
        return 0;
    }
    
    pthread_mutex_unlock(&g_dir_map_lock);
    return handle;
}

DIR *gr_dir_map_get(uint64_t handle) {
    if (handle == 0) {
        return NULL;
    }
    
    pthread_mutex_lock(&g_dir_map_lock);
    
    if (!g_dir_map_initialized) {
        pthread_mutex_unlock(&g_dir_map_lock);
        return NULL;
    }
    
    uint64_t key = handle;
    hash_node_t *node = cm_hmap_find(&g_dir_map, &g_dir_map_funcs, &key);
    gr_dir_map_item_t *item = (gr_dir_map_item_t*)node;
    
    pthread_mutex_unlock(&g_dir_map_lock);
    
    return (item != NULL) ? item->dir : NULL;
}

// Get DIR* and acquire the per-handle lock (caller must call gr_dir_map_unlock to unlock)
DIR *gr_dir_map_get_and_lock(uint64_t handle) {
    if (handle == 0) {
        return NULL;
    }
    
    pthread_mutex_lock(&g_dir_map_lock);
    
    if (!g_dir_map_initialized) {
        pthread_mutex_unlock(&g_dir_map_lock);
        return NULL;
    }
    
    uint64_t key = handle;
    hash_node_t *node = cm_hmap_find(&g_dir_map, &g_dir_map_funcs, &key);
    gr_dir_map_item_t *item = (gr_dir_map_item_t*)node;
    
    if (item == NULL) {
        pthread_mutex_unlock(&g_dir_map_lock);
        return NULL;
    }
    
    // Acquire the per-handle lock first, then release the global lock
    pthread_mutex_lock(&item->lock);
    pthread_mutex_unlock(&g_dir_map_lock);
    
    return item->dir;
}

// Unlock directory handle
void gr_dir_map_unlock(uint64_t handle) {
    if (handle == 0) {
        return;
    }
    
    pthread_mutex_lock(&g_dir_map_lock);
    
    if (!g_dir_map_initialized) {
        pthread_mutex_unlock(&g_dir_map_lock);
        return;
    }
    
    uint64_t key = handle;
    hash_node_t *node = cm_hmap_find(&g_dir_map, &g_dir_map_funcs, &key);
    gr_dir_map_item_t *item = (gr_dir_map_item_t*)node;
    
    pthread_mutex_unlock(&g_dir_map_lock);
    
    if (item != NULL) {
        pthread_mutex_unlock(&item->lock);
    }
}

void gr_dir_map_remove(uint64_t handle) {
    if (handle == 0) {
        return;
    }
    
    pthread_mutex_lock(&g_dir_map_lock);
    
    if (!g_dir_map_initialized) {
        pthread_mutex_unlock(&g_dir_map_lock);
        return;
    }
    
    uint64_t key = handle;
    hash_node_t *node = cm_hmap_delete(&g_dir_map, &g_dir_map_funcs, &key);
    if (node != NULL) {
        gr_dir_map_item_t *item = (gr_dir_map_item_t*)node;
        pthread_mutex_destroy(&item->lock);  // Destroy per-handle lock
        free(item);
        
        // Put the handle into the reuse pool
        if (g_freed_handle_count < MAX_DIR_HANDLE_COUNT) {
            g_freed_handles[g_freed_handle_count++] = handle;
        }
    }
    
    pthread_mutex_unlock(&g_dir_map_lock);
}

void gr_dir_map_get_stats(uint32_t *current_count, uint32_t *max_count, uint32_t *freed_count) {
    pthread_mutex_lock(&g_dir_map_lock);
    
    if (!g_dir_map_initialized) {
        *current_count = 0;
        *max_count = MAX_DIR_HANDLE_COUNT;
        *freed_count = 0;
        pthread_mutex_unlock(&g_dir_map_lock);
        return;
    }
    
    uint32_t count = 0;
    hash_node_t *curr = NULL;
    cm_hmap_begin(&g_dir_map, &curr);
    while (curr) {
        count++;
        hash_node_t *next = curr;
        cm_hmap_next(&g_dir_map, &g_dir_map_funcs, &next);
        curr = next;
    }
    
    *current_count = count;
    *max_count = MAX_DIR_HANDLE_COUNT;
    *freed_count = g_freed_handle_count;
    
    pthread_mutex_unlock(&g_dir_map_lock);
}

status_t gr_filesystem_mkdir(const char *name, mode_t mode) {
    GR_FS_CHECK_NULL_RETURN(name, ERR_GR_INVALID_PARAM, "Directory name is NULL");
    
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    
    if (path[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Failed to build path for directory: %s", name);
    }
    
    if (access(path, F_OK) == 0) {
        GR_FS_ERROR_RETURN(ERR_GR_DIR_CREATE_DUPLICATED, "Directory already exists: %s", name);
    }
    
    if (mkdir(path, mode) != 0) {
        GR_SYS_ERROR_RETURN("Failed to create directory: %s", name);
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
            // Both "." and ".." start with '.', second char is '\0' or '.'
            const char *entry_name = entry->d_name;
            if (entry_name[0] == '.' && (entry_name[1] == '\0' || (entry_name[1] == '.' && entry_name[2] == '\0'))) {
                continue;
            }

            int ret = snprintf_s(subpath, GR_FILE_PATH_MAX_LENGTH, GR_FILE_PATH_MAX_LENGTH - 1,
                                 "%s/%s", path, entry->d_name);
            if (ret < 0 || ret >= GR_FILE_PATH_MAX_LENGTH) {
                GR_FS_ERROR_RETURN(ERR_SYSTEM_CALL, "Failed to build subpath for: %s", entry->d_name);
                closedir(dir);
            }
            if (unlink(subpath) != 0) {
                GR_SYS_ERROR_RETURN("Failed to remove file: %s", subpath);
                closedir(dir);
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
    GR_FS_CHECK_NULL_RETURN(name, ERR_GR_INVALID_PARAM, "Directory name is NULL");
    GR_FS_CHECK_NULL_RETURN(out_handle, ERR_GR_INVALID_PARAM, "Output handle is NULL");
    
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    
    if (path[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Failed to build path for directory: %s", name);
    }
    
    DIR *dir = opendir(path);
    if (dir == NULL) {
        GR_SYS_ERROR_RETURN("Failed to open directory: %s", name);
    }
    
    LOG_RUN_INF("[FS] Successfully opened directory: %s", name);
    uint64_t handle = gr_dir_map_insert(dir);
    if (handle == 0) {
        // If insertion fails, close the opened directory
        closedir(dir);
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Failed to insert directory into map: %s", name);
    }
    *out_handle = handle;
    return CM_SUCCESS;
}

status_t gr_filesystem_closedir(uint64_t handle)
{
    // Get DIR* and acquire per-handle lock to ensure no other thread is using it
    DIR *dir = gr_dir_map_get_and_lock(handle);
    if (!dir) {
        LOG_RUN_ERR("[FS] Invalid directory handle: %lu", handle);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    if (closedir(dir) != 0) {
        gr_dir_map_unlock(handle);
        LOG_RUN_ERR("[FS] Failed to close directory, errno: %d", errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    // Note: after closedir succeeds we do not unlock, gr_dir_map_remove will destroy the lock
    gr_dir_map_remove(handle);
    LOG_RUN_INF("[FS] Successfully closed directory");
    return CM_SUCCESS;
}

#define GR_LOCK_MODE 0400
#define GR_APPEND_MODE 0600
status_t gr_filesystem_append(const char *name) {
    off_t end_position;
    GR_CALL_RETURN(gr_filesystem_get_file_end_position(name, &end_position), 
                   "Failed to get file %s size", name);
    
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    
    // When file is empty it can be changed to append mode from lock mode or expired mode
    if ((access(path, W_OK) == -1) && (end_position == 0)) {
        LOG_RUN_INF("File %s can enter into append mode.", name);
        if (chmod(path, GR_APPEND_MODE) != 0) {
            GR_SYS_ERROR_RETURN("Failed to change file %s to append mode", name);
        }
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_touch(const char *name) {
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    
    if (path[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Failed to build path for file: %s", name);
    }
    
    if (access(path, F_OK) == 0) {
        GR_FS_ERROR_RETURN(ERR_GR_DIR_CREATE_DUPLICATED, "File already exists: %s", name);
    }

    FILE *file = fopen(path, "w");
    if (!file) {
        GR_SYS_ERROR_RETURN("Failed to create file: %s", name);
    }
    (void)fclose(file);
    
    if (chmod(path, GR_LOCK_MODE) != 0) {
        GR_SYS_ERROR_RETURN("File %s enter lock mode failed", name);
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_rm(const char *name, unsigned long long attrFlag) {
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    
    if (path[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Failed to build path for file: %s", name);
    }
    
    if (attrFlag != 0) {
        LOG_RUN_INF("[FS] Changed file %s to lock mode by force", name);
        if (chmod(path, GR_LOCK_MODE) != 0) {
            GR_SYS_ERROR_RETURN("Failed to change file %s to lock mode", name);
        }
    }
    
    if (unlink(path) != 0) {
        GR_SYS_ERROR_RETURN("Failed to remove file: %s", name);
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_pwrite(int handle, int64 offset, int64 size, const char *buf, int64 *rel_size) {
    GR_FS_CHECK_NULL_RETURN(rel_size, ERR_GR_INVALID_PARAM, "rel_size pointer is NULL for write operation");
    
    *rel_size = pwrite(handle, buf, size, offset);
    if (*rel_size == -1) {
        GR_SYS_ERROR_RETURN("Failed to write to handle: %d, offset: %lld, size: %lld", handle, offset, size);
    } else if (*rel_size != size) {
        LOG_RUN_WAR("[FS] Partial write to handle: %d, offset: %lld, expected: %lld, actual: %lld, errno: %d",
                    handle, offset, size, *rel_size, errno);
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_write(int handle, int64 size, const char *buf, int64 *rel_size) {
    GR_FS_CHECK_NULL_RETURN(rel_size, ERR_GR_INVALID_PARAM, "rel_size pointer is NULL for write operation");
    
    // When file is opened with O_APPEND, write will automatically append at the file end
    *rel_size = write(handle, buf, size);
    if (*rel_size == -1) {
        GR_SYS_ERROR_RETURN("Failed to write to handle: %d, size: %lld", handle, size);
    } else if (*rel_size != size) {
        LOG_RUN_WAR("[FS] Partial write to handle: %d, expected: %lld, actual: %lld, errno: %d",
                    handle, size, *rel_size, errno);
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_pread(int handle, int64 offset, int64 size, char *buf, int64 *rel_size) {
    GR_FS_CHECK_NULL_RETURN(rel_size, ERR_GR_INVALID_PARAM, "rel_size pointer is NULL for read operation");
    
    *rel_size = pread(handle, buf, size, offset);
    if (*rel_size == -1) {
        GR_SYS_ERROR_RETURN("Failed to read from handle: %d, offset: %lld, size: %lld", handle, offset, size);
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_query_file_num(uint64_t handle, uint32_t *file_num) {
    GR_FS_CHECK_NULL_RETURN(file_num, ERR_GR_INVALID_PARAM, "file_num is NULL");
    
    DIR *dir = gr_dir_map_get(handle);
    if (!dir) {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Invalid directory handle: %lu", handle);
    }
    struct dirent *entry;
    *file_num = 0;

    rewinddir(dir);
    while ((entry = readdir(dir)) != NULL) {
        /* Skip "." and ".." */
        if (entry->d_name[0] == '.' &&
            (entry->d_name[1] == '\0' ||
             (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
            continue;
        }

        /* Fast path: d_type is clearly a regular file */
        if (entry->d_type == DT_REG) {
            (*file_num)++;
            continue;
        }

        /* For unreliable d_type (DT_UNKNOWN), use fstatat for accurate judgment */
        if (entry->d_type == DT_UNKNOWN) {
            struct stat st;
            int dir_fd = dirfd(dir);
            if (dir_fd >= 0) {
                if (fstatat(dir_fd, entry->d_name, &st, 0) == 0 && S_ISREG(st.st_mode)) {
                    (*file_num)++;
                }
            }
        }
    }
    rewinddir(dir);
    return CM_SUCCESS;
}

status_t gr_filesystem_query_file_info(uint64_t handle, gr_file_item_t *file_items, uint32_t max_files, uint32_t *file_count, bool is_continue) {
    GR_FS_CHECK_NULL_RETURN(file_items, ERR_GR_INVALID_PARAM, "file_items is NULL");
    GR_FS_CHECK_NULL_RETURN(file_count, ERR_GR_INVALID_PARAM, "file_count is NULL");
    
    // Get DIR* and acquire per-handle lock
    DIR *dir = gr_dir_map_get_and_lock(handle);
    if (!dir) {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Invalid directory handle: %lu", handle);
    }
    
    if (!is_continue) {
        rewinddir(dir);
    }
    struct dirent *entry;
    *file_count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            gr_file_item_t *current_item = &file_items[*file_count];
            errno_t err = strncpy_s(current_item->name, GR_MAX_NAME_LEN, entry->d_name, GR_MAX_NAME_LEN - 1);
            if (SECUREC_UNLIKELY(err != EOK)) {
                LOG_RUN_ERR("[FS] Failed to copy file name, errno: %d", err);
                gr_dir_map_unlock(handle);
                return CM_ERROR;
            }
            (*file_count)++;
            if (*file_count >= max_files) {
                break;
            }
        }
    }
    
    // Unlock handle
    gr_dir_map_unlock(handle);
    return CM_SUCCESS;
}

status_t gr_filesystem_get_file_end_position(const char *file_path, off_t *end_position) {
    GR_FS_CHECK_NULL_RETURN(file_path, ERR_GR_INVALID_PARAM, "file_path is NULL");
    GR_FS_CHECK_NULL_RETURN(end_position, ERR_GR_INVALID_PARAM, "end_position is NULL");
    
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(file_path, path, sizeof(path));
    
    if (path[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Failed to build path for file: %s", file_path);
    }
    
    struct stat file_stat;
    if (stat(path, &file_stat) != 0) {
        GR_SYS_ERROR_RETURN("Failed to stat file: %s", file_path);
    }

    *end_position = file_stat.st_size;
    return CM_SUCCESS;
}

status_t gr_filesystem_open(const char *file_path, int flag, int *fd) {
    GR_FS_CHECK_NULL_RETURN(file_path, ERR_GR_INVALID_PARAM, "file_path is NULL");
    GR_FS_CHECK_NULL_RETURN(fd, ERR_GR_INVALID_PARAM, "fd is NULL");
    
    GR_CALL_RETURN(gr_filesystem_append(file_path), 
                   "Failed to change file %s to append mode", file_path);
    
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(file_path, path, sizeof(path));
    
    // Check if path is valid (not empty)
    if (path[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Failed to build path for file: %s", file_path);
    }
    
    // Automatically add O_APPEND so both pwrite and append interfaces can append
    // Only add O_APPEND in write modes (O_RDWR or O_WRONLY)
    int open_flag = flag | O_SYNC;
    if ((flag & O_RDWR) || (flag & O_WRONLY)) {
        open_flag |= O_APPEND;
    }
    
    *fd = open(path, open_flag, 0);
    if (*fd == -1) {
        GR_SYS_ERROR_RETURN("Failed to open file: %s (full path: %s)", file_path, path);
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_lock(int fd)
{
    struct stat fd_stat;
    if (fstat(fd, &fd_stat) == -1) {
        GR_SYS_ERROR_RETURN("Failed to get stat for file %d", fd);
    }
    if ((fd_stat.st_mode & S_IWUSR) == 0) {
        return CM_SUCCESS;
    }
    LOG_RUN_INF("[FS] current file need to enter lock mode");
    if (fchmod(fd, GR_LOCK_MODE) != 0) {
        GR_SYS_ERROR_RETURN("Failed to change current file to lock mode");
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_close(int fd, bool32 need_lock) {
    if (need_lock) {
        GR_CALL_RETURN(gr_filesystem_lock(fd), "Failed to change file to be lock_mode");
    }
    if (close(fd) == -1) {
        GR_SYS_ERROR_RETURN("Failed to close file descriptor: %d", fd);
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_truncate(int fd, int64 length) {
    if (ftruncate(fd, length) == -1) {
        GR_SYS_ERROR_RETURN("Failed to truncate file: %d, length: %lld", fd, length);
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_mode(char *file_path, time_t file_atime, gr_file_status_t *mode) {
    int w_mode = access(file_path, W_OK);
    time_t systime = time(NULL);
    if (systime == ((time_t)-1)) {
        GR_SYS_ERROR_RETURN("Failed to get system time");
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
    
    if (path[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Failed to build path for file: %s", name);
    }
    
    struct stat file_stat;
    if (stat(path, &file_stat) != 0) {
        GR_SYS_ERROR_RETURN("Failed to stat file: %s", name);
    }
    *offset = file_stat.st_size;
    *size = file_stat.st_size;
    *atime = file_stat.st_atime;
    
    GR_CALL_RETURN(gr_filesystem_mode(path, file_stat.st_atime, mode), 
                   "Failed to get file %s mode", name);
    return CM_SUCCESS;
}

status_t gr_filesystem_check_postpone_time(const char *file_name, time_t new_time)
{
    int64 offset;
    int64 size;
    time_t atime;
    gr_file_status_t mode;
    
    GR_CALL_RETURN(gr_filesystem_stat(file_name, &offset, &size, &mode, &atime), 
                   "Failed to get current file %s expire time", file_name);

    if (atime >= new_time) {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_INVALID_EXPIRE_TIME, 
                          "New expire time should be later than current expire time, file %s current expire time is: %s",
                          file_name, ctime(&atime));
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_postpone(const char *file_path, const char *time)
{
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(file_path, path, sizeof(path));
    
    if (path[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Failed to build path for file: %s", file_path);
    }
    
    struct tm time_info = {0};
    char *parse_result = strptime(time, "%Y-%m-%d %H:%M:%S", &time_info);
    if (parse_result == NULL || *parse_result != '\0') {
        GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "Failed to parse time string: %s", time);
    }
    
    time_t new_time = mktime(&time_info);
    if (new_time == -1) {
        GR_PARAM_ERROR_RETURN(ERR_GR_INVALID_PARAM, "Failed to convert time to timestamp");
    }

    struct stat file_stat;
    if (stat(path, &file_stat) != 0) {
        GR_SYS_ERROR_RETURN("Failed to get file %s stat", file_path);
    }

    if (file_stat.st_atime >= new_time) {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_INVALID_EXPIRE_TIME, 
                          "New expire time should be later than current expire time, file %s current expire time is: %s",
                          file_path, ctime(&file_stat.st_atime));
    }

    struct utimbuf new_utimes = {new_time, file_stat.st_mtime};
    if (utime(path, &new_utimes) != 0) {
        GR_SYS_ERROR_RETURN("Failed to extend file %s expired time", file_path);
    }
    return CM_SUCCESS;
}

status_t gr_filesystem_exist_item(const char *dir_path, bool32 *result, gft_item_type_t *output_type)
{
    *result = false;
    *output_type = -1;

    if (dir_path == NULL || dir_path[0] == '\0') {
        return CM_SUCCESS;
    }
    
    const char *base_path = gr_get_base_path();
    if (base_path == NULL) {
        return CM_SUCCESS;
    }

    struct stat st;
    char path[GR_FILE_PATH_MAX_LENGTH];
    
    if (gr_build_path(path, sizeof(path), base_path, dir_path) != CM_SUCCESS) {
        return CM_SUCCESS;
    }

    if (lstat(path, &st) != 0) {
        if (errno == ENOENT) {
            *result = false;
            return CM_SUCCESS;
        }
        /* For other errors, just return not exist */
        *result = false;
        return CM_SUCCESS;
    }

    if (S_ISREG(st.st_mode)) {
        *output_type = GFT_FILE;
    } else if (S_ISDIR(st.st_mode)) {
        *output_type = GFT_PATH;
    } else if (S_ISLNK(st.st_mode)) {
        *output_type = GFT_LINK;
    } else {
        /* Unsupported file type, just return not exist */
        *result = false;
        return CM_SUCCESS;
    }
    *result = true;

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif