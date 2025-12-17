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
#include <dirent.h>
#include "cm_defs.h"
#include "cm_error.h"
#include "cm_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

// 统一错误处理宏
#define CHECK_FS_ERROR_RETURN(condition, error_code, error_msg, ...) \
    do { \
        if (!(condition)) { \
            LOG_RUN_ERR("[FS] " error_msg, ##__VA_ARGS__); \
            GR_THROW_ERROR(error_code, ##__VA_ARGS__); \
            return CM_ERROR; \
        } \
    } while(0)

#define CHECK_FS_NULL_RETURN(ptr, error_msg) \
    CHECK_FS_ERROR_RETURN((ptr) != NULL, ERR_GR_FILE_SYSTEM_ERROR, error_msg)

static void gr_get_fs_path(const char *name, char *buf, size_t buf_size)
{
        int ret = snprintf_s(buf, buf_size, buf_size - 1, "%s/%s", 
                         g_inst_cfg->params.data_file_path, name);
        if (ret < 0) {
            LOG_RUN_ERR("[FS] gr_get_fs_path snprintf_s failed: %d", ret);
            if (buf_size > 0) {
                buf[0] = '\0';
            }
        }
}

typedef struct gr_dir_map_item {
    hash_node_t node;
    uint64_t handle;
    DIR *dir;
    pthread_mutex_t lock;  // 句柄级别的锁，保护 DIR* 的并发访问
} gr_dir_map_item_t;

#define MAX_DIR_HANDLE_COUNT 10000  // 增加到10000个句柄
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
        pthread_mutex_destroy(&item->lock);  // 销毁句柄锁
        free(item);
        curr = next;
    }
    
    // Free buckets
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
    
    // 优先重用已释放的句柄
    if (g_freed_handle_count > 0) {
        handle = g_freed_handles[--g_freed_handle_count];
    } else {
        // 如果没有可重用的句柄，分配新的
        if (g_next_dir_handle >= MAX_DIR_HANDLE_COUNT) {
            pthread_mutex_unlock(&g_dir_map_lock);
            LOG_RUN_ERR("[FS] Directory handle limit exceeded: %lu (max: %d)", g_next_dir_handle, MAX_DIR_HANDLE_COUNT);
            return 0;
        }
        handle = g_next_dir_handle++;
    }
    
    gr_dir_map_item_t *item = calloc(1, sizeof(gr_dir_map_item_t));
    if (item == NULL) {
        // 如果分配失败，将句柄放回重用池
        if (g_freed_handle_count < MAX_DIR_HANDLE_COUNT) {
            g_freed_handles[g_freed_handle_count++] = handle;
        }
        pthread_mutex_unlock(&g_dir_map_lock);
        LOG_RUN_ERR("[FS] Failed to allocate memory for directory map item");
        return 0;
    }
    
    item->handle = handle;
    item->dir = dir;
    pthread_mutex_init(&item->lock, NULL);  // 初始化句柄锁
    
    // Insert into CBB hash map
    if (cm_hmap_insert(&g_dir_map, &g_dir_map_funcs, (hash_node_t*)item) != CM_TRUE) {
        pthread_mutex_destroy(&item->lock);
        free(item);
        // 如果插入失败，将句柄放回重用池
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

// 获取 DIR* 并加句柄锁（调用者必须调用 gr_dir_map_unlock 解锁）
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
    
    // 先加句柄锁，再释放全局锁
    pthread_mutex_lock(&item->lock);
    pthread_mutex_unlock(&g_dir_map_lock);
    
    return item->dir;
}

// 解锁句柄
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
        pthread_mutex_destroy(&item->lock);  // 销毁句柄锁
        free(item);
        
        // 将句柄放入重用池
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
    CHECK_FS_NULL_RETURN(name, "Directory name is NULL");
    
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    
    CHECK_FS_ERROR_RETURN(access(path, F_OK) != 0, ERR_GR_DIR_CREATE_DUPLICATED, 
                          "Directory already exists: %s", name);
    
    CHECK_FS_ERROR_RETURN(mkdir(path, mode) == 0, ERR_GR_FILE_SYSTEM_ERROR,
                          "Failed to create directory: %s, errno: %d", name, errno);
    
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
            // "." 和 ".." 的第一个字符都是 '.'，第二个字符是 '\0' 或 '.'
            const char *entry_name = entry->d_name;
            if (entry_name[0] == '.' && (entry_name[1] == '\0' || (entry_name[1] == '.' && entry_name[2] == '\0'))) {
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
    CHECK_FS_NULL_RETURN(name, "Directory name is NULL");
    CHECK_FS_NULL_RETURN(out_handle, "Output handle is NULL");
    
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    
    DIR *dir = opendir(path);
    CHECK_FS_ERROR_RETURN(dir != NULL, ERR_GR_FILE_SYSTEM_ERROR,
                          "Failed to open directory: %s, errno: %d", name, errno);
    
    LOG_RUN_INF("[FS] Successfully opened directory: %s", name);
    uint64_t handle = gr_dir_map_insert(dir);
    if (handle == 0) {
        // 如果插入失败，需要关闭已打开的目录
        closedir(dir);
        LOG_RUN_ERR("[FS] Failed to insert directory into map: %s", name);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR, "Failed to insert directory into map");
        return CM_ERROR;
    }
    *out_handle = handle;
    return CM_SUCCESS;
}

status_t gr_filesystem_closedir(uint64_t handle)
{
    // 获取 DIR* 并加句柄锁，确保没有其他线程正在使用
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
    // 注意：closedir 成功后不需要解锁，因为 gr_dir_map_remove 会销毁锁
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

status_t gr_filesystem_rm(const char *name, unsigned long long attrFlag) {
    char path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(name, path, sizeof(path));
    if (attrFlag != 0) {
        LOG_RUN_INF("[FS] Changed file %s to lock mode by force", name);
        if (chmod(path, GR_LOCK_MODE) != CM_SUCCESS) {
            LOG_RUN_ERR("[FS] Failed to change file %s to lock mode, errno: %d", name, errno);
            GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
            return CM_ERROR;
        }
    }
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

status_t gr_filesystem_write(int handle, int64 size, const char *buf, int64 *rel_size) {
    if (rel_size == NULL) {
        LOG_RUN_ERR("[FS] Invalid rel_size pointer for write operation");
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM);
        return CM_ERROR;
    }
    // 文件在open时已经自动添加了O_APPEND标志，write会自动追加到文件末尾
    *rel_size = write(handle, buf, size);
    if (*rel_size == -1) {
        LOG_RUN_ERR("[FS] Failed to write to handle: %d, size: %lld, errno: %d", handle, size, errno);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    } else if (*rel_size != size) {
        LOG_RUN_WAR("[FS] Partial write to handle: %d, expected: %lld, actual: %lld, errno: %d", handle, size, *rel_size, errno);
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
    
    // 获取 DIR* 并加句柄锁
    DIR *dir = gr_dir_map_get_and_lock(handle);
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
    
    // 解锁句柄
    gr_dir_map_unlock(handle);
    return CM_SUCCESS;
}

status_t gr_filesystem_query_file_info(uint64_t handle, gr_file_item_t *file_items, uint32_t max_files, uint32_t *file_count, bool is_continue) {
    if (!file_items || !file_count) {
        LOG_RUN_ERR("[FS] Invalid parameters: file_items or file_count is NULL");
        return CM_ERROR;
    }
    
    // 获取 DIR* 并加句柄锁
    DIR *dir = gr_dir_map_get_and_lock(handle);
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
    
    // 解锁句柄
    gr_dir_map_unlock(handle);
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
    // 自动添加O_APPEND标志，这样无论使用pwrite还是append接口都能自动追加
    // 只有在写模式下才添加O_APPEND（O_RDWR或O_WRONLY）
    int open_flag = flag | O_SYNC;
    if ((flag & O_RDWR) || (flag & O_WRONLY)) {
        open_flag |= O_APPEND;
    }
    *fd = open(path, open_flag, 0);
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

status_t gr_filesystem_exist_item(const char *dir_path, bool32 *result, gft_item_type_t *output_type)
{
    if (dir_path == NULL || dir_path[0] == '\0') {
        return CM_ERROR;
    }
    if (g_inst_cfg == NULL || g_inst_cfg->params.data_file_path == NULL) {
        LOG_RUN_ERR("[FS] gr_filesystem_exist_item: g_inst_cfg or data_file_path is NULL");
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR, "g_inst_cfg or data_file_path is NULL");
        return CM_ERROR;
    }

    *result = false;
    *output_type = -1;
    struct stat st;

    static char path[GR_FILE_PATH_MAX_LENGTH];
    int err = snprintf_s(path, GR_FILE_PATH_MAX_LENGTH, GR_FILE_PATH_MAX_LENGTH - 1,
                               "%s/%s", g_inst_cfg->params.data_file_path, (dir_path));
    GR_SECUREC_SS_RETURN_IF_ERROR(err, CM_ERROR);

    if (lstat(path, &st) != 0) {
        LOG_RUN_ERR("failed to get stat for path %s, errno %d.\n", path, errno);
        if (errno == ENOENT) {
            *result = false;
            return CM_SUCCESS;
        }
        return CM_ERROR;
    }

    if (S_ISREG(st.st_mode)) {
        *output_type = GFT_FILE;
    } else if (S_ISDIR(st.st_mode)) {
        *output_type = GFT_PATH;
    } else if (S_ISLNK(st.st_mode)) {
        *output_type = GFT_LINK;
    } else {
        LOG_RUN_ERR("file %s type is %o, not supported", path, st.st_mode);
        *output_type = -1;
        return CM_ERROR;
    }
    *result = true;

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif