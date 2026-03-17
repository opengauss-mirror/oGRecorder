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

/*
 * Logical EOF tracking
 *
 * To support O_DIRECT-style aligned IO at the physical layer while preserving
 * POSIX-style logical semantics for upper layers, we maintain a per-file
 * logical size that may be smaller than the physical file size.
 *
 * Design:
 * - On disk, each VFS directory has a single metadata file:
 *     <vfs_root>/.gr_vfs_meta
 *   which contains append-only records of the form:
 *     <logical_path> <logical_size>\n
 *   where logical_path is the GR logical path (e.g. "vfs_name/file").
 * - In memory, we keep a lightweight mapping from fd -> (logical_path, logical_size)
 *   for files opened through gr_filesystem_open. This allows pwrite/pread to
 *   compute logical EOF without knowing the original path at call sites.
 *
 * Persistence semantics:
 * - On open: logical_size is initialized from meta if present; otherwise from
 *   the current physical file size (stat), for backward compatibility.
 * - On write: after successful aligned write, we:
 *     - update in-memory logical_size for the fd
 *     - append a new record to the corresponding .gr_vfs_meta file
 * - On stat / logical-size queries: we prefer in-memory fd mapping when
 *   available, otherwise fall back to scanning .gr_vfs_meta and, if absent,
 *   to the physical size from stat.
 */

typedef struct gr_fd_meta {
    int fd;
    uint64_t logical_size;
    char logical_path[GR_FILE_PATH_MAX_LENGTH];  // GR logical path, e.g. "vfs_name/file"
    struct gr_fd_meta *next;
} gr_fd_meta_t;

static pthread_mutex_t g_fd_meta_lock = PTHREAD_MUTEX_INITIALIZER;
static gr_fd_meta_t *g_fd_meta_head = NULL;

static status_t gr_meta_extract_vfs_name(const char *logical_path, char *vfs_name, size_t vfs_name_len)
{
    const char *slash = strchr(logical_path, '/');
    size_t len = 0;

    if (slash != NULL) {
        len = (size_t)(slash - logical_path);
    } else {
        len = strlen(logical_path);
    }

    if (len == 0 || len >= vfs_name_len) {
        GR_PARAM_ERROR_RETURN(ERR_GR_FILE_PATH_ILL,
                              "invalid logical path for vfs meta (too short or too long): %s", logical_path);
    }

    errno_t err = strncpy_s(vfs_name, vfs_name_len, logical_path, len);
    if (SECUREC_UNLIKELY(err != EOK)) {
        GR_SYS_ERROR_RETURN("failed to copy vfs name for logical path: %s", logical_path);
    }
    vfs_name[len] = '\0';
    return CM_SUCCESS;
}

static status_t gr_meta_build_meta_path(const char *vfs_name, char *meta_path, size_t meta_path_len)
{
    char vfs_root[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(vfs_name, vfs_root, sizeof(vfs_root));
    if (vfs_root[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR,
                           "failed to build vfs root path for vfs: %s", vfs_name);
    }

    int ret = snprintf_s(meta_path, meta_path_len, meta_path_len - 1,
                         "%s/.gr_vfs_meta", vfs_root);
    if (ret < 0 || (size_t)ret >= meta_path_len) {
        GR_FS_ERROR_RETURN(ERR_SYSTEM_CALL,
                           "failed to build vfs meta path for vfs: %s", vfs_name);
    }
    return CM_SUCCESS;
}

static status_t gr_meta_read_logical_size_from_meta(const char *logical_path, uint64_t *logical_size)
{
    char vfs_name[GR_MAX_NAME_LEN];
    char meta_path[GR_FILE_PATH_MAX_LENGTH];
    char line[GR_FILE_PATH_MAX_LENGTH * 2];
    char path_buf[GR_FILE_PATH_MAX_LENGTH];
    uint64_t latest_size = 0;
    bool found = false;

    GR_FS_CHECK_NULL_RETURN(logical_path, ERR_GR_INVALID_PARAM, "logical_path is NULL");
    GR_FS_CHECK_NULL_RETURN(logical_size, ERR_GR_INVALID_PARAM, "logical_size is NULL");

    if (gr_meta_extract_vfs_name(logical_path, vfs_name, sizeof(vfs_name)) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (gr_meta_build_meta_path(vfs_name, meta_path, sizeof(meta_path)) != CM_SUCCESS) {
        return CM_ERROR;
    }

    FILE *fp = fopen(meta_path, "r");
    if (fp == NULL) {
        // Meta file does not exist yet; caller will fall back to physical size.
        return CM_ERROR;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long size_val = 0;
        int scan_ret = sscanf_s(line, "%s %llu", path_buf, (unsigned int)sizeof(path_buf), &size_val);
        if (scan_ret == 2 && strcmp(path_buf, logical_path) == 0) {
            latest_size = (uint64_t)size_val;
            found = true;
        }
    }

    (void)fclose(fp);

    if (!found) {
        return CM_ERROR;
    }
    *logical_size = latest_size;
    return CM_SUCCESS;
}

static void gr_meta_append_record(const char *logical_path, uint64_t logical_size)
{
    char vfs_name[GR_MAX_NAME_LEN];
    char meta_path[GR_FILE_PATH_MAX_LENGTH];

    if (logical_path == NULL) {
        return;
    }

    if (gr_meta_extract_vfs_name(logical_path, vfs_name, sizeof(vfs_name)) != CM_SUCCESS) {
        return;
    }
    if (gr_meta_build_meta_path(vfs_name, meta_path, sizeof(meta_path)) != CM_SUCCESS) {
        return;
    }

    FILE *fp = fopen(meta_path, "a");
    if (fp == NULL) {
        LOG_RUN_WAR("[FS] failed to open vfs meta file '%s' for append, errno: %d",
                    meta_path, errno);
        return;
    }

    int ret = fprintf(fp, "%s %llu\n", logical_path, (unsigned long long)logical_size);
    if (ret < 0) {
        LOG_RUN_WAR("[FS] failed to append record to vfs meta file '%s', errno: %d",
                    meta_path, errno);
    }
    (void)fclose(fp);
}

static status_t gr_meta_query_logical_size(const char *logical_path, uint64_t *logical_size)
{
    // Try meta file first
    if (gr_meta_read_logical_size_from_meta(logical_path, logical_size) == CM_SUCCESS) {
        return CM_SUCCESS;
    }

    // Fallback: use current physical file size
    char fs_path[GR_FILE_PATH_MAX_LENGTH];
    gr_get_fs_path(logical_path, fs_path, sizeof(fs_path));
    if (fs_path[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR,
                           "failed to build path for file when getting logical size: %s", logical_path);
    }

    struct stat st;
    if (stat(fs_path, &st) != 0) {
        GR_SYS_ERROR_RETURN("failed to stat file when getting logical size: %s", logical_path);
    }

    *logical_size = (uint64_t)st.st_size;
    return CM_SUCCESS;
}

static gr_fd_meta_t *gr_fd_meta_find_nolock(int fd)
{
    gr_fd_meta_t *curr = g_fd_meta_head;
    while (curr != NULL) {
        if (curr->fd == fd) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

static void gr_fd_meta_register(int fd, const char *logical_path, uint64_t logical_size)
{
    if (logical_path == NULL) {
        return;
    }

    gr_fd_meta_t *ent = (gr_fd_meta_t *)malloc(sizeof(gr_fd_meta_t));
    if (ent == NULL) {
        LOG_RUN_WAR("[FS] failed to allocate fd meta entry for fd %d", fd);
        return;
    }

    ent->fd = fd;
    ent->logical_size = logical_size;
    errno_t err = strncpy_s(ent->logical_path, sizeof(ent->logical_path),
                            logical_path, sizeof(ent->logical_path) - 1);
    if (SECUREC_UNLIKELY(err != EOK)) {
        LOG_RUN_WAR("[FS] failed to copy logical path for fd meta entry, fd %d, errno: %d", fd, err);
        free(ent);
        return;
    }

    pthread_mutex_lock(&g_fd_meta_lock);
    ent->next = g_fd_meta_head;
    g_fd_meta_head = ent;
    pthread_mutex_unlock(&g_fd_meta_lock);
}

static bool gr_fd_meta_get(int fd, uint64_t *logical_size)
{
    bool found = false;

    pthread_mutex_lock(&g_fd_meta_lock);
    gr_fd_meta_t *ent = gr_fd_meta_find_nolock(fd);
    if (ent != NULL) {
        if (logical_size != NULL) {
            *logical_size = ent->logical_size;
        }
        found = true;
    }
    pthread_mutex_unlock(&g_fd_meta_lock);
    return found;
}

static bool gr_fd_meta_get_by_path(const char *logical_path, uint64_t *logical_size)
{
    bool found = false;
    uint64_t max_size = 0;

    pthread_mutex_lock(&g_fd_meta_lock);
    gr_fd_meta_t *curr = g_fd_meta_head;
    while (curr != NULL) {
        if (strcmp(curr->logical_path, logical_path) == 0) {
            if (!found || curr->logical_size > max_size) {
                max_size = curr->logical_size;
                found = true;
            }
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&g_fd_meta_lock);

    if (found && logical_size != NULL) {
        *logical_size = max_size;
    }
    return found;
}

static void gr_fd_meta_on_write(int fd, uint64_t new_logical_end)
{
    char logical_path[GR_FILE_PATH_MAX_LENGTH];
    bool have_path = false;

    pthread_mutex_lock(&g_fd_meta_lock);
    gr_fd_meta_t *ent = gr_fd_meta_find_nolock(fd);
    if (ent != NULL) {
        if (new_logical_end > ent->logical_size) {
            ent->logical_size = new_logical_end;
        }
        errno_t err = strncpy_s(logical_path, sizeof(logical_path),
                                ent->logical_path, sizeof(logical_path) - 1);
        if (SECUREC_UNLIKELY(err == EOK)) {
            have_path = true;
        }
    }
    pthread_mutex_unlock(&g_fd_meta_lock);

    if (have_path) {
        gr_meta_append_record(logical_path, new_logical_end);
    }
}

static void gr_fd_meta_unregister(int fd)
{
    pthread_mutex_lock(&g_fd_meta_lock);
    gr_fd_meta_t *prev = NULL;
    gr_fd_meta_t *curr = g_fd_meta_head;

    while (curr != NULL) {
        if (curr->fd == fd) {
            if (prev == NULL) {
                g_fd_meta_head = curr->next;
            } else {
                prev->next = curr->next;
            }
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&g_fd_meta_lock);
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

// Return the logical path registered for a given fd, if any.
static bool gr_fd_meta_get_path(int fd, char *logical_path, size_t path_len)
{
    bool found = false;

    if (logical_path == NULL || path_len == 0) {
        return false;
    }

    pthread_mutex_lock(&g_fd_meta_lock);
    gr_fd_meta_t *ent = gr_fd_meta_find_nolock(fd);
    if (ent != NULL) {
        errno_t err = strncpy_s(logical_path, path_len, ent->logical_path, path_len - 1);
        if (SECUREC_UNLIKELY(err == EOK)) {
            found = true;
        }
    }
    pthread_mutex_unlock(&g_fd_meta_lock);

    if (!found) {
        logical_path[0] = '\0';
    }
    return found;
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
            // Changing file permission failure does not affect subsequent deletion,
            // we can safely ignore this error and just log a warning for troubleshooting.
            LOG_RUN_WAR("[FS] Failed to change file %s to lock mode, ignore errno=%d", name, errno);
        }
    }
    
    if (unlink(path) != 0) {
        GR_SYS_ERROR_RETURN("Failed to remove file: %s", name);
    }

    /*
     * The file has been removed from the filesystem; record a logical EOF of 0
     * in the VFS meta so that any future reopen or stat of a re-created file
     * with the same logical name starts from an empty logical size.
     * This also avoids meta growing stale for files that are no longer present.
     */
    gr_meta_append_record(name, 0);
    return CM_SUCCESS;
}

status_t gr_filesystem_pwrite(int handle, int64 offset, int64 size, const char *buf, int64 *rel_size) {
    GR_FS_CHECK_NULL_RETURN(rel_size, ERR_GR_INVALID_PARAM, "rel_size pointer is NULL for write operation");

    /* 
     * To support O_DIRECT safely while upper-layer IO may be unaligned,
     * we convert unaligned writes into aligned read-modify-write cycles
     * with an internal bounce buffer. This keeps the logical file size
     * unchanged and avoids exposing padding to upper layers.
     */
    const int64 align_size = 4096;  // alignment for O_DIRECT IO (page/block aligned)
    int64 aligned_off = (offset / align_size) * align_size;
    int64 end_off = offset + size;
    int64 aligned_end = ((end_off + align_size - 1) / align_size) * align_size;
    int64 aligned_len = aligned_end - aligned_off;

    if (aligned_len <= 0) {
        *rel_size = 0;
        return CM_SUCCESS;
    }

    // Remember original logical size (POSIX semantics: logical EOF is max(old_size, offset+size)).
    // Prefer in-memory logical size; fall back to physical file size if not found.
    uint64_t logical_size_u64 = 0;
    int64 logical_end = offset + size;
    if (gr_fd_meta_get(handle, &logical_size_u64)) {
        if ((int64)logical_size_u64 > logical_end) {
            logical_end = (int64)logical_size_u64;
        }
    } else {
        struct stat st;
        if (fstat(handle, &st) == 0 && (int64)st.st_size > logical_end) {
            logical_end = (int64)st.st_size;
        }
    }

    void *bounce = NULL;
    int ret = posix_memalign(&bounce, (size_t)align_size, (size_t)aligned_len);
    if (ret != 0 || bounce == NULL) {
        GR_SYS_ERROR_RETURN("Failed to allocate aligned buffer for pwrite, errno: %d", ret);
    }

    // Initialize bounce buffer with existing data (read-modify-write).
    // It is acceptable that pread reads less than aligned_len near EOF;
    // the remaining bytes will stay zero and be written as padding.
    ssize_t read_bytes = pread(handle, bounce, (size_t)aligned_len, (off_t)aligned_off);
    if (read_bytes < 0) {
        int saved_errno = errno;
        free(bounce);
        errno = saved_errno;
        GR_SYS_ERROR_RETURN("Failed to read before O_DIRECT write, handle: %d, offset: %lld, size: %lld",
                            handle, (long long)aligned_off, (long long)aligned_len);
    } else if (read_bytes < aligned_len) {
        // Zero-fill the tail that was not present in the original file
        errno_t err = memset_s((char *)bounce + read_bytes, (size_t)(aligned_len - read_bytes),
                               0, (size_t)(aligned_len - read_bytes));
        if (SECUREC_UNLIKELY(err != EOK)) {
            int saved_errno = errno;
            free(bounce);
            errno = saved_errno;
            GR_SYS_ERROR_RETURN("Failed to zero-fill bounce buffer, handle: %d", handle);
        }
    }

    // Copy user data into the correct position inside the aligned buffer
    int64 inner_off = offset - aligned_off;
    errno_t cpy_err = memcpy_s((char *)bounce + inner_off, (size_t)(aligned_len - inner_off),
                               buf, (size_t)size);
    if (SECUREC_UNLIKELY(cpy_err != EOK)) {
        int saved_errno = errno;
        free(bounce);
        errno = saved_errno;
        GR_SYS_ERROR_RETURN("Failed to copy data into bounce buffer, handle: %d", handle);
    }

    ssize_t write_bytes = pwrite(handle, bounce, (size_t)aligned_len, (off_t)aligned_off);
    int saved_errno = errno;
    free(bounce);
    errno = saved_errno;

    if (write_bytes < 0) {
        GR_SYS_ERROR_RETURN("Failed to write to handle: %d, aligned offset: %lld, aligned size: %lld",
                            handle, (long long)aligned_off, (long long)aligned_len);
    }
    if (write_bytes != aligned_len) {
        LOG_RUN_WAR("[FS] Partial aligned write to handle: %d, aligned offset: %lld, "
                    "aligned size: %lld, actual: %lld, errno: %d",
                    handle, (long long)aligned_off, (long long)aligned_len,
                    (long long)write_bytes, errno);
        GR_SYS_ERROR_RETURN("Failed to complete aligned write for handle: %d", handle);
    }

    // From upper-layer view, only 'size' bytes are logically written. We maintain the
    // logical EOF separately in metadata without trying to shrink the physical file,
    // because the underlying filesystem may not support shrinking or it may be unsafe.
    if (logical_end > 0) {
        gr_fd_meta_on_write(handle, (uint64_t)logical_end);
    }

    *rel_size = size;
    return CM_SUCCESS;
}

status_t gr_filesystem_write(int handle, int64 size, const char *buf, int64 *rel_size) {
    GR_FS_CHECK_NULL_RETURN(rel_size, ERR_GR_INVALID_PARAM, "rel_size pointer is NULL for write operation");

    /*
     * Append-style write: first get current end position, then delegate
     * to the aligned pwrite implementation so that O_DIRECT constraints
     * are still satisfied.
     */
    off_t cur_off = lseek(handle, 0, SEEK_END);
    if (cur_off == (off_t)-1) {
        GR_SYS_ERROR_RETURN("Failed to get end offset for handle: %d", handle);
    }

    return gr_filesystem_pwrite(handle, (int64)cur_off, size, buf, rel_size);
}

status_t gr_filesystem_pread(int handle, int64 offset, int64 size, char *buf, int64 *rel_size) {
    GR_FS_CHECK_NULL_RETURN(rel_size, ERR_GR_INVALID_PARAM, "rel_size pointer is NULL for read operation");

    /*
     * All reads also go through an aligned buffer so that we can work
     * safely with O_DIRECT even if the upper-layer offset/size are not
     * aligned. Logical semantics (including EOF) are preserved.
     */
    const int64 align_size = 4096;  // alignment for O_DIRECT IO (page/block aligned)

    // Determine logical EOF for this handle to clamp reads within logical size.
    uint64_t logical_size_u64 = 0;
    bool have_fd_meta = gr_fd_meta_get(handle, &logical_size_u64);
    if (!have_fd_meta || logical_size_u64 == 0) {
        // Try to resolve logical size via logical_path + meta file
        char logical_path[GR_FILE_PATH_MAX_LENGTH];
        uint64_t meta_size = 0;
        if (gr_fd_meta_get_path(handle, logical_path, sizeof(logical_path)) &&
            gr_meta_query_logical_size(logical_path, &meta_size) == CM_SUCCESS) {
            if (meta_size > logical_size_u64) {
                logical_size_u64 = meta_size;
            }
        } else {
            // Fallback: use current physical file size so that concurrent
            // readers on different fds/VFS 仍能看到已经写入的数据。
            struct stat st;
            if (fstat(handle, &st) == 0 && st.st_size > 0) {
                logical_size_u64 = (uint64_t)st.st_size;
            }
        }
    }
    if ((uint64_t)offset >= logical_size_u64) {
        *rel_size = 0;
        return CM_SUCCESS;
    }
    int64 max_by_logical = (int64)logical_size_u64 - offset;
    if (size > max_by_logical) {
        size = max_by_logical;
    }
    int64 aligned_off = (offset / align_size) * align_size;
    int64 end_off = offset + size;
    int64 aligned_end = ((end_off + align_size - 1) / align_size) * align_size;
    int64 aligned_len = aligned_end - aligned_off;

    if (aligned_len <= 0) {
        *rel_size = 0;
        return CM_SUCCESS;
    }

    void *bounce = NULL;
    int ret = posix_memalign(&bounce, (size_t)align_size, (size_t)aligned_len);
    if (ret != 0 || bounce == NULL) {
        GR_SYS_ERROR_RETURN("Failed to allocate aligned buffer for pread, errno: %d", ret);
    }

    ssize_t read_bytes = pread(handle, bounce, (size_t)aligned_len, (off_t)aligned_off);
    if (read_bytes < 0) {
        int saved_errno = errno;
        free(bounce);
        errno = saved_errno;
        GR_SYS_ERROR_RETURN("Failed to read from handle: %d, aligned offset: %lld, aligned size: %lld",
                            handle, (long long)aligned_off, (long long)aligned_len);
    }

    // Calculate how many bytes are actually available in requested range
    int64 inner_off = offset - aligned_off;
    int64 available = 0;
    if (read_bytes > inner_off) {
        int64 max_can_copy = read_bytes - inner_off;
        available = (max_can_copy > size) ? size : max_can_copy;
    }

    if (available > 0) {
        errno_t cpy_err = memcpy_s(buf, (size_t)size,
                                   (char *)bounce + inner_off, (size_t)available);
        if (SECUREC_UNLIKELY(cpy_err != EOK)) {
            int saved_errno = errno;
            free(bounce);
            errno = saved_errno;
            GR_SYS_ERROR_RETURN("Failed to copy data from bounce buffer, handle: %d", handle);
        }
    }

    free(bounce);
    *rel_size = available;
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
    
    uint64_t logical_size = 0;
    // Prefer logical size from meta; fall back to physical file size if needed.
    if (gr_fd_meta_get_by_path(file_path, &logical_size) ||
        gr_meta_query_logical_size(file_path, &logical_size) == CM_SUCCESS) {
        *end_position = (off_t)logical_size;
        return CM_SUCCESS;
    }

    // As a last resort (e.g. meta and stat failed), keep original behavior.
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
    
    // Automatically add O_APPEND so both pwrite and append interfaces can append.
    // Only add O_APPEND in write modes (O_RDWR or O_WRONLY).
    int open_flag = flag | O_SYNC;
    if ((flag & O_RDWR) || (flag & O_WRONLY)) {
        open_flag |= O_APPEND;
    }
    
    *fd = open(path, open_flag, 0);
    if (*fd == -1) {
        GR_SYS_ERROR_RETURN("Failed to open file: %s (full path: %s)", file_path, path);
    }

    // Initialize logical EOF tracking for this fd.
    uint64_t logical_size = 0;
    if (gr_meta_query_logical_size(file_path, &logical_size) != CM_SUCCESS) {
        logical_size = 0;
    }
    gr_fd_meta_register(*fd, file_path, logical_size);
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
    // Remove fd -> logical size mapping; metadata is already persisted on each write.
    gr_fd_meta_unregister(fd);
    if (close(fd) == -1) {
        GR_SYS_ERROR_RETURN("Failed to close file descriptor: %d", fd);
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

    // Determine logical size for this file.
    uint64_t logical_size_u64 = 0;
    if (!gr_fd_meta_get_by_path(name, &logical_size_u64) &&
        gr_meta_query_logical_size(name, &logical_size_u64) != CM_SUCCESS) {
        logical_size_u64 = (uint64_t)file_stat.st_size;
    }

    *offset = (int64)logical_size_u64;
    *size = (int64)logical_size_u64;
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