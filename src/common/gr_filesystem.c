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
    // Snapshot for globally ordered pagination (sorted file names)
    char **sorted_names;
    uint32_t sorted_count;
    uint32_t cursor;
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

static void gr_dir_map_free_snapshot(gr_dir_map_item_t *item)
{
    if (item == NULL || item->sorted_names == NULL) {
        return;
    }
    for (uint32_t i = 0; i < item->sorted_count; i++) {
        free(item->sorted_names[i]);
    }
    free(item->sorted_names);
    item->sorted_names = NULL;
    item->sorted_count = 0;
    item->cursor = 0;
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
        gr_dir_map_free_snapshot(item);
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
    item->sorted_names = NULL;
    item->sorted_count = 0;
    item->cursor = 0;
    
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
        gr_dir_map_free_snapshot(item);
        pthread_mutex_destroy(&item->lock);  // Destroy per-handle lock
        free(item);
        
        // Put the handle into the reuse pool
        if (g_freed_handle_count < MAX_DIR_HANDLE_COUNT) {
            g_freed_handles[g_freed_handle_count++] = handle;
        }
    }
    
    pthread_mutex_unlock(&g_dir_map_lock);
}

// Get dir map item and acquire the per-handle lock (caller must call gr_dir_map_unlock)
static gr_dir_map_item_t *gr_dir_map_get_item_and_lock(uint64_t handle)
{
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

    pthread_mutex_lock(&item->lock);
    pthread_mutex_unlock(&g_dir_map_lock);
    return item;
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
 * - Primary on-disk store: hidden per-file sidecar
 *     <dir>/.<basename>.gr_logical_meta
 *   (not visible to query_file_num / query_file_info).
 *   containing a single logical size (O(1) read/write).
 * - Legacy fallback: append-only VFS log
 *     <vfs_root>/.gr_vfs_meta
 *   scanned only when sidecar is absent (migration / old deployments).
 * - In-memory: fd -> (logical_path, logical_size) plus a path cache keyed
 *   by sidecar mtime to avoid repeated disk reads on hot pread paths.
 *
 * Persistence semantics:
 * - On open: logical_size = max(open fds, sidecar, legacy log, physical stat).
 * - On write: update in-memory fd meta and persist to sidecar (monotonic).
 * - On close: flush fd logical size to sidecar again.
 * - On pread: max(open fds on path, sidecar/cache) on every read — O(1) via
 *   sidecar mtime cache; legacy log is never scanned on the hot path.
 * - On stat: max(open fds, sidecar/cache, legacy log).
 */

typedef struct gr_fd_meta {
    int fd;
    uint64_t logical_size;
    char logical_path[GR_FILE_PATH_MAX_LENGTH];  // GR logical path, e.g. "vfs_name/file"
    struct gr_fd_meta *next;
} gr_fd_meta_t;

static pthread_mutex_t g_fd_meta_lock = PTHREAD_MUTEX_INITIALIZER;
static gr_fd_meta_t *g_fd_meta_head = NULL;

#define GR_LOGICAL_META_SUFFIX ".gr_logical_meta"

static bool gr_fs_is_dot_or_dotdot(const char *name)
{
    if (name == NULL || name[0] != '.') {
        return false;
    }
    if (name[1] == '\0') {
        return true;
    }
    return (name[1] == '.' && name[2] == '\0');
}

/* Internal metadata entries must not appear in VFS file listing APIs. */
static bool gr_fs_is_internal_metadata_name(const char *name)
{
    size_t len;
    size_t suf_len;

    if (name == NULL || name[0] == '\0') {
        return true;
    }
    if (name[0] == '.') {
        return true;
    }
    len = strlen(name);
    suf_len = sizeof(GR_LOGICAL_META_SUFFIX) - 1;
    if (len > suf_len && strcmp(name + len - suf_len, GR_LOGICAL_META_SUFFIX) == 0) {
        return true; /* legacy non-hidden sidecar: file.gr_logical_meta */
    }
    return false;
}

static status_t gr_meta_build_legacy_sidecar_path(const char *logical_path, char *sidecar_path,
    size_t sidecar_path_len)
{
    char fs_path[GR_FILE_PATH_MAX_LENGTH];

    GR_FS_CHECK_NULL_RETURN(logical_path, ERR_GR_INVALID_PARAM, "logical_path is NULL");
    GR_FS_CHECK_NULL_RETURN(sidecar_path, ERR_GR_INVALID_PARAM, "sidecar_path is NULL");

    gr_get_fs_path(logical_path, fs_path, sizeof(fs_path));
    if (fs_path[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR,
                           "failed to build fs path for legacy sidecar: %s", logical_path);
    }

    int ret = snprintf_s(sidecar_path, sidecar_path_len, sidecar_path_len - 1,
                         "%s%s", fs_path, GR_LOGICAL_META_SUFFIX);
    if (ret < 0 || (size_t)ret >= sidecar_path_len) {
        GR_FS_ERROR_RETURN(ERR_SYSTEM_CALL,
                           "failed to build legacy sidecar path for: %s", logical_path);
    }
    return CM_SUCCESS;
}

static status_t gr_meta_build_sidecar_path(const char *logical_path, char *sidecar_path, size_t sidecar_path_len)
{
    char fs_path[GR_FILE_PATH_MAX_LENGTH];
    const char *base;

    GR_FS_CHECK_NULL_RETURN(logical_path, ERR_GR_INVALID_PARAM, "logical_path is NULL");
    GR_FS_CHECK_NULL_RETURN(sidecar_path, ERR_GR_INVALID_PARAM, "sidecar_path is NULL");

    gr_get_fs_path(logical_path, fs_path, sizeof(fs_path));
    if (fs_path[0] == '\0') {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR,
                           "failed to build fs path for sidecar: %s", logical_path);
    }

    base = strrchr(fs_path, '/');
    if (base == NULL) {
        int ret = snprintf_s(sidecar_path, sidecar_path_len, sidecar_path_len - 1,
                             ".%s%s", fs_path, GR_LOGICAL_META_SUFFIX);
        if (ret < 0 || (size_t)ret >= sidecar_path_len) {
            GR_FS_ERROR_RETURN(ERR_SYSTEM_CALL,
                               "failed to build sidecar path for: %s", logical_path);
        }
        return CM_SUCCESS;
    }

    base++;
    {
        size_t dir_len = (size_t)(base - fs_path);
        int ret = snprintf_s(sidecar_path, sidecar_path_len, sidecar_path_len - 1,
                             "%.*s.%s%s", (int)dir_len, fs_path, base, GR_LOGICAL_META_SUFFIX);
        if (ret < 0 || (size_t)ret >= sidecar_path_len) {
            GR_FS_ERROR_RETURN(ERR_SYSTEM_CALL,
                               "failed to build sidecar path for: %s", logical_path);
        }
    }
    return CM_SUCCESS;
}

static void gr_meta_unlink_legacy_sidecar(const char *logical_path)
{
    char legacy_path[GR_FILE_PATH_MAX_LENGTH];

    if (gr_meta_build_legacy_sidecar_path(logical_path, legacy_path, sizeof(legacy_path)) != CM_SUCCESS) {
        return;
    }
    (void)unlink(legacy_path);
}

typedef struct gr_path_logical_cache {
    char logical_path[GR_FILE_PATH_MAX_LENGTH];
    uint64_t logical_size;
    time_t sidecar_mtime;
    struct gr_path_logical_cache *next;
} gr_path_logical_cache_t;

static pthread_mutex_t g_path_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static gr_path_logical_cache_t *g_path_cache_head = NULL;

static gr_path_logical_cache_t *gr_path_cache_find_nolock(const char *logical_path)
{
    gr_path_logical_cache_t *curr = g_path_cache_head;
    while (curr != NULL) {
        if (strcmp(curr->logical_path, logical_path) == 0) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

static void gr_path_cache_put(const char *logical_path, uint64_t logical_size, time_t sidecar_mtime)
{
    if (logical_path == NULL) {
        return;
    }

    pthread_mutex_lock(&g_path_cache_lock);
    gr_path_logical_cache_t *ent = gr_path_cache_find_nolock(logical_path);
    if (ent == NULL) {
        ent = (gr_path_logical_cache_t *)calloc(1, sizeof(gr_path_logical_cache_t));
        if (ent == NULL) {
            pthread_mutex_unlock(&g_path_cache_lock);
            LOG_RUN_WAR("[FS] failed to allocate path logical cache for '%s'", logical_path);
            return;
        }
        errno_t err = strncpy_s(ent->logical_path, sizeof(ent->logical_path),
                                logical_path, sizeof(ent->logical_path) - 1);
        if (SECUREC_UNLIKELY(err != EOK)) {
            free(ent);
            pthread_mutex_unlock(&g_path_cache_lock);
            return;
        }
        ent->next = g_path_cache_head;
        g_path_cache_head = ent;
    }
    ent->logical_size = logical_size;
    ent->sidecar_mtime = sidecar_mtime;
    pthread_mutex_unlock(&g_path_cache_lock);
}

static void gr_path_cache_invalidate(const char *logical_path)
{
    if (logical_path == NULL) {
        return;
    }

    pthread_mutex_lock(&g_path_cache_lock);
    gr_path_logical_cache_t *prev = NULL;
    gr_path_logical_cache_t *curr = g_path_cache_head;
    while (curr != NULL) {
        if (strcmp(curr->logical_path, logical_path) == 0) {
            if (prev == NULL) {
                g_path_cache_head = curr->next;
            } else {
                prev->next = curr->next;
            }
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&g_path_cache_lock);
}

static void gr_meta_remove_sidecars(const char *logical_path)
{
    char sidecar_path[GR_FILE_PATH_MAX_LENGTH];

    gr_meta_unlink_legacy_sidecar(logical_path);
    if (gr_meta_build_sidecar_path(logical_path, sidecar_path, sizeof(sidecar_path)) == CM_SUCCESS) {
        (void)unlink(sidecar_path);
    }
    gr_path_cache_invalidate(logical_path);
}

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

static status_t gr_meta_persist_logical_size(const char *logical_path, uint64_t logical_size);

static status_t gr_meta_read_sidecar_at_path(const char *logical_path, const char *sidecar_path,
    uint64_t *logical_size)
{
    struct stat st;
    FILE *fp = NULL;
    char line[64];
    unsigned long long size_val = 0;

    if (stat(sidecar_path, &st) != 0) {
        return CM_ERROR;
    }

    pthread_mutex_lock(&g_path_cache_lock);
    gr_path_logical_cache_t *cached = gr_path_cache_find_nolock(logical_path);
    if (cached != NULL && cached->sidecar_mtime == st.st_mtime) {
        *logical_size = cached->logical_size;
        pthread_mutex_unlock(&g_path_cache_lock);
        return CM_SUCCESS;
    }
    pthread_mutex_unlock(&g_path_cache_lock);

    fp = fopen(sidecar_path, "r");
    if (fp == NULL) {
        return CM_ERROR;
    }

    if (fgets(line, sizeof(line), fp) == NULL ||
        sscanf_s(line, "%llu", &size_val) != 1) {
        (void)fclose(fp);
        return CM_ERROR;
    }
    (void)fclose(fp);

    *logical_size = (uint64_t)size_val;
    gr_path_cache_put(logical_path, *logical_size, st.st_mtime);
    return CM_SUCCESS;
}

static status_t gr_meta_read_sidecar(const char *logical_path, uint64_t *logical_size)
{
    char sidecar_path[GR_FILE_PATH_MAX_LENGTH];
    char legacy_path[GR_FILE_PATH_MAX_LENGTH];

    GR_FS_CHECK_NULL_RETURN(logical_path, ERR_GR_INVALID_PARAM, "logical_path is NULL");
    GR_FS_CHECK_NULL_RETURN(logical_size, ERR_GR_INVALID_PARAM, "logical_size is NULL");

    if (gr_meta_build_sidecar_path(logical_path, sidecar_path, sizeof(sidecar_path)) == CM_SUCCESS &&
        gr_meta_read_sidecar_at_path(logical_path, sidecar_path, logical_size) == CM_SUCCESS) {
        return CM_SUCCESS;
    }

    if (gr_meta_build_legacy_sidecar_path(logical_path, legacy_path, sizeof(legacy_path)) == CM_SUCCESS &&
        gr_meta_read_sidecar_at_path(logical_path, legacy_path, logical_size) == CM_SUCCESS) {
        (void)gr_meta_persist_logical_size(logical_path, *logical_size);
        return CM_SUCCESS;
    }

    return CM_ERROR;
}

static status_t gr_meta_persist_logical_size(const char *logical_path, uint64_t logical_size)
{
    char sidecar_path[GR_FILE_PATH_MAX_LENGTH];
    FILE *fp = NULL;
    struct stat st_after;

    if (logical_path == NULL) {
        GR_FS_ERROR_RETURN(ERR_GR_INVALID_PARAM, "logical_path is NULL when persisting logical size");
    }

    if (gr_meta_build_sidecar_path(logical_path, sidecar_path, sizeof(sidecar_path)) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (logical_size != 0) {
        char legacy_path[GR_FILE_PATH_MAX_LENGTH];
        uint64_t existing_size = 0;

        if (gr_meta_read_sidecar_at_path(logical_path, sidecar_path, &existing_size) == CM_SUCCESS) {
            if (logical_size < existing_size) {
                LOG_RUN_INF("[FS] skip shrinking logical meta for '%s': proposed %llu < disk %llu",
                            logical_path, (unsigned long long)logical_size, (unsigned long long)existing_size);
                return CM_SUCCESS;
            }
            if (logical_size == existing_size) {
                return CM_SUCCESS;
            }
        } else if (gr_meta_build_legacy_sidecar_path(logical_path, legacy_path, sizeof(legacy_path)) ==
                       CM_SUCCESS &&
                   gr_meta_read_sidecar_at_path(logical_path, legacy_path, &existing_size) == CM_SUCCESS) {
            if (logical_size < existing_size) {
                LOG_RUN_INF("[FS] skip shrinking logical meta for '%s': proposed %llu < disk %llu",
                            logical_path, (unsigned long long)logical_size, (unsigned long long)existing_size);
                return CM_SUCCESS;
            }
            /* legacy-only: equal size still needs migration to new sidecar path */
        }
    }

    fp = fopen(sidecar_path, "w");
    if (fp == NULL) {
        LOG_RUN_ERR("[FS] failed to open sidecar '%s' for write, errno: %d", sidecar_path, errno);
        return CM_ERROR;
    }

    if (fprintf(fp, "%llu\n", (unsigned long long)logical_size) < 0) {
        LOG_RUN_ERR("[FS] failed to write sidecar '%s', errno: %d", sidecar_path, errno);
        (void)fclose(fp);
        return CM_ERROR;
    }
    if (fflush(fp) != 0) {
        LOG_RUN_ERR("[FS] failed to fflush sidecar '%s', errno: %d", sidecar_path, errno);
        (void)fclose(fp);
        return CM_ERROR;
    }

    int sidecar_fd = fileno(fp);
    if (sidecar_fd >= 0 && fsync(sidecar_fd) != 0) {
        LOG_RUN_ERR("[FS] failed to fsync sidecar '%s', errno: %d", sidecar_path, errno);
        (void)fclose(fp);
        return CM_ERROR;
    }
    if (fclose(fp) != 0) {
        LOG_RUN_ERR("[FS] failed to close sidecar '%s', errno: %d", sidecar_path, errno);
        return CM_ERROR;
    }

    gr_path_cache_invalidate(logical_path);
    if (stat(sidecar_path, &st_after) == 0) {
        gr_path_cache_put(logical_path, logical_size, st_after.st_mtime);
    }
    gr_meta_unlink_legacy_sidecar(logical_path);
    return CM_SUCCESS;
}

static status_t gr_meta_append_record(const char *logical_path, uint64_t logical_size)
{
    return gr_meta_persist_logical_size(logical_path, logical_size);
}

static status_t gr_meta_query_logical_size(const char *logical_path, uint64_t *logical_size)
{
    GR_FS_CHECK_NULL_RETURN(logical_path, ERR_GR_INVALID_PARAM, "logical_path is NULL");
    GR_FS_CHECK_NULL_RETURN(logical_size, ERR_GR_INVALID_PARAM, "logical_size is NULL");

    // O(1): per-file sidecar
    if (gr_meta_read_sidecar(logical_path, logical_size) == CM_SUCCESS) {
        return CM_SUCCESS;
    }

    // Legacy: scan append-only log once, then migrate to sidecar
    if (gr_meta_read_logical_size_from_meta(logical_path, logical_size) == CM_SUCCESS) {
        (void)gr_meta_persist_logical_size(logical_path, *logical_size);
        return CM_SUCCESS;
    }

    // Fallback: current physical file size
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

static void gr_fd_meta_update_local(int fd, uint64_t logical_size)
{
    if (logical_size == 0) {
        return;
    }

    pthread_mutex_lock(&g_fd_meta_lock);
    gr_fd_meta_t *ent = gr_fd_meta_find_nolock(fd);
    if (ent != NULL && logical_size > ent->logical_size) {
        ent->logical_size = logical_size;
    }
    pthread_mutex_unlock(&g_fd_meta_lock);
}

/*
 * Resolve logical EOF for an open fd: max(this fd cache, any fd on same path,
 * latest .gr_vfs_meta). Refreshes this fd's cache when a peer has grown.
 */
static void gr_logical_size_resolve_for_fd(int fd, uint64_t *logical_size_out)
{
    uint64_t resolved = 0;
    char logical_path[GR_FILE_PATH_MAX_LENGTH];

    if (logical_size_out == NULL) {
        return;
    }

    (void)gr_fd_meta_get(fd, &resolved);

    if (gr_fd_meta_get_path(fd, logical_path, sizeof(logical_path))) {
        uint64_t path_max = 0;
        if (gr_fd_meta_get_by_path(logical_path, &path_max) && path_max > resolved) {
            resolved = path_max;
        }

        uint64_t meta_size = 0;
        if (gr_meta_query_logical_size(logical_path, &meta_size) == CM_SUCCESS &&
            meta_size > resolved) {
            resolved = meta_size;
        }
    }

    *logical_size_out = resolved;
    gr_fd_meta_update_local(fd, resolved);
}

/*
 * pread: max(in-memory peer fds, sidecar/cache). Sidecar is O(1) (mtime cache);
 * legacy append log is not scanned here.
 */
static void gr_logical_size_resolve_for_read(int fd, uint64_t *logical_size_out)
{
    uint64_t resolved = 0;
    char logical_path[GR_FILE_PATH_MAX_LENGTH];

    if (logical_size_out == NULL) {
        return;
    }

    logical_path[0] = '\0';
    (void)gr_fd_meta_get(fd, &resolved);

    if (gr_fd_meta_get_path(fd, logical_path, sizeof(logical_path))) {
        uint64_t path_max = 0;
        if (gr_fd_meta_get_by_path(logical_path, &path_max) && path_max > resolved) {
            resolved = path_max;
        }

        uint64_t disk_size = 0;
        if (gr_meta_read_sidecar(logical_path, &disk_size) == CM_SUCCESS &&
            disk_size > resolved) {
            resolved = disk_size;
        }
    }

    *logical_size_out = resolved;
    gr_fd_meta_update_local(fd, resolved);
}

/*
 * Resolve logical EOF by path (no fd): max(open fd metas, .gr_vfs_meta).
 */
static bool gr_logical_size_resolve_for_path(const char *logical_path, uint64_t *logical_size_out)
{
    uint64_t resolved = 0;

    if (logical_path == NULL || logical_size_out == NULL) {
        return false;
    }

    uint64_t path_max = 0;
    if (gr_fd_meta_get_by_path(logical_path, &path_max) && path_max > resolved) {
        resolved = path_max;
    }

    uint64_t meta_size = 0;
    if (gr_meta_query_logical_size(logical_path, &meta_size) == CM_SUCCESS &&
        meta_size > resolved) {
        resolved = meta_size;
    }

    *logical_size_out = resolved;
    return resolved > 0;
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
        status_t status = gr_meta_append_record(logical_path, new_logical_end);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("[FS] failed to persist logical size %llu for '%s' after write",
                        (unsigned long long)new_logical_end, logical_path);
        }
    }
}

static status_t gr_fd_meta_flush(int fd)
{
    char logical_path[GR_FILE_PATH_MAX_LENGTH];
    uint64_t logical_size = 0;
    bool have_meta = false;

    pthread_mutex_lock(&g_fd_meta_lock);
    gr_fd_meta_t *ent = gr_fd_meta_find_nolock(fd);
    if (ent != NULL) {
        logical_size = ent->logical_size;
        errno_t err = strncpy_s(logical_path, sizeof(logical_path),
                                ent->logical_path, sizeof(logical_path) - 1);
        if (SECUREC_UNLIKELY(err == EOK)) {
            have_meta = true;
        }
    }
    pthread_mutex_unlock(&g_fd_meta_lock);

    if (!have_meta) {
        return CM_SUCCESS;
    }

    return gr_meta_append_record(logical_path, logical_size);
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
    gr_dir_map_item_t *item = gr_dir_map_get_item_and_lock(handle);
    if (item == NULL || item->dir == NULL) {
        LOG_RUN_ERR("[FS] Invalid directory handle: %lu", handle);
        GR_THROW_ERROR(ERR_GR_FILE_SYSTEM_ERROR);
        return CM_ERROR;
    }
    if (closedir(item->dir) != 0) {
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

    gr_meta_remove_sidecars(name);
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
    uint64_t logical_size_u64 = 0;
    int64 logical_end = offset + size;
    gr_logical_size_resolve_for_fd(handle, &logical_size_u64);
    if ((int64)logical_size_u64 > logical_end) {
        logical_end = (int64)logical_size_u64;
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

    // max(peer fds, sidecar/cache) — O(1), safe across connections/threads.
    uint64_t logical_size_u64 = 0;
    gr_logical_size_resolve_for_read(handle, &logical_size_u64);
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
        if (gr_fs_is_dot_or_dotdot(entry->d_name) ||
            gr_fs_is_internal_metadata_name(entry->d_name)) {
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

static int gr_cstr_name_cmp(const void *a, const void *b)
{
    const char *const *sa = (const char *const *)a;
    const char *const *sb = (const char *const *)b;
    return strcmp(*sa, *sb);
}

status_t gr_filesystem_query_file_info(uint64_t handle, gr_file_item_t *file_items, uint32_t max_files, uint32_t *file_count, bool is_continue) {
    GR_FS_CHECK_NULL_RETURN(file_items, ERR_GR_INVALID_PARAM, "file_items is NULL");
    GR_FS_CHECK_NULL_RETURN(file_count, ERR_GR_INVALID_PARAM, "file_count is NULL");
    
    // Get DIR* and acquire per-handle lock
    gr_dir_map_item_t *item = gr_dir_map_get_item_and_lock(handle);
    if (item == NULL || item->dir == NULL) {
        GR_FS_ERROR_RETURN(ERR_GR_FILE_SYSTEM_ERROR, "Invalid directory handle: %lu", handle);
    }
    
    // Build (or rebuild) sorted snapshot on first page.
    if (!is_continue) {
        gr_dir_map_free_snapshot(item);
        item->cursor = 0;

        rewinddir(item->dir);
        struct dirent *entry;
        uint32_t cap = 0;

        while ((entry = readdir(item->dir)) != NULL) {
            if (gr_fs_is_internal_metadata_name(entry->d_name)) {
                continue;
            }
            if (entry->d_type != DT_REG) {
                continue;
            }

            if (item->sorted_count == cap) {
                uint32_t new_cap = (cap == 0) ? 64 : (cap * 2);
                char **new_arr = (char **)realloc(item->sorted_names, sizeof(char *) * new_cap);
                if (new_arr == NULL) {
                    LOG_RUN_ERR("[FS] realloc failed when building sorted file snapshot");
                    gr_dir_map_free_snapshot(item);
                    gr_dir_map_unlock(handle);
                    return CM_ERROR;
                }
                item->sorted_names = new_arr;
                cap = new_cap;
            }

            size_t name_len = strnlen(entry->d_name, GR_MAX_NAME_LEN - 1);
            char *name_copy = (char *)malloc(name_len + 1);
            if (name_copy == NULL) {
                LOG_RUN_ERR("[FS] malloc failed when building sorted file snapshot");
                gr_dir_map_free_snapshot(item);
                gr_dir_map_unlock(handle);
                return CM_ERROR;
            }
            errno_t err = strncpy_s(name_copy, name_len + 1, entry->d_name, name_len);
            if (SECUREC_UNLIKELY(err != EOK)) {
                free(name_copy);
                LOG_RUN_ERR("[FS] Failed to copy file name into snapshot, errno: %d", err);
                gr_dir_map_free_snapshot(item);
                gr_dir_map_unlock(handle);
                return CM_ERROR;
            }
            item->sorted_names[item->sorted_count++] = name_copy;
        }

        if (item->sorted_count > 1) {
            qsort(item->sorted_names, (size_t)item->sorted_count, sizeof(char *), gr_cstr_name_cmp);
        }
    }

    // Page out from snapshot in globally sorted order.
    *file_count = 0;
    while (item->cursor < item->sorted_count && *file_count < max_files) {
        gr_file_item_t *current_item = &file_items[*file_count];
        errno_t err = strncpy_s(current_item->name, GR_MAX_NAME_LEN,
                                item->sorted_names[item->cursor], GR_MAX_NAME_LEN - 1);
        if (SECUREC_UNLIKELY(err != EOK)) {
            LOG_RUN_ERR("[FS] Failed to copy file name from snapshot, errno: %d", err);
            gr_dir_map_unlock(handle);
            return CM_ERROR;
        }
        item->cursor++;
        (*file_count)++;
    }
    
    // Unlock handle
    gr_dir_map_unlock(handle);
    return CM_SUCCESS;
}

status_t gr_filesystem_get_file_end_position(const char *file_path, off_t *end_position) {
    GR_FS_CHECK_NULL_RETURN(file_path, ERR_GR_INVALID_PARAM, "file_path is NULL");
    GR_FS_CHECK_NULL_RETURN(end_position, ERR_GR_INVALID_PARAM, "end_position is NULL");
    
    uint64_t logical_size = 0;
    if (gr_logical_size_resolve_for_path(file_path, &logical_size)) {
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
    
    *fd = open(path, open_flag, 0);
    if (*fd == -1) {
        GR_SYS_ERROR_RETURN("Failed to open file: %s (full path: %s)", file_path, path);
    }

    // Initialize logical EOF: max(already-open fds on this path, persisted meta).
    uint64_t logical_size = 0;
    if (!gr_logical_size_resolve_for_path(file_path, &logical_size)) {
        struct stat st;
        if (fstat(*fd, &st) == 0) {
            logical_size = (uint64_t)st.st_size;
        }
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
    status_t flush_status = gr_fd_meta_flush(fd);
    if (flush_status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS] failed to flush logical size meta for fd %d before close", fd);
        return CM_ERROR;
    }

    if (need_lock) {
        GR_CALL_RETURN(gr_filesystem_lock(fd), "Failed to change file to be lock_mode");
    }

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

    // Determine logical size: max(all open fds on path, .gr_vfs_meta), else physical.
    uint64_t logical_size_u64 = 0;
    if (!gr_logical_size_resolve_for_path(name, &logical_size_u64)) {
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