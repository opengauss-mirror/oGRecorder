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
 * wr_meta_buf.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_meta_buf.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_meta_buf.h"
#include "wr_file.h"
#include "cm_bilist.h"
#include "wr_syn_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

void wr_enter_shm_x(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    wr_lock_shm_meta_x(session, vg_item->vg_latch);
}

bool32 wr_enter_shm_time_x(wr_session_t *session, wr_vg_info_item_t *vg_item, uint32_t wait_ticks)
{
    if (!wr_lock_shm_meta_timed_x(session, vg_item->vg_latch, WR_LOCK_SHM_META_TIMEOUT)) {
        return CM_FALSE;
    }
    return CM_TRUE;
}

void wr_enter_shm_s(wr_session_t *session, wr_vg_info_item_t *vg_item, bool32 is_force, int32_t timeout)
{
    CM_ASSERT(session != NULL);

    wr_latch_offset_t latch_offset;
    latch_offset.type = WR_LATCH_OFFSET_SHMOFFSET;
    (void)wr_lock_shm_meta_s_with_stack(session, &latch_offset, vg_item->vg_latch, timeout);
}

void wr_leave_shm(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    CM_ASSERT(session != NULL);
    if (wr_is_server()) {
        wr_unlock_shm_meta_without_stack(session, vg_item->vg_latch);
    } else {
        (void)wr_unlock_shm_meta_s_with_stack(session, vg_item->vg_latch, CM_FALSE);
    }
}

wr_block_ctrl_t *wr_buffer_get_block_ctrl_addr(ga_pool_id_e pool_id, uint32_t object_id)
{
    return (wr_block_ctrl_t *)ga_object_addr(pool_id, object_id);
}

char *wr_buffer_get_meta_addr(ga_pool_id_e pool_id, uint32_t object_id)
{
    wr_block_ctrl_t *block_ctrl = wr_buffer_get_block_ctrl_addr(pool_id, object_id);
    if (block_ctrl != NULL) {
        return WR_GET_META_FROM_BLOCK_CTRL(char, block_ctrl);
    }
    return NULL;
}

static void wr_remove_recycle_meta(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_ctrl_t *block_ctrl);

bool32 wr_buffer_cache_key_compare(void *key, void *key2)
{
    uint64 id = WR_BLOCK_ID_IGNORE_UNINITED(*(uint64 *)key);
    uint64 id2 = WR_BLOCK_ID_IGNORE_UNINITED(*(uint64 *)key2);
    return cm_oamap_uint64_compare(&id, &id2);
}

static inline ga_pool_id_e wr_buffer_cache_get_pool_id(uint32_t block_type)
{
    CM_ASSERT(block_type < WR_BLOCK_TYPE_MAX);
    if (block_type == WR_BLOCK_TYPE_FT) {
        return GA_8K_POOL;
    } else if (block_type == WR_BLOCK_TYPE_FS) {
        return GA_16K_POOL;
    } else {
        return GA_FS_AUX_POOL;
    }
}

uint32_t wr_buffer_cache_get_block_size(uint32_t block_type)
{
    CM_ASSERT(block_type < WR_BLOCK_TYPE_MAX);
    if (block_type == WR_BLOCK_TYPE_FT) {
        return WR_BLOCK_SIZE;
    } else if (block_type == WR_BLOCK_TYPE_FS) {
        return WR_FILE_SPACE_BLOCK_SIZE;
    } else {
        return WR_FS_AUX_SIZE;
    }
}

static void wr_register_buffer_cache_inner(wr_session_t *session, shm_hash_ctrl_t *hash_ctrl,
    shm_hashmap_bucket_t *bucket, ga_obj_id_t obj_id, char *meta_addr, uint32_t hash)
{
    CM_ASSERT(bucket != NULL);
    CM_ASSERT(meta_addr != NULL);

    wr_block_ctrl_t *first_block_ctrl = NULL;
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
    if (bucket->has_next) {
        ga_obj_id_t first_obj_id = *(ga_obj_id_t *)&bucket->first;
        first_block_ctrl = wr_buffer_get_block_ctrl_addr(first_obj_id.pool_id, first_obj_id.obj_id);
        WR_ASSERT_LOG(first_block_ctrl != NULL, "obj meta_addr is NULL when register buffer cache");
    } else {
        block_ctrl->has_next = CM_FALSE;
    }
    block_ctrl->hash = hash;
    block_ctrl->my_obj_id = obj_id;
    SHM_HASH_BUCKET_INSERT(bucket, *(sh_mem_p *)&obj_id, block_ctrl, first_block_ctrl);
}

static void wr_unregister_buffer_cache_inner(
    shm_hash_ctrl_t *hash_ctrl, shm_hashmap_bucket_t *bucket, ga_obj_id_t next_id, char *meta_addr)
{
    wr_block_ctrl_t *prev_block_ctrl = NULL;
    wr_block_ctrl_t *next_block_ctrl = NULL;
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
    if (block_ctrl->has_prev) {
        ga_obj_id_t obj_id = *(ga_obj_id_t *)&block_ctrl->hash_prev;
        prev_block_ctrl = wr_buffer_get_block_ctrl_addr(obj_id.pool_id, obj_id.obj_id);
    }
    if (block_ctrl->has_next) {
        ga_obj_id_t obj_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
        next_block_ctrl = wr_buffer_get_block_ctrl_addr(obj_id.pool_id, obj_id.obj_id);
    }
    SHM_HASH_BUCKET_REMOVE(bucket, *(sh_mem_p *)&next_id, block_ctrl, prev_block_ctrl, next_block_ctrl);
}

status_t shm_hashmap_move_bucket_node(
    wr_session_t *session, shm_hash_ctrl_t *hash_ctrl, uint32_t old_bucket_idx, uint32_t new_bucket_idx)
{
    LOG_DEBUG_INF("[HASHMAP]Begin to move some entry from bucket %u to bucket %u.", old_bucket_idx, new_bucket_idx);
    shm_hashmap_bucket_t *old_bucket = shm_hashmap_get_bucket(hash_ctrl, old_bucket_idx, NULL);
    shm_hashmap_bucket_t *new_bucket = shm_hashmap_get_bucket(hash_ctrl, new_bucket_idx, NULL);
    WR_ASSERT_LOG(old_bucket != NULL, "[HASHMAP]Expect bucket %u is not null.", old_bucket_idx);
    WR_ASSERT_LOG(new_bucket != NULL, "[HASHMAP]Expect bucket %u is not null.", new_bucket_idx);
    ga_obj_id_t tmp_id = *(ga_obj_id_t *)&old_bucket->first;
    ga_obj_id_t next_id = *(ga_obj_id_t *)&old_bucket->first;
    bool32 has_next = old_bucket->has_next;
    char *meta_addr = NULL;
    wr_block_ctrl_t *block_ctrl = NULL;
    wr_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    uint32_t hash;
    uint32_t bucket_idx;
    while (has_next) {
        meta_addr = wr_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        WR_ASSERT_LOG(meta_addr != NULL, "[HASHMAP]Expect meta_addr is not null, pool id is %u, object id is %u.",
            next_id.pool_id, next_id.obj_id);
        block = WR_GET_COMMON_BLOCK_HEAD(meta_addr);
        block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((wr_common_block_t *)meta_addr)->id;
        hash = WR_BUFFER_CACHE_HASH(block_id_tmp);
        has_next = block_ctrl->has_next;
        tmp_id = next_id;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
        bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
        if (bucket_idx != old_bucket_idx) {
            wr_lock_shm_meta_bucket_x(session, &old_bucket->enque_lock);
            wr_lock_shm_meta_bucket_x(session, &new_bucket->enque_lock);
            wr_unregister_buffer_cache_inner(hash_ctrl, old_bucket, tmp_id, meta_addr);
            LOG_DEBUG_INF("[HASHMAP]Move block id %s from bucket %u, hash:%u, type:%u, num:%u.",
                wr_display_metaid(block_id_tmp), old_bucket_idx, hash, block->type, old_bucket->entry_num);
            WR_ASSERT_LOG(bucket_idx == new_bucket_idx, "Expect bucket idx is %u, but bucket idx is %u.",
                new_bucket_idx, bucket_idx);
            wr_register_buffer_cache_inner(session, hash_ctrl, new_bucket, tmp_id, meta_addr, hash);
            LOG_DEBUG_INF(
                "[HASHMAP]Succeed to register buffer cache, bucket %u, num %u.", new_bucket_idx, new_bucket->entry_num);
            wr_unlock_shm_meta_bucket(session, &old_bucket->enque_lock);
            wr_unlock_shm_meta_bucket(session, &new_bucket->enque_lock);
            LOG_DEBUG_INF("[HASHMAP]Move block id %s from bucket %u to bucket %u, object id:{%u,%u}, hash:%u, type:%u.",
                wr_display_metaid(block_id_tmp), old_bucket_idx, new_bucket_idx, tmp_id.pool_id, tmp_id.obj_id, hash,
                block->type);
            ga_obj_id_t new_id = *(ga_obj_id_t *)&new_bucket->first;
            WR_ASSERT_LOG(new_id.pool_id == tmp_id.pool_id && new_id.obj_id == tmp_id.obj_id,
                "[HASHMAP]new id is {%u,%u}, tmp id is {%u,%u}.", new_id.pool_id, new_id.obj_id, tmp_id.pool_id,
                tmp_id.obj_id);
        }
    }
    return CM_SUCCESS;
}

status_t wr_hashmap_redistribute(wr_session_t *session, shm_hash_ctrl_t *hash_ctrl, uint32_t old_bucket)
{
    hash_ctrl->max_bucket++;
    uint32_t new_bucket = shm_hashmap_calc_bucket_idx(hash_ctrl, hash_ctrl->max_bucket);
    return shm_hashmap_move_bucket_node(session, hash_ctrl, old_bucket, new_bucket);
}

void wr_hashmap_extend_bucket_num(shm_hash_ctrl_t *hash_ctrl)
{
    if (hash_ctrl->max_bucket >= hash_ctrl->high_mask) {
        LOG_RUN_INF("[HASHMAP]Before update hash ctrl, max_bucket %u, bucket_num:%u, low mask:%u, high mask:%u.",
            hash_ctrl->max_bucket, hash_ctrl->bucket_num, hash_ctrl->low_mask, hash_ctrl->high_mask);
        hash_ctrl->bucket_num <<= 1;
        hash_ctrl->low_mask = hash_ctrl->high_mask;
        hash_ctrl->high_mask = (hash_ctrl->max_bucket + 1) | hash_ctrl->low_mask;
        LOG_RUN_INF("[HASHMAP]Update hash ctrl, max_bucket %u, bucket_num:%u, low mask:%u, high mask:%u.",
            hash_ctrl->max_bucket, hash_ctrl->bucket_num, hash_ctrl->low_mask, hash_ctrl->high_mask);
    }
}

status_t wr_hashmap_extend_segment(shm_hash_ctrl_t *hash_ctrl)
{
    uint32_t segment = (hash_ctrl->max_bucket + 1) / WR_BUCKETS_PER_SEGMENT;
    if (segment >= hash_ctrl->nsegments) {
        WR_RETURN_IF_ERROR(shm_hashmap_extend_segment(hash_ctrl));
    }
    return CM_SUCCESS;
}

status_t wr_hashmap_extend_and_redistribute(wr_session_t *session, shm_hash_ctrl_t *hash_ctrl)
{
    uint32_t old_bucket = shm_hashmap_calc_bucket_idx(hash_ctrl, hash_ctrl->max_bucket + 1);
    WR_RETURN_IF_ERROR(wr_hashmap_extend_segment(hash_ctrl));
    wr_hashmap_extend_bucket_num(hash_ctrl);
    return wr_hashmap_redistribute(session, hash_ctrl, old_bucket);
}

status_t wr_register_buffer_cache(wr_session_t *session, wr_vg_info_item_t *vg_item, const wr_block_id_t block_id,
    ga_obj_id_t obj_id, char *meta_addr, wr_block_type_t type)
{
    wr_block_ctrl_t *block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    uint32_t hash = WR_BUFFER_CACHE_HASH(block_id);
    uint32_t bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, NULL);
    if (bucket == NULL) {
        return CM_ERROR;
    }
    errno_t errcode = memset_s(block_ctrl, sizeof(wr_block_ctrl_t), 0, sizeof(wr_block_ctrl_t));
    if (errcode) {
        LOG_RUN_ERR("Failed to memset block ctrl, block id %s.", wr_display_metaid(block_id));
        return CM_ERROR;
    }
    wr_lock_shm_meta_bucket_x(session, &bucket->enque_lock);
    WR_LOG_DEBUG_OP("Register block id %s, hash:%u, type:%u, bucket_idx is %u.", wr_display_metaid(block_id), hash,
        type, bucket_idx);
    cm_latch_init(&block_ctrl->latch);
    block_ctrl->type = type;
    block_ctrl->block_id = block_id;
    wr_register_buffer_cache_inner(session, hash_ctrl, bucket, obj_id, meta_addr, hash);
    LOG_DEBUG_INF("Succeed to register buffer cache, bucket %u, num %u.", bucket_idx, bucket->entry_num);
    wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    return CM_SUCCESS;
}

void wr_unregister_buffer_cache(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id)
{
    char *meta_addr = NULL;
    wr_block_ctrl_t *block_ctrl = NULL;
    wr_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    uint32_t hash = WR_BUFFER_CACHE_HASH(block_id);
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    uint32_t bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, NULL);
    cm_panic(bucket != NULL);
    wr_lock_shm_meta_bucket_x(session, &bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        meta_addr = wr_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(meta_addr != NULL);
        block = WR_GET_COMMON_BLOCK_HEAD(meta_addr);
        block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((wr_common_block_t *)meta_addr)->id;
        if ((block_ctrl->hash == hash) && (wr_buffer_cache_key_compare(&block_id_tmp, &block_id) == CM_TRUE)) {
            // may has been linked to recycle meta list
            wr_remove_recycle_meta(session, vg_item, block_ctrl);
            wr_unregister_buffer_cache_inner(hash_ctrl, bucket, next_id, meta_addr);
            LOG_DEBUG_INF("Move block id %s from bucket %u, hash:%u, type:%u, num:%u.",
                wr_display_metaid(block_id_tmp), bucket_idx, hash, block->type, bucket->entry_num);
            wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
            return;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    LOG_RUN_ERR("Key to remove not found");
}

status_t wr_get_block_from_disk(
    wr_vg_info_item_t *vg_item, wr_block_id_t block_id, char *buf, int64_t offset, int32_t size, bool32 calc_checksum)
{
    return CM_SUCCESS;
}

status_t wr_check_block_version(wr_vg_info_item_t *vg_item, wr_block_id_t block_id, wr_block_type_t type,
    char *meta_addr, bool32 *is_changed, bool32 force_refresh)
{
#ifndef WIN32
    char buf[WR_DISK_UNIT_SIZE] __attribute__((__aligned__(WR_DISK_UNIT_SIZE)));
#else
    char buf[WR_DISK_UNIT_SIZE];
#endif

    if (is_changed) {
        *is_changed = CM_FALSE;
    }

    uint64 version = ((wr_common_block_t *)meta_addr)->version;
    uint32_t size = wr_buffer_cache_get_block_size(type);
    int64 offset = wr_get_block_offset(vg_item, (uint64)size, block_id.block, block_id.au);
    // just read block header
    status_t status = wr_get_block_from_disk(vg_item, block_id, buf, offset, WR_DISK_UNIT_SIZE, CM_FALSE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to get block: %s from disk, meta_addr:%p, offset:%lld, size:%d.",
            wr_display_metaid(block_id), buf, offset, WR_DISK_UNIT_SIZE);
        return status;
    }
    uint64 disk_version = ((wr_common_block_t *)buf)->version;
    if (wr_compare_version(disk_version, version) || force_refresh) {
        WR_LOG_DEBUG_OP(
            "wr_check_block_version, version:%llu, disk_version:%llu, block_id: %s, type:%u, force_refresh:%u.",
            version, disk_version, wr_display_metaid(block_id), type, (uint32_t)force_refresh);
        // if size == WR_DISK_UNIT_SIZE, the buf has been changed all, not need load again
        if (size == WR_DISK_UNIT_SIZE) {
            securec_check_ret(memcpy_s(meta_addr, WR_DISK_UNIT_SIZE, buf, WR_DISK_UNIT_SIZE));
        } else {
            if (force_refresh && version == 0) {
                status = wr_get_block_from_disk(vg_item, block_id, meta_addr, offset, (int32_t)size, CM_FALSE);
            } else {
                status = wr_get_block_from_disk(vg_item, block_id, meta_addr, offset, (int32_t)size, CM_TRUE);
            }
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Failed to get block: %s from disk, meta_addr:%p, offset:%lld, size:%u.",
                    wr_display_metaid(block_id), meta_addr, offset, size);
                return status;
            }
        }
        if (is_changed) {
            *is_changed = CM_TRUE;
        }
    }

    return CM_SUCCESS;
}

static status_t wr_load_buffer_cache(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t block_id,
    wr_block_type_t type, char **block_addr, ga_obj_id_t *out_obj_id)
{
    char *meta_addr = NULL;
    wr_block_ctrl_t *block_ctrl = NULL;
    wr_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    uint32_t hash = WR_BUFFER_CACHE_HASH(block_id);
    uint32_t bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, NULL);
    if (bucket == NULL) {
        LOG_RUN_ERR("Failed to find bucket %u.", bucket_idx);
        return CM_ERROR;
    }
    wr_lock_shm_meta_bucket_x(session, &bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        meta_addr = wr_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(meta_addr != NULL);
        block = WR_GET_COMMON_BLOCK_HEAD(meta_addr);
        block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((wr_common_block_t *)meta_addr)->id;
        if ((block_ctrl->hash == hash) && (wr_buffer_cache_key_compare(&block_id_tmp, &block_id) == CM_TRUE)) {
            wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
            status_t status = wr_check_block_version(vg_item, block_id, type, meta_addr, NULL, CM_FALSE);
            if (status != CM_SUCCESS) {
                return status;
            }
            *block_addr = meta_addr;
            if (out_obj_id) {
                *out_obj_id = next_id;
            }
            block_ctrl->type = type;
            wr_inc_meta_ref_hot(block_ctrl);
            return CM_SUCCESS;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }

    ga_pool_id_e pool_id = wr_buffer_cache_get_pool_id(type);
    uint32_t size = wr_buffer_cache_get_block_size(type);
    int64_t offset = wr_get_block_offset(vg_item, (uint64)size, block_id.block, block_id.au);
    uint32_t obj_id = ga_alloc_object(pool_id, CM_INVALID_ID32);
    if (obj_id == CM_INVALID_ID32) {
        wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
        return CM_ERROR;
    }
    meta_addr = wr_buffer_get_meta_addr(pool_id, obj_id);

    status_t status = wr_get_block_from_disk(vg_item, block_id, meta_addr, offset, (int32_t)size, CM_TRUE);
    if (status != CM_SUCCESS) {
        wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
        ga_free_object(pool_id, obj_id);
        LOG_RUN_ERR("Failed to get block from disk, v:%u,au:%llu,block:%u,item:%u,type:%d.", block_id.volume,
            (uint64)block_id.au, block_id.block, block_id.item, type);
        return status;
    }
    block = WR_GET_COMMON_BLOCK_HEAD(meta_addr);
    WR_LOG_DEBUG_OP("WR load buffer cache, v:%u,au:%llu,block:%u,item:%u,type:%d.", block->id.volume,
        (uint64)block->id.au, block->id.block, block->id.item, block->type);
    block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
    errno_t errcode = memset_s(block_ctrl, sizeof(wr_block_ctrl_t), 0, sizeof(wr_block_ctrl_t));
    if (errcode != EOK) {
        wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
        ga_free_object(pool_id, obj_id);
        LOG_RUN_ERR("Failed to memset block ctrl, v:%u,au:%llu,block:%u,item:%u,type:%d.", block_id.volume,
            (uint64)block_id.au, block_id.block, block_id.item, type);
        return CM_ERROR;
    }
    cm_latch_init(&block_ctrl->latch);
    block_ctrl->type = type;
    block_ctrl->block_id = block_id;

    ga_obj_id_t ga_obj_id;
    ga_obj_id.pool_id = pool_id;
    ga_obj_id.obj_id = obj_id;
    wr_register_buffer_cache_inner(session, hash_ctrl, bucket, ga_obj_id, meta_addr, hash);
    LOG_DEBUG_INF("Succeed to register buffer cache, bucket %u, num %u.", bucket_idx, bucket->entry_num);
    wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    if (out_obj_id) {
        *out_obj_id = ga_obj_id;
    }
    *block_addr = meta_addr;
    wr_inc_meta_ref_hot(block_ctrl);
    WR_LOG_DEBUG_OP("Succeed to load meta block, v:%u,au:%llu,block:%u,item:%u,type:%d.", block_id.volume,
        (uint64)block_id.au, block_id.block, block_id.item, type);
    return CM_SUCCESS;
}

void *wr_find_block_in_bucket(wr_session_t *session, wr_vg_info_item_t *vg_item, uint32_t hash, uint64 *key,
    bool32 is_print_error_log, ga_obj_id_t *out_obj_id)
{
    CM_ASSERT(key != NULL);
    shm_hashmap_t *hashmap = vg_item->buffer_cache;
    if (hashmap == NULL) {
        if (is_print_error_log) {
            LOG_RUN_ERR("Pointer to map or compare_func is NULL");
        }
        return NULL;
    }
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    char *meta_addr = NULL;
    wr_block_ctrl_t *block_ctrl = NULL;
    auid_t block_id_tmp = {0};
    uint32_t bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    uint32_t segment_objid = WR_INVALID_ID32;
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, &segment_objid);
    if (bucket == NULL) {
        if (is_print_error_log) {
            LOG_RUN_ERR("Pointer to bucket %u is NULL.", bucket_idx);
        }
        return NULL;
    }
    if (vg_item->from_type == FROM_SHM) {
        wr_lock_shm_meta_bucket_s(session, segment_objid, &bucket->enque_lock);
    }
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        meta_addr = wr_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(meta_addr != NULL);
        block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((wr_common_block_t *)meta_addr)->id;
        if ((block_ctrl->hash == hash) && (wr_buffer_cache_key_compare(&block_id_tmp, key) == CM_TRUE)) {
            if (vg_item->from_type == FROM_SHM) {
                wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
            }
            if (out_obj_id != NULL) {
                *out_obj_id = next_id;
            }

            wr_inc_meta_ref_hot(block_ctrl);
            return meta_addr;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    if (vg_item->from_type == FROM_SHM) {
        wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    }
    return NULL;
}

// do not care content change
static void *wr_find_block_in_bucket_ex(wr_session_t *session, wr_vg_info_item_t *vg_item, uint32_t hash, uint64 *key,
    bool32 is_print_error_log, ga_obj_id_t *out_obj_id)
{
    shm_hashmap_t *map = vg_item->buffer_cache;
    CM_ASSERT(key != NULL);
    if (map == NULL) {
        if (is_print_error_log) {
            LOG_RUN_ERR("Pointer to map or compare_func is NULL");
        }
        return NULL;
    }
    char *meta_addr = NULL;
    wr_block_ctrl_t *block_ctrl = NULL;
    wr_block_ctrl_t *next_block_ctrl = NULL;
    auid_t block_id_tmp = {0};
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    uint32_t bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    uint32_t segment_objid = WR_INVALID_ID32;
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, &segment_objid);
    if (bucket == NULL) {
        if (is_print_error_log) {
            LOG_RUN_ERR("Pointer to bucket %u is NULL.", bucket_idx);
        }
        return NULL;
    }
    (void)wr_lock_shm_meta_bucket_s(session, segment_objid, &bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    if (has_next) {
        meta_addr = wr_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(meta_addr != NULL);
        block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((wr_common_block_t *)meta_addr)->id;
        wr_latch_s(&block_ctrl->latch);
    }
    wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);

    while (has_next) {
        if ((block_ctrl->hash == hash) && (wr_buffer_cache_key_compare(&block_id_tmp, key) == CM_TRUE)) {
            if (out_obj_id != NULL) {
                *out_obj_id = next_id;
            }
            wr_inc_meta_ref_hot(block_ctrl);
            wr_unlatch(&block_ctrl->latch);
            return meta_addr;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
        if (has_next) {
            meta_addr = wr_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
            cm_panic(meta_addr != NULL);
            next_block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
            block_id_tmp = ((wr_common_block_t *)meta_addr)->id;
            wr_latch_s(&next_block_ctrl->latch);
        }
        wr_unlatch(&block_ctrl->latch);
        block_ctrl = next_block_ctrl;
        next_block_ctrl = NULL;
    }

    return NULL;
}

status_t wr_find_block_objid_in_shm(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id,
    wr_block_type_t type, ga_obj_id_t *objid)
{
    char *meta_addr = NULL;
    uint32_t hash = WR_BUFFER_CACHE_HASH(block_id);
    meta_addr = wr_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, objid);
    if (meta_addr != NULL) {
        return CM_SUCCESS;
    }
    return CM_ERROR;
}

static status_t wr_add_buffer_cache_inner(wr_session_t *session, shm_hash_ctrl_t *hash_ctrl,
    shm_hashmap_bucket_t *bucket, auid_t add_block_id, wr_block_type_t type, char *refresh_buf, char **shm_buf)
{
    ga_pool_id_e pool_id = wr_buffer_cache_get_pool_id(type);
    uint32_t size = wr_buffer_cache_get_block_size(type);
    wr_block_ctrl_t *block_ctrl = NULL;
    uint32_t hash = WR_BUFFER_CACHE_HASH(add_block_id);
    uint32_t obj_id = ga_alloc_object(pool_id, CM_INVALID_ID32);
    if (obj_id == CM_INVALID_ID32) {
        WR_THROW_ERROR(ERR_WR_GA_ALLOC_OBJECT, pool_id);
        return CM_ERROR;
    }
    char *meta_addr = wr_buffer_get_meta_addr(pool_id, obj_id);
    if (meta_addr == NULL) {
        ga_free_object(pool_id, obj_id);
        WR_THROW_ERROR(ERR_WR_GA_GET_ADDR, pool_id, obj_id);
        return CM_ERROR;
    }
    errno_t errcode = memcpy_s(meta_addr, size, refresh_buf, size);
    if (errcode != EOK) {
        ga_free_object(pool_id, obj_id);
        LOG_RUN_ERR("Failed to memcpy block, v:%u,au:%llu,block:%u,item:%u,type:%d.", add_block_id.volume,
            (uint64)add_block_id.au, add_block_id.block, add_block_id.item, type);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    wr_common_block_t *block = WR_GET_COMMON_BLOCK_HEAD(meta_addr);
    WR_LOG_DEBUG_OP("wr add buffer cache, v:%u,au:%llu,block:%u,item:%u,type:%d.", block->id.volume,
        (uint64)block->id.au, block->id.block, block->id.item, block->type);
    block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
    errcode = memset_s(block_ctrl, sizeof(wr_block_ctrl_t), 0, sizeof(wr_block_ctrl_t));
    if (errcode != EOK) {
        ga_free_object(pool_id, obj_id);
        LOG_RUN_ERR("Failed to memset block ctrl, v:%u,au:%llu,block:%u,item:%u,type:%d.", add_block_id.volume,
            (uint64)add_block_id.au, add_block_id.block, add_block_id.item, type);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    cm_latch_init(&block_ctrl->latch);
    block_ctrl->type = type;
    block_ctrl->block_id = add_block_id;

    ga_obj_id_t ga_obj_id;
    ga_obj_id.pool_id = pool_id;
    ga_obj_id.obj_id = obj_id;
    wr_register_buffer_cache_inner(session, hash_ctrl, bucket, ga_obj_id, meta_addr, hash);
    wr_inc_meta_ref_hot(block_ctrl);
    WR_LOG_DEBUG_OP("Succeed to load meta_addr block, v:%u,au:%llu,block:%u,item:%u,type:%d.", add_block_id.volume,
        (uint64)add_block_id.au, add_block_id.block, add_block_id.item, type);
    *shm_buf = meta_addr;
    return CM_SUCCESS;
}

static status_t wr_add_buffer_cache(wr_session_t *session, wr_vg_info_item_t *vg_item, auid_t add_block_id,
    wr_block_type_t type, char *refresh_buf, char **shm_buf)
{
    char *meta_addr = NULL;
    wr_block_ctrl_t *block_ctrl = NULL;
    auid_t block_id_tmp = {0};
    uint32_t hash = WR_BUFFER_CACHE_HASH(add_block_id);
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    uint32_t bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, NULL);
    if (bucket == NULL) {
        return CM_ERROR;
    }
    wr_lock_shm_meta_bucket_x(session, &bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        meta_addr = wr_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        if (meta_addr == NULL) {
            wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
            WR_THROW_ERROR(ERR_WR_GA_GET_ADDR, next_id.pool_id, next_id.obj_id);
            return CM_ERROR;
        }

        block_ctrl = WR_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((wr_common_block_t *)meta_addr)->id;
        block_ctrl->type = type;
        if ((block_ctrl->hash == hash) && (wr_buffer_cache_key_compare(&block_id_tmp, &add_block_id) == CM_TRUE)) {
            wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
            if (((wr_common_block_t *)meta_addr)->type != type) {
                WR_THROW_ERROR(ERR_WR_INVALID_BLOCK_TYPE, type, ((wr_common_block_t *)meta_addr)->type);
                return ERR_WR_INVALID_BLOCK_TYPE;
            }
            uint32_t size = wr_buffer_cache_get_block_size(type);
            securec_check_ret(memcpy_s(meta_addr, size, refresh_buf, size));
            wr_common_block_t *ref_block = WR_GET_COMMON_BLOCK_HEAD(meta_addr);
            wr_inc_meta_ref_hot(block_ctrl);
            WR_LOG_DEBUG_OP("wr refresh block in shm, v:%u,au:%llu,block:%u,item:%u,type:%d.", ref_block->id.volume,
                (uint64)ref_block->id.au, ref_block->id.block, ref_block->id.item, ref_block->type);
            *shm_buf = meta_addr;
            return CM_SUCCESS;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    status_t ret = wr_add_buffer_cache_inner(session, hash_ctrl, bucket, add_block_id, type, refresh_buf, shm_buf);
    if (ret == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to register buffer cache, bucket %u, num %u.", bucket_idx, bucket->entry_num);
    }
    wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    return ret;
}

status_t wr_refresh_block_in_shm(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id,
    wr_block_type_t type, char *buf, char **shm_buf)
{
    char *meta_addr = NULL;
    uint32_t hash = WR_BUFFER_CACHE_HASH(block_id);
    meta_addr = wr_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, NULL);
    if (meta_addr != NULL) {
        if (((wr_common_block_t *)meta_addr)->type != type) {
            WR_THROW_ERROR(ERR_WR_INVALID_BLOCK_TYPE, type, ((wr_common_block_t *)meta_addr)->type);
            return ERR_WR_INVALID_BLOCK_TYPE;
        }
        uint32_t size = wr_buffer_cache_get_block_size(type);
        securec_check_ret(memcpy_s(meta_addr, size, buf, size));
        wr_common_block_t *block = WR_GET_COMMON_BLOCK_HEAD(meta_addr);
        WR_LOG_DEBUG_OP("wr refresh block in shm, v:%u,au:%llu,block:%u,item:%u,type:%d.", block->id.volume,
            (uint64)block->id.au, block->id.block, block->id.item, block->type);
        *shm_buf = meta_addr;
        return CM_SUCCESS;
    }
    return wr_add_buffer_cache(session, vg_item, block_id, type, buf, shm_buf);
}

char *wr_find_block_in_shm(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id,
    wr_block_type_t type, bool32 check_version, ga_obj_id_t *out_obj_id, bool32 active_refresh)
{
    status_t status;
    char *meta_addr = NULL;
    uint32_t hash = WR_BUFFER_CACHE_HASH(block_id);
    meta_addr = wr_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, out_obj_id);
    if (!wr_is_server()) {
        return meta_addr;
    }
    if (meta_addr != NULL) {
        if (check_version && (!wr_is_readwrite() || active_refresh)) {
            status = wr_check_block_version(vg_item, block_id, type, meta_addr, NULL, CM_FALSE);
            if (status != CM_SUCCESS) {
                return NULL;
            }
        }
        if (wr_is_readwrite()) {
            WR_ASSERT_LOG(wr_need_exec_local(), "only masterid %u can be readwrite.", wr_get_master_id());
        }
        return meta_addr;
    }

    status = wr_load_buffer_cache(session, vg_item, block_id, type, &meta_addr, out_obj_id);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to load meta_addr block, block_id: %s.", wr_display_metaid(block_id));
        return NULL;
    }
    return meta_addr;
}

char *wr_find_block_from_disk_and_refresh_shm(wr_session_t *session, wr_vg_info_item_t *vg_item,
    wr_block_id_t block_id, wr_block_type_t type, ga_obj_id_t *out_obj_id)
{
    status_t status;
    char *meta_addr = NULL;
    uint32_t hash = WR_BUFFER_CACHE_HASH(block_id);
    meta_addr = wr_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, out_obj_id);
    if (meta_addr != NULL) {
        if (((wr_common_block_t *)meta_addr)->version != 0) {
            status = wr_check_block_version(vg_item, block_id, type, meta_addr, NULL, CM_TRUE);
            if (status != CM_SUCCESS) {
                return NULL;
            }
        }
        return meta_addr;
    }

    if (!wr_is_server()) {
        return NULL;
    }
    if (wr_load_buffer_cache(session, vg_item, block_id, type, &meta_addr, out_obj_id) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to load meta_addr block, block_id: %s.", wr_display_metaid(block_id));
        return NULL;
    }
    return meta_addr;
}

char *wr_find_block_in_shm_no_refresh(
    wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id, ga_obj_id_t *out_obj_id)
{
    uint32_t hash = WR_BUFFER_CACHE_HASH(block_id);
    return wr_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, out_obj_id);
}

// do not care content change
char *wr_find_block_in_shm_no_refresh_ex(
    wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_id_t block_id, ga_obj_id_t *out_obj_id)
{
    uint32_t hash = WR_BUFFER_CACHE_HASH(block_id);
    return wr_find_block_in_bucket_ex(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, out_obj_id);
}

static status_t wr_refresh_buffer_cache_inner(wr_session_t *session, wr_vg_info_item_t *vg_item, uint32_t bucket_idx,
    ga_queue_t *obj_que, ga_pool_id_e *obj_pool_id)
{
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, NULL);
    CM_ASSERT(bucket != NULL);

    wr_block_ctrl_t *block_ctrl = NULL;
    wr_block_ctrl_t *block_ctrl_prev = NULL;
    wr_block_ctrl_t *block_ctrl_next = NULL;

    ga_obj_id_t obj_id = {0};
    ga_obj_id_t obj_id_next = {0};

    bool32 has_next = CM_FALSE;
    bool32 need_remove = CM_FALSE;

    wr_lock_shm_meta_bucket_x(session, &bucket->enque_lock);
    if (!bucket->has_next) {
        wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
        return CM_SUCCESS;
    }

    status_t status = CM_SUCCESS;
    obj_id = *(ga_obj_id_t *)&bucket->first;
    block_ctrl = wr_buffer_get_block_ctrl_addr(obj_id.pool_id, obj_id.obj_id);
    do {
        // no recycle mem for ft block because api cache the meta_addr
        if (block_ctrl->type == WR_BLOCK_TYPE_FT) {
            wr_init_wr_fs_block_cache_info(&block_ctrl->fs_block_cache_info);
            char *meta_addr = WR_GET_META_FROM_BLOCK_CTRL(char, block_ctrl);
            status = wr_check_block_version(
                vg_item, ((wr_common_block_t *)meta_addr)->id, block_ctrl->type, meta_addr, NULL, CM_FALSE);
            WR_BREAK_IF_ERROR(status);

            // no need remove ft block, so make it to the lastest prev block ctrl for remove every time
            block_ctrl_prev = block_ctrl;
        } else {
            // cache the pool info and obj info
            ga_append_into_queue_by_pool_id(obj_id.pool_id, &obj_que[block_ctrl->type], obj_id.obj_id);
            obj_pool_id[block_ctrl->type] = obj_id.pool_id;

            need_remove = CM_TRUE;
        }

        has_next = block_ctrl->has_next;
        obj_id_next = *(ga_obj_id_t *)&block_ctrl->hash_next;
        if (has_next) {
            block_ctrl_next = wr_buffer_get_block_ctrl_addr(obj_id_next.pool_id, obj_id_next.obj_id);
        } else {
            block_ctrl_next = NULL;
        }

        if (need_remove) {
            // may has been linked to recycle meta list
            wr_remove_recycle_meta(session, vg_item, block_ctrl);
            SHM_HASH_BUCKET_REMOVE(bucket, *(sh_mem_p *)&obj_id, block_ctrl, block_ctrl_prev, block_ctrl_next);
            need_remove = CM_FALSE;
        }

        obj_id = obj_id_next;
        block_ctrl = block_ctrl_next;
    } while (has_next);

    wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    return status;
}

status_t wr_refresh_buffer_cache(wr_session_t *session, wr_vg_info_item_t *vg_item, shm_hashmap_t *map)
{
    ga_queue_t obj_que[WR_BLOCK_TYPE_MAX] = {0};
    ga_pool_id_e obj_pool_id[WR_BLOCK_TYPE_MAX] = {0};
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    for (uint32_t i = 0; i <= hash_ctrl->max_bucket; i++) {
        status_t status = wr_refresh_buffer_cache_inner(session, vg_item, i, obj_que, obj_pool_id);
        if (status != CM_SUCCESS) {
            return status;
        }
    }
    // free all the obj as batch
    for (uint32_t i = 0; i < WR_BLOCK_TYPE_MAX; i++) {
        if (obj_que[i].count > 0) {
            ga_free_object_list(obj_pool_id[i], &obj_que[i]);
        }
    }
    return CM_SUCCESS;
}

void wr_init_wr_fs_block_cache_info(wr_fs_block_cache_info_t *fs_block_cache_info)
{
    (void)memset_s(fs_block_cache_info, sizeof(wr_fs_block_cache_info_t), 0x00, sizeof(wr_fs_block_cache_info_t));
}

void wr_init_vg_cache_node_info(wr_vg_info_item_t *vg_item)
{
    (void)memset_s(vg_item->vg_cache_node, sizeof(vg_item->vg_cache_node), 0x00, sizeof(vg_item->vg_cache_node));
}

// do not need control concurrence
void wr_inc_meta_ref_hot(wr_block_ctrl_t *block_ctrl)
{
    (void)cm_atomic_add((atomic_t *)&block_ctrl->ref_hot, WR_RECYCLE_META_HOT_INC_STEP);
}

// do not need control concurrence
void wr_desc_meta_ref_hot(wr_block_ctrl_t *block_ctrl)
{
    if (block_ctrl->ref_hot > 0) {
        int64 ref_hot = block_ctrl->ref_hot;
        int64 new_ref_hot = (int64)((uint64)ref_hot >> 1);
        (void)cm_atomic_cas((atomic_t *)&block_ctrl->ref_hot, ref_hot, new_ref_hot);
    }
}

static void wr_append_recycle_meta(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_ctrl_t *block_ctrl)
{
    CM_ASSERT(block_ctrl->recycle_meta_node.next == NULL);
    CM_ASSERT(block_ctrl->recycle_meta_node.prev == NULL);
    uint32_t sid = (session == NULL) ? WR_DEFAULT_SESSIONID : WR_SESSIONID_IN_LOCK(session->id);
    wr_latch_x2(&vg_item->recycle_meta_desc.latch, sid);
    cm_bilist_add_tail(&block_ctrl->recycle_meta_node, &vg_item->recycle_meta_desc.bilist);
    wr_unlatch(&vg_item->recycle_meta_desc.latch);
}

static bilist_node_t *wr_pop_recycle_meta(wr_session_t *session, wr_vg_info_item_t *vg_item)
{
    uint32_t sid = (session == NULL) ? WR_DEFAULT_SESSIONID : WR_SESSIONID_IN_LOCK(session->id);
    wr_latch_x2(&vg_item->recycle_meta_desc.latch, sid);
    bilist_node_t *recycle_meta_node = cm_bilist_pop_first(&vg_item->recycle_meta_desc.bilist);
    wr_unlatch(&vg_item->recycle_meta_desc.latch);
    if (recycle_meta_node != NULL) {
        CM_ASSERT(recycle_meta_node->next == NULL);
        CM_ASSERT(recycle_meta_node->prev == NULL);
    }
    return recycle_meta_node;
}

static void wr_remove_recycle_meta(wr_session_t *session, wr_vg_info_item_t *vg_item, wr_block_ctrl_t *block_ctrl)
{
    uint32_t sid = (session == NULL) ? WR_DEFAULT_SESSIONID : WR_SESSIONID_IN_LOCK(session->id);
    wr_latch_x2(&vg_item->recycle_meta_desc.latch, sid);
    cm_bilist_del(&block_ctrl->recycle_meta_node, &vg_item->recycle_meta_desc.bilist);
    wr_unlatch(&vg_item->recycle_meta_desc.latch);
    CM_ASSERT(block_ctrl->recycle_meta_node.next == NULL);
    CM_ASSERT(block_ctrl->recycle_meta_node.prev == NULL);
}

static uint32_t wr_try_find_recycle_meta_by_bucket(wr_session_t *session, wr_vg_info_item_t *vg_item,
    shm_hashmap_bucket_t *bucket, wr_recycle_meta_args_t *recycle_meta_args)
{
    bool32 has_next = CM_FALSE;
    ga_obj_id_t next_id = {0};
    wr_block_ctrl_t *block_ctrl = NULL;

    status_t status = wr_lock_shm_meta_bucket_s(session, vg_item->id, &bucket->enque_lock);
    if (status != CM_SUCCESS) {
        return 0;
    }

    uint32_t found_num = 0;
    uint32_t fs_usage = ga_get_pool_usage(GA_16K_POOL);
    uint32_t fs_aux_usage = ga_get_pool_usage(GA_FS_AUX_POOL);

    next_id = *(ga_obj_id_t *)&bucket->first;
    has_next = bucket->has_next;
    while (has_next) {
        block_ctrl = wr_buffer_get_block_ctrl_addr(next_id.pool_id, next_id.obj_id);
        if (!block_ctrl->recycle_disable &&
            ((fs_usage >= recycle_meta_args->recyle_meta_pos->hwm && block_ctrl->type == WR_BLOCK_TYPE_FS) ||
                (fs_aux_usage >= recycle_meta_args->recyle_meta_pos->hwm &&
                    block_ctrl->type == WR_BLOCK_TYPE_FS_AUX))) {
            wr_desc_meta_ref_hot(block_ctrl);
            if (block_ctrl->ref_hot == 0) {
                wr_append_recycle_meta(session, vg_item, block_ctrl);
                found_num++;
            }
        }

        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    wr_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    return found_num;
}

static void wr_meta_init_owner_fs_block_cache(wr_block_ctrl_t *owner_block_ctrl)
{
    return;
}

static bool32 wr_try_clean_cache_meta(wr_session_t *session, wr_block_ctrl_t *block_ctrl)
{
    if (block_ctrl->type != WR_BLOCK_TYPE_FS && block_ctrl->type != WR_BLOCK_TYPE_FS_AUX) {
        return CM_FALSE;
    }

    gft_node_t *owner_node = (gft_node_t *)block_ctrl->fs_block_cache_info.owner_node_addr;
    if (owner_node == NULL) {
        return CM_TRUE;
    }

    bool32 need_clean = CM_FALSE;
    wr_latch_x_node(session, owner_node, NULL);
    // not cached, clean the owner info
    if (WR_ID_TO_U64(owner_node->id) != block_ctrl->fs_block_cache_info.owner_node_id) {
        need_clean = CM_TRUE;
    } else {
        // cached
        wr_block_ctrl_t *owner_block_ctrl = wr_get_block_ctrl_by_node(owner_node);
        // the owner has been deleted, clean the owner's cache info, and then clean the owner info
        if (wr_is_node_deleted(owner_node)) {
            wr_meta_init_owner_fs_block_cache(owner_block_ctrl);
            need_clean = CM_TRUE;
            // the onwer is ok, but not cache this block, clean the onwer info
        } else if (owner_block_ctrl->fs_block_cache_info.entry_block_id != WR_ID_TO_U64(block_ctrl->block_id) &&
                   owner_block_ctrl->fs_block_cache_info.fs_block_id != WR_ID_TO_U64(block_ctrl->block_id) &&
                   owner_block_ctrl->fs_block_cache_info.fs_aux_block_id != WR_ID_TO_U64(block_ctrl->block_id)) {
            need_clean = CM_TRUE;
        }
    }
    wr_unlatch_node(owner_node);

    if (need_clean) {
        block_ctrl->fs_block_cache_info.owner_node_addr = NULL;
        block_ctrl->fs_block_cache_info.owner_node_id = 0;
    }
    return need_clean;
}

static void wr_try_recycle_meta_batch(wr_session_t *session, wr_vg_info_item_t *vg_item, bool32 trigger_enable)
{
    wr_block_ctrl_t *block_ctrl = NULL;
    uint32_t fs_recyle_cnt = 0;
    uint32_t fs_aux_recyle_cnt = 0;

    if (vg_item->recycle_meta_desc.bilist.count == 0) {
        return;
    }

    wr_enter_shm_x(session, vg_item);
    bilist_node_t *recycle_meta_node = wr_pop_recycle_meta(session, vg_item);
    while (recycle_meta_node) {
        block_ctrl = BILIST_NODE_OF(wr_block_ctrl_t, recycle_meta_node, recycle_meta_node);
        // only the ref_hot is 0, and not in syn meta, and clean the invalid cache info
        if (!block_ctrl->recycle_disable && block_ctrl->ref_hot == 0 && wr_try_clean_cache_meta(session, block_ctrl)) {
            if (block_ctrl->type == WR_BLOCK_TYPE_FS) {
                fs_recyle_cnt++;
                LOG_DEBUG_INF("recycle fs meta pool item id:%s", wr_display_metaid(block_ctrl->block_id));
            } else {
                fs_aux_recyle_cnt++;
                LOG_DEBUG_INF("recycle fs aux meta pool item id:%s", wr_display_metaid(block_ctrl->block_id));
            }

            wr_unregister_buffer_cache(session, vg_item, block_ctrl->block_id);
            ga_free_object(block_ctrl->my_obj_id.pool_id, block_ctrl->my_obj_id.obj_id);
        }
        recycle_meta_node = wr_pop_recycle_meta(session, vg_item);
    }
    wr_leave_shm(session, vg_item);

    LOG_DEBUG_INF("recycle fs meta pool item count:%u", fs_recyle_cnt);
    LOG_DEBUG_INF("recycle fs aux meta pool item count:%u", fs_aux_recyle_cnt);
}

static inline uint32_t wr_recycle_meta_batch_num(bool32 trigger_enable)
{
    return trigger_enable ? WR_RECYCLE_META_TRIGGER_CLEAN_BATCH_NUM : WR_RECYCLE_META_TIME_CLEAN_BATCH_NUM;
}

static void wr_recycle_meta_by_vg(wr_session_t *session, wr_vg_info_item_t *vg_item,
    wr_recycle_meta_args_t *recycle_meta_args, bool32 trigger_enable)
{
    shm_hashmap_t *map = vg_item->buffer_cache;
    if (map == NULL) {
        return;
    }

    shm_hash_ctrl_t *hash_ctrl = &map->hash_ctrl;
    // hash_ctrl->max_bucket may change
    uint32_t cur_map_num = hash_ctrl->max_bucket;
    if (cur_map_num == 0) {
        return;
    }

    shm_hashmap_bucket_t *bucket = NULL;
    uint32_t found_num = 0;
    uint32_t bucket_id = recycle_meta_args->last_bucket_id[vg_item->id];
    if (bucket_id >= cur_map_num || bucket_id >= hash_ctrl->max_bucket) {
        bucket_id = 0;
    }

    for (; (bucket_id < cur_map_num && bucket_id < hash_ctrl->max_bucket); bucket_id++) {
        bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_id, NULL);
        if (bucket == NULL || !bucket->has_next) {
            continue;
        }

        found_num += wr_try_find_recycle_meta_by_bucket(session, vg_item, bucket, recycle_meta_args);
        uint32_t batch_num = wr_recycle_meta_batch_num(trigger_enable);
        if ((found_num >= batch_num) || ((bucket_id + 1) == cur_map_num)) {
            wr_try_recycle_meta_batch(session, vg_item, trigger_enable);
            found_num = 0;
        }

        // check the recycle end
        uint32_t fs_usage = ga_get_pool_usage(GA_16K_POOL);
        uint32_t fs_aux_usage = ga_get_pool_usage(GA_FS_AUX_POOL);
        if (fs_usage <= recycle_meta_args->recyle_meta_pos->lwm &&
            fs_aux_usage <= recycle_meta_args->recyle_meta_pos->lwm) {
            break;
        }
    }
    recycle_meta_args->last_bucket_id[vg_item->id] = bucket_id;

    if (found_num > 0) {
        wr_try_recycle_meta_batch(session, vg_item, trigger_enable);
    }
}

void wr_recycle_meta(wr_session_t *session, wr_bg_task_info_t *bg_task_info, date_t *clean_time)
{
    wr_recycle_meta_args_t *recycle_meta_args = (wr_recycle_meta_args_t *)bg_task_info->task_args;

    (void)cm_wait_cond(&recycle_meta_args->trigger_cond, recycle_meta_args->trigger_clean_wait_time);
    bool32 trigger_enable = recycle_meta_args->trigger_enable;
    if (!trigger_enable) {
        uint64 time_now = (uint64)cm_now();
        if ((time_now - (*clean_time)) < (recycle_meta_args->time_clean_wait_time * MICROSECS_PER_SECOND)) {
            return;
        }
    } else {
        recycle_meta_args->trigger_enable = CM_FALSE;
    }

    // check wheather need to recycle meta first
    uint32_t fs_usage = ga_get_pool_usage(GA_16K_POOL);
    uint32_t fs_aux_usage = ga_get_pool_usage(GA_FS_AUX_POOL);
    if ((fs_usage <= recycle_meta_args->recyle_meta_pos->hwm) &&
        (fs_aux_usage <= recycle_meta_args->recyle_meta_pos->hwm)) {
        return;
    }

    LOG_DEBUG_INF("try recycle meta, trigger_enable:%u", (uint32_t)trigger_enable);
    // do recycle meta for vg one by one
    for (uint32_t i = bg_task_info->vg_id_beg; i < bg_task_info->vg_id_end; i++) {
        wr_recycle_meta_by_vg(session, &g_vgs_info->volume_group[i], recycle_meta_args, trigger_enable);
    }

    if (!trigger_enable) {
        *clean_time = cm_now();
    }

    (void)cm_wait_cond(&recycle_meta_args->trigger_cond, recycle_meta_args->trigger_clean_wait_time);
}

void wr_buffer_recycle_disable(wr_block_ctrl_t *block_ctrl, bool8 recycle_disable)
{
    block_ctrl->recycle_disable = recycle_disable;
}

void wr_set_recycle_meta_args_to_vg(wr_bg_task_info_t *bg_task_info)
{
    // do recycle meta for vg one by one
    for (uint32_t i = bg_task_info->vg_id_beg; i < bg_task_info->vg_id_end; i++) {
        g_vgs_info->volume_group[i].recycle_meta_desc.task_args = bg_task_info->task_args;
    }
}

void wr_trigger_recycle_meta(wr_vg_info_item_t *vg_item)
{
    wr_recycle_meta_args_t *recycle_meta_args = (wr_recycle_meta_args_t *)vg_item->recycle_meta_desc.task_args;
    recycle_meta_args->trigger_enable = CM_TRUE;
    cm_release_cond(&recycle_meta_args->trigger_cond);
}

#ifdef __cplusplus
}
#endif
