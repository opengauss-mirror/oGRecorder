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
 * wr_shm_hashmap.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_shm_hashmap.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_shm_hashmap.h"
#include "wr_ga.h"
#include "wr_log.h"
#include "wr_errno.h"
#include "wr_defs.h"

uint32_t shm_hashmap_calc_bucket_idx(shm_hash_ctrl_t *hash_ctrl, uint32_t hash)
{
    uint32_t bucket_idx = hash & hash_ctrl->high_mask;
    if (bucket_idx > hash_ctrl->max_bucket) {
        bucket_idx &= hash_ctrl->low_mask;
    }
    return bucket_idx;
}

status_t shm_hashmap_extend_segment(shm_hash_ctrl_t *hash_ctrl)
{
    uint32_t segment_num = hash_ctrl->nsegments;
    uint32_t objectid = ga_alloc_object(GA_SEGMENT_POOL, CM_INVALID_ID32);
    if (objectid == CM_INVALID_ID32) {
        WR_THROW_ERROR(ERR_WR_GA_ALLOC_OBJECT, GA_SEGMENT_POOL);
        return CM_ERROR;
    }
    shm_hashmap_bucket_t *addr = (shm_hashmap_bucket_t *)ga_object_addr(GA_SEGMENT_POOL, objectid);
    if (addr == NULL) {
        WR_THROW_ERROR(ERR_WR_GA_GET_ADDR, GA_SEGMENT_POOL, objectid);
        return CM_ERROR;
    }
    errno_t rc = memset_s(addr, WR_BUCKETS_SIZE_PER_SEGMENT, 0, WR_BUCKETS_SIZE_PER_SEGMENT);
    if (rc != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return CM_ERROR;
    }
    uint32_t *dirs = (uint32_t *)OFFSET_TO_ADDR(hash_ctrl->dirs);
    dirs[segment_num] = objectid;
    hash_ctrl->nsegments++;
    LOG_DEBUG_INF(
        "[HASHMAP]Succeed to extend segment, segment num is %u, object id is %u.", hash_ctrl->nsegments, objectid);
    return CM_SUCCESS;
}

shm_hashmap_bucket_t *shm_hashmap_get_bucket(shm_hash_ctrl_t *hash_ctrl, uint32_t bucket_idx, uint32_t *segment_objid)
{
    uint32_t *dirs = (uint32_t *)OFFSET_TO_ADDR(hash_ctrl->dirs);
    uint32_t segment_idx = bucket_idx / WR_BUCKETS_PER_SEGMENT;
    WR_ASSERT_LOG(segment_idx < hash_ctrl->nsegments, "segment idx %u exceeds nsegments %u, bucket_idx is %u.",
        segment_idx, hash_ctrl->nsegments, bucket_idx);
    uint32_t objectid = dirs[segment_idx];
    shm_hashmap_bucket_t *segment = (shm_hashmap_bucket_t *)ga_object_addr(GA_SEGMENT_POOL, objectid);
    if (segment == NULL) {
        WR_THROW_ERROR(ERR_WR_GA_GET_ADDR, GA_SEGMENT_POOL, objectid);
        return NULL;
    }
    if (segment_objid != NULL) {
        *segment_objid = objectid;
    }
    uint32_t sub_bucket_idx = bucket_idx % WR_BUCKETS_PER_SEGMENT;
    return &segment[sub_bucket_idx];
}
