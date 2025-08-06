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
 * cm_ga.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_ga.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_defs.h"
#include "cm_debug.h"
#include "cm_log.h"
#include "gr_defs.h"
#include "gr_errno.h"
#include "gr_ga.h"

char *g_app_area_addr;

int32_t g_sys_shm_id = -1;
int32_t g_app_shm_id = -1;

spinlock_t g_ga_attach_mutex = 0;

// clang-format off
ga_pool_t g_app_pools[GA_APP_POOL_COUNT] = {
    {"ctrl",   NULL, NULL, NULL, NULL, {NULL}, {1, GA_INSTANCE_POOL_SIZE, 0}, 0, 0}, /* ctrl pool */
    {"sesseion",   NULL, NULL, NULL, NULL, {NULL}, {0, 0, 0}, 0, 0},                 /* inst pool */
    {"meta 8k",      NULL, NULL, NULL, NULL, {NULL}, {0, 0, 0}, 0, 0},                  /* 8k pool */
    {"meta 16k",     NULL, NULL, NULL, NULL, {NULL}, {0, 0, 0}, 0, 0},                 /* 16k pool */
    {"fs aux",     NULL, NULL, NULL, NULL, {NULL}, {0, 0, 0}, 0, 0},                 /* fs aux */
    {"hash segment",     NULL, NULL, NULL, NULL, {NULL}, {0, 0, 0}, 0, 0},                 /* hash segment */
};

ga_pool_t g_app_pools_initial[GA_APP_POOL_COUNT] = {
    {"ctrl",   NULL, NULL, NULL, NULL, {NULL}, {1, GA_INSTANCE_POOL_SIZE, 0}, 0, 0}, /* ctrl pool */
    {"sesseion",   NULL, NULL, NULL, NULL, {NULL}, {0, 0, 0}, 0, 0},                 /* inst pool */
    {"meta 8k",      NULL, NULL, NULL, NULL, {NULL}, {0, 0, 0}, 0, 0},                  /* 8k pool */
    {"meta 16k",     NULL, NULL, NULL, NULL, {NULL}, {0, 0, 0}, 0, 0},                 /* 16k pool */
    {"fs aux",     NULL, NULL, NULL, NULL, {NULL}, {0, 0, 0}, 0, 0},                 /* fs aux */
    {"hash segment",  NULL, NULL, NULL, NULL, {NULL}, {0, 0, 0}, 0, 0},              /* hash segment */
};

void ga_reset_app_pools()
{
    (void)memcpy_s(g_app_pools, sizeof(g_app_pools), g_app_pools_initial, sizeof(g_app_pools_initial));
}

// clang-format on
static inline ga_pool_t *ga_get_pool(uint32_t id)
{
    return &g_app_pools[GA_POOL_IDX(id)];
}

void ga_set_pool_def(ga_pool_id_e pool_id, const ga_pool_def_t *def)
{
    ga_pool_t *pool;
    CM_ASSERT(def != NULL);
    pool = ga_get_pool((uint32_t)pool_id);
    pool->def = *def;
    pool->capacity = CM_ALIGN_512((uint32_t)sizeof(ga_pool_ctrl_t));
    pool->capacity += CM_ALIGN_512(((ulong)def->object_size + (uint32_t)sizeof(ga_object_map_t)) * def->object_count);
    LOG_RUN_INF("Succeed to init pool %s, object count is %u, object size is %u, ex_max is %u.", pool->pool_name,
        pool->def.object_count, pool->def.object_size, pool->def.ex_max);
}

static inline ga_object_map_t *ga_object_map(ga_pool_t *pool, uint32_t object_id)
{
    CM_ASSERT(pool != NULL);

    if (pool->ctrl->ex_count == 0 || object_id < pool->def.object_count) {
        return &pool->object_map[object_id];
    } else {
        uint32_t ex_pool_id = (object_id / pool->def.object_count) - 1;
        ga_object_map_t *ex_object_map = (ga_object_map_t *)pool->ex_pool_addr[ex_pool_id];
        return &ex_object_map[object_id % pool->def.object_count];
    }
}

static uint32_t ga_remove_from_queue(ga_pool_t *pool, ga_queue_t *queue)
{
    uint32_t object_id;

    CM_ASSERT(pool != NULL);
    CM_ASSERT(queue != NULL);

    if (queue->count == 0) {
        return CM_INVALID_ID32;
    }

    object_id = queue->first;
    queue->first = ga_object_map(pool, object_id)->next;
    queue->count--;
    if (queue->count > 0) {
        ga_object_map(pool, queue->first)->prior = CM_INVALID_ID32;
    }

    return object_id;
}

static void ga_concat_queue(ga_pool_t *pool, ga_queue_t *queue1, ga_queue_t *queue2)
{
    CM_ASSERT(pool != NULL);
    CM_ASSERT(queue1 != NULL);
    CM_ASSERT(queue2 != NULL);

    if (queue1->count == 0) {
        *queue1 = *queue2;
    } else {
        ga_object_map(pool, queue1->last)->next = queue2->first;
        ga_object_map(pool, queue2->first)->prior = queue1->last;
        queue1->count += queue2->count;
        queue1->last = queue2->last;
    }
}

static void ga_init_pool(ga_offset_t offset, ga_pool_t *pool)
{
    uint32_t i, object_offset;
    CM_ASSERT(pool != NULL);

    pool->addr = g_app_area_addr + offset;

    object_offset = (uint32_t)sizeof(ga_pool_ctrl_t) + pool->def.object_count * (uint32_t)sizeof(ga_object_map_t);
    pool->object_addr = pool->addr + object_offset;

    pool->ctrl = (ga_pool_ctrl_t *)pool->addr;
    pool->object_map = (ga_object_map_t *)(pool->addr + (uint32_t)sizeof(ga_pool_ctrl_t));

    pool->object_map[0].prior = CM_INVALID_ID32;

    for (i = 0; i < pool->def.object_count - 1; i++) {
        pool->object_map[i].next = i + 1;
        pool->object_map[(uint32_t)(i + 1)].prior = i;
    }

    pool->object_map[pool->def.object_count - 1].next = CM_INVALID_ID32;

    GS_INIT_SPIN_LOCK(pool->ctrl->mutex);
    pool->ctrl->def = pool->def;
    pool->ctrl->offset = offset;
    pool->ctrl->ex_count = 0;

    pool->ctrl->free_objects.count = pool->def.object_count;
    pool->ctrl->free_objects.first = 0;
    pool->ctrl->free_objects.last = pool->def.object_count - 1;
}

status_t ga_create_global_area(void)
{
    uint64 app_area_size, offset;
    uint32_t i;
    uint64 *pool_offsets;

    app_area_size = CM_ALIGN_512(GA_APP_POOL_COUNT * (uint32_t)sizeof(ulong));
    for (i = 0; i < GA_APP_POOL_COUNT; i++) {
        if (g_app_pools[i].capacity == 0) {
            LOG_RUN_ERR("The application pool %u is not defined.", i);
            return ERR_GR_GA_INIT;
        }

        app_area_size += g_app_pools[i].capacity;
    }

    g_app_area_addr = (char *)cm_get_shm(SHM_TYPE_FIXED, (uint32_t)SHM_ID_APP_GA, app_area_size, CM_SHM_ATTACH_RW);
    if (g_app_area_addr == NULL) {
        LOG_RUN_ERR("Can't create the application area because of failed to get shm, area size = %llu.", app_area_size);
        return ERR_GR_GA_INIT;
    }

    offset = CM_ALIGN_512(GA_APP_POOL_COUNT * (uint32_t)sizeof(ulong));
    pool_offsets = (uint64 *)g_app_area_addr;

    for (i = 0; i < GA_APP_POOL_COUNT; i++) {
        pool_offsets[i] = offset;
        ga_init_pool(offset, &g_app_pools[i]);
        offset += g_app_pools[i].capacity;
    }
    LOG_RUN_INF("Create global area successfully.");
    return CM_SUCCESS;
}

void ga_destroy_global_area(void)
{
    uint32_t i;

    for (i = 0; i < CM_GA_SHM_MAX_ID; i++) {
        (void)cm_del_shm(SHM_TYPE_GA, i);
    }

    (void)cm_del_shm(SHM_TYPE_FIXED, (uint32_t)SHM_ID_APP_GA);
}

static status_t ga_attach_pool(ga_pool_id_e id, uint32_t attach_perm)
{
    uint32_t i, object_offset;
    char *area_addr;
    ga_pool_t *pool = &g_app_pools[id];
    ulong *pool_offsets;

    area_addr = g_app_area_addr;
    pool_offsets = (ulong *)area_addr;

    pool->addr = area_addr + pool_offsets[id];
    pool->ctrl = (ga_pool_ctrl_t *)(pool->addr);
    pool->object_map = (ga_object_map_t *)(pool->addr + (uint32_t)sizeof(ga_pool_ctrl_t));
    pool->def = pool->ctrl->def;

    object_offset = (uint32_t)sizeof(ga_pool_ctrl_t) + pool->def.object_count * (uint32_t)sizeof(ga_object_map_t);
    pool->object_addr = pool->addr + object_offset;

    if (pool->ctrl->ex_count > GA_MAX_EXTENDED_POOLS) {
        LOG_RUN_ERR("Invalid pool info[id=%u] from shared memory: ex_count is %u, larger than maximum %u", id,
            pool->ctrl->ex_count, GA_MAX_EXTENDED_POOLS);
        return CM_ERROR;
    }

    for (i = 0; i < GA_MAX_EXTENDED_POOLS; i++) {
        pool->ex_pool_addr[i] = NULL;
    }

    for (i = 0; i < pool->ctrl->ex_count; i++) {
        pool->ex_pool_addr[i] = (char *)cm_attach_shm(SHM_TYPE_GA, (uint32_t)pool->ctrl->ex_shm_id[i], 0, attach_perm);
    }
    return CM_SUCCESS;
}

status_t ga_attach_area(uint32_t attach_perm)
{
    uint32_t i = 0;

    g_app_area_addr = (char *)cm_attach_shm(SHM_TYPE_FIXED, (uint32_t)SHM_ID_APP_GA, 0, attach_perm);
    if (g_app_area_addr == NULL) {
        uint64 app_area_size = CM_ALIGN_512(GA_APP_POOL_COUNT * (uint32_t)sizeof(ulong));
        g_app_area_addr = (char *)cm_get_shm(SHM_TYPE_FIXED, (uint32_t)SHM_ID_APP_GA, app_area_size, CM_SHM_ATTACH_RW);

        if (g_app_area_addr == NULL) {
            LOG_RUN_ERR("can't attach the application are, area size = %llu.", app_area_size);
            return ERR_GR_GA_INIT;
        }

    }

    for (i = 0; i < GA_APP_POOL_COUNT; i++) {
        if (ga_attach_pool((ga_pool_id_e)i, attach_perm) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static void ga_detach_pool(ga_pool_id_e id)
{
    ga_pool_t *pool = &g_app_pools[id];
    uint32_t i;

    if (!pool->ctrl) {
        return;
    }

    if (pool->ctrl->ex_count > GA_MAX_EXTENDED_POOLS) {
        LOG_RUN_ERR("Invalid pool info[id=%u]: ex_count is %u, larger than maximum %u", id, pool->ctrl->ex_count,
            GA_MAX_EXTENDED_POOLS);
        return;
    }

    for (i = 0; i < pool->ctrl->ex_count; i++) {
        if (pool->ex_pool_addr[i] != NULL) {
            (void)cm_detach_shm(SHM_TYPE_GA, (uint32_t)pool->ctrl->ex_shm_id[i]);
        }
    }
}

void ga_detach_area(void)
{
    uint32_t i = 0;

    for (i = 0; i < GA_APP_POOL_COUNT; i++) {
        ga_detach_pool((ga_pool_id_e)i);
    }

    (void)cm_detach_shm(SHM_TYPE_FIXED, (uint32_t)SHM_ID_APP_GA);
}

static status_t ga_extend_pool(ga_pool_id_e pool_id)
{
    ulong ex_pool_size;
    uint32_t ex_start_id, object_cost, i;
    char *ex_addr;
    ga_queue_t ex_objects;
    ga_pool_t *pool = ga_get_pool((uint32_t)pool_id);
    ga_object_map_t *object_map;
    uint32_t pool_shm_id = GA_EXT_SHM_POOLID(pool_id) * GA_MAX_EXTENDED_POOLS + pool->ctrl->ex_count;

    if (pool->def.ex_max <= pool->ctrl->ex_count) {
        GR_RETURN_IFERR2(CM_ERROR,
            LOG_RUN_ERR("the extended number of %s pool reach to limitation %u.", pool->pool_name, pool->def.ex_max));
    }

    object_cost = pool->def.object_size + (uint32_t)sizeof(ga_object_map_t);
    ex_pool_size = (ulong)object_cost * pool->def.object_count;

    ex_addr = (char *)cm_get_shm(SHM_TYPE_GA, pool_shm_id, ex_pool_size, CM_SHM_ATTACH_RW);
    if (ex_addr == NULL) {
        GR_RETURN_IFERR2(
            CM_ERROR, LOG_RUN_ERR("get shared memory in failure when extending the %s pool.", pool->pool_name));
    }

    pool->ctrl->ex_shm_id[pool->ctrl->ex_count] = (int32_t)pool_shm_id;
    pool->ex_pool_addr[pool->ctrl->ex_count] = ex_addr;
    ex_start_id = (pool->ctrl->ex_count + 1) * pool->def.object_count;

    pool->ctrl->ex_count++;

    object_map = (ga_object_map_t *)ex_addr;

    object_map[0].prior = CM_INVALID_ID32;

    for (i = 0; i < pool->def.object_count - 1; i++) {
        uint32_t object_id = ex_start_id + i;
        object_map[i].next = object_id + 1;
        object_map[(uint32_t)(i + 1)].prior = object_id;
    }

    object_map[(uint32_t)(pool->def.object_count - 1)].next = CM_INVALID_ID32;

    ex_objects.first = ex_start_id;
    ex_objects.last = ex_start_id + pool->def.object_count - 1;
    ex_objects.count = pool->def.object_count;

    ga_concat_queue(pool, &pool->ctrl->free_objects, &ex_objects);

    return CM_SUCCESS;
}

uint32_t ga_alloc_object(ga_pool_id_e pool_id, uint32_t specific_id)
{
    uint32_t object_id;
    ga_pool_t *pool = ga_get_pool((uint32_t)pool_id);

    cm_spin_lock(&pool->ctrl->mutex, NULL);

    if (pool->ctrl->free_objects.count == 0) {
        if (pool->def.ex_max == 0) {
            cm_spin_unlock(&pool->ctrl->mutex);
            return CM_INVALID_ID32;
        }

        if (ga_extend_pool(pool_id) != CM_SUCCESS) {
            cm_spin_unlock(&pool->ctrl->mutex);
            return CM_INVALID_ID32;
        }
    }

    if (specific_id != CM_INVALID_ID32) {
        uint32_t next_id = pool->object_map[specific_id].next;
        uint32_t prior_id = pool->object_map[specific_id].prior;

        if (next_id != CM_INVALID_ID32) {
            pool->object_map[next_id].prior = prior_id;
        }

        if (prior_id != CM_INVALID_ID32) {
            pool->object_map[prior_id].next = next_id;
        }

        if (pool->ctrl->free_objects.first == specific_id) {
            pool->ctrl->free_objects.first = next_id;
        }

        if (pool->ctrl->free_objects.last == specific_id) {
            pool->ctrl->free_objects.last = prior_id;
        }

        pool->ctrl->free_objects.count--;
        object_id = specific_id;
    } else {
        object_id = ga_remove_from_queue(pool, &pool->ctrl->free_objects);
    }

    cm_spin_unlock(&pool->ctrl->mutex);

    return object_id;
}

// clang-format off
#define GA_MAIN_POOL_OBJECT_OFFSET(pool, object_id)                                 \
    ((ga_offset_t)(CM_ALIGN_512(sizeof(ga_pool_ctrl_t) +                            \
    (ga_offset_t)(pool)->def.object_count * (ga_offset_t)sizeof(ga_object_map_t)) + \
    (ga_offset_t)(object_id) * (ga_offset_t)(pool)->def.object_size))

// clang-format on
char *ga_object_addr(ga_pool_id_e pool_id, uint32_t object_id)
{
    ulong offset;
    ga_pool_t *pool = ga_get_pool((uint32_t)pool_id);

    if (object_id < pool->def.object_count) {
        return pool->addr + GA_MAIN_POOL_OBJECT_OFFSET(pool, object_id);
    }

    if (pool->ctrl->ex_count == 0) {
        return NULL;
    } else {
        offset = CM_ALIGN_512((ga_offset_t)pool->def.object_count * (ga_offset_t)sizeof(ga_object_map_t));
        offset += (ga_offset_t)(object_id % pool->def.object_count) * (ga_offset_t)pool->def.object_size;
        uint32_t ex_pool_id = object_id / pool->def.object_count - 1;
        if (ex_pool_id >= pool->ctrl->ex_count) {
            return NULL;
        }
        if (pool->ex_pool_addr[ex_pool_id] == NULL) {
            cm_spin_lock(&g_ga_attach_mutex, NULL);
            if (pool->ex_pool_addr[ex_pool_id] == NULL) {
                pool->ex_pool_addr[ex_pool_id] =
                    (char *)cm_attach_shm(SHM_TYPE_GA, (uint32_t)pool->ctrl->ex_shm_id[ex_pool_id], 0, CM_SHM_ATTACH_RW);
            }

            cm_spin_unlock(&g_ga_attach_mutex);
        }

        if (pool->ex_pool_addr[ex_pool_id] == NULL) {
            return NULL;
        }

        return pool->ex_pool_addr[ex_pool_id] + offset;
    }
}