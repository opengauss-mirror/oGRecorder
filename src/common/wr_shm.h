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
 * wr_shm.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_shm.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_SHM_H_
#define __WR_SHM_H_

#ifndef WIN32
#include <sys/shm.h>
#include <sys/stat.h>
#else
#include <sys\stat.h>
#endif
#include <stdint.h>
#include "cm_types.h"
#include "cm_defs.h"
#include "cm_spinlock.h"
#include "cm_error.h"
// #ifndef ARM/*def CONFIG_64BIT_PROGRAM*/
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
typedef HANDLE cm_shm_handle_t;
#define CM_INVALID_SHM_HANDLE INVALID_HANDLE_VALUE
#else
typedef int32 cm_shm_handle_t;
#define CM_INVALID_SHM_HANDLE (-1)
#endif

extern uint32 g_shm_key;
extern bool32 g_shm_inited;

#define CM_FIXED_SHM_MAX_ID CM_FIXED_SHM_ID_TAIL
#define CM_HASH_SHM_MAX_ID 65
#define CM_GA_SHM_MAX_ID 20480U  // max total extended pool
#define CM_SHM_MAX_BLOCK ((CM_FIXED_SHM_MAX_ID) + (CM_HASH_SHM_MAX_ID) + (CM_GA_SHM_MAX_ID))
/* share memory manager control block magic string, must be 8Bytes aligned, now 48Bytes */
#define CM_SHM_MAGIC "Huawei Tech. Co., Ltd. gauss100 DB WR Software"

/* share memory control block reserved for future use */
#define CM_SHM_CTRL_RESERVED 1020

/* share memory block reserved for future use */
#define CM_SHM_BLOCK_RESERVED 16

/* pids stored in share memory block */
#define CM_SHM_BLOCK_PID_CNT 128

typedef uint32 cm_shm_key_t;

#ifdef WIN32
#define CM_SHM_ATTACH_RDONLY FILE_MAP_READ
#define CM_SHM_ATTACH_RW FILE_MAP_ALL_ACCESS
#define CM_SHM_PERMISSION 0
#else
#define CM_SHM_ATTACH_RDONLY SHM_RDONLY
#define CM_SHM_ATTACH_RW 0 /* the default attach mode is read write */
#define CM_SHM_PERMISSION 0600
#endif

#define CM_SHM_CTRL_CURRENT_VERSION 6u
#define CM_INVALID_SHM_IDX 0xFFFFFFFF
#define CM_SHM_MAKE_KEY(shm_key, idx) ((uint32)(((uint32)(shm_key) & (0xFFFF)) << 16) | (uint32)((idx) & (0xFFFF)))
#define CM_SHM_KEY2IDX(key) ((uint32)((key) & (0xFFFF)))
#define CM_SHM_KEY2INSTANCE(key) (((uint32)((key) & (0xFFFF0000))) >> 16)
#define CM_SHM_IDX_TO_KEY(idx) CM_SHM_MAKE_KEY(g_shm_key, idx)
#define CM_SHM_SIZE_OF_CTRL (sizeof(cm_shm_ctrl_t))

typedef struct tagcm_shm_ctrl {
    char magic[sizeof(CM_SHM_MAGIC)]; /* share memory control block magic string */
    uint32 self_version;              /* share memory control block version */
    uint32 instance_id;               /* mdb instance ID, to identify the share memory control block */
    spinlock_t lock_for_self;
    uint64 flag;                             /* flag for database instance initialization integrality */
    char reserved[CM_SHM_CTRL_RESERVED]; /* reserved */
} cm_shm_ctrl_t;

typedef enum tagcm_fixed_shm_id {
    SHM_ID_MNG_CTRL = 1, /* The first id must be for shared memory management control block */
    SHM_ID_APP_GA,
    SHM_ID_MNG_VG,
    SHM_ID_MNG_SESS,
    CM_FIXED_SHM_ID_TAIL
} cm_fixed_shm_id_e;

#define CM_SHM_CTRL_KEY CM_SHM_IDX_TO_KEY((uint32)SHM_ID_MNG_CTRL)

typedef struct sh_mem_struct {
    uint64_t offset : 32;
    uint64_t seg : 32;
} sh_mem_t;

typedef enum tagcm_shm_type {
    SHM_TYPE_FIXED = 0,
    SHM_TYPE_GA,
    SHM_TYPE_HASH,
} cm_shm_type_e;

typedef uint64_t sh_mem_p;

#define SHM_EXTEND_MAX_NUM (1024 * 5)

#define MAX_INSTANCE_NUM 1

#define DB_MAX_HASH_INDEX_TABLE_NUM 2

#define SHM_INVALID_ADDR 0

#define DB_BLK_SHM_MAX_NUM SHM_EXTEND_MAX_NUM

#define DB_MAX_MAP_NUM (SHM_EXTEND_MAX_NUM * 3 + DB_MAX_HASH_INDEX_TABLE_NUM)

#define MAX_SEG_NUM (DB_MAX_MAP_NUM * MAX_INSTANCE_NUM)

#define INVALID_SHM_ATTACH_NUM (-1)

#define SHM_GET_STRUCT_OFFSET(base_offset, type, element) ((base_offset) + (sh_mem_p) & (((type)0)->(element)))

#define SHM_ENABLE_HUGEPAGE_FLAGS 1

#define CM_SHM_CTRL_FLAG_TRUE ((uint64)0x0123456789ABCDEF)

#define SHM_MAX_RETRY_ATTACH_NUM 10

#define CM_SHM_CTRL_KEY CM_SHM_IDX_TO_KEY((uint32)SHM_ID_MNG_CTRL)

status_t cm_init_shm(uint32 shm_key);
void cm_destroy_shm(void);

void *cm_get_shm(cm_shm_type_e type, uint32 id, uint64 size, uint32 flag);
bool32 cm_del_shm(cm_shm_type_e type, uint32 id);
void *cm_attach_shm(cm_shm_type_e type, uint32 id, uint64 size, uint32 flag);
uint64 cm_get_shm_ctrl_flag(void);
bool32 cm_detach_shm(cm_shm_type_e type, uint32 id);
bool32 cm_native_del_shm(cm_shm_handle_t handle);
cm_shm_key_t cm_shm_key_of(cm_shm_type_e type, uint32 id);
sh_mem_p cm_trans_shm_offset(uint32_t key, void *ptr);
void *cm_do_attach_shm_without_register(cm_shm_key_t key, uint64 size, uint32 flag, bool32 logging_open_err);
void cm_set_shm_ctrl_flag(uint64 value);
bool32 del_shm_by_key(cm_shm_key_t key);
sh_mem_p cm_trans_shm_offset_from_malloc(uint32_t key, void *ptr);
typedef struct tagcm_shm_map_entry {
    cm_shm_handle_t handle;
    void *addr;     /* Attached address of the block */
    void *addr_bak; /* Attached address backup of the block */
} cm_shm_map_entry_t;

typedef struct tagcm_shm_map {
    cm_shm_map_entry_t entries[CM_SHM_MAX_BLOCK];
} cm_shm_map_t;
extern cm_shm_map_t g_shm_map;
#define OFFSET_TO_ADDR(offset_ptr)                                                                       \
    ((g_shm_map.entries[((sh_mem_t *)(void *)&(offset_ptr))->seg].addr == NULL ?                         \
            (uint8_t *)cm_do_attach_shm_without_register(                                                \
                (cm_shm_key_t)((sh_mem_t *)(void *)&(offset_ptr))->seg, 0, CM_SHM_ATTACH_RW, CM_FALSE) + \
                ((sh_mem_t *)(void *)&(offset_ptr))->offset :                                            \
            (uint8_t *)g_shm_map.entries[((sh_mem_t *)(void *)&(offset_ptr))->seg].addr +                \
                ((sh_mem_t *)(void *)&(offset_ptr))->offset))

#ifdef __cplusplus
}
#endif
#endif
