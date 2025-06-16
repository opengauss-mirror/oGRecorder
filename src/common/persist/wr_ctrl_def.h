/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * wr_ctrl_def.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_ctrl_def.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_CTRL_DEF_H__
#define __WR_CTRL_DEF_H__

#include "wr_defs.h"
#include "wr_au.h"
#include "cm_spinlock.h"
#include "wr_hashmap.h"
#include "cm_latch.h"
#include "wr_ga.h"
#include "cm_date.h"
#include "cm_bilist.h"
#include "wr_shm_hashmap.h"
#include "wr_param.h"
#include "wr_stack.h"
#include "wr_shm.h"
#include "wr_block_ctrl.h"

#define WR_GET_ROOT_BLOCK(wr_ctrl_p) ((wr_root_ft_block_t *)((wr_ctrl_p)->root))
#define WR_MAX_FT_AU_NUM 10
#define WR_GET_FT_AU_LIST(ft_au_list_p) ((wr_ft_au_list_t *)(ft_au_list_p))
#define WR_GET_FS_BLOCK_ROOT(wr_ctrl_p) ((wr_fs_block_root_t *)((wr_ctrl_p)->core.fs_block_root))
#define WR_MAX_VOLUME_GROUP_NUM (CM_HASH_SHM_MAX_ID)
#define WR_VG_ITEM_CACHE_NODE_MAX 16
#define WR_RECYLE_DIR_NAME ".recycle"

#define WR_CTRL_RESERVE_SIZE1 (SIZE_K(663))
#define WR_CTRL_RESERVE_SIZE2 (SIZE_K(15) - 512)
#define WR_CTRL_RESERVE_SIZE3 (SIZE_K(32))
#define WR_CTRL_RESERVE_SIZE4 512

#define WR_CTRL_CORE_OFFSET OFFSET_OF(wr_ctrl_t, core_data)
#define WR_CTRL_VOLUME_OFFSET OFFSET_OF(wr_ctrl_t, volume_data)
#define WR_CTRL_VG_DATA_OFFSET OFFSET_OF(wr_ctrl_t, vg_data)
#define WR_CTRL_VG_LOCK_OFFSET OFFSET_OF(wr_ctrl_t, lock)
#define WR_CTRL_ROOT_OFFSET OFFSET_OF(wr_ctrl_t, root)
#define WR_CTRL_GLOBAL_CTRL_OFFSET OFFSET_OF(wr_ctrl_t, global_data)
#define WR_CTRL_REDO_OFFSET OFFSET_OF(wr_ctrl_t, redo_ctrl_data)
#define WR_VG_LOCK_SHARE_DISK_OFFSET OFFSET_OF(wr_ctrl_t, disk_lock)

#define WR_CTRL_BAK_ADDR SIZE_M(1)
#define WR_CTRL_BAK_CORE_OFFSET (WR_CTRL_BAK_ADDR + WR_CTRL_CORE_OFFSET)
#define WR_CTRL_BAK_VOLUME_OFFSET (WR_CTRL_BAK_ADDR + WR_CTRL_VOLUME_OFFSET)
#define WR_CTRL_BAK_VG_DATA_OFFSET (WR_CTRL_BAK_ADDR + WR_CTRL_VG_DATA_OFFSET)
#define WR_CTRL_BAK_VG_LOCK_OFFSET (WR_CTRL_BAK_ADDR + WR_CTRL_VG_LOCK_OFFSET)
#define WR_CTRL_BAK_ROOT_OFFSET (WR_CTRL_BAK_ADDR + WR_CTRL_ROOT_OFFSET)
#define WR_CTRL_BAK_GLOBAL_CTRL_OFFSET (WR_CTRL_BAK_ADDR + WR_CTRL_GLOBAL_CTRL_OFFSET)
#define WR_CTRL_BAK_REDO_OFFSET (WR_CTRL_BAK_ADDR + WR_CTRL_REDO_OFFSET)

// Size of the volume header. 2MB is used to store vg_ctrl and its backup. The last 2MB is reserved.
#define WR_VOLUME_HEAD_SIZE SIZE_M(4)

#define WR_VG_IS_VALID(ctrl_p) ((ctrl_p)->vg_info.valid_flag == WR_CTRL_VALID_FLAG)

#define WR_FS_BLOCK_ROOT_SIZE 64
#define WR_AU_ROOT_SIZE 64

typedef enum en_vg_info_type {
    WR_VG_INFO_CORE_CTRL = 1,
    WR_VG_INFO_VG_HEADER,
    WR_VG_INFO_VOLUME_CTRL,
    WR_VG_INFO_ROOT_FT_BLOCK,
    WR_VG_INFO_GFT_NODE,
    WR_VG_INFO_REDO_CTRL,
    WR_VG_INFO_TYPE_END,
} wr_vg_info_type_e;

#ifdef WIN32
typedef HANDLE volume_handle_t;
#else
typedef int32_t volume_handle_t;
#endif

#define WR_VOLUME_DEF_RESVS 112

#define WR_FS_AUX_ROOT_SIZE 32
#define WR_GET_FS_AUX_ROOT(wr_ctrl_p) ((wr_fs_aux_root_t *)((wr_ctrl_p)->core.fs_aux_root))
#define WR_GET_FS_AUX_NUM_IN_AU(wr_ctrl) ((wr_get_vg_au_size(wr_ctrl)) / WR_FS_AUX_SIZE)
#define WR_CTRL_RESV_SIZE \
    ((((((WR_DISK_UNIT_SIZE) - (24)) - (WR_FS_BLOCK_ROOT_SIZE)) - (WR_AU_ROOT_SIZE)) - (WR_FS_AUX_ROOT_SIZE)))

#pragma pack(8)
typedef struct st_wr_volume_def {
    uint64 id : 16;
    uint64 flag : 3;
    uint64 reserve : 45;
    uint64 version;
    char name[WR_MAX_VOLUME_PATH_LEN];
    char code[WR_VOLUME_CODE_SIZE];
    char resv[WR_VOLUME_DEF_RESVS];
} wr_volume_def_t;  // CAUTION:If add/remove field ,please keep 256B total !!! Or modify rp_redo_add_or_remove_volume

typedef enum en_volume_slot {
    VOLUME_FREE = 0,  // free
    VOLUME_OCCUPY = 1,
    VOLUME_PREPARE = 2,  // not registered
    VOLUME_ADD = 3,      // add
    VOLUME_REMOVE = 4,   // remove
    VOLUME_REPLACE = 5,  // replace
    VOLUME_FLAG_MAX,
} volume_slot_e;

typedef struct st_wr_volume_attr {
    uint64 reverse1 : 1;
    uint64 id : 16;
    uint64 reserve2 : 47;
    uint64 size;
    uint64 hwm;
    uint64 free;
} wr_volume_attr_t;  // CAUTION:If add/remove field ,please keep 32B total !!! Or modify rp_redo_add_or_remove_volume

typedef enum wr_vg_device_Type {
    WR_VOLUME_TYPE_RAW = 0  // default is raw device
} wr_vg_device_Type_e;

typedef struct st_wr_volume {
    char name[WR_MAX_VOLUME_PATH_LEN];
    char *name_p;
    wr_volume_attr_t *attr;
    uint32_t id;
    volume_handle_t handle;
    volume_handle_t unaligned_handle;
    wr_vg_device_Type_e vg_type;
} wr_volume_t;

typedef struct st_wr_volume_disk {
    wr_volume_def_t def;
    wr_volume_attr_t attr;
    uint32_t id;
} wr_volume_disk_t;

typedef struct st_wr_metablock_header_t {
    wr_addr_t free_block_begin;
    wr_addr_t free_block_end;
    wr_addr_t first_block;
} wr_metablock_header_t;

#define WR_VOLUME_TYPE_NORMAL 0x12345678
#define WR_VOLUME_TYPE_MANAGER 0x12345679
typedef struct st_wr_volume_type_t {
    uint32_t type;
    uint32_t id;
    char entry_volume_name[WR_MAX_VOLUME_PATH_LEN];
} wr_volume_type_t;

typedef enum st_wr_bak_level_e {
    WR_BAK_LEVEL_0 = 0,  // super block only backed up on first volume, fs and ft do not backup
    WR_BAK_LEVEL_1,  // super block backed up on some specific volumes, fs and ft backed up at the end of each volume
    WR_BAK_LEVEL_2,  // super block backed up on all volumes, fs and ft backed up at the end of each volume
} wr_bak_level_e;

#define WR_MAX_BAK_LEVEL WR_BAK_LEVEL_2

typedef enum en_wr_software_version {
    WR_SOFTWARE_VERSION_0 = 0, /* version 0 */
    WR_SOFTWARE_VERSION_1 = 1, /* version 1 */
    WR_SOFTWARE_VERSION_2 = 2, /* version 2 */
} wr_software_version_e;

#define WR_SOFTWARE_VERSION WR_SOFTWARE_VERSION_2

#define WR_CTRL_VALID_FLAG 0x5f3759df
typedef struct st_wr_disk_group_header_t {
    uint32_t checksum;
    wr_volume_type_t vol_type;
    char vg_name[WR_MAX_NAME_LEN];
    uint32_t valid_flag;
    uint32_t software_version;  // for upgrade
    timeval_t create_time;
    wr_bak_level_e bak_level;
    uint32_t ft_node_ratio;  // ft_node is created for every ft_node_ratio bytes of space
    uint64 bak_ft_offset;  // Start position of the backup ft_node array
} wr_vg_header_t;

typedef wr_vg_header_t wr_volume_header_t;

typedef struct st_wr_simple_handle_t {
    uint32_t id;
    volume_handle_t handle;
    volume_handle_t unaligned_handle;
    uint64 version;
    wr_vg_device_Type_e vg_type;
} wr_simple_volume_t;

typedef struct st_wr_core_ctrl {
    uint32_t checksum;  // NOTE:checksum can not change the position in the struct.wr_get_checksum need.
    uint32_t reserve;
    uint64 version;
    uint32_t au_size;  // allocation unit size,4M,8M,16M,32M,64M
    uint32_t volume_count;
    char fs_block_root[WR_FS_BLOCK_ROOT_SIZE];  // wr_fs_block_root_t
    char au_root[WR_AU_ROOT_SIZE];              // 512-24-64,wr_au_root_t, recycle space entry
    char fs_aux_root[WR_FS_AUX_ROOT_SIZE];      // wr_fs_aux_root_t
    char resv[WR_CTRL_RESV_SIZE];
    wr_volume_attr_t volume_attrs[WR_MAX_VOLUMES];
} wr_core_ctrl_t;

typedef struct st_wr_volume_ctrl {
    uint32_t checksum;  // NOTE:can not change the position in the struct.
    uint32_t rsvd;
    uint64 version;
    char reserve[496];
    wr_volume_def_t defs[WR_MAX_VOLUMES];
} wr_volume_ctrl_t;

// struct for volume refresh
typedef struct st_refvol_ctrl {  // UNUSED
    wr_core_ctrl_t core;
    wr_volume_ctrl_t volume;
} wr_refvol_ctrl_t;

typedef struct st_wr_group_global_ctrl {
    uint64 cluster_node_info;
} wr_group_global_ctrl_t;

#define WR_MAX_EXTENDED_COUNT 8
typedef struct st_wr_redo_ctrl {
    uint32_t checksum;
    uint32_t redo_index;
    uint64 version;
    uint64 offset;  // redo offset
    uint64 lsn;     // redo lsn
    auid_t redo_start_au[WR_MAX_EXTENDED_COUNT];
    uint32_t redo_size[WR_MAX_EXTENDED_COUNT];  // except redo_size > 32KB
    uint32_t count;
    char reserve[376];
} wr_redo_ctrl_t;

typedef struct st_wr_ctrl {
    union {
        wr_vg_header_t vg_info;
        char vg_data[WR_VG_DATA_SIZE];
    };
    union {
        wr_core_ctrl_t core;
        char core_data[WR_CORE_CTRL_SIZE];  // 16K
    };

    union {
        wr_volume_ctrl_t volume;
        char volume_data[WR_VOLUME_CTRL_SIZE];  // 256K
    };
    char root[WR_ROOT_FT_DISK_SIZE];  // wr_root_ft_block_t, 8KB
    union {
        wr_redo_ctrl_t redo_ctrl;
        char redo_ctrl_data[WR_DISK_UNIT_SIZE]; // 512
    };
    char reserve1[WR_CTRL_RESERVE_SIZE1];     // 663K
    char disk_latch[WR_INIT_DISK_LATCH_SIZE]; // INIT DISK LATCH 32KB
    union {
        struct {
            char disk_lock[WR_LOCK_SHARE_DISK_SIZE]; // share disk lock, 32KB + 512, align with 8K
            char reserve4[WR_CTRL_RESERVE_SIZE4];    // 512
        };
        struct {
            char reserve3[WR_CTRL_RESERVE_SIZE3];  // 32KB
            char lock[WR_DISK_LOCK_LEN];           // align with 16K
        };
    };
    char reserve2[WR_CTRL_RESERVE_SIZE2];
    union {
        wr_group_global_ctrl_t global_ctrl;
        char global_data[WR_DISK_UNIT_SIZE];  // client disk info, size is 512
    };
} wr_ctrl_t;

static inline void wr_set_software_version(wr_vg_header_t *vg_header, uint32_t version)
{
    CM_ASSERT(vg_header != NULL);
    vg_header->software_version = version;
}

static inline uint32_t wr_get_software_version(wr_vg_header_t *vg_header)
{
    CM_ASSERT(vg_header != NULL);
    return vg_header->software_version;
}

typedef enum en_wr_vg_status {
    WR_VG_STATUS_RECOVERY = 1,
    WR_VG_STATUS_ROLLBACK,
    WR_VG_STATUS_OPEN,
} wr_vg_status_e;

#define WR_UNDO_LOG_NUM (WR_LOG_BUFFER_SIZE / 8)

typedef enum en_latch_type {
    LATCH_VG_HEADER = 0,
    LATCH_CORE_CTRL,
    LATCH_VOLUME_CTRL,
    LATCH_FT_ROOT,
    LATCH_COUNT,  // must be last
} latch_type_t;

typedef struct st_wr_vg_cache_node_t {
    latch_t latch;
    uint64 fid;
    uint64 ftid;
    char *node;
} wr_vg_cache_node_t;

typedef enum en_wr_from_type {
    FROM_SHM = 0,
    FROM_BBOX,
    FROM_DISK,
} wr_from_type_e;

typedef struct st_wr_log_file_ctrl {
    spinlock_t lock;
    char *log_buf;  // global log_buf
    bool8 used;
    uint32_t index;
    uint64 offset;
    uint64 lsn;
} wr_log_file_ctrl_t;

typedef struct st_wr_vg_info_item_t {
    uint32_t id;
    char vg_name[WR_MAX_NAME_LEN];
    char entry_path[WR_MAX_VOLUME_PATH_LEN];  // the manager volume path
    wr_vg_status_e status;
    cm_oamap_t au_map;  // UNUSED
    wr_volume_t volume_handle[WR_MAX_VOLUMES];
    wr_shared_latch_t *vg_latch;
    wr_ctrl_t *wr_ctrl;
    shm_hashmap_t *buffer_cache;
    char *align_buf;
    wr_stack stack;
    latch_t open_file_latch;
    bilist_t open_file_list;  // open file bilist.
    latch_t disk_latch;       // just for lock vg to lock the local instance.
    latch_t latch[LATCH_COUNT];
    wr_from_type_e from_type;
    wr_block_ctrl_task_desc_t syn_meta_desc;
    wr_vg_cache_node_t vg_cache_node[WR_VG_ITEM_CACHE_NODE_MAX];
    wr_log_file_ctrl_t log_file_ctrl;             // redo log ctrl
    wr_block_ctrl_task_desc_t recycle_meta_desc;  // for recycle meta
    uint32_t objectid;
    uint32_t space_alarm;
} wr_vg_info_item_t;

typedef struct st_wr_vg_info_t {
    wr_vg_info_item_t volume_group[WR_MAX_VOLUME_GROUP_NUM];
    uint32_t group_num;
} wr_vg_info_t;

typedef struct st_wr_vol_handles_t {
    wr_simple_volume_t volume_handle[WR_MAX_VOLUMES];
} wr_vol_handles_t;

typedef struct st_wr_cli_vg_handles_t {
    wr_vol_handles_t vg_vols[WR_MAX_VOLUME_GROUP_NUM];
    uint32_t group_num;
} wr_cli_vg_handles_t;

typedef struct st_wr_vg_conf_t {
    char vg_name[WR_MAX_NAME_LEN];
    char entry_path[WR_MAX_VOLUME_PATH_LEN];  // the manager volume path
} wr_vg_conf_t;

typedef struct st_wr_share_vg_item_t {
    wr_shared_latch_t vg_latch;
    shm_hashmap_t buffer_cache;
    uint32_t objectid;
    uint32_t id;
    char reserve[412];  // align 512
    wr_ctrl_t wr_ctrl;
} wr_share_vg_item_t;

#pragma pack()
#endif  // __WR_CTRL_DEF_H__
