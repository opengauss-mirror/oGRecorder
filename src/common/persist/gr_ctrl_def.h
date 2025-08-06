/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * gr_ctrl_def.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/gr_ctrl_def.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_CTRL_DEF_H__
#define __GR_CTRL_DEF_H__

#include "gr_defs.h"
#include "gr_au.h"
#include "cm_spinlock.h"
#include "gr_hashmap.h"
#include "cm_latch.h"
#include "gr_ga.h"
#include "cm_date.h"
#include "cm_bilist.h"
#include "gr_shm_hashmap.h"
#include "gr_param.h"
#include "gr_stack.h"
#include "gr_shm.h"
#include "gr_block_ctrl.h"

#define GR_GET_ROOT_BLOCK(gr_ctrl_p) ((gr_root_ft_block_t *)((gr_ctrl_p)->root))
#define GR_MAX_FT_AU_NUM 10
#define GR_GET_FT_AU_LIST(ft_au_list_p) ((gr_ft_au_list_t *)(ft_au_list_p))
#define GR_GET_FS_BLOCK_ROOT(gr_ctrl_p) ((gr_fs_block_root_t *)((gr_ctrl_p)->core.fs_block_root))
#define GR_MAX_VOLUME_GROUP_NUM (CM_HASH_SHM_MAX_ID)
#define GR_VG_ITEM_CACHE_NODE_MAX 16
#define GR_RECYLE_DIR_NAME ".recycle"

#define GR_CTRL_RESERVE_SIZE1 (SIZE_K(663))
#define GR_CTRL_RESERVE_SIZE2 (SIZE_K(15) - 512)
#define GR_CTRL_RESERVE_SIZE3 (SIZE_K(32))
#define GR_CTRL_RESERVE_SIZE4 512

#define GR_CTRL_CORE_OFFSET OFFSET_OF(gr_ctrl_t, core_data)
#define GR_CTRL_VOLUME_OFFSET OFFSET_OF(gr_ctrl_t, volume_data)
#define GR_CTRL_VG_DATA_OFFSET OFFSET_OF(gr_ctrl_t, vg_data)
#define GR_CTRL_VG_LOCK_OFFSET OFFSET_OF(gr_ctrl_t, lock)
#define GR_CTRL_ROOT_OFFSET OFFSET_OF(gr_ctrl_t, root)
#define GR_CTRL_GLOBAL_CTRL_OFFSET OFFSET_OF(gr_ctrl_t, global_data)
#define GR_CTRL_REDO_OFFSET OFFSET_OF(gr_ctrl_t, redo_ctrl_data)
#define GR_VG_LOCK_SHARE_DISK_OFFSET OFFSET_OF(gr_ctrl_t, disk_lock)

#define GR_CTRL_BAK_ADDR SIZE_M(1)
#define GR_CTRL_BAK_CORE_OFFSET (GR_CTRL_BAK_ADDR + GR_CTRL_CORE_OFFSET)
#define GR_CTRL_BAK_VOLUME_OFFSET (GR_CTRL_BAK_ADDR + GR_CTRL_VOLUME_OFFSET)
#define GR_CTRL_BAK_VG_DATA_OFFSET (GR_CTRL_BAK_ADDR + GR_CTRL_VG_DATA_OFFSET)
#define GR_CTRL_BAK_VG_LOCK_OFFSET (GR_CTRL_BAK_ADDR + GR_CTRL_VG_LOCK_OFFSET)
#define GR_CTRL_BAK_ROOT_OFFSET (GR_CTRL_BAK_ADDR + GR_CTRL_ROOT_OFFSET)
#define GR_CTRL_BAK_GLOBAL_CTRL_OFFSET (GR_CTRL_BAK_ADDR + GR_CTRL_GLOBAL_CTRL_OFFSET)
#define GR_CTRL_BAK_REDO_OFFSET (GR_CTRL_BAK_ADDR + GR_CTRL_REDO_OFFSET)

// Size of the volume header. 2MB is used to store vg_ctrl and its backup. The last 2MB is reserved.
#define GR_VOLUME_HEAD_SIZE SIZE_M(4)

#define GR_VG_IS_VALID(ctrl_p) ((ctrl_p)->vg_info.valid_flag == GR_CTRL_VALID_FLAG)

#define GR_FS_BLOCK_ROOT_SIZE 64
#define GR_AU_ROOT_SIZE 64

typedef enum en_vg_info_type {
    GR_VG_INFO_CORE_CTRL = 1,
    GR_VG_INFO_VG_HEADER,
    GR_VG_INFO_VOLUME_CTRL,
    GR_VG_INFO_ROOT_FT_BLOCK,
    GR_VG_INFO_GFT_NODE,
    GR_VG_INFO_REDO_CTRL,
    GR_VG_INFO_TYPE_END,
} gr_vg_info_type_e;

#ifdef WIN32
typedef HANDLE volume_handle_t;
#else
typedef int32_t volume_handle_t;
#endif

#define GR_VOLUME_DEF_RESVS 112

#define GR_FS_AUX_ROOT_SIZE 32
#define GR_GET_FS_AUX_ROOT(gr_ctrl_p) ((gr_fs_aux_root_t *)((gr_ctrl_p)->core.fs_aux_root))
#define GR_GET_FS_AUX_NUM_IN_AU(gr_ctrl) ((gr_get_vg_au_size(gr_ctrl)) / GR_FS_AUX_SIZE)
#define GR_CTRL_RESV_SIZE \
    ((((((GR_DISK_UNIT_SIZE) - (24)) - (GR_FS_BLOCK_ROOT_SIZE)) - (GR_AU_ROOT_SIZE)) - (GR_FS_AUX_ROOT_SIZE)))

#pragma pack(8)
typedef struct st_gr_volume_def {
    uint64 id : 16;
    uint64 flag : 3;
    uint64 reserve : 45;
    uint64 version;
    char name[GR_MAX_VOLUME_PATH_LEN];
    char code[GR_VOLUME_CODE_SIZE];
    char resv[GR_VOLUME_DEF_RESVS];
} gr_volume_def_t;  // CAUTION:If add/remove field ,please keep 256B total !!! Or modify rp_redo_add_or_remove_volume

typedef enum en_volume_slot {
    VOLUME_FREE = 0,  // free
    VOLUME_OCCUPY = 1,
    VOLUME_PREPARE = 2,  // not registered
    VOLUME_ADD = 3,      // add
    VOLUME_REMOVE = 4,   // remove
    VOLUME_REPLACE = 5,  // replace
    VOLUME_FLAG_MAX,
} volume_slot_e;

typedef struct st_gr_volume_attr {
    uint64 reverse1 : 1;
    uint64 id : 16;
    uint64 reserve2 : 47;
    uint64 size;
    uint64 hwm;
    uint64 free;
} gr_volume_attr_t;  // CAUTION:If add/remove field ,please keep 32B total !!! Or modify rp_redo_add_or_remove_volume

typedef enum gr_vg_device_Type {
    GR_VOLUME_TYPE_RAW = 0  // default is raw device
} gr_vg_device_Type_e;

typedef struct st_gr_volume {
    char name[GR_MAX_VOLUME_PATH_LEN];
    char *name_p;
    gr_volume_attr_t *attr;
    uint32_t id;
    volume_handle_t handle;
    volume_handle_t unaligned_handle;
    gr_vg_device_Type_e vg_type;
} gr_volume_t;

typedef struct st_gr_volume_disk {
    gr_volume_def_t def;
    gr_volume_attr_t attr;
    uint32_t id;
} gr_volume_disk_t;

typedef struct st_gr_metablock_header_t {
    gr_addr_t free_block_begin;
    gr_addr_t free_block_end;
    gr_addr_t first_block;
} gr_metablock_header_t;

#define GR_VOLUME_TYPE_NORMAL 0x12345678
#define GR_VOLUME_TYPE_MANAGER 0x12345679
typedef struct st_gr_volume_type_t {
    uint32_t type;
    uint32_t id;
    char entry_volume_name[GR_MAX_VOLUME_PATH_LEN];
} gr_volume_type_t;

typedef enum st_gr_bak_level_e {
    GR_BAK_LEVEL_0 = 0,  // super block only backed up on first volume, fs and ft do not backup
    GR_BAK_LEVEL_1,  // super block backed up on some specific volumes, fs and ft backed up at the end of each volume
    GR_BAK_LEVEL_2,  // super block backed up on all volumes, fs and ft backed up at the end of each volume
} gr_bak_level_e;

#define GR_MAX_BAK_LEVEL GR_BAK_LEVEL_2

typedef enum en_gr_software_version {
    GR_SOFTWARE_VERSION_0 = 0, /* version 0 */
    GR_SOFTWARE_VERSION_1 = 1, /* version 1 */
    GR_SOFTWARE_VERSION_2 = 2, /* version 2 */
} gr_software_version_e;

#define GR_SOFTWARE_VERSION GR_SOFTWARE_VERSION_2

#define GR_CTRL_VALID_FLAG 0x5f3759df
typedef struct st_gr_disk_group_header_t {
    uint32_t checksum;
    gr_volume_type_t vol_type;
    char vg_name[GR_MAX_NAME_LEN];
    uint32_t valid_flag;
    uint32_t software_version;  // for upgrade
    timeval_t create_time;
    gr_bak_level_e bak_level;
    uint32_t ft_node_ratio;  // ft_node is created for every ft_node_ratio bytes of space
    uint64 bak_ft_offset;  // Start position of the backup ft_node array
} gr_vg_header_t;

typedef gr_vg_header_t gr_volume_header_t;

typedef struct st_gr_simple_handle_t {
    uint32_t id;
    volume_handle_t handle;
    volume_handle_t unaligned_handle;
    uint64 version;
    gr_vg_device_Type_e vg_type;
} gr_simple_volume_t;

typedef struct st_gr_core_ctrl {
    uint32_t checksum;  // NOTE:checksum can not change the position in the struct.gr_get_checksum need.
    uint32_t reserve;
    uint64 version;
    uint32_t au_size;  // allocation unit size,4M,8M,16M,32M,64M
    uint32_t volume_count;
    char fs_block_root[GR_FS_BLOCK_ROOT_SIZE];  // gr_fs_block_root_t
    char au_root[GR_AU_ROOT_SIZE];              // 512-24-64,gr_au_root_t, recycle space entry
    char fs_aux_root[GR_FS_AUX_ROOT_SIZE];      // gr_fs_aux_root_t
    char resv[GR_CTRL_RESV_SIZE];
    gr_volume_attr_t volume_attrs[GR_MAX_VOLUMES];
} gr_core_ctrl_t;

typedef struct st_gr_volume_ctrl {
    uint32_t checksum;  // NOTE:can not change the position in the struct.
    uint32_t rsvd;
    uint64 version;
    char reserve[496];
    gr_volume_def_t defs[GR_MAX_VOLUMES];
} gr_volume_ctrl_t;

// struct for volume refresh
typedef struct st_refvol_ctrl {  // UNUSED
    gr_core_ctrl_t core;
    gr_volume_ctrl_t volume;
} gr_refvol_ctrl_t;

typedef struct st_gr_group_global_ctrl {
    uint64 cluster_node_info;
} gr_group_global_ctrl_t;

#define GR_MAX_EXTENDED_COUNT 8
typedef struct st_gr_redo_ctrl {
    uint32_t checksum;
    uint32_t redo_index;
    uint64 version;
    uint64 offset;  // redo offset
    uint64 lsn;     // redo lsn
    auid_t redo_start_au[GR_MAX_EXTENDED_COUNT];
    uint32_t redo_size[GR_MAX_EXTENDED_COUNT];  // except redo_size > 32KB
    uint32_t count;
    char reserve[376];
} gr_redo_ctrl_t;

typedef struct st_gr_ctrl {
    union {
        gr_vg_header_t vg_info;
        char vg_data[GR_VG_DATA_SIZE];
    };
    union {
        gr_core_ctrl_t core;
        char core_data[GR_CORE_CTRL_SIZE];  // 16K
    };

    union {
        gr_volume_ctrl_t volume;
        char volume_data[GR_VOLUME_CTRL_SIZE];  // 256K
    };
    char root[GR_ROOT_FT_DISK_SIZE];  // gr_root_ft_block_t, 8KB
    union {
        gr_redo_ctrl_t redo_ctrl;
        char redo_ctrl_data[GR_DISK_UNIT_SIZE]; // 512
    };
    char reserve1[GR_CTRL_RESERVE_SIZE1];     // 663K
    char disk_latch[GR_INIT_DISK_LATCH_SIZE]; // INIT DISK LATCH 32KB
    union {
        struct {
            char disk_lock[GR_LOCK_SHARE_DISK_SIZE]; // share disk lock, 32KB + 512, align with 8K
            char reserve4[GR_CTRL_RESERVE_SIZE4];    // 512
        };
        struct {
            char reserve3[GR_CTRL_RESERVE_SIZE3];  // 32KB
            char lock[GR_DISK_LOCK_LEN];           // align with 16K
        };
    };
    char reserve2[GR_CTRL_RESERVE_SIZE2];
    union {
        gr_group_global_ctrl_t global_ctrl;
        char global_data[GR_DISK_UNIT_SIZE];  // client disk info, size is 512
    };
} gr_ctrl_t;

static inline void gr_set_software_version(gr_vg_header_t *vg_header, uint32_t version)
{
    CM_ASSERT(vg_header != NULL);
    vg_header->software_version = version;
}

static inline uint32_t gr_get_software_version(gr_vg_header_t *vg_header)
{
    CM_ASSERT(vg_header != NULL);
    return vg_header->software_version;
}

typedef enum en_gr_vg_status {
    GR_VG_STATUS_RECOVERY = 1,
    GR_VG_STATUS_ROLLBACK,
    GR_VG_STATUS_OPEN,
} gr_vg_status_e;

#define GR_UNDO_LOG_NUM (GR_LOG_BUFFER_SIZE / 8)

typedef enum en_latch_type {
    LATCH_VG_HEADER = 0,
    LATCH_CORE_CTRL,
    LATCH_VOLUME_CTRL,
    LATCH_FT_ROOT,
    LATCH_COUNT,  // must be last
} latch_type_t;

typedef struct st_gr_vg_cache_node_t {
    latch_t latch;
    uint64 fid;
    uint64 ftid;
    char *node;
} gr_vg_cache_node_t;

typedef enum en_gr_from_type {
    FROM_SHM = 0,
    FROM_BBOX,
    FROM_DISK,
} gr_from_type_e;

typedef struct st_gr_log_file_ctrl {
    spinlock_t lock;
    char *log_buf;  // global log_buf
    bool8 used;
    uint32_t index;
    uint64 offset;
    uint64 lsn;
} gr_log_file_ctrl_t;

typedef struct st_gr_vg_info_item_t {
    uint32_t id;
    char vg_name[GR_MAX_NAME_LEN];
    char entry_path[GR_MAX_VOLUME_PATH_LEN];  // the manager volume path
    gr_vg_status_e status;
    cm_oamap_t au_map;  // UNUSED
    gr_volume_t volume_handle[GR_MAX_VOLUMES];
    gr_shared_latch_t *vg_latch;
    gr_ctrl_t *gr_ctrl;
    shm_hashmap_t *buffer_cache;
    char *align_buf;
    gr_stack stack;
    latch_t open_file_latch;
    bilist_t open_file_list;  // open file bilist.
    latch_t disk_latch;       // just for lock vg to lock the local instance.
    latch_t latch[LATCH_COUNT];
    gr_from_type_e from_type;
    gr_block_ctrl_task_desc_t syn_meta_desc;
    gr_vg_cache_node_t vg_cache_node[GR_VG_ITEM_CACHE_NODE_MAX];
    gr_log_file_ctrl_t log_file_ctrl;             // redo log ctrl
    gr_block_ctrl_task_desc_t recycle_meta_desc;  // for recycle meta
    uint32_t objectid;
    uint32_t space_alarm;
} gr_vg_info_item_t;

typedef struct st_gr_vg_info_t {
    gr_vg_info_item_t volume_group[GR_MAX_VOLUME_GROUP_NUM];
    uint32_t group_num;
} gr_vg_info_t;

typedef struct st_gr_vol_handles_t {
    gr_simple_volume_t volume_handle[GR_MAX_VOLUMES];
} gr_vol_handles_t;

typedef struct st_gr_cli_vg_handles_t {
    gr_vol_handles_t vg_vols[GR_MAX_VOLUME_GROUP_NUM];
    uint32_t group_num;
} gr_cli_vg_handles_t;

typedef struct st_gr_vg_conf_t {
    char vg_name[GR_MAX_NAME_LEN];
    char entry_path[GR_MAX_VOLUME_PATH_LEN];  // the manager volume path
} gr_vg_conf_t;

typedef struct st_gr_share_vg_item_t {
    gr_shared_latch_t vg_latch;
    shm_hashmap_t buffer_cache;
    uint32_t objectid;
    uint32_t id;
    char reserve[412];  // align 512
    gr_ctrl_t gr_ctrl;
} gr_share_vg_item_t;

#pragma pack()
#endif  // __GR_CTRL_DEF_H__
