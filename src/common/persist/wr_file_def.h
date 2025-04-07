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
 * wr_file_def.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_file_def.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_FILE_DEF_H__
#define __WR_FILE_DEF_H__

#include "wr_ctrl_def.h"
#include "wr_session.h"
// gft_node_t flag
#define WR_FT_NODE_FLAG_SYSTEM 0x00000001
#define WR_FT_NODE_FLAG_DEL 0x00000002
#define WR_FT_NODE_FLAG_NORMAL 0x00000004
#define WR_FT_NODE_FLAG_INVALID_FS_META 0x00000008
#define WR_FT_NODE_FLAG_INNER_INITED 0x80000000

#define WR_IS_FILE_INNER_INITED(flag) ((uint64)(flag)&WR_FT_NODE_FLAG_INNER_INITED)

#define WR_GFT_PATH_STR "PATH"
#define WR_GFT_FILE_STR "FILE"
#define WR_GFT_INVALID_STR "INVALID_TYPE"

#ifdef WR_TEST
#define WR_INSTANCE_OPEN_FLAG (O_RDWR | O_SYNC)
#define WR_CLI_OPEN_FLAG (O_RDWR | O_SYNC)
#else
#define WR_INSTANCE_OPEN_FLAG (O_RDWR | O_SYNC | O_DIRECT)
#define WR_CLI_OPEN_FLAG (O_RDWR | O_SYNC | O_DIRECT)
#define WR_NOD_OPEN_FLAG (O_RDWR | O_SYNC)
#endif

#define WR_BLOCK_ID_INIT (uint64)0xFFFFFFFFFFFFFFFE
#define WR_GET_COMMON_BLOCK_HEAD(au) ((wr_common_block_t *)((char *)(au)))
#define WR_GET_FS_BLOCK_FROM_AU(au, block_id) \
    ((wr_fs_block_t *)((char *)(au) + WR_FILE_SPACE_BLOCK_SIZE * (block_id)))
#define WR_GET_FT_BLOCK_FROM_AU(au, block_id) ((wr_ft_block_t *)((char *)(au) + WR_BLOCK_SIZE * (block_id)))
#define WR_GET_FT_BLOCK_NUM_IN_AU(wr_ctrl) ((wr_get_vg_au_size(wr_ctrl)) / WR_BLOCK_SIZE)
#define WR_GET_FS_BLOCK_NUM_IN_AU(wr_ctrl) ((wr_get_vg_au_size(wr_ctrl)) / WR_FILE_SPACE_BLOCK_SIZE)
#define WR_FILE_SPACE_BLOCK_BITMAP_COUNT (WR_FILE_SPACE_BLOCK_SIZE - sizeof(wr_fs_block_header)) / sizeof(auid_t)
#define WR_ENTRY_FS_INDEX 0xFFFD
#define WR_FS_INDEX_INIT 0xFFFE
#define WR_FILE_CONTEXT_FLAG_USED 1
#define WR_FILE_CONTEXT_FLAG_FREE 0

#pragma pack(8)

// GFT mean WR File Table
typedef enum en_zft_item_type {
    GFT_PATH,  // path
    GFT_FILE,
} gft_item_type_t;

typedef struct st_zft_list {
    uint32 count;
    ftid_t first;
    ftid_t last;
} gft_list_t;

// used for ft node parent and fs block ftid init,
typedef union st_gft_node {
    struct {
        gft_item_type_t type;
        time_t create_time;
        time_t update_time;
        uint32 software_version;
        uint32 flags;
        atomic_t size;  // Actually uint64, use atomic_get for client read and atomic_set for server modify.
        union {
            wr_block_id_t entry;  // for file and link
            gft_list_t items;      // for dir
        };
        ftid_t id;
        ftid_t next;
        ftid_t prev;
        char name[WR_MAX_NAME_LEN];
        uint64 fid;
        uint64 written_size;
        ftid_t parent;
        uint64 file_ver;  // the current ver of the file, when create, it's zero, when truncate the content of the file
                          // to small size, update it by in old file_ver with step 1
        uint64 min_inited_size;  // before this ,must has written data
    };
    char ft_node[256];  // to ensure that the structure size is 256
} gft_node_t;

typedef struct st_gft_block_info {
    gft_node_t *ft_node;
} gft_block_info_t;

typedef struct st_wr_check_dir_param_t {
    wr_vg_info_item_t *vg_item;
    gft_node_t *p_node;
    gft_node_t *last_node;
    gft_node_t *link_node;
    bool8 is_skip_delay_file;
    bool8 not_exist_err;
    bool8 is_find_link;
    bool8 last_is_link;
} wr_check_dir_param_t;

typedef struct st_wr_check_dir_output_t {
    gft_node_t **out_node;
    wr_vg_info_item_t **item;
    gft_node_t **parent_node;
    bool8 is_lock_x;
} wr_check_dir_output_t;

typedef enum en_wr_block_flag {
    WR_BLOCK_FLAG_RESERVE,
    WR_BLOCK_FLAG_FREE,
    WR_BLOCK_FLAG_USED,
    WR_BLOCK_FLAG_MAX,
} wr_block_flag_e;

typedef struct st_wr_common_block_t {
    uint32_t checksum;
    uint32_t type;
    uint64 version;
    wr_block_id_t id;
    uint8_t flags;
    uint8_t reserve[7];
} wr_common_block_t;

typedef union st_wr_ft_block {
    struct {
        wr_common_block_t common;
        uint32_t node_num;
        uint32_t reserve;
        wr_block_id_t next;
    };
    char ft_block[256];  // to ensure that the structure size is 256
} wr_ft_block_t;

typedef struct st_wr_fs_block_list_t {
    uint64 count;
    wr_block_id_t first;
    wr_block_id_t last;
} wr_fs_block_list_t;

typedef struct st_wr_fs_root_t {
    uint64 version;
    wr_fs_block_list_t free;
} wr_fs_block_root_t;

typedef struct st_wr_block_header {
    wr_common_block_t common;
    wr_block_id_t next;
    wr_block_id_t ftid;
    uint16_t used_num;
    uint16_t total_num;
    uint16_t index;
    uint16_t reserve;
} wr_fs_block_header;

// file space block
typedef struct st_wr_fs_block_t {
    wr_fs_block_header head;
    wr_block_id_t bitmap[0];
} wr_fs_block_t;

#define WR_FS_BLOCK_ITEM_NUM ((WR_FILE_SPACE_BLOCK_SIZE - sizeof(wr_fs_block_header)) / sizeof(auid_t))
typedef struct st_gft_root_t {
    gft_list_t free_list;  // free file table node list
    gft_list_t items;      // not used for now
    uint64 fid;            // the current max file id in the system;
    wr_block_id_t first;  // the first allocated block.
    wr_block_id_t last;
} gft_root_t;

typedef struct st_wr_root_ft_header {
    wr_common_block_t common;
    uint32_t node_num;
    uint32_t reserve;
    wr_block_id_t next;
    char reserver2[8];
} wr_root_ft_header_t;

typedef union st_wr_root_ft_block {
    struct {
        wr_root_ft_header_t ft_block;
        gft_root_t ft_root;
    };
    char root_ft_block[256];  // to ensure that the structure size is 256
} wr_root_ft_block_t;

#pragma pack()

typedef enum en_wr_file_mode {
    WR_FILE_MODE_READ = 0x00000001,
    WR_FILE_MODE_WRITE = 0x00000002,
    WR_FILE_MODE_RDWR = WR_FILE_MODE_READ | WR_FILE_MODE_WRITE,
} wr_file_mode_e;

typedef struct st_wr_file_context {
    latch_t latch;
    gft_node_t *node;
    uint32 next;
    uint32 flag : 2;  // WR_FILE_CONTEXT_FLAG_USED,WR_FILE_CONTEXT_FLAG_FREE
    uint32 tid : 22;  // 64-bit OS: pid_max [0, 2^22]
    uint32 reserve : 8;
    int64 offset;
    int64 vol_offset;
    wr_vg_info_item_t *vg_item;
    uint64 fid;
    char file_path[WR_MAX_NAME_LEN];
    uint32 vgid;
    uint32 id;
    wr_file_mode_e mode;
} wr_file_context_t;

typedef struct st_wr_file_context_group_t {
    wr_file_context_t *files_group[WR_MAX_FILE_CONTEXT_GROUP_NUM];
    uint32_t group_num;
} wr_file_context_group_t;

typedef struct st_wr_ft_au_list_t {
    void *au_addr[WR_MAX_FT_AU_NUM];
    uint32_t count;
} wr_ft_au_list_t;

typedef struct st_wr_file_run_ctx {
    uint32 max_open_file;
    uint32 has_opened_files;
    uint32 file_free_first;  // the first free file context.
    wr_file_context_group_t files;
} wr_file_run_ctx_t;

typedef struct st_wr_env {
    latch_t latch;
    bool32 initialized;
    uint32 instance_id;
    latch_t conn_latch;
    uint32 conn_count;
    thread_t thread_heartbeat;
    wr_config_t inst_cfg;
#ifdef ENABLE_WRTEST
    pid_t inittor_pid;
#endif
    wr_file_run_ctx_t file_run_ctx;
} wr_env_t;

typedef struct st_wr_dir_t {
    wr_vg_info_item_t *vg_item;
    uint64 version;
    ftid_t cur_ftid;
    gft_node_t cur_node;
    ftid_t pftid;  // path ftid
} wr_vfs_t;

typedef struct st_wr_find_node_t {
    ftid_t ftid;
    char vg_name[WR_MAX_NAME_LEN];
} wr_find_node_t;

#endif  // __WR_FILE_DEF_H__
