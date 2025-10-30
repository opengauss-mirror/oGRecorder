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
 * gr_file_def.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/gr_file_def.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_FILE_DEF_H__
#define __GR_FILE_DEF_H__

#include "gr_ctrl_def.h"
#include "gr_session.h"
// gft_node_t flag
#define GR_FT_NODE_FLAG_SYSTEM 0x00000001
#define GR_FT_NODE_FLAG_DEL 0x00000002
#define GR_FT_NODE_FLAG_NORMAL 0x00000004
#define GR_FT_NODE_FLAG_INVALID_FS_META 0x00000008
#define GR_FT_NODE_FLAG_INNER_INITED 0x80000000

#define GR_IS_FILE_INNER_INITED(flag) ((uint64)(flag)&GR_FT_NODE_FLAG_INNER_INITED)

#define GR_GFT_PATH_STR "PATH"
#define GR_GFT_FILE_STR "FILE"
#define GR_GFT_INVALID_STR "INVALID_TYPE"

#ifdef GR_TEST
#define GR_INSTANCE_OPEN_FLAG (O_RDWR | O_SYNC)
#define GR_CLI_OPEN_FLAG (O_RDWR | O_SYNC)
#else
#define GR_INSTANCE_OPEN_FLAG (O_RDWR | O_SYNC | O_DIRECT)
#define GR_CLI_OPEN_FLAG (O_RDWR | O_SYNC | O_DIRECT)
#define GR_NOD_OPEN_FLAG (O_RDWR | O_SYNC)
#endif

#define GR_BLOCK_ID_INIT (uint64)0xFFFFFFFFFFFFFFFE
#define GR_GET_COMMON_BLOCK_HEAD(au) ((gr_common_block_t *)((char *)(au)))
#define GR_GET_FS_BLOCK_FROM_AU(au, block_id) \
    ((gr_fs_block_t *)((char *)(au) + GR_FILE_SPACE_BLOCK_SIZE * (block_id)))
#define GR_GET_FT_BLOCK_FROM_AU(au, block_id) ((gr_ft_block_t *)((char *)(au) + GR_BLOCK_SIZE * (block_id)))
#define GR_GET_FT_BLOCK_NUM_IN_AU(gr_ctrl) ((gr_get_vg_au_size(gr_ctrl)) / GR_BLOCK_SIZE)
#define GR_GET_FS_BLOCK_NUM_IN_AU(gr_ctrl) ((gr_get_vg_au_size(gr_ctrl)) / GR_FILE_SPACE_BLOCK_SIZE)
#define GR_FILE_SPACE_BLOCK_BITMAP_COUNT (GR_FILE_SPACE_BLOCK_SIZE - sizeof(gr_fs_block_header)) / sizeof(auid_t)
#define GR_ENTRY_FS_INDEX 0xFFFD
#define GR_FS_INDEX_INIT 0xFFFE
#define GR_FILE_CONTEXT_FLAG_USED 1
#define GR_FILE_CONTEXT_FLAG_FREE 0

#pragma pack(8)

// GFT mean GR File Table
typedef enum en_zft_item_type {
    GFT_PATH,  // path
    GFT_FILE,
    GFT_LINK,
} gft_item_type_t;

typedef struct st_zft_list {
    uint32_t count;
    ftid_t first;
    ftid_t last;
} gft_list_t;

// used for ft node parent and fs block ftid init,
typedef union st_gft_node {
    struct {
        gft_item_type_t type;
        time_t create_time;
        time_t update_time;
        uint32_t software_version;
        uint32_t flags;
        atomic_t size;  // Actually uint64, use atomic_get for client read and atomic_set for server modify.
        union {
            gr_block_id_t entry;  // for file and link
            gft_list_t items;      // for dir
        };
        ftid_t id;
        ftid_t next;
        ftid_t prev;
        char name[GR_MAX_NAME_LEN];
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

typedef struct st_gr_check_dir_param_t {
    gft_node_t *p_node;
    gft_node_t *last_node;
    gft_node_t *link_node;
    bool8 is_skip_delay_file;
    bool8 not_exist_err;
    bool8 is_find_link;
    bool8 last_is_link;
} gr_check_dir_param_t;

typedef struct st_gr_check_dir_output_t {
    gft_node_t **out_node;
    gft_node_t **parent_node;
    bool8 is_lock_x;
} gr_check_dir_output_t;

typedef enum en_gr_block_flag {
    GR_BLOCK_FLAG_RESERVE,
    GR_BLOCK_FLAG_FREE,
    GR_BLOCK_FLAG_USED,
    GR_BLOCK_FLAG_MAX,
} gr_block_flag_e;

typedef struct st_gr_common_block_t {
    uint32_t checksum;
    uint32_t type;
    uint64 version;
    gr_block_id_t id;
    uint8_t flags;
    uint8_t reserve[7];
} gr_common_block_t;

typedef union st_gr_ft_block {
    struct {
        gr_common_block_t common;
        uint32_t node_num;
        uint32_t reserve;
        gr_block_id_t next;
    };
    char ft_block[256];  // to ensure that the structure size is 256
} gr_ft_block_t;

typedef struct st_gr_fs_block_list_t {
    uint64 count;
    gr_block_id_t first;
    gr_block_id_t last;
} gr_fs_block_list_t;

typedef struct st_gr_fs_root_t {
    uint64 version;
    gr_fs_block_list_t free;
} gr_fs_block_root_t;

typedef struct st_gr_block_header {
    gr_common_block_t common;
    gr_block_id_t next;
    gr_block_id_t ftid;
    uint16_t used_num;
    uint16_t total_num;
    uint16_t index;
    uint16_t reserve;
} gr_fs_block_header;

// file space block
typedef struct st_gr_fs_block_t {
    gr_fs_block_header head;
    gr_block_id_t bitmap[0];
} gr_fs_block_t;

#define GR_FS_BLOCK_ITEM_NUM ((GR_FILE_SPACE_BLOCK_SIZE - sizeof(gr_fs_block_header)) / sizeof(auid_t))
typedef struct st_gft_root_t {
    gft_list_t free_list;  // free file table node list
    gft_list_t items;      // not used for now
    uint64 fid;            // the current max file id in the system;
    gr_block_id_t first;  // the first allocated block.
    gr_block_id_t last;
} gft_root_t;

typedef struct st_gr_root_ft_header {
    gr_common_block_t common;
    uint32_t node_num;
    uint32_t reserve;
    gr_block_id_t next;
    char reserver2[8];
} gr_root_ft_header_t;

typedef union st_gr_root_ft_block {
    struct {
        gr_root_ft_header_t ft_block;
        gft_root_t ft_root;
    };
    char root_ft_block[256];  // to ensure that the structure size is 256
} gr_root_ft_block_t;

#pragma pack()

typedef enum en_gr_file_mode {
    GR_FILE_MODE_READ = 0x00000001,
    GR_FILE_MODE_WRITE = 0x00000002,
    GR_FILE_MODE_RDWR = GR_FILE_MODE_READ | GR_FILE_MODE_WRITE,
} gr_file_mode_e;
typedef struct st_gr_ft_au_list_t {
    void *au_addr[GR_MAX_FT_AU_NUM];
    uint32_t count;
} gr_ft_au_list_t;

typedef struct st_gr_env {
    latch_t latch;
    bool32 initialized;
    uint32_t instance_id;
    latch_t conn_latch;
    uint32_t conn_count;
    thread_t thread_heartbeat;
    gr_config_t inst_cfg;
#ifdef ENABLE_GRTEST
    pid_t inittor_pid;
#endif
} gr_env_t;

typedef struct st_gr_dir_t {
    uint64 version;
    ftid_t cur_ftid;
    gft_node_t cur_node;
    ftid_t pftid;  // path ftid
} gr_vfs_t;

typedef struct st_gr_find_node_t {
    ftid_t ftid;
    char vg_name[GR_MAX_NAME_LEN];
} gr_find_node_t;

typedef enum en_gr_file_status {
    GR_FILE_INIT,
    GR_FILE_LOCK,
    GR_FILE_APPEND,
    GR_FILE_EXPIRED
} gr_file_status_t;

#endif  // __GR_FILE_DEF_H__
