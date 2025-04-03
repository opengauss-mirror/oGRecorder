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
 * wr_defs_print.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/wr_defs_print.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_log.h"
#include "wr_malloc.h"
#include "wr_defs_print.h"

uint8 g_print_level = 0;

void printf_auid(const auid_t *first)
{
    char *tab = wr_get_print_tab(g_print_level);
    (void)printf("%s    auid = %llu\n", tab, *(uint64 *)first);
    (void)printf("%s      volume = %llu\n", tab, (uint64)first->volume);
    (void)printf("%s      au = %llu\n", tab, (long long unsigned int)(first->au));
    (void)printf("%s      block = %llu\n", tab, (uint64)first->block);
    (void)printf("%s      item = %llu\n", tab, (uint64)first->item);
}

void printf_wr_fs_block_list(wr_fs_block_list_t *free)
{
    return;
}

void printf_wr_fs_aux_root(wr_fs_aux_root_t *root)
{
    (void)printf("    version = %llu\n", root->version);

    wr_fs_block_list_t *free = &root->free;
    (void)printf("    free = {\n");
    printf_wr_fs_block_list(free);
    (void)printf("    }\n");
}

void printf_wr_fs_block_root(wr_fs_block_root_t *root)
{
    return;
}

void printf_wr_volume_attr(const wr_volume_attr_t *volume_attrs)
{
    (void)printf("    id = %llu\n", (uint64)volume_attrs->id);
    (void)printf("    size = %llu\n", volume_attrs->size);
    (void)printf("    hwm = %llu\n", volume_attrs->hwm);
    (void)printf("    free = %llu\n", volume_attrs->free);
}

static void printf_wr_au_list(wr_au_list_t *free_list)
{
    (void)printf("      count = %u\n", free_list->count);
    (void)printf("      frist = {\n");
    printf_auid(&free_list->first);
    (void)printf("      }\n");
    (void)printf("      last = {\n");
    printf_auid(&free_list->last);
    (void)printf("      }\n");
}

void printf_wr_au_root(wr_au_root_t *au_root)
{
    (void)printf("    version = %llu\n", au_root->version);
    (void)printf("    free_root = %llu\n", au_root->free_root);
    (void)printf("    count = %llu\n", au_root->count);
    (void)printf("    free_vol_id = %u\n", au_root->free_vol_id);
    (void)printf("    reserve = %u\n", au_root->reserve);

    wr_au_list_t *free_list = &au_root->free_list;
    (void)printf("    free_list = {\n");
    printf_wr_au_list(free_list);
    (void)printf("    }\n");
}

void wr_printf_core_ctrl_base(wr_core_ctrl_t *core_ctrl)
{
    return;
}

void printf_gft_list(gft_list_t *items)
{
    (void)printf("      count = %u\n", items->count);
    (void)printf("      first = {\n");

    ftid_t *first = &items->first;
    printf_auid(first);
    (void)printf("      }\n");
    (void)printf("      last = {\n");

    ftid_t *last = &items->last;
    printf_auid(last);
    (void)printf("      }\n");
}

void printf_gft_root(gft_root_t *ft_root)
{
    (void)printf("    free_list = {\n");

    gft_list_t *free_list = &ft_root->free_list;
    printf_gft_list(free_list);
    (void)printf("    }\n");
    (void)printf("    items = {\n");

    gft_list_t *items = &ft_root->items;
    printf_gft_list(items);
    (void)printf("    }\n");
    (void)printf("    fid = %llu\n", ft_root->fid);
    (void)printf("    first = {\n");

    wr_block_id_t *block_id_first = &ft_root->first;
    printf_auid(block_id_first);
    (void)printf("    }\n");
    (void)printf("    last = {\n");

    wr_block_id_t *block_id_last = &ft_root->last;
    printf_auid(block_id_last);
    (void)printf("    }\n");
}

void printf_gft_node(gft_node_t *gft_node, const char *tab)
{
    if (gft_node->type == GFT_PATH) {
        (void)printf("%s  type = GFT_PATH\n", tab);
        gft_list_t *items = &gft_node->items;
        (void)printf("%s  items = {\n", tab);
        printf_gft_list(items);
        (void)printf("%s  }\n", tab);
    } else if (gft_node->type == GFT_FILE) {
        (void)printf("%s  type = GFT_FILE\n", tab);
        wr_block_id_t *entry = &gft_node->entry;
        (void)printf("%s  entry = {\n", tab);
        printf_auid(entry);
        (void)printf("%s  }\n", tab);
    }
    (void)printf("%s  software_version = %u\n", tab, gft_node->software_version);
    (void)printf("%s  name = %s\n", tab, gft_node->name);
    (void)printf("%s  fid = %llu\n", tab, gft_node->fid);
    (void)printf("%s  flags = %u\n", tab, gft_node->flags);
    (void)printf("%s  size = %lld\n", tab, gft_node->size);
    (void)printf("%s  written_size = %llu\n", tab, gft_node->written_size);
    (void)printf("%s  parent = {\n", tab);
    printf_auid(&gft_node->parent);
    (void)printf("%s  }\n", tab);
    (void)printf("%s  file_ver = %llu\n", tab, gft_node->file_ver);
    (void)printf("%s  min_inited_size = %llu\n", tab, gft_node->min_inited_size);
    char time[512];
    (void)cm_time2str(gft_node->create_time, "YYYY-MM-DD HH24:mi:ss", time, sizeof(time));
    (void)printf("%s  create_time = %s\n", tab, time);
    (void)cm_time2str(gft_node->update_time, "YYYY-MM-DD HH24:mi:ss", time, sizeof(time));
    (void)printf("%s  update_time = %s\n", tab, time);

    auid_t *id = &gft_node->id;
    (void)printf("%s  id = {\n", tab);
    printf_auid(id);
    (void)printf("%s  }\n", tab);

    auid_t *next = &gft_node->next;
    (void)printf("%s  next= {\n", tab);
    printf_auid(next);
    (void)printf("%s  }\n", tab);

    auid_t *prev = &gft_node->prev;
    (void)printf("%s  prev = {\n", tab);
    printf_auid(prev);
    (void)printf("%s  }\n", tab);
}
