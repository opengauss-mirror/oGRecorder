#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "wr_api.h"

#define MAX_STR_LEN 128
#define MAX_FILE_NAME_LEN 64
#define MAX_BUF_LEN 1024

static wr_instance_handle g_inst = NULL;
static wr_vfs_handle g_vfs = {0};
static int g_inited = 0;

// 初始化和清理
__attribute__((constructor))
static void fuzz_init() {
    if (!g_inited) {
        wr_create_inst("127.0.0.1:19225", &g_inst);
        wr_vfs_create(g_inst, "fuzzdir", 0);
        wr_vfs_mount(g_inst, "fuzzdir", &g_vfs);
        g_inited = 1;
    }
}
__attribute__((destructor))
static void fuzz_cleanup() {
    if (g_inited) {
        wr_vfs_unmount(&g_vfs);
        wr_delete_inst(g_inst);
        g_inst = NULL;
        g_inited = 0;
    }
}

// 辅助函数：安全字符串生成
static void make_safe_str(char *dst, const uint8_t *data, size_t size, size_t maxlen) {
    size_t len = size > maxlen - 1 ? maxlen - 1 : size;
    memcpy(dst, data, len);
    dst[len] = '\0';
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || g_inst == NULL) return 0;

    // 用前几个字节决定调用哪个API
    uint8_t api_id = data[0] % 10;
    size_t offset = 1;

    char str1[MAX_STR_LEN] = {0};
    char str2[MAX_STR_LEN] = {0};
    char buf[MAX_BUF_LEN] = {0};
    make_safe_str(str1, data + offset, size - offset, MAX_STR_LEN);
    offset += MAX_STR_LEN / 2;
    if (offset < size) {
        make_safe_str(str2, data + offset, size - offset, MAX_STR_LEN);
        offset += MAX_STR_LEN / 2;
    }

    // 文件名
    char file_name[MAX_FILE_NAME_LEN] = {0};
    if (offset < size) {
        make_safe_str(file_name, data + offset, size - offset, MAX_FILE_NAME_LEN);
        offset += MAX_FILE_NAME_LEN / 2;
    }

    // 选择API进行fuzz
    switch (api_id) {
        case 0:
            wr_set_conf(g_inst, str1, str2);
            break;
        case 1:
            wr_get_conf(g_inst, str1, buf);
            break;
        case 2:
            wr_vfs_create(g_inst, str1, 0);
            break;
        case 3:
            wr_vfs_mount(g_inst, str1, &g_vfs);
            break;
        case 4:
            wr_file_create(g_vfs, file_name, NULL);
            break;
        case 5: {
            wr_file_handle fh;
            wr_file_open(g_vfs, file_name, 0, &fh);
            wr_file_close(g_vfs, &fh, 0);
            break;
        }
        case 6: {
            wr_file_handle fh;
            wr_file_open(g_vfs, file_name, 0, &fh);
            wr_file_pwrite(g_vfs, &fh, buf, (offset < size ? data[offset] : 10), 0);
            wr_file_close(g_vfs, &fh, 0);
            break;
        }
        case 7: {
            wr_file_handle fh;
            wr_file_open(g_vfs, file_name, 0, &fh);
            wr_file_pread(g_vfs, fh, buf, (offset < size ? data[offset] : 10), 0);
            wr_file_close(g_vfs, &fh, 0);
            break;
        }
        case 8:
            wr_file_delete(g_vfs, file_name);
            break;
        case 9: {
            int file_num = 0;
            wr_vfs_query_file_num(g_vfs, &file_num);
            break;
        }
        default:
            break;
    }
    return 0;
}