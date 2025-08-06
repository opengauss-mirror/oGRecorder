/* gcc test1.c -I GR/src/interface -lgrapi -L GR/output/lib */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gr_api.h"
#include "gr_errno.h"

#define TEST_LOG_DIR "./test_log"
#define TEST_DIR "testdir1"
#define TEST_FILE1 "testdir1/testfile1"
#define ONE_GB 1024 * 1024 * 1024
#define SERVER_ADDR "127.0.0.1:18440"

int main() {
    int errorcode = 0;
    const char *errormsg = NULL;
    gr_instance_handle g_inst_handle = NULL;
    int handle1 = 0;

    // 初始化日志
    if (gr_init_logger(TEST_LOG_DIR, 255, 100, ONE_GB) != GR_SUCCESS) {
        fprintf(stderr, "Failed to initialize logger\n");
        return EXIT_FAILURE;
    }

    // 创建实例
    if (gr_create_inst(SERVER_ADDR, &g_inst_handle) != GR_SUCCESS) {
        gr_get_error(&errorcode, &errormsg);
        fprintf(stderr, "Error creating instance: %d : %s\n", errorcode, errormsg);
        return EXIT_FAILURE;
    }

    // 创建VFS
    if (gr_vfs_create(TEST_DIR, g_inst_handle) != GR_SUCCESS) {
        gr_get_error(&errorcode, &errormsg);
        fprintf(stderr, "Error creating VFS: %d : %s\n", errorcode, errormsg);
        return EXIT_FAILURE;
    }

    // 创建文件
    if (gr_file_create(TEST_FILE1, 0, g_inst_handle) != GR_SUCCESS) {
        gr_get_error(&errorcode, &errormsg);
        fprintf(stderr, "Error creating file: %d : %s\n", errorcode, errormsg);
        return EXIT_FAILURE;
    }

    // 打开文件
    if (gr_file_open(TEST_FILE1, 0, &handle1, g_inst_handle) != GR_SUCCESS) {
        gr_get_error(&errorcode, &errormsg);
        fprintf(stderr, "Error opening file: %d : %s\n", errorcode, errormsg);
        return EXIT_FAILURE;
    }

    // 创建一个大于8KB的数据块
    const int large_data_size = 10 * 1024; // 10KB
    char *large_data = (char *)malloc(large_data_size);
    if (!large_data) {
        fprintf(stderr, "Memory allocation failed\n");
        return EXIT_FAILURE;
    }
    memset(large_data, 'A', large_data_size);

    // 写入大数据块到文件
    if (gr_file_pwrite(handle1, large_data, large_data_size, 0, g_inst_handle) != GR_SUCCESS) {
        gr_get_error(&errorcode, &errormsg);
        fprintf(stderr, "Error writing to file: %d : %s\n", errorcode, errormsg);
        free(large_data);
        return EXIT_FAILURE;
    }

    // 读取大数据块
    char *read_buffer = (char *)malloc(large_data_size);
    if (!read_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        free(large_data);
        return EXIT_FAILURE;
    }
    if (gr_file_pread(handle1, read_buffer, large_data_size, 0, g_inst_handle) != GR_SUCCESS) {
        gr_get_error(&errorcode, &errormsg);
        fprintf(stderr, "Error reading from file: %d : %s\n", errorcode, errormsg);
        free(large_data);
        free(read_buffer);
        return EXIT_FAILURE;
    }

    // 验证读取的数据是否与写入的数据一致
    if (memcmp(large_data, read_buffer, large_data_size) != 0) {
        fprintf(stderr, "Data mismatch\n");
        free(large_data);
        free(read_buffer);
        return EXIT_FAILURE;
    }

    printf("Large data write and read test passed.\n");

    // 清理动态分配的内存
    free(large_data);
    free(read_buffer);

    // 关闭文件
    if (gr_file_close(handle1, g_inst_handle, true) != GR_SUCCESS) {
        gr_get_error(&errorcode, &errormsg);
        fprintf(stderr, "Error closing file: %d : %s\n", errorcode, errormsg);
        return EXIT_FAILURE;
    }

    // 删除文件
    if (gr_file_delete(TEST_FILE1, g_inst_handle) != GR_SUCCESS) {
        gr_get_error(&errorcode, &errormsg);
        fprintf(stderr, "Error deleting file: %d : %s\n", errorcode, errormsg);
        return EXIT_FAILURE;
    }

    // 删除VFS
    if (gr_vfs_delete(TEST_DIR, g_inst_handle) != GR_SUCCESS) {
        gr_get_error(&errorcode, &errormsg);
        fprintf(stderr, "Error deleting VFS: %d : %s\n", errorcode, errormsg);
        return EXIT_FAILURE;
    }

    printf("All operations completed successfully.\n");
    return EXIT_SUCCESS;
}