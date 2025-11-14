/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * GR is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You can may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * test_buffer_tamper.c
 *
 * Test program for buffer tampering scenarios in pwrite operations
 *
 * IDENTIFICATION
 *    test/test_buffer_tamper.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "gr_api.h"
#include "gr_errno.h"

#define SERVER_ADDR "20.20.20.193:19228"
#define TEST_DIR "buffer_tamper_test"
#define TEST_FILE "tamper_test_file"
#define BUFFER_SIZE (1024 * 1024)  // 1MB buffer
#define NUM_WRITES 10
 
// Global buffer
static char *g_write_buffer = NULL;

// Initialize GR logging system
static int init_gr_logging(void)
{
    gr_param_t gr_param;
    
    strcpy(gr_param.log_home, "./testlog");
    gr_param.log_level = 255;
    gr_param.log_backup_file_count = 10;
    gr_param.log_max_file_size = 100 * 1024 * 1024;
    
    int result = gr_init(gr_param);
    if (result != GR_SUCCESS) {
        printf("Error: Failed to initialize GR logging, error code: %d\n", result);
        return -1;
    }
    
    printf("GR logging system initialized successfully\n");
    return 0;
}
 
 // Test buffer tampering during pwrite operations
static int test_buffer_tamper(void)
{
    int result;
    gr_instance_handle inst_handle;
    gr_vfs_handle vfs_handle;
    gr_file_handle file_handle;
    
    printf("=== Buffer Tamper Test Started ===\n");
    
    // 1. Create instance
    printf("1. Creating instance...\n");
    result = gr_create_inst(SERVER_ADDR, &inst_handle);
    if (result != GR_SUCCESS) {
        printf("Error: Failed to create instance, error code: %d\n", result);
        return -1;
    }
    printf("   Instance created successfully\n");
    
    // 2. Create VFS
    printf("2. Creating VFS...\n");
    result = gr_vfs_create(inst_handle, TEST_DIR, 0);
    if (result != GR_SUCCESS) {
        printf("Error: Failed to create VFS, error code: %d\n", result);
        gr_delete_inst(inst_handle);
        return -1;
    }
    printf("   VFS created successfully\n");
    
    // 3. Mount VFS
    printf("3. Mounting VFS...\n");
    result = gr_vfs_mount(inst_handle, TEST_DIR, &vfs_handle);
    if (result != GR_SUCCESS) {
        printf("Error: Failed to mount VFS, error code: %d\n", result);
        gr_vfs_delete(inst_handle, TEST_DIR, 1);
        gr_delete_inst(inst_handle);
        return -1;
    }
    printf("   VFS mounted successfully\n");
    
    // 4. Create file
    printf("4. Creating file...\n");
    result = gr_file_create(vfs_handle, TEST_FILE, NULL);
    if (result != GR_SUCCESS) {
        printf("Error: Failed to create file, error code: %d\n", result);
        gr_vfs_unmount(&vfs_handle);
        gr_vfs_delete(inst_handle, TEST_DIR, 1);
        gr_delete_inst(inst_handle);
        return -1;
    }
    printf("   File created successfully\n");
    
    // 5. Open file
    printf("5. Opening file...\n");
    result = gr_file_open(vfs_handle, TEST_FILE, O_RDWR | O_SYNC, &file_handle);
    if (result != GR_SUCCESS) {
        printf("Error: Failed to open file, error code: %d\n", result);
        gr_vfs_unmount(&vfs_handle);
        gr_vfs_delete(inst_handle, TEST_DIR, 1);
        gr_delete_inst(inst_handle);
        return -1;
    }
    printf("   File opened successfully\n");
    
    // 6. Allocate and initialize write buffer
    printf("6. Preparing write buffer...\n");
    g_write_buffer = (char*)malloc(BUFFER_SIZE);
    if (g_write_buffer == NULL) {
        printf("Error: Memory allocation failed\n");
        gr_file_close(vfs_handle, &file_handle, false);
        gr_vfs_unmount(&vfs_handle);
        gr_vfs_delete(inst_handle, TEST_DIR, 1);
        gr_delete_inst(inst_handle);
        return -1;
    }
    
    // Initialize buffer with test pattern
    memset(g_write_buffer, 0xCC, BUFFER_SIZE);
    printf("   Write buffer allocated and initialized (%d bytes)\n", BUFFER_SIZE);
     
    // 7. Perform multiple pwrite operations with in-place buffer mutations (single-threaded)
    printf("7. Performing pwrite operations with in-place buffer mutations (single-threaded)...\n");
    printf("   Number of writes: %d\n", NUM_WRITES);
    printf("   Buffer size per write: %d bytes\n", BUFFER_SIZE);
    
    int success_count = 0;
    int failure_count = 0;
    
    for (int i = 0; i < NUM_WRITES; i++) {
    // Mutate buffer content in the main thread to simulate tampering
    switch (i % 4) {
        case 0:
            memset(g_write_buffer, 0xAA + (i % 10), BUFFER_SIZE);
            break;
        case 1:
            for (int j = 0; j < BUFFER_SIZE; j++) {
                g_write_buffer[j] = (char)((j + i) % 256);
            }
            break;
        case 2:
            for (int j = 0; j < BUFFER_SIZE; j++) {
                g_write_buffer[j] = (j % 2) ? 0xFF : 0x00;
            }
            break;
        case 3:
            memset(g_write_buffer, 0xDE, BUFFER_SIZE);
            break;
    }

    // Construct test hash for each write (only from 7th write onwards)
        if (i >= 6) {
            unsigned char test_hash[32] = {0};
            memset(test_hash, 0xAB + i, sizeof(test_hash));
            memcpy(file_handle.hash, test_hash, sizeof(test_hash));
        }
        
    // Perform pwrite operation
        long long offset = (long long)i * BUFFER_SIZE;
        result = gr_file_pwrite(vfs_handle, &file_handle, g_write_buffer, BUFFER_SIZE, offset);
        
        if (result == BUFFER_SIZE) {
            success_count++;
            printf("   Write %d: SUCCESS (offset: %lld, size: %d)\n", i+1, offset, BUFFER_SIZE);
        } else {
            failure_count++;
            printf("   Write %d: FAILED (expected: %d, actual: %lld)\n", i+1, BUFFER_SIZE, result);
        }
        
        // Small delay between writes
        usleep(50000);  // 50ms
    }
     
    // 8. Test results summary
    printf("8. Test results summary:\n");
    printf("    Total writes: %d\n", NUM_WRITES);
    printf("    Successful writes: %d\n", success_count);
    printf("    Failed writes: %d\n", failure_count);
    printf("    Success rate: %.1f%%\n", (double)success_count / NUM_WRITES * 100);
     
    // 9. Cleanup resources
    printf("9. Cleaning up resources...\n");
    free(g_write_buffer);
    gr_file_close(vfs_handle, &file_handle, false);
    gr_vfs_unmount(&vfs_handle);
    gr_vfs_delete(inst_handle, TEST_DIR, 1);
    gr_delete_inst(inst_handle);
    
    printf("=== Buffer Tamper Test Completed ===\n");
    return (failure_count > 0) ? -1 : 0;
}

int main(int argc, char *argv[])
{
    printf("GR Buffer Tamper Test Program\n");
    printf("=============================\n");
    
    if (argc > 1) {
        printf("Usage: %s\n", argv[0]);
        printf("Note: Please ensure GR server is running on %s\n", SERVER_ADDR);
        return 1;
    }
    
    // Initialize GR logging system
    printf("Initializing GR logging system...\n");
    int log_result = init_gr_logging();
    if (log_result != 0) {
        printf("Warning: Failed to initialize GR logging, continuing without logging\n");
    }
    
    // Run the test
    int result = test_buffer_tamper();
    if (result == 0) {
        printf("\nTest completed successfully - no buffer tampering issues detected!\n");
    } else {
        printf("\nTest completed with failures - buffer tampering may have caused issues!\n");
    }   
    
    return result;
}

 