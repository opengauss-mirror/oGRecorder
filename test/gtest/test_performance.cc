#include <gtest/gtest.h>
#include <fcntl.h>
#include <chrono>
#include <iostream>
extern "C" {
#include "wr_api.h"
#include "wr_errno.h"
}

#define ONE_GB 1024 * 1024 * 1024
#define SERVER_ADDR "127.0.0.1:19225"

#define TEST_DIR "performancedir"
#define TEST_FILE "performance_test_file1"
#define ONE_MB 1024 * 1024

wr_param_t g_wr_param;

class WrApiPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        strcpy(g_wr_param.log_home, "./testlog");
        g_wr_param.log_level = 255;
        g_wr_param.log_backup_file_count = 100;
        g_wr_param.log_max_file_size = ONE_GB;
        wr_init(g_wr_param); 
        int result = wr_create_inst(SERVER_ADDR, &g_inst_handle);
        ASSERT_EQ(result, WR_SUCCESS) << "Failed to create instance";

        result = wr_vfs_create(g_inst_handle, TEST_DIR, 0);
        ASSERT_EQ(result, WR_SUCCESS) << "Failed to create VFS";

        result = wr_vfs_mount(g_inst_handle, TEST_DIR, &g_vfs_handle);
        ASSERT_EQ(result, WR_SUCCESS) << "Failed to mount VFS";

        result = wr_file_create(g_vfs_handle, TEST_FILE, NULL);
        ASSERT_EQ(result, WR_SUCCESS) << "Failed to create test file";

        result = wr_file_open(g_vfs_handle, TEST_FILE, O_RDWR | O_SYNC, &handle);
        ASSERT_EQ(result, WR_SUCCESS) << "Failed to open test file";

        result = wr_file_truncate(g_vfs_handle, handle, 0, ONE_GB);
        ASSERT_EQ(result, WR_SUCCESS) << "Failed to truncate test file";
    }

    void TearDown() override {
        wr_file_close(g_vfs_handle, handle);
        wr_file_delete(g_vfs_handle, TEST_FILE);
        wr_vfs_delete(g_inst_handle, TEST_DIR, 0);
    }

    wr_instance_handle g_inst_handle = NULL;
    wr_vfs_handle g_vfs_handle;
    int handle = 0;
};

TEST_F(WrApiPerformanceTest, TestWritePerformance) {
    const int data_size = ONE_GB;
    char *data = new char[data_size];
    memset(data, 'A', data_size);

    auto start = std::chrono::high_resolution_clock::now();
    int result = wr_file_pwrite(g_vfs_handle, handle, data, data_size, 0);
    auto end = std::chrono::high_resolution_clock::now();

    ASSERT_EQ(result, WR_SUCCESS) << "Failed to write data";

    std::chrono::duration<double, std::milli> duration = end - start; // 以毫秒为单位
    double milliseconds = duration.count();
    double speed = data_size / (1024.0 * 1024.0) / (milliseconds / 1000.0); // MB/s

    std::cout << "Write time: " << milliseconds << " milliseconds" << std::endl;
    std::cout << "Write speed: " << speed << " MB/s" << std::endl;

    delete[] data;
}

TEST_F(WrApiPerformanceTest, TestWritePerformanceWith8KSteps) {
    const int step_size = 8 * 1024; // 8KB
    const int total_size = ONE_GB; // 1GB
    char *data = new char[step_size];
    memset(data, 'B', step_size); // 用'B'填充数据

    auto total_start = std::chrono::high_resolution_clock::now();
    int result = WR_SUCCESS;
    double total_latency = 0.0;
    int write_count = total_size / step_size;

    for (int offset = 0; offset < total_size; offset += step_size) {
        auto start = std::chrono::high_resolution_clock::now();
        result = wr_file_pwrite(g_vfs_handle, handle, data, step_size, offset);
        auto end = std::chrono::high_resolution_clock::now();

        ASSERT_EQ(result, WR_SUCCESS) << "Failed to write data at offset " << offset;

        std::chrono::duration<double, std::milli> latency = end - start; // 以毫秒为单位
        total_latency += latency.count();
    }
    auto total_end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> total_duration = total_end - total_start;
    double total_seconds = total_duration.count();
    double speed = total_size / (1024.0 * 1024.0) / total_seconds; // MB/s
    double average_latency = total_latency / write_count; // 平均时延，毫秒

    std::cout << "Total write time with 8KB steps: " << total_seconds << " seconds" << std::endl;
    std::cout << "Write speed with 8KB steps: " << speed << " MB/s" << std::endl;
    std::cout << "Average latency per 8KB write: " << average_latency << " milliseconds" << std::endl;

    delete[] data;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}