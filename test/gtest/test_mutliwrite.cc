#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <string>
#include <iostream>
#include <fcntl.h>
#include <chrono>
extern "C" {
#include "wr_api.h"
#include "wr_errno.h"
}

#define SERVER_ADDR "127.0.0.1:19225"
#define TEST_DIR "concurrentdir"
#define ONE_MB 1024 * 1024
#define ONE_GB 1024 * 1024 * 1024
#define NUM_THREADS 12

wr_param_t g_wr_param;
wr_instance_handle g_inst_handle[NUM_THREADS];
wr_vfs_handle g_vfs_handle[NUM_THREADS];

class WrApiConcurrentPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        /*
         *   strcpy(g_wr_param.log_home, "./testlog");
         *   g_wr_param.log_level = 255;
         *   g_wr_param.log_backup_file_count = 100;
         *   g_wr_param.log_max_file_size = ONE_GB;
         *   wr_init(g_wr_param); 
        */
        for (int i = 0; i < NUM_THREADS; i++) {
            int result = wr_create_inst(SERVER_ADDR, &g_inst_handle[i]);
            ASSERT_EQ(result, WR_SUCCESS) << "Failed to create instance";

            std::string dir_name = std::string("testdir") + std::to_string(i);
            result = wr_vfs_create(g_inst_handle[i], dir_name.c_str(), 0);
            ASSERT_EQ(result, WR_SUCCESS) << "Failed to create VFS";

            result = wr_vfs_mount(g_inst_handle[i], dir_name.c_str(), &g_vfs_handle[i]);
            ASSERT_EQ(result, WR_SUCCESS) << "Failed to mount VFS";


            std::string file_name = std::string("testfile");
            result = wr_file_create(g_vfs_handle[i], file_name.c_str(), NULL);
            ASSERT_EQ(result, WR_SUCCESS) << "Failed to create file " << file_name;
        }

    }

    void TearDown() override {
        for (int i = 0; i < NUM_THREADS; i++) {
            std::string dir_name = std::string("testdir") + std::to_string(i);
            wr_vfs_delete(g_inst_handle[i], dir_name.c_str(), 1);
        }
    }
};

void writeToFileWithPerformance(wr_vfs_handle vfs_handle, const std::string& file_name, const char* data, size_t step_size, size_t total_size) {
    int handle;
    int result;
    result = wr_file_open(vfs_handle, file_name.c_str(), O_RDWR | O_SYNC, &handle);
    ASSERT_EQ(result, WR_SUCCESS) << "Failed to open file " << file_name;

    auto total_start = std::chrono::high_resolution_clock::now();
    double total_latency = 0.0;
    int write_count = total_size / step_size;

    for (int offset = 0; offset < total_size; offset += step_size) {
        auto start = std::chrono::high_resolution_clock::now();
        result = wr_file_pwrite(vfs_handle, handle, data, step_size, offset);
        auto end = std::chrono::high_resolution_clock::now();

        ASSERT_EQ(result, WR_SUCCESS) << "Failed to write data at offset " << offset;

        std::chrono::duration<double, std::milli> latency = end - start;
        total_latency += latency.count();
    }
    auto total_end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> total_duration = total_end - total_start;
    double total_seconds = total_duration.count();
    double speed = total_size / (1024.0 * 1024.0) / total_seconds; // MB/s
    double average_latency = total_latency / write_count; // 平均时延，毫秒

    std::cout << "File: " << file_name << " - Total write time: " << total_seconds << " seconds" << std::endl;
    std::cout << "File: " << file_name << " - Write speed: " << speed << " MB/s" << std::endl;
    std::cout << "File: " << file_name << " - Average latency per write: " << average_latency << " milliseconds" << std::endl;

    wr_file_close(vfs_handle, handle);
}

TEST_F(WrApiConcurrentPerformanceTest, TestConcurrentWritePerformance) {
    const int step_size = 8 * 1024; // 8KB
    const int total_size = 80 * 1024 * 1024; // 80MB
    char *data = new char[step_size];
    memset(data, 'C', step_size);

    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; ++i) {
        std::string file_name = std::string("testfile");
        threads.emplace_back(writeToFileWithPerformance, g_vfs_handle[i], file_name, data, step_size, total_size);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    delete[] data;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}