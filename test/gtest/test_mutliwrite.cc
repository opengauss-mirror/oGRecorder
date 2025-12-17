#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <fcntl.h>
#include <chrono>
extern "C" {
#include "gr_api.h"
#include "gr_errno.h"
}

#define SERVER_ADDR "127.0.0.1:19225"
#define TEST_DIR "concurrentdir"
#define ONE_MB 1024 * 1024
#define ONE_GB 1024 * 1024 * 1024
#define NUM_THREADS 1

// 写入模式枚举
enum WriteMode {
    WRITE_MODE_PWRITE = 0,
    WRITE_MODE_APPEND = 1
};

int errorcode = 0;
const char *errormsg = NULL;

gr_param_t g_gr_param;
gr_instance_handle g_inst_handle[NUM_THREADS];
gr_vfs_handle g_vfs_handle[NUM_THREADS];

// 全局写入模式，默认为 pwrite
WriteMode g_write_mode = WRITE_MODE_PWRITE;

class GRApiConcurrentPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        /*
         *   strcpy(g_gr_param.log_home, "./testlog");
         *   g_gr_param.log_level = 255;
         *   g_gr_param.log_backup_file_count = 100;
         *   g_gr_param.log_max_file_size = ONE_GB;
         *   gr_init(g_gr_param); 
        */
        for (int i = 0; i < NUM_THREADS; i++) {
            int result = gr_create_inst(SERVER_ADDR, &g_inst_handle[i]);
            ASSERT_EQ(result, GR_SUCCESS) << "Failed to create instance";

            std::string dir_name = std::string("testdir") + std::to_string(i);
            result = gr_vfs_create(g_inst_handle[i], dir_name.c_str(), 0);
            // ASSERT_EQ(result, GR_SUCCESS) << "Failed to create VFS";

            result = gr_vfs_mount(g_inst_handle[i], dir_name.c_str(), &g_vfs_handle[i]);
            ASSERT_EQ(result, GR_SUCCESS) << "Failed to mount VFS";


            std::string file_name = std::string("testfile");
            result = gr_file_create(g_vfs_handle[i], file_name.c_str(), NULL);
            // ASSERT_EQ(result, GR_SUCCESS) << "Failed to create file " << file_name;
        }

    }

    void TearDown() override {
        for (int i = 0; i < NUM_THREADS; i++) {
            std::string dir_name = std::string("testdir") + std::to_string(i);
            gr_vfs_delete(g_inst_handle[i], dir_name.c_str(), 1);
        }
    }
};

void writeToFileWithPerformance(gr_vfs_handle vfs_handle, const std::string& file_name, const char* data, size_t step_size, size_t total_size) {
    int handle;
    int result;
    gr_file_handle file_handle;
    result = gr_file_open(vfs_handle, file_name.c_str(), O_RDWR | O_SYNC, &file_handle);
    ASSERT_EQ(result, GR_SUCCESS) << "Failed to open file " << file_name;

    auto total_start = std::chrono::high_resolution_clock::now();
    double total_latency = 0.0;
    int write_count = total_size / step_size;
    const char* write_mode_name = (g_write_mode == WRITE_MODE_APPEND) ? "append" : "pwrite";

    for (int offset = 0; offset < total_size; offset += step_size) {
        auto start = std::chrono::high_resolution_clock::now();
        
        if (g_write_mode == WRITE_MODE_APPEND) {
            // 使用 append 模式，不需要 offset
            result = gr_file_append(vfs_handle, &file_handle, data, step_size);
        } else {
            // 使用 pwrite 模式，需要 offset
            result = gr_file_pwrite(vfs_handle, &file_handle, data, step_size, offset);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        
        if (result != (long long)step_size) {
            gr_get_error(&errorcode, &errormsg);
            printf("gr_file_%s interaction failure. code:%d msg:%s\n", write_mode_name, errorcode, errormsg);
            return;
        }

        std::chrono::duration<double, std::milli> latency = end - start;
        total_latency += latency.count();
    }
    auto total_end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> total_duration = total_end - total_start;
    double total_seconds = total_duration.count();
    double speed = total_size / (1024.0 * 1024.0) / total_seconds; // MB/s
    double average_latency = total_latency / write_count; // 平均时延，毫秒

    std::cout << "File: " << file_name << " - Write mode: " << write_mode_name << std::endl;
    std::cout << "File: " << file_name << " - Total write time: " << total_seconds << " seconds" << std::endl;
    std::cout << "File: " << file_name << " - Write speed: " << speed << " MB/s" << std::endl;
    std::cout << "File: " << file_name << " - Average latency per write: " << average_latency << " milliseconds" << std::endl;

    gr_file_close(vfs_handle, &file_handle, false);
}

TEST_F(GRApiConcurrentPerformanceTest, TestConcurrentWritePerformance) {
    const int step_size = 1024 * 1024; // 1MB
    const long long total_size = 10LL * 1024LL * 1024LL * 1024LL; // 10GB
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

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS] [gtest options...]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --write-mode=MODE    Set write mode: 'append' or 'pwrite' (default: pwrite)" << std::endl;
    std::cout << "  --help               Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " --write-mode=append" << std::endl;
    std::cout << "  " << program_name << " --write-mode=pwrite" << std::endl;
}

int main(int argc, char **argv) {
    // 解析自定义参数
    std::vector<char*> gtest_args;
    gtest_args.push_back(argv[0]); // 程序名
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else if (arg.find("--write-mode=") == 0) {
            std::string mode = arg.substr(13); // 跳过 "--write-mode="
            if (mode == "append") {
                g_write_mode = WRITE_MODE_APPEND;
                std::cout << "Using write mode: append" << std::endl;
            } else if (mode == "pwrite") {
                g_write_mode = WRITE_MODE_PWRITE;
                std::cout << "Using write mode: pwrite" << std::endl;
            } else {
                std::cerr << "Error: Invalid write mode '" << mode << "'. Use 'append' or 'pwrite'." << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        } else {
            // 其他参数传递给 GoogleTest
            gtest_args.push_back(argv[i]);
        }
    }
    
    // 如果没有指定模式，使用默认的 pwrite
    if (g_write_mode == WRITE_MODE_PWRITE) {
        std::cout << "Using default write mode: pwrite (use --write-mode=append to use append)" << std::endl;
    }
    
    // 初始化 GoogleTest，传递过滤后的参数
    int gtest_argc = gtest_args.size();
    ::testing::InitGoogleTest(&gtest_argc, gtest_args.data());
    return RUN_ALL_TESTS();
}