// 解决Google Test与C++标准库兼容性问题
#define GTEST_HAS_TR1_TUPLE 0
#define GTEST_USE_OWN_TR1_TUPLE 0
#define GTEST_LANG_CXX11 1
#define GTEST_HAS_STD_FUNCTION_ 1

#include <gtest/gtest.h>
#include <string>
#include <iostream>
#include <fcntl.h>
#include <chrono>
#include <cstring>
#include <functional>
extern "C" {
#include "gr_api.h"
#include "gr_errno.h"
}

#define DEFAULT_SERVER_ADDR "127.0.0.1:19225"
#define ONE_MB 1024 * 1024
#define ONE_GB 1024 * 1024 * 1024

int errorcode = 0;
const char *errormsg = NULL;

gr_param_t g_gr_param;
gr_instance_handle g_inst_handle;
gr_vfs_handle g_vfs_handle;

// 全局变量存储服务器地址
std::string g_server_addr = DEFAULT_SERVER_ADDR;

class GRApiSingleThreadPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        /*
         *   strcpy(g_gr_param.log_home, "./testlog");
         *   g_gr_param.log_level = 255;
         *   g_gr_param.log_backup_file_count = 100;
         *   g_gr_param.log_max_file_size = ONE_GB;
         *   gr_init(g_gr_param); 
         */
        int result = gr_create_inst(g_server_addr.c_str(), &g_inst_handle);
        ASSERT_EQ(result, GR_SUCCESS) << "Failed to create instance";

        std::string dir_name = "singletestdir";
        result = gr_vfs_create(g_inst_handle, dir_name.c_str(), 0);
        // ASSERT_EQ(result, GR_SUCCESS) << "Failed to create VFS";

        result = gr_vfs_mount(g_inst_handle, dir_name.c_str(), &g_vfs_handle);
        ASSERT_EQ(result, GR_SUCCESS) << "Failed to mount VFS";

        std::string file_name = "single_testfile";
        result = gr_file_create(g_vfs_handle, file_name.c_str(), NULL);
        // ASSERT_EQ(result, GR_SUCCESS) << "Failed to create file " << file_name;
    }

    void TearDown() override {
        std::string dir_name = "singletestdir";
        gr_vfs_delete(g_inst_handle, dir_name.c_str(), 1);
    }
};

// 单线程写入性能测试函数
void singleThreadWriteToFileWithPerformance(gr_vfs_handle vfs_handle, const std::string& file_name, const char* data, size_t step_size, size_t total_size) {
    int result;
    gr_file_handle file_handle;
    result = gr_file_open(vfs_handle, file_name.c_str(), O_RDWR | O_SYNC, &file_handle);
    ASSERT_EQ(result, GR_SUCCESS) << "Failed to open file " << file_name;

    auto total_start = std::chrono::high_resolution_clock::now();
    double total_latency = 0.0;
    size_t write_count = total_size / step_size;

    std::cout << "开始单线程写入测试..." << std::endl;
    std::cout << "文件: " << file_name << std::endl;
    std::cout << "总大小: " << total_size / (1024ULL * 1024ULL) << " MB" << std::endl;
    std::cout << "步长: " << step_size / (1024ULL * 1024ULL) << " MB" << std::endl;
    std::cout << "写入次数: " << write_count << std::endl;

    for (size_t offset = 0; offset < total_size; offset += step_size) {
        auto start = std::chrono::high_resolution_clock::now();
        result = gr_file_pwrite(vfs_handle, &file_handle, data, step_size, offset);
        auto end = std::chrono::high_resolution_clock::now();

        if (result != step_size) {
            gr_get_error(&errorcode, &errormsg);
            printf("gr_file_pwrite 写入失败. code:%d msg:%s\n", errorcode, errormsg);
            return;
        }

        std::chrono::duration<double, std::milli> latency = end - start;
        total_latency += latency.count();

        // 每写入100MB显示一次进度
        if ((offset + step_size) % (100ULL * 1024ULL * 1024ULL) == 0) {
            double progress = (double)(offset + step_size) / total_size * 100;
            std::cout << "进度: " << progress << "% (" << (offset + step_size) / (1024ULL * 1024ULL) << " MB)" << std::endl;
        }
    }
    auto total_end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> total_duration = total_end - total_start;
    double total_seconds = total_duration.count();
    double speed = total_size / (1024.0 * 1024.0) / total_seconds; // MB/s
    double average_latency = total_latency / write_count; // 平均时延，毫秒

    std::cout << "=== 单线程写入性能测试结果 ===" << std::endl;
    std::cout << "文件: " << file_name << std::endl;
    std::cout << "总写入时间: " << total_seconds << " 秒" << std::endl;
    std::cout << "写入速度: " << speed << " MB/s" << std::endl;
    std::cout << "平均每次写入时延: " << average_latency << " 毫秒" << std::endl;
    std::cout << "总写入次数: " << write_count << std::endl;
    std::cout << "================================" << std::endl;

    gr_file_close(vfs_handle, &file_handle);
}

// 单线程大文件写入性能测试
TEST_F(GRApiSingleThreadPerformanceTest, TestSingleThreadWritePerformance) {
    const size_t step_size = 1024ULL * 1024ULL; // 1MB
    const size_t total_size = 1024ULL * 1024ULL * 1024ULL; // 1GB
    char *data = new char[step_size];
    memset(data, 'S', step_size); // 使用'S'字符标识单线程测试

    std::string file_name = "single_testfile";
    singleThreadWriteToFileWithPerformance(g_vfs_handle, file_name, data, step_size, total_size);

    delete[] data;
}

// 单线程小文件写入性能测试
TEST_F(GRApiSingleThreadPerformanceTest, TestSingleThreadSmallFileWritePerformance) {
    const size_t step_size = 4ULL * 1024ULL; // 4KB
    const size_t total_size = 100ULL * 1024ULL * 1024ULL; // 100MB
    char *data = new char[step_size];
    memset(data, 's', step_size); // 使用's'字符标识小文件测试

    std::string file_name = "single_small_testfile";
    
    // 先创建小文件
    int result = gr_file_create(g_vfs_handle, file_name.c_str(), NULL);
    // ASSERT_EQ(result, GR_SUCCESS) << "Failed to create small file " << file_name;

    singleThreadWriteToFileWithPerformance(g_vfs_handle, file_name, data, step_size, total_size);

    delete[] data;
}

// 单线程中等文件写入性能测试
TEST_F(GRApiSingleThreadPerformanceTest, TestSingleThreadMediumFileWritePerformance) {
    const size_t step_size = 64ULL * 1024ULL; // 64KB
    const size_t total_size = 500ULL * 1024ULL * 1024ULL; // 500MB
    char *data = new char[step_size];
    memset(data, 'M', step_size); // 使用'M'字符标识中等文件测试

    std::string file_name = "single_medium_testfile";
    
    // 先创建中等文件
    int result = gr_file_create(g_vfs_handle, file_name.c_str(), NULL);
    // ASSERT_EQ(result, GR_SUCCESS) << "Failed to create medium file " << file_name;

    singleThreadWriteToFileWithPerformance(g_vfs_handle, file_name, data, step_size, total_size);

    delete[] data;
}

// 单线程超大文件写入性能测试
TEST_F(GRApiSingleThreadPerformanceTest, TestSingleThreadLargeFileWritePerformance) {
    const size_t step_size = 2ULL * 1024ULL * 1024ULL; // 2MB
    const size_t total_size = 2ULL * 1024ULL * 1024ULL * 1024ULL; // 2GB
    char *data = new char[step_size];
    memset(data, 'L', step_size); // 使用'L'字符标识大文件测试

    std::string file_name = "single_large_testfile";
    
    // 先创建大文件
    int result = gr_file_create(g_vfs_handle, file_name.c_str(), NULL);
    // ASSERT_EQ(result, GR_SUCCESS) << "Failed to create large file " << file_name;

    singleThreadWriteToFileWithPerformance(g_vfs_handle, file_name, data, step_size, total_size);

    delete[] data;
}

// 单线程随机大小写入性能测试
TEST_F(GRApiSingleThreadPerformanceTest, TestSingleThreadRandomSizeWritePerformance) {
    const size_t step_size = 16ULL * 1024ULL; // 16KB
    const size_t total_size = 200ULL * 1024ULL * 1024ULL; // 200MB
    char *data = new char[step_size];
    memset(data, 'R', step_size); // 使用'R'字符标识随机大小测试

    std::string file_name = "single_random_testfile";
    
    // 先创建文件
    int result = gr_file_create(g_vfs_handle, file_name.c_str(), NULL);
    // ASSERT_EQ(result, GR_SUCCESS) << "Failed to create random file " << file_name;

    singleThreadWriteToFileWithPerformance(g_vfs_handle, file_name, data, step_size, total_size);

    delete[] data;
}

// 解析命令行参数
void parseCommandLineArgs(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--server-addr") == 0 || strcmp(argv[i], "-s") == 0) {
            if (i + 1 < argc) {
                g_server_addr = argv[i + 1];
                i++; // 跳过下一个参数，因为它是值
            } else {
                std::cerr << "Error: --server-addr requires a value" << std::endl;
                exit(1);
            }
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  --server-addr, -s <address>  Server address (default: " << DEFAULT_SERVER_ADDR << ")" << std::endl;
            std::cout << "  --help, -h                   Show this help message" << std::endl;
            exit(0);
        }
    }
}

int main(int argc, char **argv) {
    // 解析命令行参数
    parseCommandLineArgs(argc, argv);
    
    std::cout << "Using server address: " << g_server_addr << std::endl;
    
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}