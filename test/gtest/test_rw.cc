#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <fcntl.h>
extern "C" {
#include "wr_api.h"
#include "wr_errno.h"
}

#define TEST_LOG_DIR "./test_log"
#define TEST_DIR "complexdir"
#define TEST_FILE1 "complexfile1"
#define TEST_FILE2 "complexfile2"
#define ONE_GB 1024 * 1024 * 1024
#define SERVER_ADDR "127.0.0.1:19225"

int errorcode = 0;
const char *errormsg = NULL;
wr_instance_handle g_inst_handle1 = NULL;
wr_instance_handle g_inst_handle2 = NULL;
wr_vfs_handle g_vfs_handle1;
wr_vfs_handle g_vfs_handle2;
int handle1 = 0, handle2 = 0;

wr_param_t g_wr_param;

class ComplexWrApiTest : public ::testing::Test {
protected:
    void SetUp() override {
        strcpy(g_wr_param.log_home, "./testlog");
        g_wr_param.log_level = 255;
        g_wr_param.log_backup_file_count = 100;
        g_wr_param.log_max_file_size = ONE_GB;
        int result = wr_init(g_wr_param);
        ASSERT_EQ(result, WR_SUCCESS) << "Failed to initialize logger";

        EXPECT_EQ(wr_create_inst(SERVER_ADDR, &g_inst_handle1), WR_SUCCESS);
        EXPECT_EQ(wr_create_inst(SERVER_ADDR, &g_inst_handle2), WR_SUCCESS);
        EXPECT_EQ(wr_vfs_create(g_inst_handle1, TEST_DIR, 0), WR_SUCCESS);
        EXPECT_EQ(wr_vfs_mount(g_inst_handle1, TEST_DIR, &g_vfs_handle1), WR_SUCCESS);
        EXPECT_EQ(wr_vfs_mount(g_inst_handle2, TEST_DIR, &g_vfs_handle2), WR_SUCCESS);
        

        EXPECT_EQ(wr_file_create(g_vfs_handle1, TEST_FILE1, NULL), WR_SUCCESS);
        EXPECT_EQ(wr_file_create(g_vfs_handle1, TEST_FILE2, NULL), WR_SUCCESS);
        EXPECT_EQ(wr_file_open(g_vfs_handle1, TEST_FILE1, O_RDWR | O_SYNC, &handle1), WR_SUCCESS);
        EXPECT_EQ(wr_file_open(g_vfs_handle1, TEST_FILE2, O_RDWR | O_SYNC, &handle2), WR_SUCCESS);
    }

    void TearDown() override {
        EXPECT_EQ(wr_file_close(g_vfs_handle1, handle1), WR_SUCCESS);
        EXPECT_EQ(wr_file_close(g_vfs_handle1, handle2), WR_SUCCESS);
        EXPECT_EQ(wr_file_delete(g_vfs_handle1, TEST_FILE1), WR_SUCCESS);
        EXPECT_EQ(wr_file_delete(g_vfs_handle1, TEST_FILE2), WR_SUCCESS);
        EXPECT_EQ(wr_vfs_unmount(&g_vfs_handle1), WR_SUCCESS);
        EXPECT_EQ(wr_vfs_unmount(&g_vfs_handle2), WR_SUCCESS);
        EXPECT_EQ(wr_vfs_delete(g_inst_handle1, TEST_DIR, 0), WR_SUCCESS);
    }
};

void writeData(int handle, wr_vfs_handle vfs_handle, const char* data, size_t size, int64_t offset) {
    EXPECT_EQ(wr_file_pwrite(vfs_handle, handle, data, size, offset), WR_SUCCESS);
}

void readData(int handle, wr_vfs_handle vfs_handle, char* buffer, size_t size, int64_t offset) {
    EXPECT_EQ(wr_file_pread(vfs_handle, handle, buffer, size, offset), WR_SUCCESS);
}

TEST_F(ComplexWrApiTest, TestConcurrentReadWrite) {
    const int data_size1 = 512 * 1024; // 512KB
    const int data_size2 = 256 * 1024; // 256KB
    char *data1 = new char[data_size1];
    char *data2 = new char[data_size2];
    memset(data1, 'X', data_size1);
    memset(data2, 'Y', data_size2);

    char *read_buffer1 = new char[data_size1];
    char *read_buffer2 = new char[data_size2];

    std::vector<std::thread> threads;

    // 启动并发写线程
    threads.emplace_back(writeData, handle1, g_vfs_handle1, data1, data_size1, 0);
    threads.emplace_back(writeData, handle2, g_vfs_handle2, data2, data_size2, 0);
    // 启动并发读线程
    threads.emplace_back(readData, handle1, g_vfs_handle1, read_buffer1, data_size1, 0);
    threads.emplace_back(readData, handle2, g_vfs_handle2, read_buffer2, data_size2, 0);

    // 等待所有线程完成
    for (auto& t : threads) {
        t.join();
    }

    // 验证读取的数据是否与写入的数据一致
    EXPECT_EQ(memcmp(data1, read_buffer1, data_size1), 0);
    EXPECT_EQ(memcmp(data2, read_buffer2, data_size2), 0);

    delete[] data1;
    delete[] data2;
    delete[] read_buffer1;
    delete[] read_buffer2;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}