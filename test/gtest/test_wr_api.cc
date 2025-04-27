#include <gtest/gtest.h>
extern "C" {
#include "wr_api.h"
#include "wr_errno.h"
}
#define TEST_LOG_DIR "./test_log"
#define TEST_DIR "testdir1"
#define TEST_FILE1 "testdir1/testfile1"
#define TEST_FILE2 "testdir1/testfile2"
#define TEST_FILE3 "testdir1/testfile3"
#define ONE_GB 1024 * 1024 * 1024
#define SERVER_ADDR "127.0.0.1:19225"

int errorcode = 0;
const char *errormsg = NULL;
wr_instance_handle g_inst_handle = NULL;
wr_vfs_handle g_vfs_handle;
int handle1 = 0, handle2 = 0, handle3 = 0;

wr_param_t g_wr_param;


class WrApiTest : public ::testing::Test {
protected:
    void SetUp() override {
        strcpy(g_wr_param.log_home, "./testlog");
        g_wr_param.log_level = 255;
        g_wr_param.log_backup_file_count = 100;
        g_wr_param.log_max_file_size = ONE_GB;
        // 初始化日志
        int result = wr_init(g_wr_param);
        ASSERT_EQ(result, WR_SUCCESS) << "Failed to initialize logger";
    }

    void TearDown() override {
        wr_get_error(&errorcode, &errormsg);
        if (errorcode != 0) {
            printf("Error code: %d, Error message: %s\n", errorcode, errormsg);
        }
    }
};

TEST_F(WrApiTest, TestWrCreateInstance) {
    int result = wr_create_inst(SERVER_ADDR, &g_inst_handle);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsCreate) {
    int result = wr_vfs_create(g_inst_handle, TEST_DIR, 0);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsMount) {
    int result = wr_vfs_mount(g_inst_handle, TEST_DIR, &g_vfs_handle);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsCreateFiles) {
    int result1 = wr_file_create(g_vfs_handle, TEST_FILE1, NULL);
    int result2 = wr_file_create(g_vfs_handle, TEST_FILE2, NULL);
    int result3 = wr_file_create(g_vfs_handle, TEST_FILE3, NULL);
    EXPECT_EQ(result1, WR_SUCCESS);
    EXPECT_EQ(result2, WR_SUCCESS);
    EXPECT_EQ(result3, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrfileOpen) {
    int result1 = wr_file_open(g_vfs_handle, TEST_FILE1, 0, &handle1);
    int result2 = wr_file_open(g_vfs_handle, TEST_FILE2, 0, &handle2);
    int result3 = wr_file_open(g_vfs_handle, TEST_FILE3, 0, &handle3);
    EXPECT_EQ(result1, WR_SUCCESS);
    EXPECT_EQ(result2, WR_SUCCESS);
    EXPECT_EQ(result3, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrfileWriteReadLargeData) {
    // 创建一个大于8KB的数据块
    const int large_data_size = 100 * 1024; // 10KB
    char *large_data = new char[large_data_size];
    memset(large_data, 'A', large_data_size); // 用'A'填充数据

    // 写入大数据块到文件
    EXPECT_EQ(wr_file_pwrite(handle1, large_data, large_data_size, 0, g_vfs_handle), WR_SUCCESS);

    // 读取大数据块
    char *read_buffer = new char[large_data_size];
    EXPECT_EQ(wr_file_pread(handle1, read_buffer, large_data_size, 0, g_vfs_handle), WR_SUCCESS);

    // 验证读取的数据是否与写入的数据一致
    EXPECT_EQ(memcmp(large_data, read_buffer, large_data_size), 0);

    // 清理动态分配的内存
    delete[] large_data;
    delete[] read_buffer;
}

TEST_F(WrApiTest, TestWrfileWriteRead) {
    const char *data1 = "hello world 1";
    const char *data2 = "hello world 2";
    const char *data3 = "hello world 3";

    // Write to files
    EXPECT_EQ(wr_file_pwrite(handle1, data1, strlen(data1), 0, g_vfs_handle), WR_SUCCESS);
    EXPECT_EQ(wr_file_pwrite(handle2, data2, strlen(data2), 0, g_vfs_handle), WR_SUCCESS);
    EXPECT_EQ(wr_file_pwrite(handle3, data3, strlen(data3), 0, g_vfs_handle), WR_SUCCESS);

    // Read from files
    char buf1[100] = {0}, buf2[100] = {0}, buf3[100] = {0};
    EXPECT_EQ(wr_file_pread(handle1, buf1, strlen(data1), 0, g_vfs_handle), WR_SUCCESS);
    EXPECT_EQ(wr_file_pread(handle2, buf2, strlen(data2), 0, g_vfs_handle), WR_SUCCESS);
    EXPECT_EQ(wr_file_pread(handle3, buf3, strlen(data3), 0, g_vfs_handle), WR_SUCCESS);

    printf("buf1: %s\n", buf1);
    printf("buf2: %s\n", buf2);
    printf("buf3: %s\n", buf3);
}

TEST_F(WrApiTest, TestWrfileClose) {
    EXPECT_EQ(wr_file_close(g_vfs_handle, handle1), WR_SUCCESS);
    EXPECT_EQ(wr_file_close(g_vfs_handle, handle2), WR_SUCCESS);
    EXPECT_EQ(wr_file_close(g_vfs_handle, handle3), WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsQueryFileNum) {
    int file_num = 0;
    EXPECT_EQ(wr_vfs_query_file_num(g_inst_handle, TEST_DIR, &file_num), WR_SUCCESS);
    EXPECT_EQ(file_num, 3);
}

TEST_F(WrApiTest, TestWrVfsDeleteFiles) {
    EXPECT_EQ(wr_file_delete(g_vfs_handle, TEST_FILE1), WR_SUCCESS);
    EXPECT_EQ(wr_file_delete(g_vfs_handle, TEST_FILE2), WR_SUCCESS);
    EXPECT_EQ(wr_file_delete(g_vfs_handle, TEST_FILE3), WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsUnmount) {
    int result = wr_vfs_unmount(g_inst_handle, g_vfs_handle);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsDelete) {
    EXPECT_EQ(wr_vfs_delete(g_inst_handle, TEST_DIR, 0), WR_SUCCESS);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}