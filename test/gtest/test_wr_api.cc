#include <gtest/gtest.h>
#include <fcntl.h>
extern "C" {
#include "wr_api.h"
#include "wr_errno.h"
}
#define TEST_LOG_DIR "./test_log"
#define TEST_DIR "testdir1"
#define TEST_FILE1 "testfile1"
#define TEST_FILE2 "testfile2"
#define TEST_FILE3 "testfile3"
#define ONE_GB 1024 * 1024 * 1024
#define SERVER_ADDR "127.0.0.1:19225"

int errorcode = 0;
const char *errormsg = NULL;
wr_instance_handle g_inst_handle = NULL;
wr_vfs_handle g_vfs_handle;
int handle1 = 0, handle2 = 0, handle3 = 0;

wr_param_t g_wr_param;
wr_file_handle file_handle1;
wr_file_handle file_handle2;
wr_file_handle file_handle3;

typedef enum en_wr_file_status {
    WR_FILE_INIT,
    WR_FILE_LOCK,
    WR_FILE_APPEND,
    WR_FILE_EXPIRED
} wr_file_status_t;

class FailureListener : public ::testing::EmptyTestEventListener {
public:
    void OnTestEnd(const ::testing::TestInfo& test_info) override {
        if (test_info.result()->Failed()) {
            std::cout << "Test " << test_info.test_case_name() << "." << test_info.name() << " failed." << std::endl;
            wr_get_error(&errorcode, &errormsg);
            printf("errorcode: %d, errormsg: %s\n", errorcode, errormsg);
        }
    }
};

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
};

TEST_F(WrApiTest, TestWrCreateInstance) {
    EXPECT_EQ(wr_create_inst(SERVER_ADDR, &g_inst_handle), WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrSetGetConf) {
    char buf[100];
    EXPECT_EQ(wr_set_conf(g_inst_handle, "_LOG_LEVEL", "7"), WR_SUCCESS);
    EXPECT_EQ(wr_get_conf(g_inst_handle, "_LOG_LEVEL", buf), WR_SUCCESS);
    EXPECT_EQ(strcmp(buf, "7"), 0);
    EXPECT_EQ(wr_set_conf(g_inst_handle, "_LOG_LEVEL", "255"), WR_SUCCESS);
    EXPECT_EQ(wr_get_conf(g_inst_handle, "_LOG_LEVEL", buf), WR_SUCCESS);
    EXPECT_EQ(strcmp(buf, "255"), 0);
}

TEST_F(WrApiTest, TestWrVfsCreate) {
    EXPECT_EQ(wr_vfs_create(g_inst_handle, TEST_DIR, 0), WR_SUCCESS);
    EXPECT_NE(wr_vfs_create(g_inst_handle, TEST_DIR, 0), WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsMount) {
    EXPECT_EQ(wr_vfs_mount(g_inst_handle, TEST_DIR, &g_vfs_handle), WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsCreateFiles) {
    EXPECT_EQ(wr_file_create(g_vfs_handle, TEST_FILE1, NULL), WR_SUCCESS);
    EXPECT_EQ(wr_file_create(g_vfs_handle, TEST_FILE2, NULL), WR_SUCCESS);
    EXPECT_EQ(wr_file_create(g_vfs_handle, TEST_FILE3, NULL), WR_SUCCESS);
    EXPECT_NE(wr_file_create(g_vfs_handle, TEST_FILE1, NULL), WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrfileOpen) {
    EXPECT_EQ(wr_file_open(g_vfs_handle, TEST_FILE1, O_RDWR | O_SYNC, &file_handle1), WR_SUCCESS);
    EXPECT_EQ(wr_file_open(g_vfs_handle, TEST_FILE2, O_RDWR | O_SYNC, &file_handle2), WR_SUCCESS);
    EXPECT_EQ(wr_file_open(g_vfs_handle, TEST_FILE3, O_RDWR | O_SYNC, &file_handle3), WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrfileWriteReadLargeData) {
    // 创建一个大于8KB的数据块
    const int large_data_size = 100 * 1024; // 10KB
    char *large_data = new char[large_data_size];
    memset(large_data, 'A', large_data_size); // 用'A'填充数据

    // 写入大数据块到文件
    EXPECT_EQ(wr_file_pwrite(g_vfs_handle, &file_handle1, large_data, large_data_size, 0), large_data_size);

    // 读取大数据块
    char *read_buffer = new char[large_data_size];
    EXPECT_EQ(wr_file_pread(g_vfs_handle, file_handle1, read_buffer, large_data_size, 0), large_data_size);

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
    EXPECT_EQ(wr_file_pwrite(g_vfs_handle, &file_handle1, data1, strlen(data1), 0), strlen(data1));
    EXPECT_EQ(wr_file_pwrite(g_vfs_handle, &file_handle2, data2, strlen(data2), 0), strlen(data2));
    EXPECT_EQ(wr_file_pwrite(g_vfs_handle, &file_handle3, data3, strlen(data3), 0), strlen(data3));

    // Read from files
    char buf1[100] = {0}, buf2[100] = {0}, buf3[100] = {0};
    EXPECT_EQ(wr_file_pread(g_vfs_handle, file_handle1, buf1, strlen(data1), 0), strlen(data1));
    EXPECT_EQ(wr_file_pread(g_vfs_handle, file_handle2, buf2, strlen(data2), 0), strlen(data2));
    EXPECT_EQ(wr_file_pread(g_vfs_handle, file_handle3, buf3, strlen(data3), 0), strlen(data3));
}

TEST_F(WrApiTest, TestWrfileTruncate) {
    EXPECT_EQ(wr_file_truncate(g_vfs_handle, file_handle1, 0, ONE_GB), WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrfileStat) {
    long long offset = 0;
    unsigned long long size = 0;
    int mode = 0;
    char *time = NULL;
    EXPECT_EQ(wr_file_stat(g_vfs_handle, TEST_FILE1, &offset, &size, &mode, &time), WR_SUCCESS);
    EXPECT_EQ(offset, ONE_GB);
    EXPECT_EQ(size, ONE_GB);
    EXPECT_EQ(mode, WR_FILE_APPEND);
}

TEST_F(WrApiTest, TestWrfilePostpone) {
    const char *time1 = "2025-06-23 10:00:00";
    const char *time2 = "2025-06-24 11:00:00";
    const char *time3 = "2025-06-22 23:00:00";
    EXPECT_EQ(wr_file_postpone(g_vfs_handle, TEST_FILE1, time1), WR_SUCCESS);
    EXPECT_EQ(wr_file_postpone(g_vfs_handle, TEST_FILE2, time2), WR_SUCCESS);
    EXPECT_EQ(wr_file_postpone(g_vfs_handle, TEST_FILE3, time3), WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrfileClose) {
    EXPECT_EQ(wr_file_close(g_vfs_handle, &file_handle1, false), WR_SUCCESS);
    EXPECT_EQ(wr_file_close(g_vfs_handle, &file_handle2, false), WR_SUCCESS);
    EXPECT_EQ(wr_file_close(g_vfs_handle, &file_handle3, false), WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsQueryFileNum) {
    int file_num = 0;
    EXPECT_EQ(wr_vfs_query_file_num(g_inst_handle, TEST_DIR, &file_num), WR_SUCCESS);
    EXPECT_EQ(file_num, 3);
}

TEST_F(WrApiTest, TestWrVfsDeleteFiles) {
    EXPECT_EQ(wr_file_delete(g_vfs_handle, TEST_FILE1), WR_ERROR);
    EXPECT_EQ(wr_file_delete(g_vfs_handle, TEST_FILE2), WR_ERROR);
}

TEST_F(WrApiTest, TestWrVfsForceDelete) {
    EXPECT_EQ(wr_vfs_delete(g_inst_handle, TEST_DIR, 1), WR_ERROR);
}

TEST_F(WrApiTest, TestWrVfsUnmount) {
    EXPECT_EQ(wr_vfs_unmount(&g_vfs_handle), WR_SUCCESS);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::TestEventListeners& listeners = ::testing::UnitTest::GetInstance()->listeners();
    listeners.Append(new FailureListener);
    return RUN_ALL_TESTS();
}