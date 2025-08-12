#include <gtest/gtest.h>
#include <fcntl.h>
extern "C" {
#include "gr_api.h"
#include "gr_errno.h"
}
#define TEST_LOG_DIR "./test_log"
#define TEST_DIR "testdir1"
#define TEST_FILE1 "TEST_FILE_1"
#define TEST_FILE2 "TEST_FILE_2"
#define TEST_FILE3 "TEST_FILE_3"
#define ONE_GB 1024 * 1024 * 1024
#define SERVER_ADDR "127.0.0.1:19225"

int errorcode = 0;
const char *errormsg = NULL;
gr_instance_handle g_inst_handle = NULL;
gr_vfs_handle g_vfs_handle;
int handle1 = 0, handle2 = 0, handle3 = 0;

gr_param_t g_gr_param;
gr_file_handle file_handle1;
gr_file_handle file_handle2;
gr_file_handle file_handle3;

typedef enum en_gr_file_status {
    GR_FILE_INIT,
    GR_FILE_LOCK,
    GR_FILE_APPEND,
    GR_FILE_EXPIRED
} gr_file_status_t;

class FailureListener : public ::testing::EmptyTestEventListener {
public:
    void OnTestEnd(const ::testing::TestInfo& test_info) override {
        if (test_info.result()->Failed()) {
            std::cout << "Test " << test_info.test_case_name() << "." << test_info.name() << " failed." << std::endl;
            gr_get_error(&errorcode, &errormsg);
            printf("errorcode: %d, errormsg: %s\n", errorcode, errormsg);
        }
    }
};

class GRApiTest : public ::testing::Test {
protected:
    void SetUp() override {
        strcpy(g_gr_param.log_home, "./testlog");
        g_gr_param.log_level = 255;
        g_gr_param.log_backup_file_count = 100;
        g_gr_param.log_max_file_size = ONE_GB;
        // 初始化日志
        int result = gr_init(g_gr_param);
        ASSERT_EQ(result, GR_SUCCESS) << "Failed to initialize logger";
    }

    void TearDown() override {
        gr_exit();
    }
};

TEST_F(GRApiTest, TestGRCreateInstance) {
    EXPECT_EQ(gr_create_inst(SERVER_ADDR, &g_inst_handle), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRSetGetConf) {
    char buf[100];
    EXPECT_EQ(gr_set_conf(g_inst_handle, "LOG_LEVEL", "7"), GR_SUCCESS);
    EXPECT_EQ(gr_get_conf(g_inst_handle, "LOG_LEVEL", buf), GR_SUCCESS);
    EXPECT_EQ(strcmp(buf, "7"), 0);
    EXPECT_EQ(gr_set_conf(g_inst_handle, "LOG_LEVEL", "255"), GR_SUCCESS);
    EXPECT_EQ(gr_get_conf(g_inst_handle, "LOG_LEVEL", buf), GR_SUCCESS);
    EXPECT_EQ(strcmp(buf, "255"), 0);
}

TEST_F(GRApiTest, TestGRVfsCreate) {
    EXPECT_EQ(gr_vfs_create(g_inst_handle, TEST_DIR, 0), GR_SUCCESS);
    EXPECT_NE(gr_vfs_create(g_inst_handle, TEST_DIR, 0), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRVfsMount) {
    EXPECT_EQ(gr_vfs_mount(g_inst_handle, TEST_DIR, &g_vfs_handle), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRVfsCreateFiles) {
    char file_name[256];
    bool is_exist = false;
    for (int i = 1; i <= 200; i++) {
        snprintf(file_name, sizeof(file_name), "TEST_FILE_%d", i);
        EXPECT_EQ(gr_file_create(g_vfs_handle, file_name, NULL), GR_SUCCESS);
    }
    EXPECT_EQ(gr_file_exist(g_vfs_handle, "TEST_FILE_1", &is_exist), GR_SUCCESS);
    EXPECT_EQ(is_exist, true);

    // 测试重复创建第一个文件
    EXPECT_NE(gr_file_create(g_vfs_handle, "TEST_FILE_1", NULL), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRfileOpen) {
    EXPECT_EQ(gr_file_open(g_vfs_handle, TEST_FILE1, O_RDWR | O_SYNC, &file_handle1), GR_SUCCESS);
    EXPECT_EQ(gr_file_open(g_vfs_handle, TEST_FILE2, O_RDWR | O_SYNC, &file_handle2), GR_SUCCESS); 
    EXPECT_EQ(gr_file_open(g_vfs_handle, TEST_FILE3, O_RDWR | O_SYNC, &file_handle3), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRfileWriteReadLargeData) {
    // 创建一个大于8KB的数据块
    const int large_data_size = 100 * 1024; // 10KB
    char *large_data = new char[large_data_size];
    memset(large_data, 'A', large_data_size); // 用'A'填充数据

    // 写入大数据块到文件
    EXPECT_EQ(gr_file_pwrite(g_vfs_handle, &file_handle1, large_data, large_data_size, 0), large_data_size);

    // 读取大数据块
    char *read_buffer = new char[large_data_size];
    EXPECT_EQ(gr_file_pread(g_vfs_handle, file_handle1, read_buffer, large_data_size, 0), large_data_size);

    // 验证读取的数据是否与写入的数据一致
    EXPECT_EQ(memcmp(large_data, read_buffer, large_data_size), 0);

    // 清理动态分配的内存
    delete[] large_data;
    delete[] read_buffer;
}

TEST_F(GRApiTest, TestGRfileWriteRead) {
    const char *data1 = "hello world 1";
    const char *data2 = "hello world 2";
    const char *data3 = "hello world 3";

    // Write to files
    EXPECT_EQ(gr_file_pwrite(g_vfs_handle, &file_handle1, data1, strlen(data1), 0), strlen(data1));
    EXPECT_EQ(gr_file_pwrite(g_vfs_handle, &file_handle2, data2, strlen(data2), 0), strlen(data2));
    EXPECT_EQ(gr_file_pwrite(g_vfs_handle, &file_handle3, data3, strlen(data3), 0), strlen(data3));

    // Read from files
    char buf1[100] = {0}, buf2[100] = {0}, buf3[100] = {0};
    EXPECT_EQ(gr_file_pread(g_vfs_handle, file_handle1, buf1, strlen(data1), 0), strlen(data1));
    EXPECT_EQ(gr_file_pread(g_vfs_handle, file_handle2, buf2, strlen(data2), 0), strlen(data2));
    EXPECT_EQ(gr_file_pread(g_vfs_handle, file_handle3, buf3, strlen(data3), 0), strlen(data3));
}

#ifndef ENABLE_WORM
TEST_F(GRApiTest, TestGRfileTruncate) {
    EXPECT_EQ(gr_file_truncate(g_vfs_handle, file_handle1, 0, ONE_GB), GR_SUCCESS);
}
#endif

TEST_F(GRApiTest, TestGRfileStat) {
    long long offset = 0;
    unsigned long long size = 0;
    int mode = 0;
    char *time = NULL;
    EXPECT_EQ(gr_file_stat(g_vfs_handle, TEST_FILE1, &offset, &size, &mode, &time), GR_SUCCESS);
#ifndef ENABLE_WORM
    EXPECT_EQ(offset, ONE_GB);
    EXPECT_EQ(size, ONE_GB);
#else
    EXPECT_EQ(mode, GR_FILE_APPEND);
#endif
}

TEST_F(GRApiTest, TestGRfilePostpone) {
    const char *time1 = "2025-07-23 10:00:00";
    const char *time2 = "2025-07-24 11:00:00";
    const char *time3 = "2025-07-22 23:00:00";
    EXPECT_EQ(gr_file_postpone(g_vfs_handle, TEST_FILE1, time1), GR_SUCCESS);
    EXPECT_EQ(gr_file_postpone(g_vfs_handle, TEST_FILE2, time2), GR_SUCCESS);
    EXPECT_EQ(gr_file_postpone(g_vfs_handle, TEST_FILE3, time3), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRfileClose) {
    EXPECT_EQ(gr_file_close(g_vfs_handle, &file_handle1, false), GR_SUCCESS);
    EXPECT_EQ(gr_file_close(g_vfs_handle, &file_handle2, false), GR_SUCCESS);
    EXPECT_EQ(gr_file_close(g_vfs_handle, &file_handle3, false), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRVfsQueryFileNum) {
    #define FILE_INFO_NUM 100
    // 确保文件数量查询正确
    int file_num = 0;
    gr_file_item_t file_info[FILE_INFO_NUM] = {0};
    EXPECT_EQ(gr_vfs_query_file_num(g_vfs_handle, &file_num), GR_SUCCESS);
    EXPECT_EQ(file_num, 200);
    EXPECT_EQ(gr_vfs_query_file_info(g_vfs_handle, file_info, true), GR_SUCCESS);

    // 校验文件名唯一且格式正确（只校验前100个）
    std::set<std::string> file_names;
    for (int i = 0; i < FILE_INFO_NUM; i++) {
        file_names.insert(file_info[i].name);
        // 校验格式
        EXPECT_EQ(strncmp(file_info[i].name, "TEST_FILE_", 10), 0);
        int num = atoi(file_info[i].name + 10);
        EXPECT_GE(num, 1);
        EXPECT_LE(num, 200);
    }
    // 校验无重复
    EXPECT_EQ(file_names.size(), FILE_INFO_NUM);

    // 可选：再次获取校验
    EXPECT_EQ(gr_vfs_query_file_info(g_vfs_handle, file_info, true), GR_SUCCESS);
    file_names.clear();
    for (int i = 0; i < FILE_INFO_NUM; i++) {
        file_names.insert(file_info[i].name);
        EXPECT_EQ(strncmp(file_info[i].name, "TEST_FILE_", 10), 0);
        int num = atoi(file_info[i].name + 10);
        EXPECT_GE(num, 1);
        EXPECT_LE(num, 200);
    }
    EXPECT_EQ(file_names.size(), FILE_INFO_NUM);
}

#ifdef ENABLE_WORM
TEST_F(GRApiTest, TestGRVfsDeleteFiles) {
    EXPECT_EQ(gr_file_delete(g_vfs_handle, TEST_FILE1), GR_ERROR);
    EXPECT_EQ(gr_file_delete(g_vfs_handle, TEST_FILE2), GR_ERROR);
}

TEST_F(GRApiTest, TestGRVfsForceDelete) {
    EXPECT_EQ(gr_vfs_delete(g_inst_handle, TEST_DIR, 1), GR_ERROR);
}
#else
TEST_F(GRApiTest, TestGRVfsDeleteFiles) {
    EXPECT_EQ(gr_file_delete(g_vfs_handle, TEST_FILE1), GR_SUCCESS);
    EXPECT_EQ(gr_file_delete(g_vfs_handle, TEST_FILE2), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRVfsForceDelete) {
    EXPECT_EQ(gr_vfs_delete(g_inst_handle, TEST_DIR, 1), GR_SUCCESS);
}
#endif

TEST_F(GRApiTest, TestGRVfsUnmount) {
    EXPECT_EQ(gr_vfs_unmount(&g_vfs_handle), GR_SUCCESS);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::TestEventListeners& listeners = ::testing::UnitTest::GetInstance()->listeners();
    listeners.Append(new FailureListener);
    return RUN_ALL_TESTS();
}