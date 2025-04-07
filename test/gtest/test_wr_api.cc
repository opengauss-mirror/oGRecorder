#include <gtest/gtest.h>
extern "C" {
#include "wr_api.h"
#include "wr_errno.h"
}
#define TEST_LOG_DIR "./test_log"
#define TEST_DIR "testdir1"
#define TEST_FILE "testdir1/testfile1"
#define ONE_GB 1024 * 1024 * 1024
int errorcode = 0;
const char *errormsg = NULL;
wr_instance_handle g_inst_handle = NULL;
int handle = 0;

class WrApiTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 初始化日志
        int result = wr_init_logger(TEST_LOG_DIR, 255, 100, ONE_GB);
        ASSERT_EQ(result, WR_SUCCESS) << "Failed to initialize logger";
    }
};

TEST_F(WrApiTest, TestWrCreateInstance) {
    int result = wr_create_instance("127.0.0.1:19225", &g_inst_handle);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsCreate) {
    int result = wr_vfs_create(TEST_DIR, g_inst_handle);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsCreateNegative) {
    // Negative test case: create directory with invalid name
    int result = wr_vfs_create("", g_inst_handle);
    EXPECT_NE(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsCreateFile) {
    int result = wr_file_create(TEST_FILE, 0, g_inst_handle);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsCreateFileNegative) {
    // Negative test case: create file with invalid path
    int result = wr_file_create(NULL, 0, g_inst_handle);
    EXPECT_NE(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrfileOpen) {
    int result = wr_file_open(TEST_FILE, 0, &handle, g_inst_handle);
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrfileWrite) {
    int result = wr_file_pwrite(handle, "hello world", sizeof("hello world"), 0, g_inst_handle);
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrfileRead) {
    char buf[100];
    int result = wr_file_pread(handle, buf, sizeof("hello world"), 0, g_inst_handle);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
    printf("buf: %s\n", buf);
}

TEST_F(WrApiTest, TestWrfileClose) {
    int result = wr_file_close(handle, g_inst_handle);
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsDeleteFile) {
    char *path = (char *)malloc(strlen(TEST_DIR) + strlen("/testfile1") + 1);
    strcpy(path, TEST_DIR);
    strcat(path, "/testfile1");
    int result = wr_file_delete(path, g_inst_handle);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
    free(path);
}

TEST_F(WrApiTest, TestWrVfsDeleteFileNegative) {
    // Negative test case: delete non-existent file
    int result = wr_file_delete("non_existent_file", g_inst_handle);
    EXPECT_NE(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsDelete) {
    int result = wr_vfs_delete(TEST_DIR, g_inst_handle);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST_F(WrApiTest, TestWrVfsDeleteNegative) {
    // Negative test case: delete non-existent directory
    int result = wr_vfs_delete("non_existent_dir", g_inst_handle);
    EXPECT_NE(result, WR_SUCCESS);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}