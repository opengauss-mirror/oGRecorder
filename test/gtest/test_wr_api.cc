#include <gtest/gtest.h>
extern "C" {
#include "wr_api.h"
#include "wr_errno.h"
}
#define TEST_LOG_DIR "./test_log"
#define TEST_DIR "testdir1"
#define ONE_GB 1024 * 1024 * 1024
int errorcode = 0;
const char *errormsg = NULL;

TEST(WrApiTest, TestInitLogger) {
    int result = wr_init_logger(TEST_LOG_DIR, 255, 100, ONE_GB);
    if (result != WR_SUCCESS) {
        printf("wr_init_logger failed, result: %d\n", result);
    }
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST(WrApiTest, TestInitLoggerNegative) {
    // Negative test case: invalid log directory
    int result = wr_init_logger(NULL, 255, 100, ONE_GB);
    EXPECT_NE(result, WR_SUCCESS);
}

TEST(WrApiTest, TestWrVfsCreate) {
    int result = wr_vfs_create(TEST_DIR);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST(WrApiTest, TestWrVfsCreateNegative) {
    // Negative test case: create directory with invalid name
    int result = wr_vfs_create("");
    EXPECT_NE(result, WR_SUCCESS);
}

TEST(WrApiTest, TestWrVfsCreateFile) {
    char *path = (char *)malloc(strlen(TEST_DIR) + strlen("/testfile1") + 1);
    strcpy(path, TEST_DIR);
    strcat(path, "/testfile1");
    int result = wr_file_create(path, 0);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
    free(path);
}

TEST(WrApiTest, TestWrVfsCreateFileNegative) {
    // Negative test case: create file with invalid path
    int result = wr_file_create(NULL, 0);
    EXPECT_NE(result, WR_SUCCESS);
}

TEST(WrApiTest, TestWrVfsDeleteFile) {
    char *path = (char *)malloc(strlen(TEST_DIR) + strlen("/testfile1") + 1);
    strcpy(path, TEST_DIR);
    strcat(path, "/testfile1");
    int result = wr_file_delete(path);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
    free(path);
}

TEST(WrApiTest, TestWrVfsDeleteFileNegative) {
    // Negative test case: delete non-existent file
    int result = wr_file_delete("non_existent_file");
    EXPECT_NE(result, WR_SUCCESS);
}

TEST(WrApiTest, TestWrVfsDelete) {
    int result = wr_vfs_delete(TEST_DIR);
    if (result != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }
    EXPECT_EQ(result, WR_SUCCESS);
}

TEST(WrApiTest, TestWrVfsDeleteNegative) {
    // Negative test case: delete non-existent directory
    int result = wr_vfs_delete("non_existent_dir");
    EXPECT_NE(result, WR_SUCCESS);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}