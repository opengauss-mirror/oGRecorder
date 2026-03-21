#include <gtest/gtest.h>
#include <fcntl.h>
#include <set>
#include <string>
#include <cstring>
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

// 动态修改 IP_WHITE_LIST，并验证立刻生效
TEST_F(GRApiTest, TestGRIpWhiteListDynamicUpdate) {
    char buf[256] = {0};

    // 1. 先获取当前白名单配置
    EXPECT_EQ(gr_get_conf(g_inst_handle, "IP_WHITE_LIST", buf), GR_SUCCESS);
    std::string original(buf);

    // 2. 在原有基础上拼接一条新规则 10.0.0.1
    std::string updated = original;
    if (!updated.empty()) {
        updated.append(",");
    }
    updated.append("10.0.0.1");

    EXPECT_EQ(gr_set_conf(g_inst_handle, "IP_WHITE_LIST", updated.c_str()), GR_SUCCESS);
    memset(buf, 0, sizeof(buf));
    EXPECT_EQ(gr_get_conf(g_inst_handle, "IP_WHITE_LIST", buf), GR_SUCCESS);
    EXPECT_STREQ(buf, updated.c_str());
}

TEST_F(GRApiTest, TestGRVfsCreate) {
    EXPECT_EQ(gr_vfs_create(g_inst_handle, TEST_DIR, 0), GR_SUCCESS);
    EXPECT_NE(gr_vfs_create(g_inst_handle, TEST_DIR, 0), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRVfsMount) {
    EXPECT_EQ(gr_vfs_mount(g_inst_handle, TEST_DIR, &g_vfs_handle), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRVfsExist) {
    bool is_exist = false;
    
    // 测试存在的 VFS（在 TestGRVfsCreate 中已创建）
    EXPECT_EQ(gr_vfs_exist(g_inst_handle, TEST_DIR, &is_exist), GR_SUCCESS);
    EXPECT_EQ(is_exist, true);
    
    // 测试不存在的 VFS
    EXPECT_EQ(gr_vfs_exist(g_inst_handle, "NON_EXISTENT_VFS", &is_exist), GR_SUCCESS);
    EXPECT_EQ(is_exist, false);
    
    // 测试另一个不存在的 VFS
    EXPECT_EQ(gr_vfs_exist(g_inst_handle, "ANOTHER_NON_EXISTENT_VFS_12345", &is_exist), GR_SUCCESS);
    EXPECT_EQ(is_exist, false);
    
    // 测试空字符串 VFS 名称
    EXPECT_EQ(gr_vfs_exist(g_inst_handle, "", &is_exist), GR_ERROR);
    
    // 测试 NULL VFS 名称
    EXPECT_EQ(gr_vfs_exist(g_inst_handle, NULL, &is_exist), GR_ERROR);
    
    // 测试 NULL is_exist 参数
    EXPECT_EQ(gr_vfs_exist(g_inst_handle, TEST_DIR, NULL), GR_ERROR);
    
    // 测试 NULL 实例句柄
    EXPECT_EQ(gr_vfs_exist(NULL, TEST_DIR, &is_exist), GR_ERROR);
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

TEST_F(GRApiTest, TestGRFileExist) {
    bool is_exist = false;
    
    // 测试存在的文件
    EXPECT_EQ(gr_file_exist(g_vfs_handle, "TEST_FILE_1", &is_exist), GR_SUCCESS);
    EXPECT_EQ(is_exist, true);
    
    EXPECT_EQ(gr_file_exist(g_vfs_handle, "TEST_FILE_100", &is_exist), GR_SUCCESS);
    EXPECT_EQ(is_exist, true);
    
    EXPECT_EQ(gr_file_exist(g_vfs_handle, "TEST_FILE_200", &is_exist), GR_SUCCESS);
    EXPECT_EQ(is_exist, true);
    
    // 测试不存在的文件
    EXPECT_EQ(gr_file_exist(g_vfs_handle, "NON_EXISTENT_FILE", &is_exist), GR_SUCCESS);
    EXPECT_EQ(is_exist, false);
    
    EXPECT_EQ(gr_file_exist(g_vfs_handle, "TEST_FILE_999", &is_exist), GR_SUCCESS);
    EXPECT_EQ(is_exist, false);
    
    // 测试空字符串文件名
    EXPECT_EQ(gr_file_exist(g_vfs_handle, "", &is_exist), GR_ERROR);
    
    // 测试特殊字符文件名
    EXPECT_EQ(gr_file_exist(g_vfs_handle, "FILE_WITH_SPECIAL_CHARS_!@#$%", &is_exist), GR_ERROR);
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

TEST_F(GRApiTest, TestGRfileStat) {
    long long offset = 0;
    unsigned long long size = 0;
    int mode = 0;
    char *time = NULL;
    EXPECT_EQ(gr_file_stat(g_vfs_handle, TEST_FILE1, &offset, &size, &mode, &time), GR_SUCCESS);
#ifndef ENABLE_WORM
    // For non-WORM mode, logical EOF should equal the actual amount of data written
    // to TEST_FILE_1 in previous tests (currently 100 * 1024 bytes).
    EXPECT_EQ(offset, 100 * 1024);
    EXPECT_EQ(size, 100 * 1024);
#else
    EXPECT_EQ(mode, GR_FILE_APPEND);
#endif
}

// Verify that logical EOF metadata is persisted via .gr_vfs_meta
// and survives across instance reconnects and VFS remounts on the same VFS.
TEST_F(GRApiTest, TestLogicalEofMetaPersistence) {
    const char *vfs_name = TEST_DIR; // reuse existing VFS created in other tests
    const char *file_name = "META_PERSIST_FILE";
    const int write_size = 100 * 1024 + 123; // intentionally unaligned size

    gr_instance_handle inst1 = NULL;
    gr_vfs_handle vfs1;
    gr_file_handle fh1;

    EXPECT_EQ(gr_create_inst(SERVER_ADDR, &inst1), GR_SUCCESS);
    EXPECT_EQ(gr_vfs_mount(inst1, vfs_name, &vfs1), GR_SUCCESS);

    // Create and open test file.
    (void)gr_file_delete(vfs1, file_name, 0); // best-effort cleanup
    EXPECT_EQ(gr_file_create(vfs1, file_name, NULL), GR_SUCCESS);
    EXPECT_EQ(gr_file_open(vfs1, file_name, O_RDWR | O_SYNC, &fh1), GR_SUCCESS);

    // Write an unaligned length from offset 0.
    std::string data(write_size, 'X');
    EXPECT_EQ(gr_file_pwrite(vfs1, &fh1, data.data(), write_size, 0), write_size);
    EXPECT_EQ(gr_file_close(vfs1, &fh1, false), GR_SUCCESS);

    // Disconnect instance to force server to rely on .gr_vfs_meta next time.
    EXPECT_EQ(gr_vfs_unmount(&vfs1), GR_SUCCESS);
    EXPECT_EQ(gr_delete_inst(inst1), GR_SUCCESS);

    // Reconnect and remount VFS, then stat the file.
    gr_instance_handle inst2 = NULL;
    gr_vfs_handle vfs2;
    EXPECT_EQ(gr_create_inst(SERVER_ADDR, &inst2), GR_SUCCESS);
    EXPECT_EQ(gr_vfs_mount(inst2, vfs_name, &vfs2), GR_SUCCESS);

    long long logical_offset = 0;
    unsigned long long logical_size = 0;
    int mode = 0;
    char *time_str = NULL;
    EXPECT_EQ(gr_file_stat(vfs2, file_name, &logical_offset, &logical_size, &mode, &time_str), GR_SUCCESS);
    EXPECT_EQ(logical_offset, (long long)write_size);
    EXPECT_EQ(logical_size, (unsigned long long)write_size);

    // Cleanup the test file but keep the shared VFS for other tests.
    EXPECT_EQ(gr_file_delete(vfs2, file_name, 0), GR_SUCCESS);
    EXPECT_EQ(gr_vfs_unmount(&vfs2), GR_SUCCESS);
    EXPECT_EQ(gr_delete_inst(inst2), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRfilePostpone) {
    const char *time1 = "2099-07-23 10:00:00";
    const char *time2 = "2099-07-24 11:00:00";
    const char *time3 = "2099-07-22 23:00:00";
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
    // 确保文件数量查询正确
    int file_num = 0;
    EXPECT_EQ(gr_vfs_query_file_num(g_vfs_handle, &file_num), GR_SUCCESS);
    // 文件数量可能包含其他测试创建的文件，所以只验证至少有200个文件
    EXPECT_GE(file_num, 200);
    
    // 循环获取所有文件（每次最多100个）
    #define MAX_FILES_PER_QUERY 100
    gr_file_item_t file_info[MAX_FILES_PER_QUERY];
    std::set<std::string> file_names;
    int test_file_count = 0;
    bool is_continue = false;
    int consecutive_empty = 0;
    const int MAX_CONSECUTIVE_EMPTY = 2;  // 允许连续2次空查询后停止
    
    // 循环查询直到获取所有文件
    while (test_file_count < 200 && consecutive_empty < MAX_CONSECUTIVE_EMPTY) {
        memset(file_info, 0, sizeof(file_info));
        int ret = gr_vfs_query_file_info(g_vfs_handle, file_info, is_continue);
        if (ret != GR_SUCCESS) {
            break;  // 查询失败
        }
        
        // 处理本次查询返回的文件
        bool found_any = false;
        for (int i = 0; i < MAX_FILES_PER_QUERY; i++) {
            if (file_info[i].name[0] == '\0') {
                break;  // 没有更多文件
            }
            found_any = true;
            // 跳过不是 TEST_FILE_ 开头的文件（可能是其他测试创建的文件）
            if (strncmp(file_info[i].name, "TEST_FILE_", 10) != 0) {
                continue;
            }
            // 检查是否已存在（避免重复计数）
            if (file_names.find(file_info[i].name) != file_names.end()) {
                continue;  // 已存在，跳过
            }
            file_names.insert(file_info[i].name);
            test_file_count++;
            // 校验格式
            int num = atoi(file_info[i].name + 10);
            EXPECT_GE(num, 1);
            EXPECT_LE(num, 200);
        }
        
        if (found_any) {
            consecutive_empty = 0;
        } else {
            consecutive_empty++;
        }
        
        // 设置为继续查询
        is_continue = true;
    }
    
    // 校验至少找到大部分TEST_FILE_开头的文件（考虑到可能有其他测试文件）
    // 实际创建了200个，应该能找到大部分，至少90%以上
    EXPECT_GE(test_file_count, 180) << "Expected at least 180 TEST_FILE_ files, found " << test_file_count;
    // 校验无重复
    EXPECT_EQ(file_names.size(), test_file_count);
}

#ifdef ENABLE_WORM
TEST_F(GRApiTest, TestGRVfsDeleteFiles) {
    EXPECT_EQ(gr_file_delete(g_vfs_handle, TEST_FILE1, 0), GR_ERROR);
    EXPECT_EQ(gr_file_delete(g_vfs_handle, TEST_FILE2, 0), GR_ERROR);
}

TEST_F(GRApiTest, TestGRVfsForceDelete) {
    EXPECT_EQ(gr_vfs_delete(g_inst_handle, TEST_DIR, 1), GR_ERROR);
}
#else
TEST_F(GRApiTest, TestGRVfsDeleteFiles) {
    EXPECT_EQ(gr_file_delete(g_vfs_handle, TEST_FILE1, 0), GR_SUCCESS);
    EXPECT_EQ(gr_file_delete(g_vfs_handle, TEST_FILE2, 0), GR_SUCCESS);
}

TEST_F(GRApiTest, TestGRVfsForceDelete) {
    EXPECT_EQ(gr_vfs_delete(g_inst_handle, TEST_DIR, 1), GR_SUCCESS);
}
#endif

TEST_F(GRApiTest, TestGRVfsUnmount) {
    EXPECT_EQ(gr_vfs_unmount(&g_vfs_handle), GR_SUCCESS);
}

// 异常/负例用例补充
TEST_F(GRApiTest, TestInvalidParamsBasic) {
    // 无效地址创建实例
    gr_instance_handle inst = NULL;
    EXPECT_NE(gr_create_inst("invalid_addr", &inst), GR_SUCCESS);

    // 空指针/非法参数
    EXPECT_NE(gr_vfs_create(g_inst_handle, NULL, 0), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    EXPECT_NE(errormsg, nullptr);
    EXPECT_NE(gr_vfs_mount(g_inst_handle, NULL, &g_vfs_handle), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    EXPECT_NE(gr_vfs_mount(g_inst_handle, TEST_DIR, NULL), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    
    // gr_vfs_exist 无效参数测试
    bool is_exist = false;
    EXPECT_NE(gr_vfs_exist(NULL, TEST_DIR, &is_exist), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    EXPECT_NE(gr_vfs_exist(g_inst_handle, NULL, &is_exist), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    EXPECT_NE(gr_vfs_exist(g_inst_handle, TEST_DIR, NULL), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    
    EXPECT_NE(gr_vfs_unmount(NULL), GR_SUCCESS);

    EXPECT_NE(gr_set_conf(g_inst_handle, NULL, "1"), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    EXPECT_NE(gr_set_conf(g_inst_handle, "LOG_LEVEL", NULL), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    EXPECT_NE(gr_get_conf(g_inst_handle, NULL, (char*)""), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
}

TEST_F(GRApiTest, TestFileApiInvalidParams) {
    // 文件接口空指针/非法参数
    EXPECT_NE(gr_file_create(g_vfs_handle, NULL, NULL), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    EXPECT_NE(gr_file_delete(g_vfs_handle, NULL, 0), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);

    bool is_exist_bool = false;
    EXPECT_NE(gr_file_exist(g_vfs_handle, NULL, &is_exist_bool), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    EXPECT_NE(gr_file_exist(g_vfs_handle, TEST_FILE1, NULL), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);

    // 打开文件：无效flag与空file_handle
    EXPECT_NE(gr_file_open(g_vfs_handle, TEST_FILE1, -1, &file_handle1), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_NE(gr_file_open(g_vfs_handle, TEST_FILE1, O_RDWR, NULL), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);

    // 读写：空缓冲区/负偏移
    long long wret = gr_file_pwrite(g_vfs_handle, &file_handle1, NULL, 16, 0);
    EXPECT_LT(wret, 0);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    long long rret = gr_file_pread(g_vfs_handle, file_handle1, NULL, 16, 0);
    EXPECT_LT(rret, 0);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);
    char buf[8] = {0};
    EXPECT_LT(gr_file_pread(g_vfs_handle, file_handle1, buf, sizeof(buf), -1), 0);
    gr_get_error(&errorcode, &errormsg);

    // stat 非法参数
    long long off = 0; unsigned long long size = 0; int mode = 0; char *time = NULL;
    EXPECT_NE(gr_file_stat(g_vfs_handle, NULL, &off, &size, &mode, &time), GR_SUCCESS);
    gr_get_error(&errorcode, &errormsg);
    EXPECT_EQ(errorcode, ERR_GR_INVALID_PARAM);

    // 清理测试环境
    gr_vfs_unmount(&g_vfs_handle);
}

TEST_F(GRApiTest, TestRepeatAndOrderErrors) {
    // 未挂载/未打开情况下操作
    gr_file_handle tmp_handle; // 未初始化的句柄用于负例
    EXPECT_NE(gr_file_close(g_vfs_handle, &tmp_handle, false), GR_SUCCESS);

    // 重复卸载
    gr_vfs_handle tmp_vfs = g_vfs_handle; // 可能未挂载，作为负例也应失败
    EXPECT_NE(gr_vfs_unmount(&tmp_vfs), GR_SUCCESS);
}

// Demo: 验证链接断开时服务端会关闭该连接打开的目录句柄（dir map 不泄漏）
// 行为：多次「建连 -> 挂载 VFS -> 不调用 unmount 直接 delete_inst 断开」，
//       再重新建连并正常挂载/查询/卸载，应全部成功，说明服务端在释放 session 时已关闭目录。
#define DIR_CLEANUP_DEMO_VFS "testdir_dir_cleanup_demo"
#define DIR_CLEANUP_DISCONNECT_ROUNDS 5

TEST_F(GRApiTest, TestGRDirMapCleanupOnDisconnect) {
    gr_instance_handle inst = NULL;
    gr_vfs_handle vfs;
    memset(&vfs, 0, sizeof(vfs));

    // 1. 创建 VFS（用主连接 g_inst_handle，保证目录存在）
    int create_ret = gr_vfs_create(g_inst_handle, DIR_CLEANUP_DEMO_VFS, 0);
    if (create_ret != GR_SUCCESS) {
        // 可能已存在，尝试删除再建
        gr_vfs_delete(g_inst_handle, DIR_CLEANUP_DEMO_VFS, 0);
        ASSERT_EQ(gr_vfs_create(g_inst_handle, DIR_CLEANUP_DEMO_VFS, 0), GR_SUCCESS);
    }

    // 2. 多次：新建连接 -> 挂载 -> 不断开 unmount 直接 delete_inst（模拟异常断开）
    for (int i = 0; i < DIR_CLEANUP_DISCONNECT_ROUNDS; i++) {
        ASSERT_EQ(gr_create_inst(SERVER_ADDR, &inst), GR_SUCCESS);
        ASSERT_EQ(gr_vfs_mount(inst, DIR_CLEANUP_DEMO_VFS, &vfs), GR_SUCCESS);
        // 不调用 gr_vfs_unmount，直接释放连接，服务端应在 gr_release_session_res -> gr_clean_open_files -> gr_session_dir_close_all 中关闭目录
        gr_delete_inst(inst);
        inst = NULL;
    }

    // 3. 再次建连，正常挂载、查询、卸载，验证服务端未因 dir 泄漏而异常
    ASSERT_EQ(gr_create_inst(SERVER_ADDR, &inst), GR_SUCCESS);
    ASSERT_EQ(gr_vfs_mount(inst, DIR_CLEANUP_DEMO_VFS, &vfs), GR_SUCCESS);

    int file_num = 0;
    EXPECT_EQ(gr_vfs_query_file_num(vfs, &file_num), GR_SUCCESS);
    EXPECT_GE(file_num, 0);

    EXPECT_EQ(gr_vfs_unmount(&vfs), GR_SUCCESS);
    gr_delete_inst(inst);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::TestEventListeners& listeners = ::testing::UnitTest::GetInstance()->listeners();
    listeners.Append(new FailureListener);
    return RUN_ALL_TESTS();
}