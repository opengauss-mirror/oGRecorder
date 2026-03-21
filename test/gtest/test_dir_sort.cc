/*
 * 单独验证 VFS 目录列举按字典序排序（gr_filesystem_query_file_info 的快照 + qsort）。
 * 依赖：GR Server 已启动，地址与 test_api 一致。
 *
 * 运行（在 test/gtest 构建目录）：
 *   ./test_dir_sort
 * 或：
 *   ctest -R DirSort -V
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "gr_api.h"
}

static const char *kServerAddr = "127.0.0.1:19225";
static const int kBatchCap = 100; /* 与服务端 GR_MAX_FILE_NUM 一致 */

static void CollectAllNames(gr_vfs_handle vfs, std::vector<std::string> *out)
{
    out->clear();
    gr_file_item_t *batch = new gr_file_item_t[kBatchCap];
    bool cont = false;
    for (;;) {
        memset(batch, 0, sizeof(gr_file_item_t) * (size_t)kBatchCap);
        int ret = gr_vfs_query_file_info(vfs, batch, cont);
        ASSERT_EQ(ret, GR_SUCCESS);
        int got = 0;
        for (int i = 0; i < kBatchCap; ++i) {
            if (batch[i].name[0] == '\0') {
                break;
            }
            out->push_back(batch[i].name);
            ++got;
        }
        if (got == 0) {
            break;
        }
        cont = true;
    }
    delete[] batch;
}

static bool IsNonDecreasing(const std::vector<std::string> &names)
{
    for (size_t i = 1; i < names.size(); ++i) {
        if (names[i - 1] > names[i]) {
            return false;
        }
    }
    return true;
}

class DirSortTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        gr_param_t param{};
        (void)strcpy(param.log_home, "./testlog_dirsort");
        param.log_level = 255;
        param.log_backup_file_count = 10;
        param.log_max_file_size = 1024ULL * 1024 * 1024;
        ASSERT_EQ(gr_init(param), GR_SUCCESS);
    }

    void TearDown() override { gr_exit(); }

    static void EnsureFreshVfs(gr_instance_handle inst, const char *vfs_name)
    {
        bool exist = false;
        ASSERT_EQ(gr_vfs_exist(inst, vfs_name, &exist), GR_SUCCESS);
#ifdef ENABLE_WORM
        if (exist) {
            FAIL() << "VFS " << vfs_name << " 已存在；WORM 构建无法 gr_vfs_delete 清理，请换干净环境或改名";
        }
#else
        if (exist) {
            ASSERT_EQ(gr_vfs_delete(inst, vfs_name, 1), GR_SUCCESS);
        }
#endif
        ASSERT_EQ(gr_vfs_create(inst, vfs_name, 0), GR_SUCCESS);
    }
};

/* 少量文件、故意乱序创建，期望一次查询内为 strcmp 字典序 */
TEST_F(DirSortTest, VfsQueryFileInfo_LexicographicOrder)
{
    gr_instance_handle inst = NULL;
    ASSERT_EQ(gr_create_inst(kServerAddr, &inst), GR_SUCCESS);

    const char *vfs_name = "vfs_dsort_sm";
    EnsureFreshVfs(inst, vfs_name);

    gr_vfs_handle vfs{};
    ASSERT_EQ(gr_vfs_mount(inst, vfs_name, &vfs), GR_SUCCESS);

    const char *create_order[] = {"sort_z_last", "sort_a_first", "sort_m_mid", "sort_09", "sort_10"};
    const size_t n = sizeof(create_order) / sizeof(create_order[0]);
    for (size_t i = 0; i < n; ++i) {
        ASSERT_EQ(gr_file_create(vfs, create_order[i], NULL), GR_SUCCESS);
    }

    int file_num = 0;
    ASSERT_EQ(gr_vfs_query_file_num(vfs, &file_num), GR_SUCCESS);
    ASSERT_EQ(file_num, (int)n);

    std::vector<std::string> names;
    CollectAllNames(vfs, &names);
    ASSERT_EQ(names.size(), n);
    EXPECT_TRUE(IsNonDecreasing(names));

    const char *expected[] = {"sort_09", "sort_10", "sort_a_first", "sort_m_mid", "sort_z_last"};
    for (size_t i = 0; i < n; ++i) {
        EXPECT_STREQ(names[i].c_str(), expected[i]);
    }

    /* 游标耗尽后再 continue，应返回空批 */
    gr_file_item_t tail[kBatchCap];
    memset(tail, 0, sizeof(tail));
    EXPECT_EQ(gr_vfs_query_file_info(vfs, tail, true), GR_SUCCESS);
    EXPECT_EQ(tail[0].name[0], '\0');

    ASSERT_EQ(gr_vfs_unmount(&vfs), GR_SUCCESS);
#ifndef ENABLE_WORM
    EXPECT_EQ(gr_vfs_delete(inst, vfs_name, 1), GR_SUCCESS);
#endif
    gr_delete_inst(inst);
}

/*
 * 超过单页上限（服务端每页 100），验证全局有序且分页边界正确。
 * 文件名固定宽度，字典序与编号序一致。
 */
TEST_F(DirSortTest, VfsQueryFileInfo_PaginationKeepsGlobalOrder)
{
    const int total = 105;
    gr_instance_handle inst = NULL;
    ASSERT_EQ(gr_create_inst(kServerAddr, &inst), GR_SUCCESS);

    const char *vfs_name = "vfs_dsort_pg";
    EnsureFreshVfs(inst, vfs_name);

    gr_vfs_handle vfs{};
    ASSERT_EQ(gr_vfs_mount(inst, vfs_name, &vfs), GR_SUCCESS);

    /* 倒序创建，避免偶然与磁盘顺序一致 */
    for (int i = total - 1; i >= 0; --i) {
        char name[GR_MAX_NAME_LEN];
        snprintf(name, sizeof(name), "pg_%03d", i);
        ASSERT_EQ(gr_file_create(vfs, name, NULL), GR_SUCCESS);
    }

    int file_num = 0;
    ASSERT_EQ(gr_vfs_query_file_num(vfs, &file_num), GR_SUCCESS);
    ASSERT_EQ(file_num, total);

    gr_file_item_t batch[kBatchCap];
    memset(batch, 0, sizeof(batch));
    ASSERT_EQ(gr_vfs_query_file_info(vfs, batch, false), GR_SUCCESS);

    int first_page = 0;
    for (int i = 0; i < kBatchCap && batch[i].name[0]; ++i) {
        ++first_page;
    }
    EXPECT_EQ(first_page, kBatchCap);

    char expect_first[GR_MAX_NAME_LEN];
    snprintf(expect_first, sizeof(expect_first), "pg_%03d", 0);
    EXPECT_STREQ(batch[0].name, expect_first);

    memset(batch, 0, sizeof(batch));
    ASSERT_EQ(gr_vfs_query_file_info(vfs, batch, true), GR_SUCCESS);
    int second_page = 0;
    for (int i = 0; i < kBatchCap && batch[i].name[0]; ++i) {
        ++second_page;
    }
    EXPECT_EQ(second_page, total - kBatchCap);

    char expect_100[GR_MAX_NAME_LEN];
    snprintf(expect_100, sizeof(expect_100), "pg_%03d", kBatchCap);
    EXPECT_STREQ(batch[0].name, expect_100);

    std::vector<std::string> all;
    CollectAllNames(vfs, &all);
    ASSERT_EQ(all.size(), (size_t)total);
    EXPECT_TRUE(IsNonDecreasing(all));

    ASSERT_EQ(gr_vfs_unmount(&vfs), GR_SUCCESS);
#ifndef ENABLE_WORM
    EXPECT_EQ(gr_vfs_delete(inst, vfs_name, 1), GR_SUCCESS);
#endif
    gr_delete_inst(inst);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
