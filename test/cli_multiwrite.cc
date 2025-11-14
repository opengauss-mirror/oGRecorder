#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <iostream>
#include <fcntl.h>

extern "C" {
#include "gr_api.h"
#include "gr_errno.h"
}

static void print_usage(const char *prog) {
    printf("Usage: %s --server <addr[,addr2,...]> [--vfs <name>] [--file <name>] [--step_mb <n>] [--total_mb <n>]\n", prog);
    printf("  --server    服务器地址，例: 127.0.0.1:19225 或 20.20.20.56:16364,20.20.20.54:16364\n");
    printf("  --vfs       VFS名称（默认: testdir_cli）\n");
    printf("  --file      文件名（默认: testfile_cli）\n");
    printf("  --step_mb   单次写入大小MB（默认: 1）\n");
    printf("  --total_mb  总写入大小MB（默认: 1024，即1GB）\n");
}

int main(int argc, char **argv) {
    const char *server = nullptr;
    std::string vfs_name = "testdir_cli";
    std::string file_name = "testfile_cli";
    long long step_mb = 1;        // 1MB
    long long total_mb = 1024;    // 1GB

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            server = argv[++i];
        } else if (strcmp(argv[i], "--vfs") == 0 && i + 1 < argc) {
            vfs_name = argv[++i];
        } else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            file_name = argv[++i];
        } else if (strcmp(argv[i], "--step_mb") == 0 && i + 1 < argc) {
            step_mb = atoll(argv[++i]);
        } else if (strcmp(argv[i], "--total_mb") == 0 && i + 1 < argc) {
            total_mb = atoll(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            printf("Unknown arg: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (server == nullptr) {
        printf("Error: --server is required\n");
        print_usage(argv[0]);
        return 1;
    }

    // 初始化日志（可选）
    gr_param_t gr_param;
    memset(&gr_param, 0, sizeof(gr_param));
    strcpy(gr_param.log_home, "./testlog");
    gr_param.log_level = 255;
    gr_param.log_backup_file_count = 10;
    gr_param.log_max_file_size = 1024 * 1024 * 1024; // 1GB
    (void)gr_init(gr_param);

    gr_instance_handle inst = NULL;
    int ret = gr_create_inst(server, &inst);
    if (ret != GR_SUCCESS) {
        int errcode; const char *errmsg = NULL;
        gr_get_error(&errcode, &errmsg);
        printf("Failed to create instance. code:%d msg:%s\n", errcode, errmsg ? errmsg : "");
        return 2;
    }

    // 创建VFS（忽略已存在错误）
    (void)gr_vfs_create(inst, vfs_name.c_str(), 0);

    gr_vfs_handle vfs = NULL;
    ret = gr_vfs_mount(inst, vfs_name.c_str(), &vfs);
    if (ret != GR_SUCCESS) {
        int errcode; const char *errmsg = NULL;
        gr_get_error(&errcode, &errmsg);
        printf("Failed to mount vfs '%s'. code:%d msg:%s\n", vfs_name.c_str(), errcode, errmsg ? errmsg : "");
        (void)gr_delete_inst(inst);
        return 3;
    }

    // 创建文件（忽略已存在错误）
    (void)gr_file_create(vfs, file_name.c_str(), NULL);

    gr_file_handle fh;
    ret = gr_file_open(vfs, file_name.c_str(), O_RDWR | O_SYNC, &fh);
    if (ret != GR_SUCCESS) {
        int errcode; const char *errmsg = NULL;
        gr_get_error(&errcode, &errmsg);
        printf("Failed to open file '%s'. code:%d msg:%s\n", file_name.c_str(), errcode, errmsg ? errmsg : "");
        (void)gr_vfs_unmount(&vfs);
        (void)gr_delete_inst(inst);
        return 4;
    }

    const size_t step_size = (size_t)step_mb * 1024 * 1024;
    const long long total_size = total_mb * 1024LL * 1024LL;

    std::vector<char> buf(step_size, 'C');

    auto total_start = std::chrono::high_resolution_clock::now();
    double total_latency_ms = 0.0;
    long long write_count = (total_size + step_size - 1) / step_size;

    for (long long offset = 0, idx = 0; offset < total_size; offset += step_size, ++idx) {
        size_t curr = (size_t)std::min<long long>(step_size, total_size - offset);
        auto t1 = std::chrono::high_resolution_clock::now();
        int w = gr_file_pwrite(vfs, &fh, buf.data(), curr, offset);
        auto t2 = std::chrono::high_resolution_clock::now();
        if (w != (int)curr) {
            int errcode; const char *errmsg = NULL;
            gr_get_error(&errcode, &errmsg);
            printf("gr_file_pwrite failure at idx=%lld. expect=%zu got=%d code:%d msg:%s\n",
                   idx, curr, w, errcode, errmsg ? errmsg : "");
            break;
        }
        std::chrono::duration<double, std::milli> lat = t2 - t1;
        total_latency_ms += lat.count();
    }

    auto total_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_dur = total_end - total_start;
    double seconds = total_dur.count();
    double mb = total_size / (1024.0 * 1024.0);
    double speed = seconds > 0 ? (mb / seconds) : 0.0;
    double avg_latency = write_count > 0 ? (total_latency_ms / write_count) : 0.0;

    std::cout << "VFS: " << vfs_name
              << ", File: " << file_name
              << ", Total: " << mb << " MB"
              << ", Step: " << step_mb << " MB"
              << ", Speed: " << speed << " MB/s"
              << ", AvgLatency: " << avg_latency << " ms" << std::endl;

    (void)gr_file_close(vfs, &fh, false);
    (void)gr_vfs_unmount(&vfs);
    // 可选：清理VFS内文件及目录
    // (void)gr_vfs_delete(inst, vfs_name.c_str(), 1);
    (void)gr_delete_inst(inst);

    return 0;
}
