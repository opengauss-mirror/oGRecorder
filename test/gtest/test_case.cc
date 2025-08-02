#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "wr_api.h"

/* gcc -o test test.c -I /usr1/hmm_wr/GR/src/interface -lwrapi -L /usr1/hmm_wr/GR/output/lib  */

/*
 * 功能描述：
 * 1. 初始化
 * 2. 创建实例
 * 3. 创建VFS
 * 4. 挂载VFS
 * 5. 查询VFS内文件数量
 * 6. 创建文件
 * 7. 构造空间不足
 * 8. 打开文件
 * 10. 删除文件
 * 11. 卸载VFS
 * 12. 删除VFS
 * 13. 删除实例
 * 14. 退出实例
*/

int errorcode = 0;
const char *errormsg = NULL;
wr_instance_handle ins_handle = NULL;
int attrFlag = 1;
int flags = O_RDWR | O_SYNC;
FileParameter *param = NULL;
wr_file_handle file_handle;

void test_wr_ini(wr_param_t param) {
    int ret = wr_init(param);
    if (ret != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_init interaction failure. code:%d msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_init interaction success. code:%d\n", errorcode);
}

void test_wr_create_inst(char *serverAddr, wr_instance_handle *ins_handle){
    int ret = wr_create_inst(serverAddr, ins_handle);
    if (ret != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_create_inst interaction failure. code:%d msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_create_inst interaction success. code:%d\n", errorcode);
}

void test_wr_vfs_create(wr_instance_handle ins_handle, char *vfsName, int attrFlag){
    int ret = wr_vfs_create(ins_handle, vfsName, attrFlag);
    if (ret != 0 ) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_vfs_create interaction failure. code:%d msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_vfs_create interaction success. code:%d\n", errorcode);
}

void test_wr_vfs_mount(wr_instance_handle ins_handle, char *vfsName, wr_vfs_handle *vfs){
    int ret = wr_vfs_mount(ins_handle, vfsName, vfs);
    if (ret != 0 ) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_vfs_mount interaction failure. code:%d msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_vfs_mount interaction success. code:%d\n", errorcode);
}

void test_vfs_query_file_num(wr_instance_handle ins_handle, char *vfsName, int *fileNum){
    int ret = wr_vfs_query_file_num(ins_handle, vfsName, fileNum);
    if (ret!= 0 ) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_vfs_query_file_num interaction failure. code:%d  msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_vfs_query_file_num interaction success. code:%d\n", errorcode);
}

void test_wr_file_create(wr_vfs_handle vfs, const char *fileName, const FileParameter *param){
    int ret = wr_file_create(vfs, fileName, param);
    if (ret!= 0 ) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_file_create interaction failure. code:%d msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_file_create interaction success. code:%d\n", errorcode);
}

void test_wr_file_open(wr_vfs_handle vfs, const char *fileName, int flags, wr_file_handle *file_handle){
    int ret = wr_file_open(vfs, fileName, flags, file_handle);
    if (ret!= 0 ) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_file_open interaction failure. code:%d msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_file_open interaction success. code:%d\n", errorcode);
}

void test_wr_file_delete(wr_vfs_handle vfs, const char *fileName){
    int ret = wr_file_delete(vfs, fileName);
    if (ret!= 0 ) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_file_delete interaction failure. code:%d msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_file_delete interaction success. code:%d\n", errorcode);
}

void test_wr_vfs_unmount(wr_vfs_handle vfs){
    int ret = wr_vfs_unmount(&vfs);
    if (ret!= 0 ) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_vfs_unmount interaction failure. code:%d msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_vfs_unmount interaction success. code:%d\n", errorcode);
}

void test_wr_vfs_delete(wr_instance_handle ins_handle, char *vfsName, int attrFlag){
    int ret = wr_vfs_delete(ins_handle, vfsName, attrFlag);
    if (ret != 0 ) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_vfs_delete interaction failure. code:%d msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_vfs_delete interaction success. code:%d\n", errorcode);
}

void test_wr_delete_inst(wr_instance_handle ins_handle){
    int ret = wr_delete_inst(ins_handle);
    if (ret != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_delete_inst interaction failure. code:%d msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_delete_inst interaction success. code:%d\n", errorcode);
}

void test_wr_exit() {
    int ret = wr_exit();
    if (ret != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("wr_exit interaction failure. code:%d msg:%s\n", errorcode, errormsg);
        return;
    }
    printf("wr_exit interaction success. code:%d\n", errorcode);
}

wr_vfs_handle vfs;

int main(int argc, char *argv[]) {
    // 初始化日志模块
    wr_param_t param;
    strcpy(param.log_home, "./test_re_wr_case07");
    param.log_level = 255;
    param.log_backup_file_count = 200;
    param.log_max_file_size = 4096;
    test_wr_ini(param);

    // 创建实例
    char *serverAddr = argv[1];
    test_wr_create_inst(serverAddr, &ins_handle);

    // 创建VFS
    const char *vfsName = "test_re_vfs_case007";
    test_wr_vfs_create(ins_handle, vfsName, attrFlag);

    // 挂载VFS
    test_wr_vfs_mount(ins_handle, vfsName, &vfs);

    // 查询VFS内文件数量
    int fileNum;
    test_vfs_query_file_num(ins_handle, vfsName, &fileNum);
    printf("The number of files in the VFS is: %d\n", fileNum);

    // 创建文件
    FileParameter file_param;
    const char *fileName = "test_re_file_case007";
    test_wr_file_create(vfs, fileName, &file_param);

    // 打开文件
    //int fd;
    test_wr_file_open(vfs, fileName, flags, &file_handle);

    // 删除文件
    test_wr_file_delete(vfs, fileName);

    // 卸载VFS
    test_wr_vfs_unmount(vfs);

    // 删除VFS
    test_wr_vfs_delete(ins_handle, vfsName, attrFlag);

    // 删除实例句柄
    test_wr_delete_inst(ins_handle);

    // 退出实例
    test_wr_exit();
    return 0;
}