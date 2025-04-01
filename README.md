# WR

WR：WAL Recorder，WAL日志记录器，是一款提供WAL日志记录服务的基础组件。

## 一、工程说明

### 1. 编程语言
- C

### 2. 编译工具
- cmake或make，建议使用cmake

### 3. 目录说明
- **WR**：主目录，CMakeLists.txt为主工程入口；
- **src**: 源代码目录，按子目录划分通用功能函数；
- **build/build.sh**：工程构建脚本

## 二、编译指导

### 1. 操作系统和软件依赖要求
支持以下操作系统：
- CentOS 7.6（x86）
- openEuler-20.03-LTS
- openEuler-22.03-LTS
- openEuler-24.03-LTS

适配其他系统，可参照openGauss数据库编译指导。

### 2. 下载WR
可以从开源社区下载WR。

### 3. 代码编译
使用 `WR/build/build.sh` 编译代码, 参数说明请见以下表格。

| 选项 | 参数               | 说明                                     |
|------|--------------------|------------------------------------------|
| -3rd | [binarylibs path]  | 指定binarylibs路径。该路径必须是绝对路径。|
| -m   | [version_mode]     | 编译目标版本，Debug或者Release。默认Release|
| -t   | [build_tool]       | 指定编译工具，cmake或者make。默认cmake   |

现在只需使用如下命令即可编译：

```bash
[user@linux]$ sh build.sh -3rd [binarylibs path] -m Release -t cmake
```

完成编译后，动态库生成在 `WR/output/lib` 目录中，可执行文件生成在 `WR/output/bin` 目录中。

### 4. UT测试
修改 `WR/test/test_home/test_env` 中的 `CODE_BASE` 为WR目录的绝对路径。执行 `WR/test/gtest/build.sh` 编译UT代码。

```bash
./test_wr_api
```