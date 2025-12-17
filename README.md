# GR

GR（WAL Recorder）是一款提供WAL日志记录服务的基础组件。

## 工程说明

### 编程语言
- C

### 编译工具
- CMake（推荐）
- Make

### 目录结构
- **GR**：主目录，包含主工程入口`CMakeLists.txt`
- **src**：源代码目录，按子目录划分通用功能函数
- **build/build.sh**：工程构建脚本

## 编译指导

### 操作系统和软件依赖
支持以下操作系统：
- CentOS 7.6（x86）
- openEuler-20.03-LTS
- openEuler-22.03-LTS
- openEuler-24.03-LTS

适配其他系统，可参照openGauss数据库编译指导。

### 下载GR及第三方库
可以从开源社区下载GR。第三方库下载地址：

| 系统版本 | 下载链接 |
|----------|----------|
| openEuler_arm | [下载链接](https://opengauss.obs.cn-south-1.myhuaweicloud.com/latest/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_arm.tar.gz) |
| openEuler_x86 | [下载链接](https://opengauss.obs.cn-south-1.myhuaweicloud.com/latest/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_x86_64.tar.gz) |
| Centos_x86 | [下载链接](https://opengauss.obs.cn-south-1.myhuaweicloud.com/latest/binarylibs/gcc10.3/openGauss-third_party_binarylibs_Centos7.6_x86_64.tar.gz) |
| openEuler 22.03 arm | [下载链接](https://opengauss.obs.cn-south-1.myhuaweicloud.com/latest/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_2203_arm.tar.gz) |
| openEuler 22.03 x86 | [下载链接](https://opengauss.obs.cn-south-1.myhuaweicloud.com/latest/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_2203_x86_64.tar.gz) |
| openEuler 24.03 arm | [下载链接](https://opengauss.obs.cn-south-1.myhuaweicloud.com/latest/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_2403_arm.tar.gz) |
| openEuler 24.03 x86 | [下载链接](https://opengauss.obs.cn-south-1.myhuaweicloud.com/latest/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_2403_x86_64.tar.gz) |

### 代码编译
使用 `GR/build/build.sh` 编译代码，参数说明如下：

| 选项 | 参数 | 说明 |
|------|------|------|
| -3rd | [binarylibs path] | 指定binarylibs路径（三方库解压完成的路径）。该路径必须是绝对路径。|
| -m   | [version_mode] | 编译目标版本，Debug或者Release。默认Release |
| -t   | [build_tool] | 指定编译工具，cmake或者make。默认cmake |
| -pkg   | 无需参数 | 是否生成安装包的开关参数，默认不生成；指定该参数则生成安装包 |

编译命令示例：

```bash
sh build.sh -3rd [binarylibs path] -m Release -t cmake -pkg
```

编译完成后，动态库生成在 `GR/output/lib` 目录中，可执行文件生成在 `GR/output/bin` 目录中，安装包生成再 `GR` 目录中（包名：openGauss-oGRecorder-xxxx.tar.gz）。

### 使用

1. 修改 `GR/test/test_home/test_env` 中的 `CODE_BASE` 为GR目录的绝对路径。
2. 执行 `source GR/test/test_home/test_env` 设置环境变量。
3. 启动WAL日志记录服务：`grserver &`
4. 停止WAL日志记录服务：`grcmd stop`

### 单元测试

执行 `GR/test/gtest/build.sh` 编译单元测试代码：

```bash
./test_api
```
