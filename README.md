# WR

WR：Distributed Storage Service，分布式存储服务，是一款提供分布式存储服务的基础组件。
支持裸设备的访问及管理，提供卷组、卷、目录、文件的创建、删除、访问等API操作及运维工具；支持多节点相同文件元数据同步，支撑数据库共享存储架构。

#### 一、工程说明
##### 1、编程语言：C
##### 2、编译工具：cmake或make，建议使用cmake
##### 3、目录说明：
-   WR：主目录，CMakeLists.txt为主工程入口；
-   src: 源代码目录，按子目录划分通用功能函数；
-   build：工程构建脚本

#### 二、编译指导
##### 1、操作系统和软件依赖要求
支持以下操作系统：
-   CentOS 7.6（x86）
-   openEuler-20.03-LTS
-   openEuler-22.03-LTS
-   openEuler-24.03-LTS

适配其他系统，可参照openGauss数据库编译指导
##### 2、下载WR
可以从开源社区下载WR。
##### 3、代码编译
使用WR/build/linux/opengauss/build.sh编译代码, 参数说明请见以下表格。<br>
| 选项 | 参数               | 说明                                     |
| ---  |:---               | :---                                     |
| -3rd | [binarylibs path] | 指定binarylibs路径。该路径必须是绝对路径。  |
| -m   | [version_mode]    | 编译目标版本，Debug或者Release。默认Release|
| -t   | [build_tool]      | 指定编译工具，cmake或者make。默认cmake     |

现在只需使用如下命令即可编译：<br>
[user@linux]$ sh build.sh -3rd [binarylibs path] -m Release -t cmake <br>
完成编译后，动态库生成在WR/output/lib目录中