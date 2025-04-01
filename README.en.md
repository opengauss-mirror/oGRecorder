# WR

WR: WAL Recorder, a basic component providing WAL log recording services.

## 1. Project Description

### 1. Programming Language
- C

### 2. Build Tools
- cmake or make, cmake is recommended

### 3. Directory Structure
- **WR**: Main directory, CMakeLists.txt is the main project entry;
- **src**: Source code directory, divided into subdirectories for common function modules;
- **build/build.sh**: Project build script

## 2. Compilation Guide

### 1. Supported Operating Systems and Software Dependencies
Supported operating systems:
- CentOS 7.6 (x86)
- openEuler-20.03-LTS
- openEuler-22.03-LTS
- openEuler-24.03-LTS

For other systems, refer to the openGauss database compilation guide.

### 2. Download WR
WR can be downloaded from the open-source community.

### 3. Code Compilation
Use `WR/build/build.sh` to compile the code. The parameters are explained in the table below.

| Option | Parameter          | Description                                      |
|--------|--------------------|--------------------------------------------------|
| -3rd   | [binarylibs path]  | Specify the binarylibs path. It must be an absolute path. |
| -m     | [version_mode]     | Target version for compilation, Debug or Release. Default is Release. |
| -t     | [build_tool]       | Specify the build tool, cmake or make. Default is cmake. |

To compile, simply use the following command:

```bash
[user@linux]$ sh build.sh -3rd [binarylibs path] -m Release -t cmake
```

After compilation, the dynamic libraries are generated in the `WR/output/lib` directory, and the executables are generated in the `WR/output/bin` directory.

### 4. UT Testing
Modify `WR/test/test_home/test_env` to set `CODE_BASE` to the absolute path of the WR directory. Execute `WR/test/gtest/build.sh` to compile the UT code.

```bash
./test_wr_api
```