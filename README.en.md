# GR

GR: WAL Recorder, a basic component providing WAL log recording services.

## 1. Project Description

### 1. Programming Language
- C

### 2. Build Tools
- cmake or make, cmake is recommended

### 3. Directory Structure
- **GR**: Main directory, CMakeLists.txt is the main project entry;
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

### 2. Download GR
GR can be downloaded from the open-source community.

### 3. Code Compilation
Use `GR/build/build.sh` to compile the code. The parameters are explained in the table below.

| Option | Parameter          | Description                                      |
|--------|--------------------|--------------------------------------------------|
| -3rd   | [binarylibs path]  | Specify the binarylibs path. It must be an absolute path. |
| -m     | [version_mode]     | Target version for compilation, Debug or Release. Default is Release. |
| -t     | [build_tool]       | Specify the build tool, cmake or make. Default is cmake. |
| -pkg   | No required        | Switch parameter for whether to generate an installation package, default is not to generate; specify this parameter to generate the installation package. |

To compile, simply use the following command:

```bash
[user@linux]$ sh build.sh -3rd [binarylibs path] -m Release -t cmake -pkg
```

After compilation, the dynamic libraries are generated in the `GR/output/lib` directory, and the executables are generated in the `GR/output/bin` directory, the installation package is generated in the `GR` directory (package name: openGauss-oGRecorder-xxxx.tar.gz).After compilation, the dynamic libraries are placed in the `GR/output/lib` directory, the executables are placed in the `GR/output/bin` directory, and the installation package (named `openGauss-oGRecorder-xxxx.tar.gz`) is generated in the `GR` directory.

### 4. UT Testing
Modify `GR/test/test_home/test_env` to set `CODE_BASE` to the absolute path of the GR directory. Execute `GR/test/gtest/build.sh` to compile the UT code.

```bash
./test_api
```