#!/bin/bash
#############################################################################
# Copyright (c) 2020 Huawei Technologies Co.,Ltd.
#
# openGauss is licensed under Mulan PSL v2.
# You can use this software according to the terms
# and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# ----------------------------------------------------------------------------
# Description  : gr build for opengauss
#############################################################################

set -e

function print_help()
{
    echo "Usage: $0 [OPTION]
    -h|--help              show help information.
    -3rd|--binarylib_dir   the directory of third party binarylibs.
    -m|--version_mode      this values of paramenter is Debug, Release, Memcheck, DebugGRtest, ReleaseGRtest, MemcheckGRtest the default value is Release.
    -t|--build_tool          this values of parameter is cmake, make, the default value is cmake.
    -s|--storage_mode      storage device type. values is disk, ceph. default is disk. 
"
}

pkg_flag=OFF

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            print_help
            exit 1
            ;;
        -3rd|--binarylib_dir)
            if [ "$2"X = X ]; then
                echo "no given binarylib directory values"
                exit 1
            fi
            binarylib_dir=$2
            shift 2
            ;;
        -m|--version_mode)
          if [ "$2"X = X ]; then
              echo "no given version number values"
              exit 1
          fi
          version_mode=$2
          shift 2
          ;;
        -t|--build_tool)
          if [ "$2"X = X ]; then
              echo "no given build_tool values"
              exit 1
          fi
          build_tool=$2
          shift 2
          ;;
        -s|--storage_mode)
          storage_mode=$2
          shift 2
          ;;
        --pkg|-pkg)
          pkg_flag=ON
          shift 1
          ;;
         *)
            echo "Internal Error: option processing error: $1" 1>&2
            echo "please input right paramtenter, the following command may help you"
            echo "./build.sh --help or ./build.sh -h"
            exit 1
    esac
done

enable_grtest=OFF
if [ -z "${version_mode}" ] || [ "$version_mode"x == ""x ]; then
    version_mode=Release
fi
if [ -z "${binarylib_dir}" ]; then
    echo "ERROR: 3rd bin dir not set"
    exit 1
fi
if [ -z "${build_tool}" ] || [ "$build_tool"x == ""x ]; then
    build_tool=cmake
fi
if [ ! "$version_mode"x == "Debug"x ] && [ ! "$version_mode"x == "Release"x ] && [ ! "$version_mode"x == "DebugGRtest"x ] && [ ! "$version_mode"x == "ReleaseGRtest"x ] && [ ! "$version_mode"x == "Memcheck"x ] && [ ! "$version_mode"x == "MemcheckGRtest"x ]; then
    echo "ERROR: version_mode param is error"
    exit 1
fi
if [ "$version_mode"x == "DebugGRtest"x ]; then
    version_mode=Debug
    enable_grtest=ON
fi
if [ "$version_mode"x == "ReleaseGRtest"x ]; then
    version_mode=Release
    enable_grtest=ON
fi
if [ "$version_mode"x == "MemcheckGRtest"x ]; then
    version_mode=Memcheck
    enable_grtest=ON
fi
if [ ! "$build_tool"x == "make"x ] && [ ! "$build_tool"x == "cmake"x ]; then
    echo "ERROR: build_tool param is error"
    exit 1
fi

declare export_api=ON

export CFLAGS="-std=gnu99"

LOCAL_PATH=${0}

CUR_PATH=$(pwd)
LOCAL_DIR=$(dirname "${LOCAL_PATH}")
export PACKAGE=$CUR_PATH/../
export OUT_PACKAGE=gr

export GR_OPEN_SRC_PATH=$(pwd)/../open_source
export GR_LIBRARYS=$(pwd)/../library

[ -d "${GR_LIBRARYS}" ] && rm -rf ${GR_LIBRARYS}
mkdir -p $GR_LIBRARYS/huawei_security
mkdir -p $GR_LIBRARYS/openssl
mkdir -p $GR_LIBRARYS/zlib
mkdir -p $GR_LIBRARYS/cbb

export LIB_PATH=$binarylib_dir/kernel/dependency
export P_LIB_PATH=$binarylib_dir/kernel/platform
COPT_LIB_PATH=${binarylib_dir}/kernel/component

cp -r $P_LIB_PATH/Huawei_Secure_C/comm/lib     $GR_LIBRARYS/huawei_security/lib
cp -r $LIB_PATH/openssl/comm/lib               $GR_LIBRARYS/openssl/lib
cp -r $LIB_PATH/zlib1.2.11/comm/lib            $GR_LIBRARYS/zlib/lib

cp -r $P_LIB_PATH/Huawei_Secure_C/comm/include    $GR_LIBRARYS/huawei_security/include
cp -r $LIB_PATH/openssl/comm/include              $GR_LIBRARYS/openssl/include
cp -r $LIB_PATH/zlib1.2.11/comm/include           $GR_LIBRARYS/zlib/include
cp -r $COPT_LIB_PATH/cbb/include                  $GR_LIBRARYS/cbb/include
cp -r $COPT_LIB_PATH/cbb/lib                      $GR_LIBRARYS/cbb/lib

cd $GR_LIBRARYS/openssl/lib
cp -r libssl_static.a libssl.a
cp -r libcrypto_static.a libcrypto.a

cd $PACKAGE
if [ "$build_tool"x == "cmake"x ];then
    cmake_opts="-DCMAKE_BUILD_TYPE=${version_mode} -DENABLE_GRTEST=${enable_grtest} -DOPENGAUSS_FLAG=ON -DIOFENCE_FLAG=OFF -DVG_FILE_LOCK=OFF \
    -DENABLE_EXPORT_API=${export_api}"
    cmake ${cmake_opts} CMakeLists.txt
    make all -sj 8
else
    make clean
    make BUILD_TYPE=${version_mode} -sj 8
fi

mkdir -p $binarylib_dir/kernel/component/${OUT_PACKAGE}/bin
mkdir -p $binarylib_dir/kernel/component/${OUT_PACKAGE}/lib
mkdir -p $binarylib_dir/kernel/component/${OUT_PACKAGE}/include
cp -r output/lib/libgr* $binarylib_dir/kernel/component/${OUT_PACKAGE}/lib
cp -r output/bin/gr* $binarylib_dir/kernel/component/${OUT_PACKAGE}/bin
cp -r src/interface/*.h $binarylib_dir/kernel/component/${OUT_PACKAGE}/include
echo "build GR SUCCESS"

os_name=$(source /etc/os-release && echo ${NAME} | tr ' ' '_')
os_version=$(source /etc/os-release && echo ${VERSION_ID})
arch=$(uname -m)
gr_version="7.0.0-RC2"
pkg_name="openGauss-oGRecorder-${gr_version}-${os_name}${os_version}-${arch}.tar.gz"

if [ "$pkg_flag"x == "ON"x ]; then
    tmp_dir="gr_package_tmp"
    rm -rf $tmp_dir

    # server 目录
    mkdir -p $tmp_dir/oGRecorder-Server/bin
    mkdir -p $tmp_dir/oGRecorder-Server/lib
    mkdir -p $tmp_dir/oGRecorder-Server/install

    cp -r output/bin/gr* $tmp_dir/oGRecorder-Server/bin/
    cp -r output/lib/libgr* $tmp_dir/oGRecorder-Server/lib/
    cp -r install/* $tmp_dir/oGRecorder-Server/install/

    # sdk 目录
    mkdir -p $tmp_dir/oGRecorder-SDK/include
    mkdir -p $tmp_dir/oGRecorder-SDK/lib

    cp -r src/interface/*.h $tmp_dir/oGRecorder-SDK/include/
    cp -r output/lib/libgr* $tmp_dir/oGRecorder-SDK/lib/

    # 分别压缩 server 和 sdk（只打包内容，不带顶层目录）
    tar -czvf $tmp_dir/oGRecorder-Server.tar.gz -C $tmp_dir/oGRecorder-Server . 
    tar -czvf $tmp_dir/oGRecorder-SDK.tar.gz -C $tmp_dir/oGRecorder-SDK .

    # 再打成总包
    tar -czvf $pkg_name -C $tmp_dir oGRecorder-Server.tar.gz oGRecorder-SDK.tar.gz

    rm -rf $tmp_dir
    echo "Package created: $pkg_name"
fi