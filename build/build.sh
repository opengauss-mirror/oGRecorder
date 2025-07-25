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
# Description  : wr build for opengauss
#############################################################################

set -e

function print_help()
{
    echo "Usage: $0 [OPTION]
    -h|--help              show help information.
    -3rd|--binarylib_dir   the directory of third party binarylibs.
    -m|--version_mode      this values of paramenter is Debug, Release, Memcheck, DebugWRtest, ReleaseWRtest, MemcheckWRtest the default value is Release.
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

enable_wrtest=OFF
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
if [ ! "$version_mode"x == "Debug"x ] && [ ! "$version_mode"x == "Release"x ] && [ ! "$version_mode"x == "DebugWRtest"x ] && [ ! "$version_mode"x == "ReleaseWRtest"x ] && [ ! "$version_mode"x == "Memcheck"x ] && [ ! "$version_mode"x == "MemcheckWRtest"x ]; then
    echo "ERROR: version_mode param is error"
    exit 1
fi
if [ "$version_mode"x == "DebugWRtest"x ]; then
    version_mode=Debug
    enable_wrtest=ON
fi
if [ "$version_mode"x == "ReleaseWRtest"x ]; then
    version_mode=Release
    enable_wrtest=ON
fi
if [ "$version_mode"x == "MemcheckWRtest"x ]; then
    version_mode=Memcheck
    enable_wrtest=ON
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
export OUT_PACKAGE=wr

export WR_OPEN_SRC_PATH=$(pwd)/../open_source
export WR_LIBRARYS=$(pwd)/../library

[ -d "${WR_LIBRARYS}" ] && rm -rf ${WR_LIBRARYS}
mkdir -p $WR_LIBRARYS/huawei_security
mkdir -p $WR_LIBRARYS/openssl
mkdir -p $WR_LIBRARYS/zlib
mkdir -p $WR_LIBRARYS/lz4
mkdir -p $WR_LIBRARYS/libaio/include
mkdir -p $WR_LIBRARYS/cbb

export LIB_PATH=$binarylib_dir/kernel/dependency
export P_LIB_PATH=$binarylib_dir/kernel/platform
COPT_LIB_PATH=${binarylib_dir}/kernel/component

cp -r $P_LIB_PATH/Huawei_Secure_C/comm/lib     $WR_LIBRARYS/huawei_security/lib
cp -r $LIB_PATH/openssl/comm/lib               $WR_LIBRARYS/openssl/lib
cp -r $LIB_PATH/zlib1.2.11/comm/lib            $WR_LIBRARYS/zlib/lib
cp -r $LIB_PATH/lz4/comm/lib                   $WR_LIBRARYS/lz4/lib

cp -r $P_LIB_PATH/Huawei_Secure_C/comm/include    $WR_LIBRARYS/huawei_security/include
cp -r $LIB_PATH/openssl/comm/include              $WR_LIBRARYS/openssl/include
cp -r $LIB_PATH/zlib1.2.11/comm/include           $WR_LIBRARYS/zlib/include
cp -r $LIB_PATH/lz4/comm/include                  $WR_LIBRARYS/lz4/include

status=0
if [ -f "/usr/include/libaio.h" ];then
    echo "begin cp libaio.h from /usr/include/"
    cp -r /usr/include/libaio.h                   $WR_LIBRARYS/libaio/include
    status=1
fi

if [ ${status} -eq 0 ];then
    for file in "${WR_OPEN_SRC_PATH}"/libaio/libaio-*/src/libaio.h
    do
        if [ -f "${file}" ];then
            echo "begin cp libaio.h from open_source/libaio/"
            cp -r ${WR_OPEN_SRC_PATH}/libaio/libaio-*/src/libaio.h $WR_LIBRARYS/libaio/include
            status=1
        fi
    done

    if [ ${status} -eq 0 ];then
        echo "system does not install libaio software, pls install by yum install libaio-devel"
        exit 1
    fi
fi

cp -r $COPT_LIB_PATH/cbb/include                  $WR_LIBRARYS/cbb/include
cp -r $COPT_LIB_PATH/cbb/lib                      $WR_LIBRARYS/cbb/lib

cd $WR_LIBRARYS/openssl/lib
cp -r libssl_static.a libssl.a
cp -r libcrypto_static.a libcrypto.a

cd $PACKAGE
if [ "$build_tool"x == "cmake"x ];then
    cmake_opts="-DCMAKE_BUILD_TYPE=${version_mode} -DENABLE_WRTEST=${enable_wrtest} -DOPENGAUSS_FLAG=ON -DIOFENCE_FLAG=OFF -DVG_FILE_LOCK=OFF \
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
cp -r output/lib/libwr* $binarylib_dir/kernel/component/${OUT_PACKAGE}/lib
cp -r output/bin/wr* $binarylib_dir/kernel/component/${OUT_PACKAGE}/bin
cp -r src/interface/*.h $binarylib_dir/kernel/component/${OUT_PACKAGE}/include
echo "build WR SUCCESS"

if [ "$pkg_flag"x == "ON"x ]; then
    pkg_name="wr_package.tar.gz"
    tmp_dir="wr_package_tmp"
    rm -rf $tmp_dir
    mkdir -p $tmp_dir/bin
    mkdir -p $tmp_dir/lib
    mkdir -p $tmp_dir/include

    cp -r output/bin/wr* $tmp_dir/bin/
    cp -r output/lib/libwr* $tmp_dir/lib/
    cp -r src/interface/*.h $tmp_dir/include/

    tar -czvf $pkg_name -C $tmp_dir .
    rm -rf $tmp_dir
    echo "Package created: $pkg_name"
fi