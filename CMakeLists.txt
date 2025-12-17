CMAKE_MINIMUM_REQUIRED(VERSION 3.12.1)
PROJECT(gr)

message(${CMAKE_BUILD_TYPE})
if (${CMAKE_BUILD_TYPE} STREQUAL "Debug"
        OR ${CMAKE_BUILD_TYPE} STREQUAL "")
    message(STATUS "CMAKE_BUILD_TYPE is Debug")
    set(CMAKE_BUILD_TYPE Debug)
    add_compile_definitions(_DEBUG DB_DEBUG_VERSION)
elseif (${CMAKE_BUILD_TYPE} STREQUAL "Memcheck" OR ${CMAKE_BUILD_TYPE} STREQUAL "MemcheckGRtest")
    message(STATUS "CMAKE_BUILD_TYPE is Memcheck")
    set(CMAKE_BUILD_TYPE Memcheck)
    add_compile_definitions(_DEBUG DB_DEBUG_VERSION)
    add_compile_options(-fsanitize=address -fsanitize=leak -fno-omit-frame-pointer -lasan)
    add_link_options(-fsanitize=address -fsanitize=leak -fno-omit-frame-pointer -lasan)
    message(STATUS "Toolchain: Build with ASAN TEST Configure")
elseif (${CMAKE_BUILD_TYPE} STREQUAL "Release")
    message(STATUS "CMAKE_BUILD_TYPE is Release")
    set(CMAKE_BUILD_TYPE Release)
    set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
else ()
    message(STATUS "unknown CMAKE_BUILD_TYPE = " ${CMAKE_BUILD_TYPE})
endif ()

set(COMPONENT "oGRecorder Kernel")

option(OPENGAUSS_FLAG OFF)
if (OPENGAUSS_FLAG)
    add_definitions(-DOPENGAUSS)
    message(STATUS "openGauss on")
    set(COMPONENT "openGauss")
endif (OPENGAUSS_FLAG)

option(IOFENCE_FLAG OFF)
if (IOFENCE_FLAG)
    add_definitions(-DIOFENCE)
    message(STATUS "iofence on")
endif (IOFENCE_FLAG)

option(VG_FILE_LOCK OFF)
if (VG_FILE_LOCK)
    add_definitions(-DVG_FILE_LOCK)
    message(STATUS "vg file lock on")
endif (VG_FILE_LOCK)

# ==================== ARM 优化配置 ====================
# 自动检测ARM平台并启用优化
# 编译时硬编码选择实现分支，无运行时开销

# 自动检测ARM平台
set(IS_ARM_PLATFORM FALSE)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM|aarch64|ARM64|arm64")
    set(IS_ARM_PLATFORM TRUE)
    message(STATUS "Detected ARM platform: ${CMAKE_SYSTEM_PROCESSOR}")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # 尝试通过uname检测
    find_program(UNAME_EXECUTABLE uname)
    if(UNAME_EXECUTABLE)
        execute_process(
            COMMAND ${UNAME_EXECUTABLE} -m
            OUTPUT_VARIABLE UNAME_MACHINE
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(UNAME_MACHINE MATCHES "arm|aarch64|arm64")
            set(IS_ARM_PLATFORM TRUE)
            message(STATUS "Detected ARM platform via uname: ${UNAME_MACHINE}")
        endif()
    endif()
endif()

# 根据检测结果自动设置
if(IS_ARM_PLATFORM)
    set(ENABLE_ARM_NEON ON)
    set(ENABLE_ARM_CRC32 ON)
    message(STATUS "ARM optimizations: ENABLED (ARM platform detected)")
else()
    set(ENABLE_ARM_NEON OFF)
    set(ENABLE_ARM_CRC32 OFF)
    message(STATUS "ARM optimizations: DISABLED (not ARM platform)")
endif()

# 应用ARM NEON优化
if(ENABLE_ARM_NEON)
    message(STATUS "ARM NEON optimization: ENABLED")
    add_definitions(-DENABLE_ARM_NEON)
    
    # 检测并设置编译选项
    include(CheckCCompilerFlag)
    check_c_compiler_flag("-march=armv8-a+simd" COMPILER_SUPPORTS_ARM_NEON)
    if(COMPILER_SUPPORTS_ARM_NEON)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+simd")
        message(STATUS "  Using ARMv8 NEON instructions")
    else()
        check_c_compiler_flag("-mfpu=neon" COMPILER_SUPPORTS_ARM_NEON_V7)
        if(COMPILER_SUPPORTS_ARM_NEON_V7)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=neon -march=armv7-a")
            message(STATUS "  Using ARMv7 NEON instructions")
        else()
            message(WARNING "  Compiler may not support NEON, but ENABLE_ARM_NEON=ON")
            message(WARNING "  Continuing anyway - ensure your compiler supports NEON")
        endif()
    endif()
else()
    message(STATUS "ARM NEON optimization: DISABLED (using generic 64-bit implementation)")
endif()

# 应用ARM CRC32优化
if(ENABLE_ARM_CRC32)
    message(STATUS "ARM CRC32 hardware acceleration: ENABLED")
    add_definitions(-DENABLE_ARM_CRC32)
    
    include(CheckCCompilerFlag)
    check_c_compiler_flag("-march=armv8-a+crc" COMPILER_SUPPORTS_ARM_CRC32)
    if(COMPILER_SUPPORTS_ARM_CRC32)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+crc")
        message(STATUS "  Using ARMv8 CRC32 instructions")
    else()
        message(WARNING "  Compiler may not support CRC32, but ENABLE_ARM_CRC32=ON")
        message(WARNING "  Continuing anyway - ensure your compiler supports CRC32")
    endif()
else()
    message(STATUS "ARM CRC32 hardware acceleration: DISABLED")
endif()

# ARM平台通用优化
if(ENABLE_ARM_NEON AND CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mtune=native")
    message(STATUS "  Added -mtune=native for Release build")
endif()
# ==================== ARM 优化配置结束 ====================

EXECUTE_PROCESS(
        COMMAND bash -c "git rev-parse HEAD | cut -b 1-8"
        OUTPUT_VARIABLE COMMIT_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
EXECUTE_PROCESS(
        COMMAND bash -c "date \"+%Y-%m-%d %H:%M:%S\""
        OUTPUT_VARIABLE COMPILE_TIME
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# GR_VERSION_STR can be used for api/cmd/server
# GR_VERSION_STR like: (openGauss build ab4a14da) compiled at 2000-01-01 00:00:00 debug)
if (ENABLE_GRTEST)
    SET(GR_VERSION_STR
        "(${COMPONENT} build ${COMMIT_ID}) compiled at ${COMPILE_TIME} ${CMAKE_BUILD_TYPE} (GRTEST ON)"
    )
else()
    SET(GR_VERSION_STR
        "(${COMPONENT} build ${COMMIT_ID}) compiled at ${COMPILE_TIME} ${CMAKE_BUILD_TYPE} (GRTEST OFF)"
    )
endif()

message(STATUS "Version info: ${GR_VERSION_STR}")

set(CMAKE_C_FLAGS "-std=c99 ${CMAKE_C_FLAGS} -D__FILE_NAME__='\"$(notdir $(subst .o,,$(abspath $@)))\"'" )


add_compile_options(-fPIC -Wall -MMD -fno-strict-aliasing -fsigned-char -fms-extensions -lpthread)
add_compile_definitions(_GNU_SOURCE _LARGEFILE64_SOURCE KNL_PREFIX _REENTRANT __PERF_STAT__)
add_link_options(-pie)
add_link_options(-Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now)
add_compile_options(-fvisibility=default -fstack-protector-strong --param ssp-buffer-size=4)

# 安全编译选项
set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -ldl -pthread -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now")
add_compile_options(-fno-common)
add_compile_options(-Wtrampolines)
add_compile_options(-freg-struct-return)
add_compile_options(-Wl,-Bsymbolic)
add_compile_options(-rdynamic)
add_compile_options(-Wall)
add_compile_options(-Werror)

add_compile_options(-Wvla)
add_compile_options(-Wcast-align)
add_compile_options(-Wshadow)
add_compile_options(-Wundef)
add_compile_options(-Wswitch-default)
add_compile_options(-Wfloat-equal)
add_compile_options(-Wdate-time)
add_compile_options(-Wunused)
add_compile_options(-fstrong-eval-order)
add_compile_options(-Werror=frame-larger-than=1048576)
add_compile_options(-Wextra)
add_compile_options(-Wstack-usage=1048576)
add_compile_options(-Wno-sign-compare)
add_compile_options(-Wno-type-limits)
add_compile_options(-Wno-implicit-fallthrough)
add_compile_options(-Wno-unused-parameter)
add_compile_options(-Wno-missing-field-initializers)
add_compile_options(-Wno-ignored-qualifiers)
if(CMAKE_COMPILER_IS_GNUCC AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 8.0)
    add_compile_options(-Wno-cast-function-type)
endif()
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wno-enum-conversion)
endif()
if(CMAKE_COMPILER_IS_GNUCC AND CMAKE_C_COMPILER_VERSION VERSION_GREATER 9.0)
    add_compile_options(-Wno-psabi)
endif()
if (NOT HOT_PATCH_SPEC)
    add_compile_options(-pipe)
endif()

OPTION(ENABLE_GCOV "Enable gcov (debug, Linux builds only)" OFF)
message(STATUS "ENABLE_GCOV = ${ENABLE_GCOV}")
IF (ENABLE_GCOV AND NOT WIN32 AND NOT APPLE)
    message(STATUS "Enable gcov (debug, Linux builds only).")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage -lgcov")
    add_definitions(-DENABLE_GCOV)
ENDIF()

OPTION(USE_ASAN "Enable ASAN (debug, Linux builds only)" OFF)
message(STATUS "USE_ASAN = ${USE_ASAN}")
IF (USE_ASAN AND NOT WIN32 AND NOT APPLE)
    message(STATUS "Enable ASAN (debug, Linux builds only).")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fsanitize-recover=address,all -O0 -Wall -g -fPIC -fno-omit-frame-pointer")
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fsanitize-recover=address,all -O0 -Wall -g -fPIC -fno-omit-frame-pointer")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fsanitize-recover=address,all -O0 -Wall -g -fPIC -fno-omit-frame-pointer")
ENDIF()

OPTION(ENABLE_FUZZASAN "ENABLE FUZZASAN (debug, Linux builds only)" OFF)
message(STATUS "ENABLE_FUZZASAN = ${ENABLE_FUZZASAN}")
IF (ENABLE_FUZZASAN)
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage -lgcov")
    set(GR_FUZZ_LIB_PATH ${PROJECT_SOURCE_DIR}/test/fuzz_test/lib)
    message(STATUS "GR_FUZZ_LIB_PATH = ${GR_FUZZ_LIB_PATH}")
ENDIF()

OPTION(ENABLE_EXPORT_API "Enable hidden internal api" OFF)
message(STATUS "ENABLE_EXPORT_API = ${ENABLE_EXPORT_API}")
IF (ENABLE_EXPORT_API)
    add_compile_options(-fvisibility=hidden)
ENDIF()

OPTION(ENABLE_DEFAULT_FILE_FLAG_INNER_INITED "Enable default file flag inited" OFF)
message(STATUS "ENABLE_DEFAULT_FILE_FLAG_INNER_INITED = ${ENABLE_DEFAULT_FILE_FLAG_INNER_INITED}")
IF (ENABLE_DEFAULT_FILE_FLAG_INNER_INITED)
    add_definitions(-DGR_DEFAULT_FILE_FLAG_INNER_INITED)
ENDIF()

OPTION(ENABLE_GRTEST "Enable gr test" OFF)
message(STATUS "ENABLE_GRTEST = ${ENABLE_GRTEST}")
IF (ENABLE_GRTEST)
    add_definitions(-DENABLE_GRTEST)
ENDIF()

execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE OS_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(CMAKE_SYSTEM_PROCESSOR ${OS_ARCH})
if (OS_ARCH STREQUAL "aarch64")
    option(USE_H1620 OFF)
    if (USE_H1620)
        add_compile_options(-march=armv8-a+crc+lse)
        message(STATUS "Toolchain: Build aarch64 USE_H1620")
    else ()
        add_compile_options(-march=armv8-a+crc)
    endif (USE_H1620)

    add_compile_options(-mtune=cortex-a72 -fsigned-char -g -ggdb3 -march=armv8-a+crc -funwind-tables)
else ()
    add_compile_options(-msse4.2 )
endif ()
Add_Definitions(-DWSEC_COMPILE_CAC_OPENSSL -DWSEC_AES_GCM_SUPPORT -DWSEC_USE_OPENSSL_110)

## GR include_directories
set(GR_COMMON_PATH ${PROJECT_SOURCE_DIR}/src/common)
set(GR_LOG_PATH ${PROJECT_SOURCE_DIR}/src/log)
set(GR_PARAMS_PATH ${PROJECT_SOURCE_DIR}/src/params)
set(GR_COMMON_API_PATH ${PROJECT_SOURCE_DIR}/src/common_api)
set(GR_CMD_PATH ${PROJECT_SOURCE_DIR}/src/cmd)
set(GR_SER_PATH ${PROJECT_SOURCE_DIR}/src/service)
set(GR_INTERFACE_PATH ${PROJECT_SOURCE_DIR}/src/interface)

## other dependency include
set(GR_SECUREC_INC_PATH        "${CMAKE_CURRENT_SOURCE_DIR}/library/huawei_security/include")
set(GR_OPENSSL_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/openssl/include")
set(GR_CBB_PATH                "${CMAKE_CURRENT_SOURCE_DIR}/library/cbb/include")
set(LIBAIO_INC_PATH             "${CMAKE_CURRENT_SOURCE_DIR}/library/libaio/include")
set(ZLIB_INC_PATH               "${CMAKE_CURRENT_SOURCE_DIR}/library/zlib/include")
set(JAVA_HOME                   "$ENV{JAVA_HOME}/include")
set(JAVA_HOME_INCLUDE           "$ENV{JAVA_HOME}/include/linux")

## lib
set(SECUREC_LIB_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/huawei_security/lib")
set(OPENSSL_LIB_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/openssl/lib")
set(CBB_LIB_PATH                "${CMAKE_CURRENT_SOURCE_DIR}/library/cbb/lib")
set(LIBZ_PATH                   "${CMAKE_CURRENT_SOURCE_DIR}/library/zlib/lib")

## output path
set (LIBRARY_OUTPUT_PATH        ${CMAKE_CURRENT_SOURCE_DIR}/output/lib)
set (EXECUTABLE_OUTPUT_PATH     ${CMAKE_CURRENT_SOURCE_DIR}/output/bin)

CONFIGURE_FILE(config.h.in ${GR_COMMON_API_PATH}/config.h)
CONFIGURE_FILE(config.h.in ${GR_SER_PATH}/config.h)
## add source
link_directories(${LIBRARY_OUTPUT_PATH} ${SECUREC_LIB_PATH} ${LIBZ_PATH} ${LZ4_PATH} ${CBB_LIB_PATH})
IF (ENABLE_FUZZASAN)
    link_directories(${GR_FUZZ_LIB_PATH})
    set(fuzz_lib "libSecodefuzz.a")
ENDIF()

set(vpp_libsecurec "libsecurec.a")
set(3rd_libccb "libcbb.a")
set(libz "libz.a")
set(lz4 "lz4")

set(vpp_libipsi_crypto "libcrypto.a")
set(3rd_libssl "libssl.a")
link_directories(${OPENSSL_LIB_PATH})

add_subdirectory(src)
