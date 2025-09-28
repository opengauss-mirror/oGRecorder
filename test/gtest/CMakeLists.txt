cmake_minimum_required(VERSION 3.10)

# 项目名称
project(GRApiTest)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address")

if(ENABLE_WORM STREQUAL "1")
    add_definitions(-DENABLE_WORM=1)
endif()

find_package(GTest REQUIRED)

# 包含头文件目录
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(../../src/interface)

link_directories(../../output/lib)

# 添加测试源文件
add_executable(test_api test_api.cc)
add_executable(test_performance test_performance.cc)
add_executable(test_rw test_rw.cc)
add_executable(test_mutliwrite test_mutliwrite.cc)
add_executable(test_appendwrite test_appendwrite.cc)
add_executable(test_insthandle test_insthandle.cc)
add_executable(test_singlewrite test_singlewrite.cc)

# 链接 Google Test 库和项目库
target_link_libraries(test_api ${GTEST_LIBRARIES} pthread grapi)
target_link_libraries(test_performance ${GTEST_LIBRARIES} pthread grapi)
target_link_libraries(test_rw ${GTEST_LIBRARIES} pthread grapi)
target_link_libraries(test_mutliwrite ${GTEST_LIBRARIES} pthread grapi)
target_link_libraries(test_appendwrite ${GTEST_LIBRARIES} pthread grapi)
target_link_libraries(test_insthandle ${GTEST_LIBRARIES} pthread grapi)
target_link_libraries(test_singlewrite ${GTEST_LIBRARIES} pthread grapi)

# 启用测试
enable_testing()

# 添加测试
add_test(NAME GRApiTest COMMAND test_api)
add_test(NAME GRApiPerformanceTest COMMAND test_performance)
add_test(NAME GRApiRwTest COMMAND test_rw)
add_test(NAME GRApiMultiWriteTest COMMAND test_mutliwrite)
add_test(NAME GRApiAppendWriteTest COMMAND test_appendwrite)
add_test(NAME GRCreateInstHandle COMMAND test_insthandle)
add_test(NAME GRSingleWriteTest COMMAND test_singlewrite)


if(DEFINED AUTO_TEST AND AUTO_TEST)
    add_custom_target(run_all_tests ALL
        DEPENDS test_api test_performance test_rw test_mutliwrite test_appendwrite test_insthandle
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
endif()