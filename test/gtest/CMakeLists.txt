cmake_minimum_required(VERSION 3.10)

# 项目名称
project(WrApiTest)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_BUILD_TYPE Debug)

find_package(GTest REQUIRED)

# 包含头文件目录
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(../../src/interface)

link_directories(../../output/lib)

# 添加测试源文件
add_executable(test_wr_api test_wr_api.cc)
add_executable(test_performance test_performance.cc)
add_executable(test_rw test_rw.cc)

# 链接 Google Test 库和项目库
target_link_libraries(test_wr_api ${GTEST_LIBRARIES} pthread wrapi)
target_link_libraries(test_performance ${GTEST_LIBRARIES} pthread wrapi)
target_link_libraries(test_rw ${GTEST_LIBRARIES} pthread wrapi)

# 启用测试
enable_testing()

# 添加测试
add_test(NAME WrApiTest COMMAND test_wr_api)
add_test(NAME WrApiPerformanceTest COMMAND test_performance)
add_test(NAME WrApiRwTest COMMAND test_rw)

