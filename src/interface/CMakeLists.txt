## include
include_directories($ENV{JAVA_HOME}/include)
include_directories($ENV{JAVA_HOME}/include/linux)
include_directories(${GR_COMMON_PATH})
include_directories(${GR_COMMON_PATH}/persist)
include_directories(${GR_LOG_PATH})
include_directories(${GR_PARAMS_PATH})
include_directories(${GR_COMMON_API_PATH})
include_directories(${GR_INTERFACE_PATH})
include_directories(${GR_HOTPATCH_PATH})

option(ENABLE_FUZZASAN OFF)
if (ENABLE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
endif(ENABLE_FUZZASAN)

## other dependency include
include_directories(${GR_SECUREC_INC_PATH})
include_directories(${GR_OPENSSL_PATH})
include_directories(${GR_CBB_PATH})
include_directories(${LZ4_INC_PATH})
## source

aux_source_directory(${GR_COMMON_PATH} GR_COMMON_SRC)
aux_source_directory(${GR_COMMON_PATH}/persist GR_COMMON_SRC)
aux_source_directory(${GR_LOG_PATH} GR_LOG_SRC)
aux_source_directory(${GR_PARAMS_PATH} GR_PARAMS_SRC)
aux_source_directory(${GR_COMMON_API_PATH} GR_COMMON_API_SRC)
aux_source_directory(${GR_INTERFACE_PATH} GR_INTERFACE_SRC)
aux_source_directory(${GR_SER_PATH} GR_SER_SRC)

set(COMMON_ALL_SRC
        ${GR_COMMON_SRC}
        ${GR_LOG_SRC}
        ${GR_PARAMS_SRC}
        ${GR_COMMON_API_SRC}
        ${GR_INTERFACE_SRC}
        ${GR_SER_SRC}
        )

add_library(grapi SHARED ${COMMON_ALL_SRC})

if (ENABLE_FUZZASAN)
    target_link_libraries(grapi PRIVATE pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${HOTPATCH_DEPENDENCY_LIB} ${HOTPATCH_LDS} ${3rd_libssl} ${libz} ${lz4} ${fuzz_lib} -Wl,-Bstatic ${3rd_libccb} -Wl,-Bdynamic ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
else()
    target_link_libraries(grapi PRIVATE pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${HOTPATCH_DEPENDENCY_LIB} ${HOTPATCH_LDS} ${3rd_libssl} ${libz} ${lz4} -Wl,-Bstatic ${3rd_libccb} -Wl,-Bdynamic ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
endif(ENABLE_FUZZASAN)

