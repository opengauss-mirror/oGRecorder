## include
include_directories($ENV{JAVA_HOME}/include)
include_directories($ENV{JAVA_HOME}/include/linux)
include_directories(${WR_COMMON_PATH})
include_directories(${WR_COMMON_PATH}/persist)
include_directories(${WR_LOG_PATH})
include_directories(${WR_PARAMS_PATH})
include_directories(${WR_COMMON_API_PATH})
include_directories(${WR_INTERFACE_PATH})
include_directories(${WR_HOTPATCH_PATH})

option(ENABLE_FUZZASAN OFF)
if (ENABLE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
endif(ENABLE_FUZZASAN)

## other dependency include
include_directories(${WR_SECUREC_INC_PATH})
include_directories(${WR_OPENSSL_PATH})
include_directories(${LIBAIO_INC_PATH})
include_directories(${WR_CBB_PATH})
include_directories(${LZ4_INC_PATH})
## source

aux_source_directory(${WR_COMMON_PATH} WR_COMMON_SRC)
aux_source_directory(${WR_COMMON_PATH}/persist WR_COMMON_SRC)
aux_source_directory(${WR_LOG_PATH} WR_LOG_SRC)
aux_source_directory(${WR_PARAMS_PATH} WR_PARAMS_SRC)
aux_source_directory(${WR_COMMON_API_PATH} WR_COMMON_API_SRC)
aux_source_directory(${WR_INTERFACE_PATH} WR_INTERFACE_SRC)
aux_source_directory(${WR_SER_PATH} WR_SER_SRC)

set(COMMON_ALL_SRC
        ${WR_COMMON_SRC}
        ${WR_LOG_SRC}
        ${WR_PARAMS_SRC}
        ${WR_COMMON_API_SRC}
        ${WR_INTERFACE_SRC}
        ${WR_SER_SRC}
        )

add_library(wrapi SHARED ${COMMON_ALL_SRC})

if (ENABLE_FUZZASAN)
    target_link_libraries(wrapi PRIVATE pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${HOTPATCH_DEPENDENCY_LIB} ${HOTPATCH_LDS} ${3rd_libssl} ${libz} ${lz4} ${fuzz_lib} -Wl,-Bstatic ${3rd_libccb} -Wl,-Bdynamic ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
else()
    target_link_libraries(wrapi PRIVATE pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${HOTPATCH_DEPENDENCY_LIB} ${HOTPATCH_LDS} ${3rd_libssl} ${libz} ${lz4} -Wl,-Bstatic ${3rd_libccb} -Wl,-Bdynamic ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
endif(ENABLE_FUZZASAN)

