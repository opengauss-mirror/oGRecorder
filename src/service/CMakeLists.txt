## include
include_directories(${WR_COMMON_PATH})
include_directories(${WR_COMMON_PATH}/persist)
include_directories(${WR_LOG_PATH})
include_directories(${WR_PARAMS_PATH})
include_directories(${WR_INTERFACE_PATH})
include_directories(${WR_HOTPATCH_PATH})

option(ENABLE_FUZZASAN OFF)
if (ENABLE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
endif(ENABLE_FUZZASAN)

## other dependency include 
include_directories(${WR_SECUREC_INC_PATH})
include_directories(${WR_OPENSSL_PATH})
include_directories(${WR_CBB_PATH})
include_directories(${LZ4_INC_PATH})
aux_source_directory(${WR_COMMON_PATH} COMMON_SRC)
aux_source_directory(${WR_COMMON_PATH}/persist COMMON_SRC)
aux_source_directory(${WR_LOG_PATH} LOG_SRC)
aux_source_directory(${WR_PARAMS_PATH} PARAMS_SRC)
aux_source_directory(${WR_SER_PATH} SER_SRC)

set(COMMON_ALL_SRC
        ${COMMON_SRC}
        ${LOG_SRC}
        ${PARAMS_SRC}
        ${SER_SRC}
        )

ADD_EXECUTABLE(grserver ${COMMON_ALL_SRC})

if (ENABLE_FUZZASAN)
    target_link_libraries(grserver pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${HOTPATCH_DEPENDENCY_LIB} ${HOTPATCH_LDS} ${3rd_libssl} ${libz} ${lz4} ${3rd_libccb} ${vpp_libipsi_crypto} ${fuzz_lib} -Wl,--no-whole-archive)
else()
    target_link_libraries(grserver pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${HOTPATCH_DEPENDENCY_LIB} ${HOTPATCH_LDS} ${3rd_libssl} ${libz} ${lz4} ${3rd_libccb} ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
endif(ENABLE_FUZZASAN)
