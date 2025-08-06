## include
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
endif (ENABLE_FUZZASAN)

## other dependency include 
include_directories(${GR_SECUREC_INC_PATH})
include_directories(${GR_OPENSSL_PATH})
include_directories(${GR_CBB_PATH})

aux_source_directory(${GR_COMMON_PATH} COMMON_SRC)
aux_source_directory(${GR_COMMON_PATH}/persist COMMON_SRC)
aux_source_directory(${GR_LOG_PATH} LOG_SRC)
aux_source_directory(${GR_PARAMS_PATH} PARAMS_SRC)
aux_source_directory(${GR_COMMON_API_PATH} COMMON_API_SRC)
aux_source_directory(${GR_CMD_PATH} CMD_SRC)

link_directories(${LIBRARY_OUTPUT_PATH} ${CBB_LIB_PATH})

set(COMMON_ALL_SRC
        ${COMMON_SRC}
        ${LOG_SRC}
        ${PARAMS_SRC}
        ${COMMON_API_SRC}
        ${CMD_SRC}
        )

ADD_EXECUTABLE(grcmd ${COMMON_ALL_SRC})

if (ENABLE_FUZZASAN)
    target_link_libraries(grcmd grapi pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${libz} ${lz4} ${3rd_libssl} ${3rd_libccb} ${vpp_libipsi_crypto} ${fuzz_lib} -Wl,--no-whole-archive)
else()
    target_link_libraries(grcmd grapi pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${libz} ${lz4} ${3rd_libssl} ${3rd_libccb} ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
endif(ENABLE_FUZZASAN)

if (ENABLE_GRTEST)
    add_library(grcmd_test SHARED ${COMMON_ALL_SRC})
    if (ENABLE_FUZZASAN)
        target_link_libraries(grcmd_test grapi pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${libz} ${lz4} ${3rd_libssl} ${3rd_libccb} ${vpp_libipsi_crypto} ${fuzz_lib} -Wl,--no-whole-archive)
    else()
        target_link_libraries(grcmd_test grapi pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${libz} ${lz4} ${3rd_libssl} ${3rd_libccb} ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
    endif(ENABLE_FUZZASAN)
endif(ENABLE_GRTEST)

