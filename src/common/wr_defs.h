/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * WR is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * wr_defs.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_DEFS_H__
#define __WR_DEFS_H__

#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_FALSE (uint8)0
#define WR_TRUE (uint8)1

#define WR_FILE_NAME_BUFFER_SIZE (uint32_t)256
#define WR_FILE_PATH_MAX_LENGTH (SIZE_K(1) + 1)
#define WR_FKEY_FILENAME "server.key.rand"
#define WR_MAX_AUDIT_PATH_LENGTH (SIZE_K(2) + 512)

#define WR_VG_ALARM_CHECK_COUNT 10
#define WR_VG_USAGE_MIN 0
#define WR_VG_USAGE_MAX 100

/* invalid id */
#define WR_INVALID_INT8 ((int8)(-1))
#define WR_INVALID_ID8 (uint8)0xFF
#define WR_INVALID_OFFSET16 (uint16)0xFFFF
#define WR_INVALID_ID16 (uint16)0xFFFF
#define WR_INVALID_ID24 (uint32_t)0xFFFFFF
#define WR_INVALID_ID32 (uint32_t)0xFFFFFFFF
#define WR_INVALID_OFFSET32 (uint32_t)0xFFFFFFFF
#define WR_INVALID_ID64 (uint64)0xFFFFFFFFFFFFFFFF
#define WR_INFINITE32 (uint32_t)0xFFFFFFFF
#define WR_NULL_VALUE_LEN (uint16)0xFFFF
#define WR_INVALID_ASN (uint32_t)0
#define WR_INVALID_INT32 (uint32_t)0x7FFFFFFF
#define WR_INVALID_INT64 (int64)0x7FFFFFFFFFFFFFFF
#define WR_INVALID_FILEID WR_INVALID_ID16
#define WR_INVALID_CHECKSUM (uint16)0

#define WR_ULL_MAX (uint64)0xFFFFFFFFFFFFFFFF

#ifdef WIN32
#define WR_INVALID_HANDLE NULL
#else
#define WR_INVALID_HANDLE (-1)
#endif

#define WR_DEFAULT_AU_SIZE SIZE_M(8)
#define WR_MAX_AU_SIZE SIZE_M(64)
#define WR_MIN_AU_SIZE SIZE_M(2)

#define WR_MAX_VOLUMES 256
#define WR_CTRL_SIZE WR_DEFAULT_AU_SIZE
#define WR_LOG_BUFFER_SIZE SIZE_K(512)
#define WR_CORE_CTRL_SIZE SIZE_K(16)
#define WR_VOLUME_CTRL_SIZE SIZE_K(256)
#define WR_VG_DATA_SIZE 512
#define WR_MIN_BUFFER_BLOCKS 32
#define WR_MIN_SESSIONID 0
#define WR_MAX_SESSIONS 16320
#define WR_SESSION_NUM_PER_GROUP 128
#define WR_MIN_SESSIONID_CFG 16  // allow config min sessionid in wr_inst.ini
#define WR_MIN_INST_ID 0
#define WR_MAX_INST_ID WR_MAX_INSTANCES
#define WR_LOCK_VG_TIMEOUT 1000000  // usecs
#define WR_LOCK_VG_TIMEOUT_MS (WR_LOCK_VG_TIMEOUT / 1000)  // ms
#define WR_LOKC_ALIGN_SIZE_512 512
#define WR_MIN_LOCK_INTERVAL 1
#define WR_MAX_LOCK_INTERVAL 600000
#define WR_MIN_DLOCK_RETRY_COUNT 1
#define WR_MAX_DLOCK_RETRY_COUNT 500000
#define WR_MIN_DELAY_CLEAN_INTERVAL 5
#define WR_MAX_DELAY_CLEAN_INTERVAL 1000000
#define WR_MIN_SHM_KEY 1
#define WR_MAX_SHM_KEY 64
#define WR_MAX_SHM_KEY_BITS 8

#define WR_MAX_NAME_LEN 64
#define WR_MAX_VOLUME_PATH_LEN 64
#define WR_MAX_CMD_LEN (512)
#define WR_MAX_FILE_LEN (256)
#define WR_MAX_OPEN_VG (WR_MAX_VOLUME_GROUP_NUM)

#define WR_BLOCK_SIZE 512
#define WR_ROOT_FT_DISK_SIZE SIZE_K(8)
#define WR_LOCK_SHARE_DISK_SIZE (SIZE_K(32) + 512)
#define WR_INIT_DISK_LATCH_SIZE (SIZE_K(32))

#define WR_NAME_BUFFER_SIZE (uint32_t)68
#define WR_NAME_USER_BUFFER_SIZE (WR_NAME_BUFFER_SIZE - 16)  // reserve 16 bytes for system
#define WR_VOLUME_CODE_SIZE 64

#define WR_DISK_LOCK_LEN 1024

#define WR_FILE_SPACE_BLOCK_SIZE SIZE_K(16)  // unit:K
#define WR_BLOCK_CTRL_SIZE 512
#define WR_LOADDISK_BUFFER_SIZE SIZE_M(1)
#define WR_MAX_META_BLOCK_SIZE (SIZE_K(16) + 512)

#define WR_INVALID_64 WR_INVALID_ID64

#define WR_DISK_UNIT_SIZE 512

#define WR_MAX_OPEN_FILES 1000000
#define WR_DEFAULT_OPEN_FILES_NUM 10000
#define WR_FILE_CONTEXT_PER_GROUP 1000
#define WR_MAX_FILE_CONTEXT_GROUP_NUM 1000

#define WR_STATIC_ASSERT(condition) ((void)sizeof(char[1 - 2 * (int32_t)(!(condition))]))

#define WR_MAX_BIT_NUM_VOLUME 10
#define WR_MAX_BIT_NUM_AU 34
#define WR_MAX_BIT_NUM_BLOCK 17
#define WR_MAX_BIT_NUM_ITEM 3
#define WR_MAX_VOLUME_SIZE ((1 << WR_MAX_BIT_NUM_AU) * WR_DEFAULT_AU_SIZE)

#define WR_INIT_HASH_MAP_SIZE SIZE_K(16)

#define WR_CFG_NAME "wr_inst.ini"

#define WR_MAX_MEM_BLOCK_SIZE SIZE_M(8)

#define WR_BLOCK_HASH_SIZE SIZE_M(1)

#define WR_MAX_FILE_SIZE SIZE_T(8)

#define WR_USOCKET_PERMSSION (S_IRUSR | S_IWUSR)

#define WR_ID_TO_U64(id) (*(uint64 *)&(id))

#define WR_MAX_STACK_BUF_SIZE SIZE_K(512)

#define WR_CMS_RES_TYPE "wr"

#define WR_FILE_HASH_SIZE (uint32_t)5000

#define WR_MAX_PATH_BUFFER_SIZE (uint32_t)(WR_FILE_NAME_BUFFER_SIZE - WR_NAME_BUFFER_SIZE)

#define WR_PROTO_CODE *(uint32_t *)"\xFE\xDC\xBA\x98"
#define WR_UNIX_PATH_MAX (uint32_t)108
#define WR_MAX_INSTANCES 64
#define WR_VERSION_MAX_LEN 256
#define WR_WAIT_TIMEOUT 5

#define WR_ENV_HOME (char *)"WR_HOME"

/* file */
#define WR_MAX_CONFIG_FILE_SIZE SIZE_K(64) /* 64K */
#define WR_MAX_CONFIG_BUFF_SIZE SIZE_M(1)
#define WR_MAX_CONFIG_LINE_SIZE SIZE_K(2)
#define WR_MAX_SQL_FILE_SIZE SIZE_M(2)
#define WR_MIN_SYSTEM_DATAFILE_SIZE SIZE_M(128)
#define WR_MIN_USER_DATAFILE_SIZE SIZE_M(1)
#define WR_DFLT_CTRL_BLOCK_SIZE SIZE_K(16)
#define WR_DFLT_LOG_BLOCK_SIZE (uint32_t)512
#define WR_MAX_ARCH_FILES_SIZE SIZE_T(32)

#define GSDB_UDS_EMERG_CLIENT "gsdb_uds_emerg.client"
#define GSDB_UDS_EMERG_SERVER "gsdb_uds_emerg.server"

#define CM_MAX_UDS_FILE_PERMISSIONS (uint16)777
#define CM_DEF_UDS_FILE_PERMISSIONS (uint16)600

#define WR_MAX_PACKET_SIZE (uint32_t)(10240) /* 10KB */
#define WR_MAX_PACKET_DATA_SIZE (((WR_MAX_PACKET_SIZE) - sizeof(wr_packet_head_t)) - sizeof(uint32_t))

#define WR_PARAM_BUFFER_SIZE (uint32_t)1024
#define WR_ALIGN_SIZE (uint32_t)512
#define WR_MIN_PORT (uint32_t)1024
#define CM_ALIGN_512(size) (((size) + 0x000001FF) & 0xFFFFFE00)
#define WR_DEFAULT_NULL_VALUE (uint32_t)0xFFFFFFFF
#define WR_TCP_CONNECT_TIMEOUT (int32_t)(30000) /* 30 seconds */
#define WR_TCP_SOCKET_TIMEOUT (int32_t)0x4FFFFFFF
#define WR_SEEK_MAXWR 3 /* Used for seek actual file size for openGauss */

#define WR_MIN_IOTHREADS_CFG 1
#define WR_MAX_IOTHREADS_CFG 8
#define WR_MIN_WORKTHREADS_CFG 16
#define WR_MAX_WORKTHREADS_CFG 128

#define WR_DIR_PARENT ".."
#define WR_DIR_SELF "."

#define WR_RETURN_IF_ERROR(ret)      \
    do {                              \
        int _status_ = (ret);         \
        if (_status_ != CM_SUCCESS) { \
            return _status_;          \
        }                             \
    } while (0)

#define WR_RETURN_IFERR2(func, hook)                   \
    do {                                                \
        int _status_ = (func);                          \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            hook;                                       \
            return _status_;                            \
        }                                               \
    } while (0)

#define WR_RETURN_IFERR3(func, hook1, hook2)           \
    do {                                                \
        int _status_ = (func);                          \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            hook1;                                      \
            hook2;                                      \
            return _status_;                            \
        }                                               \
    } while (0)

#define WR_RETURN_IF_FALSE2(ret, hook)           \
    do {                                          \
        if (SECUREC_UNLIKELY((ret) != CM_TRUE)) { \
            hook;                                 \
            return CM_ERROR;                      \
        }                                         \
    } while (0)

#define WR_RETURN_IFERR4(func, hook1, hook2, hook3)    \
    do {                                                \
        int _status_ = (func);                          \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            hook1;                                      \
            hook2;                                      \
            hook3;                                      \
            return _status_;                            \
        }                                               \
    } while (0)

#define WR_RETURN_IF_FALSE3(ret, hook1, hook2)   \
    do {                                          \
        if (SECUREC_UNLIKELY((ret) != CM_TRUE)) { \
            hook1;                                \
            hook2;                                \
            return CM_ERROR;                      \
        }                                         \
    } while (0)

#define WR_RETURN_IF_SUCCESS(ret)    \
    do {                              \
        int _status_ = (ret);         \
        if (_status_ == CM_SUCCESS) { \
            return _status_;          \
        }                             \
    } while (0)

#define WR_RETURN_STATUS_IF_TRUE(cond, status) \
    do {                                        \
        int _status_ = (status);                \
        if ((cond) == CM_TRUE) {                \
            return _status_;                    \
        }                                       \
    } while (0)

#define WR_SECUREC_RETURN_IF_ERROR(err, ret)       \
    {                                               \
        if ((err) != EOK) {                         \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (err)); \
            return ret;                             \
        }                                           \
    }

#define WR_SECUREC_RETURN_IF_ERROR2(err, hook, ret) \
    {                                                \
        if ((err) != EOK) {                          \
            hook;                                    \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (err));  \
            return ret;                              \
        }                                            \
    }

#define WR_SECUREC_SS_RETURN_IF_ERROR(err, ret)    \
    {                                               \
        if ((err) == -1) {                          \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (err)); \
            return ret;                             \
        }                                           \
    }

#define WR_RETURN_IF_NULL(ret) \
    do {                        \
        if ((ret) == NULL) {    \
            return CM_ERROR;    \
        }                       \
    } while (0)

#define WR_BREAK_IF_ERROR(ret) \
    if ((ret) != CM_SUCCESS) {  \
        break;                  \
    }

#define WR_BREAK_IFERR2(func, hook)              \
    if (SECUREC_UNLIKELY((func) != CM_SUCCESS)) { \
        hook;                                     \
        break;                                    \
    }

#define WR_BREAK_IFERR3(func, hook1, hook2)      \
    if (SECUREC_UNLIKELY((func) != CM_SUCCESS)) { \
        hook1;                                    \
        hook2;                                    \
        break;                                    \
    }

#define WR_RETURN_DRIECT_IFERR(ret) \
    do {                             \
        if ((ret) != CM_SUCCESS) {   \
            return;                  \
        }                            \
    } while (0)

#ifdef WIN32
#define WR_LOG_WITH_OS_MSG(user_fmt_str, ...)                                                                    \
    do {                                                                                                          \
        char os_errmsg_buf[64];                                                                                   \
        (void)snprintf_s(                                                                                         \
            os_errmsg_buf, sizeof(os_errmsg_buf), sizeof(os_errmsg_buf) - 1, "Unknown error %d", GetLastError()); \
        strerror_s(os_errmsg_buf, sizeof(os_errmsg_buf), GetLastError());                                         \
        LOG_DEBUG_ERR(user_fmt_str ", OS errno=%d, OS errmsg=%s", __VA_ARGS__, GetLastError(), os_errmsg_buf);    \
    } while (0)
#else
#define WR_LOG_WITH_OS_MSG(user_fmt_str, ...)                                                                        \
    do {                                                                                                              \
        char os_errmsg_buf[64];                                                                                       \
        (void)snprintf_s(os_errmsg_buf, sizeof(os_errmsg_buf), sizeof(os_errmsg_buf) - 1, "Unknown error %d", errno); \
        /* here we use GNU version of strerror_r, make sure _GNU_SOURCE is defined */                                 \
        LOG_DEBUG_ERR(user_fmt_str ", OS errno=%d, OS errmsg=%s", __VA_ARGS__, errno,                                 \
            strerror_r(errno, os_errmsg_buf, sizeof(os_errmsg_buf)));                                                 \
    } while (0)
#endif

#define WR_ASSERT_LOG(condition, format, ...)                                         \
    do {                                                                               \
        if (SECUREC_UNLIKELY(!(condition))) {                                          \
            LOG_RUN_ERR(format, ##__VA_ARGS__);                                        \
            LOG_RUN_ERR("Assertion throws an exception at line %u", (uint32_t)__LINE__); \
            cm_fync_logfile();                                                         \
            CM_ASSERT(0);                                                              \
        }                                                                              \
    } while (0)

#define WR_BYTE_BITS_SIZE 8

// if want change the default, compile the wr with set WR_PAGE_SIZE=page_size_you_want
#ifndef WR_PAGE_SIZE
#define WR_PAGE_SIZE 8192
#endif

#if WR_PAGE_SIZE != 4096 && WR_PAGE_SIZE != 8192 && WR_PAGE_SIZE != 16384 && WR_PAGE_SIZE != 32768
#error "WR_PAGE_SIZE only can be one of [4096, 8192, 16384, 32768]"
#endif

#define WR_FS_AUX_HEAD_SIZE_MAX WR_DISK_UNIT_SIZE

#define WR_FS_AUX_BITMAP_SIZE(au_size) (((au_size) / WR_PAGE_SIZE) / WR_BYTE_BITS_SIZE)
#define WR_MAX_FS_AUX_BITMAP_SIZE (WR_FS_AUX_BITMAP_SIZE(WR_MAX_AU_SIZE))
#define WR_MIN_FS_AUX_BITMAP_SIZE (WR_FS_AUX_BITMAP_SIZE(WR_MIN_AU_SIZE))
// default is 1.5k
#define WR_FS_AUX_SIZE (WR_MAX_FS_AUX_BITMAP_SIZE + WR_FS_AUX_HEAD_SIZE_MAX)

#define WR_FREE_POINT(pointer)  \
    {                            \
        if ((pointer) != NULL) { \
            free(pointer);       \
            (pointer) = NULL;    \
        }                        \
    }

#ifdef __cplusplus
}
#endif

#endif
