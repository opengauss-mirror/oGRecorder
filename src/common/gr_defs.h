/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * GR is licensed under Mulan PSL v2.
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
 * gr_defs.h
 *
 *
 * IDENTIFICATION
 *    src/common/gr_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_DEFS_H__
#define __GR_DEFS_H__

#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GR_FALSE (uint8)0
#define GR_TRUE (uint8)1

#define GR_FILE_NAME_BUFFER_SIZE (uint32_t)256
#define GR_FILE_PATH_MAX_LENGTH (SIZE_K(1) + 1)
#define GR_FKEY_FILENAME "server.key.rand"
#define GR_MAX_AUDIT_PATH_LENGTH (SIZE_K(2) + 512)

#define GR_VG_ALARM_CHECK_COUNT 10
#define GR_DISK_USAGE_MIN 0
#define GR_DISK_USAGE_MAX 100

/* invalid id */
#define GR_INVALID_INT8 ((int8)(-1))
#define GR_INVALID_ID8 (uint8)0xFF
#define GR_INVALID_OFFSET16 (uint16)0xFFFF
#define GR_INVALID_ID16 (uint16)0xFFFF
#define GR_INVALID_ID24 (uint32_t)0xFFFFFF
#define GR_INVALID_ID32 (uint32_t)0xFFFFFFFF
#define GR_INVALID_OFFSET32 (uint32_t)0xFFFFFFFF
#define GR_INVALID_ID64 (uint64)0xFFFFFFFFFFFFFFFF
#define GR_INFINITE32 (uint32_t)0xFFFFFFFF
#define GR_NULL_VALUE_LEN (uint16)0xFFFF
#define GR_INVALID_ASN (uint32_t)0
#define GR_INVALID_INT32 (uint32_t)0x7FFFFFFF
#define GR_INVALID_INT64 (int64)0x7FFFFFFFFFFFFFFF
#define GR_INVALID_FILEID GR_INVALID_ID16
#define GR_INVALID_CHECKSUM (uint16)0

#define GR_ULL_MAX (uint64)0xFFFFFFFFFFFFFFFF

#ifdef WIN32
#define GR_INVALID_HANDLE NULL
#else
#define GR_INVALID_HANDLE (-1)
#endif

#define GR_DEFAULT_AU_SIZE SIZE_M(8)
#define GR_MAX_AU_SIZE SIZE_M(64)
#define GR_MIN_AU_SIZE SIZE_M(2)

#define GR_MAX_VOLUMES 256
#define GR_CTRL_SIZE GR_DEFAULT_AU_SIZE
#define GR_LOG_BUFFER_SIZE SIZE_K(512)
#define GR_CORE_CTRL_SIZE SIZE_K(16)
#define GR_VOLUME_CTRL_SIZE SIZE_K(256)
#define GR_VG_DATA_SIZE 512
#define GR_MIN_BUFFER_BLOCKS 32
#define GR_MIN_SESSIONID 0
#define GR_MAX_SESSIONS 16320
#define GR_SESSION_NUM_PER_GROUP 128
#define GR_MIN_SESSIONID_CFG 16  // allow config min sessionid in gr_inst.ini
#define GR_MIN_INST_ID 0
#define GR_MAX_INST_ID GR_MAX_INSTANCES
#define GR_LOCK_VG_TIMEOUT 1000000  // usecs
#define GR_LOCK_VG_TIMEOUT_MS (GR_LOCK_VG_TIMEOUT / 1000)  // ms
#define GR_LOKC_ALIGN_SIZE_512 512
#define GR_MIN_LOCK_INTERVAL 1
#define GR_MAX_LOCK_INTERVAL 600000
#define GR_MIN_DLOCK_RETRY_COUNT 1
#define GR_MAX_DLOCK_RETRY_COUNT 500000
#define GR_MIN_DELAY_CLEAN_INTERVAL 5
#define GR_MAX_DELAY_CLEAN_INTERVAL 1000000
#define GR_MIN_SHM_KEY 1
#define GR_MAX_SHM_KEY 64
#define GR_MAX_SHM_KEY_BITS 8

#define GR_MAX_NAME_LEN 64
#define GR_MAX_VOLUME_PATH_LEN 64
#define GR_MAX_CMD_LEN (512)
#define GR_MAX_FILE_LEN (256)
#define GR_MAX_OPEN_VG (GR_MAX_VOLUME_GROUP_NUM)

#define GR_BLOCK_SIZE 512
#define GR_ROOT_FT_DISK_SIZE SIZE_K(8)
#define GR_LOCK_SHARE_DISK_SIZE (SIZE_K(32) + 512)
#define GR_INIT_DISK_LATCH_SIZE (SIZE_K(32))

#define GR_NAME_BUFFER_SIZE (uint32_t)68
#define GR_NAME_USER_BUFFER_SIZE (GR_NAME_BUFFER_SIZE - 16)  // reserve 16 bytes for system
#define GR_VOLUME_CODE_SIZE 64

#define GR_DISK_LOCK_LEN 1024

#define GR_FILE_SPACE_BLOCK_SIZE SIZE_K(16)  // unit:K
#define GR_BLOCK_CTRL_SIZE 512
#define GR_LOADDISK_BUFFER_SIZE SIZE_M(1)
#define GR_MAX_META_BLOCK_SIZE (SIZE_K(16) + 512)

#define GR_INVALID_64 GR_INVALID_ID64

#define GR_DISK_UNIT_SIZE 512

#define GR_MAX_OPEN_FILES 1000000
#define GR_DEFAULT_OPEN_FILES_NUM 10000
#define GR_FILE_CONTEXT_PER_GROUP 1000
#define GR_MAX_FILE_CONTEXT_GROUP_NUM 1000

#define GR_STATIC_ASSERT(condition) ((void)sizeof(char[1 - 2 * (int32_t)(!(condition))]))

#define GR_MAX_BIT_NUM_VOLUME 10
#define GR_MAX_BIT_NUM_AU 34
#define GR_MAX_BIT_NUM_BLOCK 17
#define GR_MAX_BIT_NUM_ITEM 3
#define GR_MAX_VOLUME_SIZE ((1 << GR_MAX_BIT_NUM_AU) * GR_DEFAULT_AU_SIZE)

#define GR_INIT_HASH_MAP_SIZE SIZE_K(16)

#define GR_CFG_NAME "gr_inst.ini"

#define GR_MAX_MEM_BLOCK_SIZE SIZE_M(8)

#define GR_BLOCK_HASH_SIZE SIZE_M(1)

#define GR_MAX_FILE_SIZE SIZE_T(8)

#define GR_USOCKET_PERMSSION (S_IRUSR | S_IWUSR)

#define GR_ID_TO_U64(id) (*(uint64 *)&(id))

#define GR_MAX_STACK_BUF_SIZE SIZE_K(512)

#define GR_CMS_RES_TYPE "wr"

#define GR_FILE_HASH_SIZE (uint32_t)5000

#define GR_MAX_PATH_BUFFER_SIZE (uint32_t)(GR_FILE_NAME_BUFFER_SIZE - GR_NAME_BUFFER_SIZE)

#define GR_PROTO_CODE *(uint32_t *)"\xFE\xDC\xBA\x98"
#define GR_UNIX_PATH_MAX (uint32_t)108
#define GR_MAX_INSTANCES 64
#define GR_VERSION_MAX_LEN 256
#define GR_WAIT_TIMEOUT 5

#define GR_ENV_HOME (char *)"GR_HOME"

/* file */
#define GR_MAX_CONFIG_FILE_SIZE SIZE_K(64) /* 64K */
#define GR_MAX_CONFIG_BUFF_SIZE SIZE_M(1)
#define GR_MAX_CONFIG_LINE_SIZE SIZE_K(2)
#define GR_MAX_SQL_FILE_SIZE SIZE_M(2)
#define GR_MIN_SYSTEM_DATAFILE_SIZE SIZE_M(128)
#define GR_MIN_USER_DATAFILE_SIZE SIZE_M(1)
#define GR_DFLT_CTRL_BLOCK_SIZE SIZE_K(16)
#define GR_DFLT_LOG_BLOCK_SIZE (uint32_t)512
#define GR_MAX_ARCH_FILES_SIZE SIZE_T(32)

#define GSDB_UDS_EMERG_CLIENT "gsdb_uds_emerg.client"
#define GSDB_UDS_EMERG_SERVER "gsdb_uds_emerg.server"

#define CM_MAX_UDS_FILE_PERMISSIONS (uint16)777
#define CM_DEF_UDS_FILE_PERMISSIONS (uint16)600

#define GR_MAX_PACKET_SIZE (uint32_t)(10240) /* 10KB */
#define GR_MAX_PACKET_DATA_SIZE (((GR_MAX_PACKET_SIZE) - sizeof(gr_packet_head_t)) - sizeof(uint32_t))

#define GR_PARAM_BUFFER_SIZE (uint32_t)1024
#define GR_ALIGN_SIZE (uint32_t)512
#define GR_MIN_PORT (uint32_t)1024
#define CM_ALIGN_512(size) (((size) + 0x000001FF) & 0xFFFFFE00)
#define GR_DEFAULT_NULL_VALUE (uint32_t)(60000) /* 60 seconds */
#define GR_TCP_CONNECT_TIMEOUT (int32_t)(5000) /* 5 seconds */
#define GR_TCP_SOCKET_TIMEOUT (int32_t)(10000) /* 10 seconds */
#define GR_SEEK_MAXGR 3 /* Used for seek actual file size for openGauss */

#define GR_MIN_IOTHREADS_CFG 1
#define GR_MAX_IOTHREADS_CFG 8
#define GR_MIN_WORKTHREADS_CFG 16
#define GR_MAX_WORKTHREADS_CFG 128

#define GR_DIR_PARENT ".."
#define GR_DIR_SELF "."

#define GR_RETURN_IF_ERROR(ret)      \
    do {                              \
        int _status_ = (ret);         \
        if (_status_ != CM_SUCCESS) { \
            return _status_;          \
        }                             \
    } while (0)

#define GR_RETURN_IFERR2(func, hook)                   \
    do {                                                \
        int _status_ = (func);                          \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            hook;                                       \
            return _status_;                            \
        }                                               \
    } while (0)

#define GR_RETURN_IFERR3(func, hook1, hook2)           \
    do {                                                \
        int _status_ = (func);                          \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            hook1;                                      \
            hook2;                                      \
            return _status_;                            \
        }                                               \
    } while (0)

#define GR_RETURN_IF_FALSE2(ret, hook)           \
    do {                                          \
        if (SECUREC_UNLIKELY((ret) != CM_TRUE)) { \
            hook;                                 \
            return CM_ERROR;                      \
        }                                         \
    } while (0)

#define GR_RETURN_IFERR4(func, hook1, hook2, hook3)    \
    do {                                                \
        int _status_ = (func);                          \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            hook1;                                      \
            hook2;                                      \
            hook3;                                      \
            return _status_;                            \
        }                                               \
    } while (0)

#define GR_RETURN_IF_FALSE3(ret, hook1, hook2)   \
    do {                                          \
        if (SECUREC_UNLIKELY((ret) != CM_TRUE)) { \
            hook1;                                \
            hook2;                                \
            return CM_ERROR;                      \
        }                                         \
    } while (0)

#define GR_RETURN_IF_SUCCESS(ret)    \
    do {                              \
        int _status_ = (ret);         \
        if (_status_ == CM_SUCCESS) { \
            return _status_;          \
        }                             \
    } while (0)

#define GR_RETURN_STATUS_IF_TRUE(cond, status) \
    do {                                        \
        int _status_ = (status);                \
        if ((cond) == CM_TRUE) {                \
            return _status_;                    \
        }                                       \
    } while (0)

#define GR_SECUREC_RETURN_IF_ERROR(err, ret)       \
    {                                               \
        if ((err) != EOK) {                         \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (err)); \
            return ret;                             \
        }                                           \
    }

#define GR_SECUREC_RETURN_IF_ERROR2(err, hook, ret) \
    {                                                \
        if ((err) != EOK) {                          \
            hook;                                    \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (err));  \
            return ret;                              \
        }                                            \
    }

#define GR_SECUREC_SS_RETURN_IF_ERROR(err, ret)    \
    {                                               \
        if ((err) == -1) {                          \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (err)); \
            return ret;                             \
        }                                           \
    }

#define GR_RETURN_IF_NULL(ret) \
    do {                        \
        if ((ret) == NULL) {    \
            return CM_ERROR;    \
        }                       \
    } while (0)

#define GR_BREAK_IF_ERROR(ret) \
    if ((ret) != CM_SUCCESS) {  \
        break;                  \
    }

#define GR_BREAK_IFERR2(func, hook)              \
    if (SECUREC_UNLIKELY((func) != CM_SUCCESS)) { \
        hook;                                     \
        break;                                    \
    }

#define GR_BREAK_IFERR3(func, hook1, hook2)      \
    if (SECUREC_UNLIKELY((func) != CM_SUCCESS)) { \
        hook1;                                    \
        hook2;                                    \
        break;                                    \
    }

#define GR_RETURN_DRIECT_IFERR(ret) \
    do {                             \
        if ((ret) != CM_SUCCESS) {   \
            return;                  \
        }                            \
    } while (0)

#ifdef WIN32
#define GR_LOG_WITH_OS_MSG(user_fmt_str, ...)                                                                    \
    do {                                                                                                          \
        char os_errmsg_buf[64];                                                                                   \
        (void)snprintf_s(                                                                                         \
            os_errmsg_buf, sizeof(os_errmsg_buf), sizeof(os_errmsg_buf) - 1, "Unknown error %d", GetLastError()); \
        strerror_s(os_errmsg_buf, sizeof(os_errmsg_buf), GetLastError());                                         \
        LOG_DEBUG_ERR(user_fmt_str ", OS errno=%d, OS errmsg=%s", __VA_ARGS__, GetLastError(), os_errmsg_buf);    \
    } while (0)
#else
#define GR_LOG_WITH_OS_MSG(user_fmt_str, ...)                                                                        \
    do {                                                                                                              \
        char os_errmsg_buf[64];                                                                                       \
        (void)snprintf_s(os_errmsg_buf, sizeof(os_errmsg_buf), sizeof(os_errmsg_buf) - 1, "Unknown error %d", errno); \
        /* here we use GNU version of strerror_r, make sure _GNU_SOURCE is defined */                                 \
        LOG_DEBUG_ERR(user_fmt_str ", OS errno=%d, OS errmsg=%s", __VA_ARGS__, errno,                                 \
            strerror_r(errno, os_errmsg_buf, sizeof(os_errmsg_buf)));                                                 \
    } while (0)
#endif

#define GR_ASSERT_LOG(condition, format, ...)                                         \
    do {                                                                               \
        if (SECUREC_UNLIKELY(!(condition))) {                                          \
            LOG_RUN_ERR(format, ##__VA_ARGS__);                                        \
            LOG_RUN_ERR("Assertion throws an exception at line %u", (uint32_t)__LINE__); \
            cm_fync_logfile();                                                         \
            CM_ASSERT(0);                                                              \
        }                                                                              \
    } while (0)

#define GR_BYTE_BITS_SIZE 8

// if want change the default, compile the gr with set GR_PAGE_SIZE=page_size_you_want
#ifndef GR_PAGE_SIZE
#define GR_PAGE_SIZE 8192
#endif

#if GR_PAGE_SIZE != 4096 && GR_PAGE_SIZE != 8192 && GR_PAGE_SIZE != 16384 && GR_PAGE_SIZE != 32768
#error "GR_PAGE_SIZE only can be one of [4096, 8192, 16384, 32768]"
#endif

#define GR_FS_AUX_HEAD_SIZE_MAX GR_DISK_UNIT_SIZE

#define GR_FS_AUX_BITMAP_SIZE(au_size) (((au_size) / GR_PAGE_SIZE) / GR_BYTE_BITS_SIZE)
#define GR_MAX_FS_AUX_BITMAP_SIZE (GR_FS_AUX_BITMAP_SIZE(GR_MAX_AU_SIZE))
#define GR_MIN_FS_AUX_BITMAP_SIZE (GR_FS_AUX_BITMAP_SIZE(GR_MIN_AU_SIZE))
// default is 1.5k
#define GR_FS_AUX_SIZE (GR_MAX_FS_AUX_BITMAP_SIZE + GR_FS_AUX_HEAD_SIZE_MAX)

#define GR_FREE_POINT(pointer)  \
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
