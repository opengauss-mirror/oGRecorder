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
 * wr_protocol.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_protocol.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_PROTOCOL_H__
#define __WR_PROTOCOL_H__
#include "cm_base.h"
#ifndef WIN32
#include <string.h>
#endif

#include "cm_defs.h"
#include "cs_packet.h"
#include "cs_pipe.h"
#include "wr_defs.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "wr_errno.h"
#include "wr_log.h"

#ifdef __cplusplus
extern "C" {
#endif

// The value of each command type cannot be changed for compatibility reasons.
// If you want to add a command type, add it at the end. Before WR_CMD_END
typedef enum {
    WR_CMD_BASE,
    WR_CMD_BEGIN,
    WR_CMD_MODIFY_BEGIN = WR_CMD_BEGIN,
    WR_CMD_MKDIR = WR_CMD_MODIFY_BEGIN,
    WR_CMD_RMDIR,
    WR_CMD_MOUNT_VFS,
    WR_CMD_UNMOUNT_VFS,
    WR_CMD_QUERY_FILE_NUM,
    WR_CMD_QUERY_FILE_INFO,
    WR_CMD_OPEN_FILE,
    WR_CMD_CLOSE_FILE,
    WR_CMD_CREATE_FILE,
    WR_CMD_DELETE_FILE,
    WR_CMD_WRITE_FILE,
    WR_CMD_READ_FILE,
    WR_CMD_RENAME_FILE,
    WR_CMD_TRUNCATE_FILE,
    WR_CMD_STAT_FILE,
    WR_CMD_LOAD_CTRL,
    WR_CMD_UPDATE_WRITTEN_SIZE,
    WR_CMD_STOP_SERVER,
    WR_CMD_SETCFG,
    WR_CMD_SET_MAIN_INST,
    WR_CMD_SWITCH_LOCK,
    WR_CMD_POSTPONE_FILE_TIME,
    WR_CMD_RELOAD_CERTS,
    WR_CMD_GET_DISK_USAGE,
    WR_CMD_MODIFY_END = 127,
    WR_CMD_QUERY_BEGIN = WR_CMD_MODIFY_END,
    WR_CMD_HANDSHAKE = WR_CMD_QUERY_BEGIN,
    WR_CMD_EXIST,  // 128
    WR_CMD_GET_FTID_BY_PATH,
    WR_CMD_GETCFG,
    WR_CMD_GET_INST_STATUS,
    WR_CMD_GET_TIME_STAT,
    WR_CMD_EXEC_REMOTE,
    WR_CMD_QUERY_HOTPATCH,
    WR_CMD_QUERY_END,
    WR_CMD_EXCHANGE_KEY,
    WR_CMD_END  // must be the last item
} wr_cmd_type_e;

#define WR_CMD_TYPE_OFFSET(cmd_id) ((uint32_t)(cmd_id) - (uint32_t)WR_CMD_BEGIN)

#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_BITS   256

char *wr_get_cmd_desc(wr_cmd_type_e cmd_type);

static inline bool32 wr_can_cmd_type_no_open(wr_cmd_type_e type)
{
    return ((type == WR_CMD_GET_INST_STATUS) || (type == WR_CMD_HANDSHAKE) || (type == WR_CMD_STOP_SERVER) ||
            (type == WR_CMD_SETCFG) || (type == WR_CMD_GETCFG));
}

typedef struct st_wr_packet_head {
    uint32_t version;
    uint32_t client_version;
    uint32_t size;
    uint8 cmd;    /* command in request packet */
    uint8 result; /* code in response packet, success(0) or error(1) */
    uint16 flags;
    uint32_t serial_number;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    uint8 reserve[28];
} wr_packet_head_t;

typedef enum en_wr_packet_version {
    WR_VERSION_0 = 0, /* version 0 */
    WR_VERSION_1 = 1, /* version 1 */
    WR_VERSION_2 = 2, /* version 2 */
} wr_packet_version_e;

#define WR_PROTO_VERSION WR_VERSION_2
#define WR_INVALID_VERSION (int32_t)0x7FFFFFFF

#define WR_PACKET_SIZE(pack) ((pack)->head->size)
#define WR_WRITE_ADDR(pack) ((pack)->buf + (pack)->head->size)
#define WR_REMAIN_SIZE(pack) ((pack)->buf_size - ((pack)->head->size))
#define WR_READ_ADDR(pack) ((pack)->buf + (pack)->offset)

typedef struct st_wr_packet {
    uint32_t offset;   // for reading
    uint32_t options;  // options
    wr_packet_head_t *head;
    uint32_t max_buf_size;  // MAX_ALLOWED_PACKET
    uint32_t buf_size;
    char *buf;
    char init_buf[WR_MAX_PACKET_SIZE];
} wr_packet_t;

// file hash struct
typedef struct st_file_hash_info {
    uint32_t file_handle;
    uint8_t curr_hash[SHA256_DIGEST_LENGTH];
    uint8_t prev_hash[SHA256_DIGEST_LENGTH];
    uint64_t last_update_time;
} file_hash_info_t;

// hash manager struct
typedef struct st_session_hash_mgr {
    spinlock_t lock;
    uint32_t hash_count;
    uint32_t hash_capacity;
    file_hash_info_t *hash_items;
} session_hash_mgr_t;

static inline void wr_init_packet(wr_packet_t *pack, uint32_t options)
{
    CM_ASSERT(pack != NULL);
    pack->offset = 0;
    pack->max_buf_size = WR_MAX_PACKET_SIZE;
    pack->buf_size = WR_MAX_PACKET_SIZE;
    pack->buf = pack->init_buf;
    pack->head = (wr_packet_head_t *)pack->buf;
    pack->options = options;
}

static inline void wr_set_client_version(wr_packet_t *pack, uint32_t version)
{
    CM_ASSERT(pack != NULL);
    pack->head->client_version = version;
}

static inline void wr_set_version(wr_packet_t *pack, uint32_t version)
{
    CM_ASSERT(pack != NULL);
    pack->head->version = version;
}

static inline uint32_t wr_get_client_version(wr_packet_t *pack)
{
    CM_ASSERT(pack != NULL);
    return pack->head->client_version;
}

static inline uint32_t wr_get_version(wr_packet_t *pack)
{
    CM_ASSERT(pack != NULL);
    return pack->head->version;
}

static inline void wr_init_get(wr_packet_t *pack)
{
    if (pack == NULL) {
        return;
    }
    pack->offset = (uint32_t)sizeof(wr_packet_head_t);
}

static inline void wr_init_set(wr_packet_t *pack, uint32_t proto_version)
{
    if (pack == NULL) {
        return;
    }
    (void)memset_s(pack->head, sizeof(wr_packet_head_t), 0, sizeof(wr_packet_head_t));
    pack->head->size = (uint32_t)sizeof(wr_packet_head_t);
    wr_set_version(pack, proto_version);
    wr_set_client_version(pack, WR_PROTO_VERSION);
}

static inline status_t wr_put_str(wr_packet_t *pack, const char *str)
{
    uint32_t size;
    errno_t errcode = 0;

    CM_ASSERT(pack != NULL);
    CM_ASSERT(str != NULL);
    size = (uint32_t)strlen(str);
    char *addr = WR_WRITE_ADDR(pack);
    uint32_t estimated_size = pack->head->size + CM_ALIGN4(size + 1);
    if (estimated_size > pack->buf_size) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, estimated_size, pack->buf_size);
        return CM_ERROR;
    }
    if (size != 0) {
        errcode = memcpy_s(addr, WR_REMAIN_SIZE(pack), str, size);
        WR_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    }
    WR_WRITE_ADDR(pack)[size] = '\0';
    pack->head->size = estimated_size;

    return CM_SUCCESS;
}

static inline status_t wr_put_sha256(wr_packet_t *pack, const unsigned char *sha256_value)
{
    errno_t errcode = 0;
    CM_ASSERT(pack != NULL);
    CM_ASSERT(sha256_value != NULL);

    char *addr = WR_WRITE_ADDR(pack);
    uint32_t estimated_size = pack->head->size + SHA256_DIGEST_LENGTH;
    if (estimated_size > pack->buf_size) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, estimated_size, pack->buf_size);
        return CM_ERROR;
    }

    errcode = memcpy_s(addr, WR_REMAIN_SIZE(pack), sha256_value, SHA256_DIGEST_LENGTH);
    WR_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);

    pack->head->size += SHA256_DIGEST_LENGTH;

    return CM_SUCCESS;
}

static inline status_t wr_put_data(wr_packet_t *pack, const void *data, uint32_t size)
{
    errno_t errcode = 0;

    CM_ASSERT(pack != NULL);
    CM_ASSERT(data != NULL);

    if (size != 0) {
        errcode = memcpy_s(WR_WRITE_ADDR(pack), WR_REMAIN_SIZE(pack), data, size);
        WR_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    }
    pack->head->size += CM_ALIGN4(size);
    return CM_SUCCESS;
}

static inline status_t wr_put_int64(wr_packet_t *pack, uint64 value)
{
    CM_ASSERT(pack != NULL);

    *(uint64 *)WR_WRITE_ADDR(pack) = (CS_DIFFERENT_ENDIAN(pack->options) != 0) ? cs_reverse_int64(value) : value;
    pack->head->size += (uint32_t)sizeof(uint64);
    return CM_SUCCESS;
}

static inline status_t wr_put_int32(wr_packet_t *pack, uint32_t value)
{
    CM_ASSERT(pack != NULL);

    *(uint32_t *)WR_WRITE_ADDR(pack) = (CS_DIFFERENT_ENDIAN(pack->options) != 0) ? cs_reverse_int32(value) : value;
    pack->head->size += (uint32_t)sizeof(uint32_t);
    return CM_SUCCESS;
}

static inline status_t wr_reserv_text_buf(wr_packet_t *pack, uint32_t size, char **data_buf)
{
    CM_ASSERT(pack != NULL);
    CM_ASSERT(data_buf != NULL);
    if (CM_ALIGN4(size) >= WR_REMAIN_SIZE(pack) - sizeof(uint32_t)) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, size, WR_REMAIN_SIZE(pack) - 1);
        return CM_ERROR;
    }

    // record the size first
    *(uint32_t *)WR_WRITE_ADDR(pack) = (CS_DIFFERENT_ENDIAN(pack->options) != 0) ? cs_reverse_int32(size) : size;
    pack->head->size += (uint32_t)sizeof(uint32_t);

    *data_buf = WR_WRITE_ADDR(pack);
    pack->head->size += CM_ALIGN4(size);
    return CM_SUCCESS;
}

static inline status_t wr_pack_check_len(wr_packet_t *pack, uint32_t inc)
{
    if ((pack->offset + inc) > pack->head->size) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, (pack->offset + inc), pack->head->size);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static inline status_t wr_get_sha256(wr_packet_t *pack, unsigned char *buf)
{
    errno_t errcode = 0;
    CM_ASSERT(pack != NULL);

    CM_RETURN_IFERR(wr_pack_check_len(pack, SHA256_DIGEST_LENGTH));
    if (buf != NULL) {
        errcode = memcpy_s(buf, SHA256_DIGEST_LENGTH, WR_READ_ADDR(pack), SHA256_DIGEST_LENGTH);
        WR_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    }
    pack->offset += SHA256_DIGEST_LENGTH;
    return CM_SUCCESS;
}

static inline status_t calculate_data_hash(const void *data, size_t size, uint8_t *hash)
{
    CM_ASSERT(data != NULL);
    CM_ASSERT(hash != NULL);

    if (size <=0 || size > WR_PAGE_SIZE) {
        LOG_RUN_ERR("[hash]: invalid length: %zu.", size);
        return CM_ERROR;
    }

    SHA256_CTX sha256;
    if (SHA256_Init(&sha256) != 1) {
        LOG_RUN_ERR("[hash]: Failed to init sha256.");
        return CM_ERROR;
    }

    if (SHA256_Update(&sha256, data, size) != 1) {
        LOG_RUN_ERR("[hash]: Failed to update sha256.");
        return CM_ERROR;
    }

    if (SHA256_Final(hash, &sha256) != 1) {
        LOG_RUN_ERR("[hash]: Failed to calculate sha256.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

// combine_hash = data_hash ^ pre_hash
static inline status_t xor_sha256_hash(const uint8_t *data_hash,
                        const uint8_t *pre_hash, uint8_t *combine_hash)
{
    if (data_hash == NULL || pre_hash == NULL || combine_hash == NULL) {
        LOG_RUN_ERR("[hash]: invalid param.");
        return CM_ERROR;
    }

    // XOR operation on bytes
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        combine_hash[i] = data_hash[i] ^ pre_hash[i];
    }

    return CM_SUCCESS;
}

static inline status_t wr_get_data(wr_packet_t *pack, uint32_t size, void **buf)
{
    int64 len;
    CM_ASSERT(pack != NULL);

    len = (int64)CM_ALIGN4(size);
    TO_UINT32_OVERFLOW_CHECK(len, int64);
    CM_RETURN_IFERR(wr_pack_check_len(pack, len));
    char *temp_buf = WR_READ_ADDR(pack);
    pack->offset += CM_ALIGN4(size);
    if (buf != NULL) {
        *buf = (void *)temp_buf;
    }
    return CM_SUCCESS;
}

static inline status_t wr_get_packet_strlen(wr_packet_t *pack, char *str, size_t *str_len)
{
    uint32_t rem_len = (pack->head->size - pack->offset) - 1;
    while (str[*str_len] != '\0') {
        if ((*str_len)++ > rem_len) {
            CM_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED STRING");
            return CM_ERROR;
        }
    }
    (*str_len)++;
    return CM_SUCCESS;
}

static inline status_t wr_get_str(wr_packet_t *pack, char **buf)
{
    int64 len;
    size_t str_len = 0;
    CM_ASSERT(pack != NULL);

    CM_RETURN_IFERR(wr_pack_check_len(pack, 1));
    char *str = WR_READ_ADDR(pack);
    CM_RETURN_IFERR(wr_get_packet_strlen(pack, str, &str_len));
    len = (int64)CM_ALIGN4(str_len);
    TO_UINT32_OVERFLOW_CHECK(len, int64);
    pack->offset += (uint32_t)len;
    if (buf != NULL) {
        *buf = str;
    }
    return CM_SUCCESS;
}

static inline status_t wr_get_int64(wr_packet_t *pack, int64 *value)
{
    int64 temp_value;
    CM_ASSERT(pack != NULL);

    CM_RETURN_IFERR(wr_pack_check_len(pack, sizeof(int64)));

    temp_value = *(int64 *)WR_READ_ADDR(pack);
    temp_value = (CS_DIFFERENT_ENDIAN(pack->options) != 0) ? (int64)cs_reverse_int64((uint64)temp_value) : temp_value;
    pack->offset += (uint32_t)sizeof(int64);
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

static inline status_t wr_get_int32(wr_packet_t *pack, int32_t *value)
{
    int32_t temp_value;
    CM_ASSERT(pack != NULL);

    CM_RETURN_IFERR(wr_pack_check_len(pack, sizeof(int32_t)));

    temp_value = *(int32_t *)WR_READ_ADDR(pack);
    pack->offset += (uint32_t)sizeof(int32_t);
    temp_value = (CS_DIFFERENT_ENDIAN(pack->options) != 0) ? (int32_t)cs_reverse_int32((uint32_t)temp_value) : temp_value;
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

static inline status_t wr_get_text(wr_packet_t *pack, text_t *text)
{
    CM_ASSERT(pack != NULL);
    CM_ASSERT(text != NULL);

    CM_RETURN_IFERR(wr_get_int32(pack, (int32_t *)&text->len));
    if ((text->len > WR_MAX_PACKET_SIZE)) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, "PACKET OVERFLOW");
        return CM_ERROR;
    }
    if (text->len == 0) {
        return CM_SUCCESS;
    }

    return wr_get_data(pack, text->len, (void **)&(text->str));
}

static inline void wr_free_packet_buffer(wr_packet_t *pack)
{
    if (pack->buf != pack->init_buf) {
        if (pack->buf != NULL) {
            free(pack->buf);
            pack->buf = NULL;
        }

        wr_init_packet(pack, 0);
    }
}

static inline status_t compare_sha256(
    const unsigned char *hash1, const unsigned char *hash2)
{
    if (hash1 == NULL || hash2 == NULL) {
        LOG_RUN_ERR("[hash]: invalid param, failed to compare hash");
        return CM_ERROR;
    }

    errno_t err = memcmp(hash1, hash2, SHA256_DIGEST_LENGTH);
    
    if (err != EOK) {
        LOG_RUN_ERR("[hash]: failed to compare hash, errno:%d", err);
        WR_THROW_ERROR(ERR_WR_MEM_CMP_FAILED);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t wr_put_text(wr_packet_t *pack, text_t *text);
status_t wr_put_str_with_cutoff(wr_packet_t *pack, const char *str);
status_t wr_write_packet(cs_pipe_t *pipe, wr_packet_t *pack);
status_t wr_write(cs_pipe_t *pipe, wr_packet_t *pack);
status_t wr_read(cs_pipe_t *pipe, wr_packet_t *pack, bool32 cs_client);
status_t wr_call_ex(cs_pipe_t *pipe, wr_packet_t *req, wr_packet_t *ack);

#ifdef __cplusplus
}
#endif

#endif  // __WR_PROTOCOL_H__
