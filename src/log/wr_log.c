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
 * wr_log.c
 *
 *
 * IDENTIFICATION
 *    src/log/wr_log.c
 *
 * -------------------------------------------------------------------------
 */

#include "wr_log.h"
#include "cm_num.h"
#include "wr_defs.h"
#include "wr_param.h"
#include "wr_param_verify.h"
#include "wr_session.h"
#include "cm_system.h"

/*
 * one error no corresponds to one error desc
 * Attention: keep the array index same as error no
 */
const char *g_wr_error_desc[WR_ERROR_COUNT] = {
    // Zenith File System, range [2000, 2500]
    [ERR_WR_VG_CREATE] = "Create volume group %s failed, reason %s",
    [ERR_WR_VG_LOCK] = "Lock volume group %s failed",
    [ERR_WR_VG_REMOVE] = "Forbidden remove volume group's superblock",
    [ERR_WR_VG_CHECK] = "Check volume group %s failed, reason %s",
    [ERR_WR_VG_CHECK_NOT_INIT] = "The volume group has not been initialized.",
    [ERR_WR_VG_NOT_EXIST] = "Failed to find volume group %s, please check vg config file.",
    [ERR_WR_VOLUME_SYSTEM_IO] = "Failed to operate volume %s for system I/O error.",
    [ERR_WR_VOLUME_OPEN] = "Open volume '%s' failed, reason %d",
    [ERR_WR_VOLUME_READ] = "Read volume '%s' failed, volume id %d, reason %d",
    [ERR_WR_VOLUME_WRITE] = "Write volume '%s' failed, volume id %d, reason %d",
    [ERR_WR_VOLUME_SEEK] = "Seek volume '%s' failed, volume id %d, reason %d",
    [ERR_WR_VOLUME_ADD] = "Failed to add volume %s, reason %s.",
    [ERR_WR_VOLUME_EXISTED] = "Add/Replace an existed volume %s of volume-group %s failed",
    [ERR_WR_VOLUME_NOEXIST] = "Remove/Replace a non-existent volume %s of volume-group %s failed",
    [ERR_WR_VOLUME_REMOVE_NONEMPTY] = "Remove a nonempty volume %s failed",
    [ERR_WR_VOLUME_REMOVE_SUPER_BLOCK] = "Remove super block %s failed",
    [ERR_WR_VOLUME_REPLACE] = "Failed to replace volume %s, reason %s.",
    [ERR_WR_FILE_SEEK] = "Failed to seek file, vgid:%u, fid:%llu, offset:%lld, file size:%llu",
    [ERR_WR_FILE_REMOVE_OPENING] = "WR file is open",
    [ERR_WR_FILE_REMOVE_SYSTEM] = "WR file %s is system file",
    [ERR_WR_FILE_RENAME] = "Rename failed, reason %s",
    [ERR_WR_FILE_RENAME_DIFF_VG] = "Failed to rename from vg %s to another vg %s, function not supported",
    [ERR_WR_FILE_RENAME_EXIST] = "Rename failed, reason %s",
    [ERR_WR_FILE_RENAME_OPENING_REMOTE] = "Failed to rename %s to %s, while source file is opend by other instance.",
    [ERR_WR_FILE_CLOSE] = "Close file failed, reason %s",
    [ERR_WR_FILE_CREATE] = "Create file failed, reason %s",
    [ERR_WR_FILE_RDWR_INSUFF_PER] = "Insufficient permission to %s file, while the permission is %u.",
    [ERR_WR_FILE_NOT_EXIST] = "The file %s of %s does not exist",
    [ERR_WR_FILE_OPENING_REMOTE] = "The file is open in other inst: %hhu, command:%u exec failed.",
    [ERR_WR_FILE_TYPE_MISMATCH] = "The type of directory link or file %s is not matched.",
    [ERR_WR_FILE_PATH_ILL] = "Path %s decode error %s",
    [ERR_WR_FILE_INVALID_SIZE] = "Invalid extend offset %lld, size %d.",
    [ERR_WR_DIR_REMOVE_NOT_EMPTY] = "The dir is not empty, can not remove.",
    [ERR_WR_DIR_CREATE_DUPLICATED] = "Make dir or Create file failed, %s has already existed",
    [ERR_WR_LINK_READ_NOT_LINK] = "The path %s is not a soft link.",
    [ERR_WR_LINK_CREATE] = "Failed to create symbolic link, reason %s",
    [ERR_WR_CONFIG_FILE_OVERSIZED] = "The size of config file %s is too large",
    [ERR_WR_CONFIG_LOAD] = "Please check wr_vg_conf.ini, reason %s",
    [ERR_WR_CONFIG_LINE_OVERLONG] = "The length of row %d is too long",
    [ERR_WR_REDO_ILL] = "WR redo log error, reason %s",
    [ERR_WR_OAMAP_INSERT] = "Failed to insert hash map ",
    [ERR_WR_OAMAP_INSERT_DUP_KEY] = "Hash map duplicated key",
    [ERR_WR_OAMAP_FETCH] = "Failed to fetch hash map",
    [ERR_WR_SKLIST_ERR] = "Error WR skip list.",
    [ERR_WR_SKLIST_NOT_INIT] = "Error WR skip list not init.",
    [ERR_WR_SKLIST_NOT_EXIST] = "Error WR skip list not exist.",
    [ERR_WR_SKLIST_EXIST] = "Error WR skip list key value exist.",
    [ERR_WR_SHM_CREATE] = "Failed to create shared memory, key=0x%08x, size=%llu",
    [ERR_WR_SHM_CHECK] = "Failed to check shared memory ctrl, key=0x%08x, reason=%s",
    [ERR_WR_SHM_LOCK] = "Failed to lock vg shared memory, reason=%s",
    [ERR_WR_SHM_LOCK_TIMEOUT] = "Try to get shm lock timeout",
    [ERR_WR_GA_INIT] = "WR ga init error, reason %s",
    [ERR_WR_GA_GET_ADDR] = "WR ga get addr error, pool id %d, object id%u.",
    [ERR_WR_GA_ALLOC_OBJECT] = "WR ga alloc object error, pool id %d.",
    [ERR_WR_SESSION_INVALID_ID] = "Invalid session %d",
    [ERR_WR_SESSION_CREATE] = "Create new WR session failed, no free sessions, %d sessions used.",
    [ERR_WR_SESSION_EXTEND] = "Extend WR session failed, reason : %s.",
    [ERR_WR_INVALID_PARAM] = "Invalid WR parameter: %s",
    [ERR_WR_NO_SPACE] = "WR no space in the vg",
    [ERR_WR_ENV_NOT_INITIALIZED] = "The WR env has not been initialized.",
    [ERR_WR_CLI_EXEC_FAIL] = "WR client exec cmd '%s' failed, reason %s.",
    [ERR_WR_FNODE_CHECK] = "WR fnode error, reason %s",
    [ERR_WR_LOCK_TIMEOUT] = "WR lock timeout",
    [ERR_WR_SERVER_IS_DOWN] = "WR server is down",
    [ERR_WR_CHECK_SIZE] = "Failed to specify size %d which is not  aligned with WR allocate-unit size %d",
    [ERR_WR_MES_ILL] = "WR message contact error, reason %s",
    [ERR_WR_STRING_TOO_LONG] = "The length(%u) of text can't be larger than %u, text = %s",
    [ERR_WR_TCP_TIMEOUT_REMAIN] = "Waiting for request head(size) timeout, %d bytes remained",
    [ERR_WR_UDS_INVALID_URL] = "Invalid unix domain socket url:%s, length %d. \
                                Eg:server_locator=\"UDS:UNIX_emserver.domain\"",
    [ERR_WR_RECV_MSG_FAILED] = "Recv msg failed, errcode:%d, inst:%u.",
    [ERR_WR_INIT_LOGGER_FAILED] = "Log init failed.",
    [ERR_WR_OUT_OF_MEM] = "Failed to apply for memory.",
    [ERR_WR_INVALID_ID] = "Invalid %s id : %llu.",
    [ERR_WR_PROCESS_REMOTE] = "Failed to process remote, errcode: %d, errmsg: %s.",
    [ERR_WR_CONNECT_FAILED] = "Failed to connect wr server, errcode: %d, errmsg: %s.",
    [ERR_WR_VERSION_NOT_MATCH] =
        "[CHECK_PROTO]Protocol version need be changed, old protocol version is %u, new protocol version is %u.",
    [ERR_WR_INVALID_BLOCK_TYPE] = "Get Invalid block type, expect type is %u, but the type in share memory is %u.",
    [ERR_WR_SERVER_REBOOT] = "WR server has reboot or close, wr client need reboot or close.",
    [ERR_WR_UNSUPPORTED_CMD] =
        "Command \"%s\" is not supported in current version(%u) of wrserver, least supporting version is %u.",
    [ERR_WR_VOLUME_FENCE_CHECK_COND] = "Fail to check fence cond:%s.",
    [ERR_WR_MASTER_CHANGE] = "Master id has changed.",
    [ERR_WR_RECOVER_CAUSE_BREAK] = "Req break by recovery.",
    [ERR_WR_FILE_SYSTEM_ERROR] = "File system error, reason %m.",
    [ERR_WR_CONNECTION_CLOSED] = "WR connection is closed",
};

wr_log_def_t g_wr_cmd_log[] = {
    {LOG_DEBUG, "debug/wrcmd.dlog"},
    {LOG_OPER, "oper/wrcmd.olog"},
    {LOG_RUN, "run/wrcmd.rlog"},
    {LOG_ALARM, "wrcmd_alarm.log"},
};

wr_log_def_t g_wr_instance_log[] = {
    {LOG_DEBUG, "debug/wrinstance.dlog"},
    {LOG_OPER, "oper/wrinstance.olog"},
    {LOG_RUN, "run/wrinstance.rlog"},
    {LOG_ALARM, "wrinstance_alarm.log"},
    {LOG_AUDIT, "audit/wrinstance.aud"},
    {LOG_BLACKBOX, "blackbox/wrinstance.blog"},
};

uint32 g_wr_warn_id[] = {
    WARN_WR_SPACEUSAGE_ID,
};

char *g_wr_warn_desc[] = {
    "WRSpaceUsageUpToHWM",
};

#define WR_MAX_PRINT_LEVEL 4
static char *g_wr_printf_tab[WR_MAX_PRINT_LEVEL] = {"", "\t", "\t\t", "\t\t\t"};

char *wr_get_print_tab(uint8 level)
{
    return g_wr_printf_tab[level];
}

wr_log_def_t *wr_get_instance_log_def()
{
    return g_wr_instance_log;
}
wr_log_def_t *wr_get_cmd_log_def()
{
    return g_wr_cmd_log;
}
uint32 wr_get_instance_log_def_count()
{
    return sizeof(g_wr_instance_log) / sizeof(wr_log_def_t);
}
uint32 wr_get_cmd_log_def_count()
{
    return sizeof(g_wr_cmd_log) / sizeof(wr_log_def_t);
}

static status_t wr_init_log_file(log_param_t *log_param, wr_config_t *inst_cfg)
{
    int64 val_int64;
    uint16 val_uint16;
    char *value = NULL;

    value = cm_get_config_value(&inst_cfg->config, "_LOG_MAX_FILE_SIZE");
    status_t status = cm_str2size(value, &val_int64);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "_LOG_MAX_FILE_SIZE"));
    if (val_int64 < CM_MIN_LOG_FILE_SIZE || val_int64 > CM_MAX_LOG_FILE_SIZE) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "_LOG_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    log_param->max_log_file_size = (uint64)val_int64;

    value = cm_get_config_value(&inst_cfg->config, "_AUDIT_MAX_FILE_SIZE");
    status = cm_str2size(value, &val_int64);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "_AUDIT_MAX_FILE_SIZE"));
    if (val_int64 < CM_MIN_LOG_FILE_SIZE || val_int64 > CM_MAX_LOG_FILE_SIZE) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "_AUDIT_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    log_param->max_audit_file_size = (uint64)val_int64;

    value = cm_get_config_value(&inst_cfg->config, "_LOG_FILE_PERMISSIONS");
    status = cm_str2uint16(value, &val_uint16);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "_LOG_FILE_PERMISSIONS"));
    if (val_uint16 < CM_DEF_LOG_FILE_PERMISSIONS || val_uint16 > CM_MAX_LOG_PERMISSIONS) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "_LOG_FILE_PERMISSIONS");
        return CM_ERROR;
    }
    cm_log_set_file_permissions(val_uint16);

    value = cm_get_config_value(&inst_cfg->config, "_LOG_PATH_PERMISSIONS");
    status = cm_str2uint16(value, &val_uint16);
    WR_RETURN_IFERR2(status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "_LOG_PATH_PERMISSIONS"));
    if (val_uint16 < CM_DEF_LOG_PATH_PERMISSIONS || val_uint16 > CM_MAX_LOG_PERMISSIONS) {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "_LOG_PATH_PERMISSIONS");
        return CM_ERROR;
    }
    cm_log_set_path_permissions(val_uint16);

    return CM_SUCCESS;
}

static status_t wr_init_log_home_ex(wr_config_t *inst_cfg, char *log_parm_value, char *log_param_name, char *log_dir)
{
    errno_t errcode = 0;
    bool32 verify_flag = CM_FALSE;
    // register error callback function
    char *value = cm_get_config_value(&inst_cfg->config, log_param_name);
    uint32 val_len = (value == NULL) ? 0 : (uint32)strlen(value);
    if (val_len >= CM_MAX_LOG_HOME_LEN) {
        WR_THROW_ERROR(ERR_INIT_LOGGER, "%s value: %s is out of range.", log_param_name, log_parm_value);
        return CM_ERROR;
    }
    if (val_len > 0) {
        errcode = strncpy_s(log_parm_value, CM_MAX_LOG_HOME_LEN, value, val_len);
        securec_check_ret(errcode);
        verify_flag = CM_TRUE;
    } else {
        char *home = wr_get_cfg_dir(inst_cfg);
        if (snprintf_s(log_parm_value, CM_MAX_LOG_HOME_LEN, CM_MAX_LOG_HOME_LEN - 1, "%s/%s", home, log_dir) == -1) {
            WR_ASSERT_LOG(0, "Init log dir:%s/%s failed.", home, log_dir);
        }
    }
    status_t status = wr_verify_log_file_dir_name(log_parm_value);
    WR_RETURN_IFERR2(
        status, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "failed to load params, invalid %s", log_param_name));
    if (verify_flag && wr_verify_log_file_real_path(log_parm_value) != CM_SUCCESS) {
        WR_RETURN_IFERR2(
            CM_ERROR, WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "failed to load params, invalid %s", log_param_name));
    }
    return CM_SUCCESS;
}

static status_t wr_init_log_home(wr_config_t *inst_cfg, log_param_t *log_param, char *alarm_dir)
{
    status_t status;
    status = wr_init_log_home_ex(inst_cfg, log_param->log_home, "LOG_HOME", "log");
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }
    status = wr_init_log_home_ex(inst_cfg, alarm_dir, "LOG_ALARM_HOME", "log/alarm");
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
static status_t wr_load_log_compressed(wr_config_t *inst_cfg, log_param_t *log_param)
{
    char *value = cm_get_config_value(&inst_cfg->config, "LOG_COMPRESSED");
    if (cm_str_equal_ins(value, "TRUE")) {
        log_param->log_compressed = CM_TRUE;
        log_param->log_compress_buf = malloc(CM_LOG_COMPRESS_BUFSIZE);
        if (log_param->log_compress_buf == NULL) {
            log_param->log_compressed = CM_FALSE;
            LOG_RUN_ERR("Failed to alloc compree buf when init log.");
            WR_THROW_ERROR(ERR_WR_INIT_LOGGER_FAILED);
            return CM_ERROR;
        }
    } else if (cm_str_equal_ins(value, "FALSE")) {
        log_param->log_compressed = CM_FALSE;
        log_param->log_compress_buf = NULL;
    } else {
        WR_THROW_ERROR(ERR_WR_INVALID_PARAM, "LOG_COMPRESSED");
        return CM_ERROR;
    }
    LOG_RUN_INF("LOG_COMPRESSED = %u.", log_param->log_compressed);
    return CM_SUCCESS;
}
static status_t wr_init_loggers_inner(wr_config_t *inst_cfg, log_param_t *log_param)
{
    uint32 val_uint32;
    char *value = NULL;

    value = cm_get_config_value(&inst_cfg->config, "_LOG_BACKUP_FILE_COUNT");
    if (cm_str2uint32(value, &val_uint32) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "_LOG_BACKUP_FILE_COUNT");
        return CM_ERROR;
#ifdef OPENGAUSS
    } else if (val_uint32 > CM_MAX_LOG_FILE_COUNT_LARGER) {
#else
    } else if (val_uint32 > CM_MAX_LOG_FILE_COUNT) {
#endif
        CM_THROW_ERROR(ERR_INVALID_PARAM, "_LOG_BACKUP_FILE_COUNT");
        return CM_ERROR;
    } else {
        log_param->log_backup_file_count = val_uint32;
    }

    value = cm_get_config_value(&inst_cfg->config, "_AUDIT_BACKUP_FILE_COUNT");
    if (cm_str2uint32(value, &val_uint32) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "_AUDIT_BACKUP_FILE_COUNT");
        return CM_ERROR;
#ifdef OPENGAUSS
    } else if (val_uint32 > CM_MAX_LOG_FILE_COUNT_LARGER) {
#else
    } else if (val_uint32 > CM_MAX_LOG_FILE_COUNT) {
#endif
        CM_THROW_ERROR(ERR_INVALID_PARAM, "_AUDIT_BACKUP_FILE_COUNT");
        return CM_ERROR;
    } else {
        log_param->audit_backup_file_count = val_uint32;
    }

    status_t status = wr_init_log_file(log_param, inst_cfg);
    WR_RETURN_IF_ERROR(status);

    value = cm_get_config_value(&inst_cfg->config, "_LOG_LEVEL");
    status = cm_str2uint32(value, (uint32 *)&log_param->log_level);
    WR_RETURN_IFERR2(status, CM_THROW_ERROR(ERR_INVALID_PARAM, "_LOG_LEVEL"));
    if (log_param->log_level > MAX_LOG_LEVEL) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "_LOG_LEVEL");
        return CM_ERROR;
    }

    value = cm_get_config_value(&inst_cfg->config, "_AUDIT_LEVEL");
    if (cm_str2uint32(value, (uint32 *)&log_param->audit_level) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "_AUDIT_LEVEL");
        return CM_ERROR;
    }
    if (log_param->audit_level > WR_AUDIT_ALL) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "_AUDIT_LEVEL");
        return CM_ERROR;
    }
    return wr_load_log_compressed(inst_cfg, log_param);
}

status_t wr_init_loggers(wr_config_t *inst_cfg, wr_log_def_t *log_def, uint32 log_def_count, char *name)
{
    char file_name[CM_FULL_PATH_BUFFER_SIZE];
    uint32 buffer_len = CM_FULL_PATH_BUFFER_SIZE;
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_level = 0;
    char alarm_dir[CM_MAX_LOG_HOME_LEN];
    if (wr_init_log_home(inst_cfg, log_param, alarm_dir) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (wr_init_loggers_inner(inst_cfg, log_param) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (wr_init_log_file(log_param, inst_cfg) != CM_SUCCESS) {
        return CM_ERROR;
    }

    int32 ret;
    for (size_t i = 0; i < log_def_count; i++) {
        if (log_def[i].log_id == LOG_ALARM) {
            ret = snprintf_s(file_name, buffer_len, (buffer_len - 1), "%s/%s", alarm_dir, log_def[i].log_filename);
        } else {
            ret = snprintf_s(
                file_name, buffer_len, (buffer_len - 1), "%s/%s", log_param->log_home, log_def[i].log_filename);
        }
        WR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
        if (cm_log_init(log_def[i].log_id, file_name) != CM_SUCCESS) {
            return CM_ERROR;
        }
        cm_log_open_compress(log_def[i].log_id, WR_TRUE);
    }
    log_param->log_instance_startup = CM_TRUE;
    cm_init_error_handler(cm_set_log_error);
    status_t status = cm_set_log_module_name(name, (int32)strlen(name));
    WR_RETURN_IF_ERROR(status);
    errno_t rc = strcpy_sp(log_param->instance_name, CM_MAX_NAME_LEN, name);
    if (rc != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return CM_ERROR;
    }
    LOG_RUN_INF("wr set log param _LOG_LEVEL, param_value = %u", log_param->log_level);
    LOG_RUN_INF("wr set log param _AUDIT_LEVEL, param_value = %u", log_param->audit_level);
    return CM_SUCCESS;
}

static void sql_audit_init_assist(
    wr_session_t *session, status_t status, wr_cmd_type_e cmd_type, wr_audit_assist_t *assist)
{
    int32 ret, tz_hour, tz_min;
    const char *err_msg = NULL;
    char *user_name = cm_sys_user_name();
    cs_get_remote_host(&session->pipe, assist->os_host);
    MEMS_RETVOID_IFERR(strcpy_s(assist->db_user, CM_NAME_BUFFER_SIZE, (const char *)user_name));

    // DATE
    assist->tz = g_timer()->tz;
    tz_hour = TIMEZONE_GET_HOUR(assist->tz);
    tz_min = TIMEZONE_GET_MINUTE(assist->tz);
    if (tz_hour >= 0) {
        ret = snprintf_s(assist->date, CM_MAX_TIME_STRLEN, CM_MAX_TIME_STRLEN - 1, "UTC+%02d:%02d ", tz_hour, tz_min);
    } else {
        ret = snprintf_s(assist->date, CM_MAX_TIME_STRLEN, CM_MAX_TIME_STRLEN - 1, "UTC%02d:%02d ", tz_hour, tz_min);
    }
    if (ret == -1) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return;
    }

    (void)cm_date2str(
        g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", assist->date + ret, CM_MAX_TIME_STRLEN - (uint32)ret);

    // SESSIONID
    assist->sid = (int32)session->id;
    assist->session_id.str = assist->session_buf;
    cm_int2text(assist->sid, &assist->session_id);
    assist->session_id.str[assist->session_id.len] = '\0';

    // RETURNCODE
    assist->return_code.str = assist->return_code_buf;
    assist->code = 0;
    if (status != CM_SUCCESS) {
        cm_get_error(&assist->code, &err_msg);
    }
    PRTS_RETVOID_IFERR(
        snprintf_s(assist->return_code_buf, CM_MAX_NUMBER_LEN, CM_MAX_NUMBER_LEN - 1, "WR-%05d", assist->code));
    assist->return_code.len = (uint32)strlen(assist->return_code_buf);
    assist->return_code.str[assist->return_code.len] = '\0';
}

static void sql_audit_create_message(
    wr_audit_assist_t *assist, char *resource, char *action, char *log_msg, uint32 *log_msg_len)
{
    int32 ret = snprintf_s(log_msg, CM_T2S_LARGER_BUFFER_SIZE, CM_T2S_LARGER_BUFFER_SIZE - 1,
        "SESSIONID:[%u] \"%s\" USER:[%u] \"%s\" HOST:[%u] \"%s\" "
        "RESOURCE:[%u] \"%s\" ACTION:[%u] \"%s\" RETURNCODE:[%u] \"%s\" ",
        assist->session_id.len, assist->session_id.str,     // SESSIONID
        (uint32)strlen(assist->db_user), assist->db_user,   // USER
        (uint32)strlen(assist->os_host), assist->os_host,   // HOST
        (uint32)strlen(resource), resource,                 // RESOURCE
        (uint32)strlen(action), action,                     // ACTION
        assist->return_code.len, assist->return_code.str);  // RETURNCODE
    if (SECUREC_UNLIKELY(ret == -1) || (uint32)(ret + 1) > CM_T2S_LARGER_BUFFER_SIZE) {
        *log_msg_len = CM_T2S_LARGER_BUFFER_SIZE - 1;
        log_msg[CM_T2S_LARGER_BUFFER_SIZE - 1] = '\0';
        return;
    }

    *log_msg_len = (uint32)ret + 1;
    log_msg[*log_msg_len - 1] = '\"';
    log_msg[*log_msg_len] = '\0';
}

static void sql_audit_log(wr_session_t *session, status_t status, uint8 cmd_type)
{
    wr_audit_assist_t assist = {0};
    char *log_msg = cm_get_t2s_addr();
    uint32 log_msg_len;

    sql_audit_init_assist(session, status, cmd_type, &assist);
    sql_audit_create_message(&assist, session->audit_info.resource, session->audit_info.action, log_msg, &log_msg_len);
    LOG_AUDIT("%s\nLENGTH: \"%u\"\n%s\n", assist.date, log_msg_len, log_msg);
}

void sql_record_audit_log(void *sess, status_t status, uint8 cmd_type)
{
    if (cmd_type >= WR_CMD_QUERY_END) {
        return;
    }
    wr_session_t *session = (wr_session_t *)sess;
    uint32 audit_level = cm_log_param_instance()->audit_level;
    if ((audit_level & WR_AUDIT_MODIFY) == 0 && cmd_type >= WR_CMD_MODIFY_BEGIN && cmd_type < WR_CMD_MODIFY_END) {
        return;
    }
    if ((audit_level & WR_AUDIT_QUERY) == 0 && cmd_type >= WR_CMD_QUERY_BEGIN && cmd_type < WR_CMD_QUERY_END) {
        return;
    }
    sql_audit_log(session, status, cmd_type);
}
