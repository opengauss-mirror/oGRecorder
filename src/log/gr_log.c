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
 * gr_log.c
 *
 *
 * IDENTIFICATION
 *    src/log/gr_log.c
 *
 * -------------------------------------------------------------------------
 */

#include "gr_log.h"
#include "cm_num.h"
#include "gr_defs.h"
#include "gr_param.h"
#include "gr_param_verify.h"
#include "gr_session.h"
#include "cm_system.h"

/*
 * one error no corresponds to one error desc
 * Attention: keep the array index same as error no
 */
const char *g_gr_error_desc[GR_ERROR_COUNT] = {
    // Zenith File System, range [2000, 2500]
    [ERR_GR_FILE_SEEK] = "Failed to seek file, vgid:%u, fid:%llu, offset:%lld, file size:%llu",
    [ERR_GR_FILE_REMOVE_OPENING] = "GR file is open",
    [ERR_GR_FILE_REMOVE_SYSTEM] = "GR file %s is system file",
    [ERR_GR_FILE_RENAME] = "Rename failed, reason %s",
    [ERR_GR_FILE_RENAME_DIFF_VG] = "Failed to rename from vg %s to another vg %s, function not supported",
    [ERR_GR_FILE_RENAME_EXIST] = "Rename failed, reason %s",
    [ERR_GR_FILE_RENAME_OPENING_REMOTE] = "Failed to rename %s to %s, while source file is opend by other instance.",
    [ERR_GR_FILE_CLOSE] = "Close file failed, reason %s",
    [ERR_GR_FILE_CREATE] = "Create file failed, reason %s",
    [ERR_GR_FILE_RDWR_INSUFF_PER] = "Insufficient permission to %s file, while the permission is %u.",
    [ERR_GR_FILE_NOT_EXIST] = "The file %s of %s does not exist",
    [ERR_GR_FILE_OPENING_REMOTE] = "The file is open in other inst: %hhu, command:%u exec failed.",
    [ERR_GR_FILE_TYPE_MISMATCH] = "The type of directory link or file %s is not matched.",
    [ERR_GR_FILE_PATH_ILL] = "Path %s decode error %s",
    [ERR_GR_FILE_INVALID_SIZE] = "Invalid extend offset %lld, size %d.",
    [ERR_GR_FILE_INVALID_FLAG] = "Invalid gr file flag, O_CREAT and O_TRUNC not supported.",
    [ERR_GR_FILE_INVALID_EXPIRE_TIME] = "Invalid expire time.",
    [ERR_GR_DIR_REMOVE_NOT_EMPTY] = "The dir is not empty, can not remove.",
    [ERR_GR_DIR_CREATE_DUPLICATED] = "Make dir or Create file failed, %s has already existed",
    [ERR_GR_LINK_READ_NOT_LINK] = "The path %s is not a soft link.",
    [ERR_GR_LINK_CREATE] = "Failed to create symbolic link, reason %s",
    [ERR_GR_CONFIG_FILE_OVERSIZED] = "The size of config file %s is too large",
    [ERR_GR_CONFIG_LOAD] = "Please check gr_vg_conf.ini, reason %s",
    [ERR_GR_CONFIG_LINE_OVERLONG] = "The length of row %d is too long",
    [ERR_GR_REDO_ILL] = "GR redo log error, reason %s",
    [ERR_GR_OAMAP_INSERT] = "Failed to insert hash map ",
    [ERR_GR_OAMAP_INSERT_DUP_KEY] = "Hash map duplicated key",
    [ERR_GR_OAMAP_FETCH] = "Failed to fetch hash map",
    [ERR_GR_SESSION_INVALID_ID] = "Invalid session %d",
    [ERR_GR_SESSION_CREATE] = "Create new GR session failed, no free sessions, %d sessions used.",
    [ERR_GR_SESSION_EXTEND] = "Extend GR session failed, reason : %s.",
    [ERR_GR_INVALID_PARAM] = "Invalid GR parameter: %s",
    [ERR_GR_NO_SPACE] = "GR no space in the vg",
    [ERR_GR_ENV_NOT_INITIALIZED] = "The GR env has not been initialized.",
    [ERR_GR_CLI_EXEC_FAIL] = "GR client exec cmd '%s' failed, reason %s.",
    [ERR_GR_FNODE_CHECK] = "GR fnode error, reason %s",
    [ERR_GR_LOCK_TIMEOUT] = "GR lock timeout",
    [ERR_GR_SERVER_IS_DOWN] = "GR server is down",
    [ERR_GR_CHECK_SIZE] = "Failed to specify size %d which is not  aligned with GR allocate-unit size %d",
    [ERR_GR_MES_ILL] = "GR message contact error, reason %s",
    [ERR_GR_STRING_TOO_LONG] = "The length(%u) of text can't be larger than %u, text = %s",
    [ERR_GR_TCP_TIMEOUT_REMAIN] = "Waiting for request head(size) timeout, %d bytes remained",
    [ERR_GR_TCP_INVALID_URL] = "Invalid tcp url:%s, length %d. \
                                Eg:server_locator=\"TCP:127.0.0.1:8080\"",
    [ERR_GR_RECV_MSG_FAILED] = "Recv msg failed, errcode:%d, inst:%u.",
    [ERR_GR_INIT_LOGGER_FAILED] = "Log init failed.",
    [ERR_GR_OUT_OF_MEM] = "Failed to apply for memory.",
    [ERR_GR_INVALID_ID] = "Invalid %s id : %llu.",
    [ERR_GR_PROCESS_REMOTE] = "Failed to process remote, errcode: %d, errmsg: %s.",
    [ERR_GR_CONNECT_FAILED] = "Failed to connect gr server, errcode: %d, errmsg: %s.",
    [ERR_GR_VERSION_NOT_MATCH] =
        "[CHECK_PROTO]Protocol version need be changed, old protocol version is %u, new protocol version is %u.",
    [ERR_GR_INVALID_BLOCK_TYPE] = "Get Invalid block type, expect type is %u, but the type in share memory is %u.",
    [ERR_GR_SERVER_REBOOT] = "GR server has reboot or close, gr client need reboot or close.",
    [ERR_GR_UNSUPPORTED_CMD] =
        "Command \"%s\" is not supported in current version(%u) of grserver, least supporting version is %u.",
    [ERR_GR_MASTER_CHANGE] = "Master id has changed.",
    [ERR_GR_RECOVER_CAUSE_BREAK] = "Req break by recovery.",
    [ERR_GR_FILE_SYSTEM_ERROR] = "File system error, reason %m.",
    [ERR_GR_CONNECTION_CLOSED] = "GR connection is closed",
    [ERR_GR_MEM_CMP_FAILED] = "pwrite failed to compare hash",
    [ERR_GR_READONLY] = "GR is in read-only mode, operation not allowed, cannot %s.",
    [ERR_GR_WHITELIST_INVALID] = "GR handshake rejected: IP %s not in whitelist",
    [ERR_GR_CALL_SERVER_FAILED] = "gr client call server failed."
};

gr_log_def_t g_gr_cmd_log[] = {
    {CM_LOG_DEBUG, "debug/grcmd.dlog"},
    {CM_LOG_OPER, "oper/grcmd.olog"},
    {CM_LOG_RUN, "run/grcmd.rlog"},
    {CM_LOG_ALARM, "grcmd_alarm.log"},
};

gr_log_def_t g_gr_instance_log[] = {
    {CM_LOG_DEBUG, "debug/grinstance.dlog"},
    {CM_LOG_OPER, "oper/grinstance.olog"},
    {CM_LOG_RUN, "run/grinstance.rlog"},
    {CM_LOG_ALARM, "grinstance_alarm.log"},
    {CM_LOG_AUDIT, "audit/grinstance.aud"},
    {CM_LOG_BLACKBOX, "blackbox/grinstance.blog"},
};

uint32_t g_gr_warn_id[] = {
    WARN_GR_SPACEUSAGE_ID,
};

char *g_gr_warn_desc[] = {
    "GRSpaceUsageUpToHWM",
};

#define GR_MAX_PRINT_LEVEL 4

gr_log_def_t *gr_get_instance_log_def()
{
    return g_gr_instance_log;
}
gr_log_def_t *gr_get_cmd_log_def()
{
    return g_gr_cmd_log;
}
uint32_t gr_get_instance_log_def_count()
{
    return sizeof(g_gr_instance_log) / sizeof(gr_log_def_t);
}
uint32_t gr_get_cmd_log_def_count()
{
    return sizeof(g_gr_cmd_log) / sizeof(gr_log_def_t);
}

static status_t gr_init_log_file(log_param_t *log_param, gr_config_t *inst_cfg)
{
    log_param->max_log_file_size = LOG_MAX_FILE_SIZE;
    log_param->max_audit_file_size = AUDIT_MAX_FILE_SIZE;

    cm_log_set_file_permissions(LOG_FILE_PERMISSIONS);
    cm_log_set_path_permissions(LOG_PATH_PERMISSIONS);
    LOG_RUN_INF("LOG MAX FILE SIZE: %llu", log_param->max_log_file_size);
    LOG_RUN_INF("AUDIT LOG MAX FILE SIZE: %llu", log_param->max_audit_file_size);
    LOG_RUN_INF("LOG FILE PERMISSIONS: %u", LOG_FILE_PERMISSIONS);
    LOG_RUN_INF("LOG PATH PERMISSIONS: %u", LOG_PATH_PERMISSIONS);
    return CM_SUCCESS;
}

static status_t gr_init_log_home_ex(gr_config_t *inst_cfg, char *log_parm_value, char *log_param_name, char *log_dir)
{
    errno_t errcode = 0;
    bool32 verify_flag = CM_FALSE;
    // register error callback function
    char *value = cm_get_config_value(&inst_cfg->config, log_param_name);
    uint32_t val_len = (value == NULL) ? 0 : (uint32_t)strlen(value);
    if (val_len >= CM_MAX_LOG_HOME_LEN) {
        GR_THROW_ERROR(ERR_INIT_LOGGER, "%s value: %s is out of range.", log_param_name, log_parm_value);
        return CM_ERROR;
    }
    if (val_len > 0) {
        errcode = strncpy_s(log_parm_value, CM_MAX_LOG_HOME_LEN, value, val_len);
        securec_check_ret(errcode);
        verify_flag = CM_TRUE;
    } else {
        char *home = gr_get_cfg_dir(inst_cfg);
        if (snprintf_s(log_parm_value, CM_MAX_LOG_HOME_LEN, CM_MAX_LOG_HOME_LEN - 1, "%s/%s", home, log_dir) == -1) {
            GR_ASSERT_LOG(0, "Init log dir:%s/%s failed.", home, log_dir);
        }
    }
    status_t status = gr_verify_log_file_dir_name(log_parm_value);
    GR_RETURN_IFERR2(
        status, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "failed to load params, invalid %s", log_param_name));
    if (verify_flag && gr_verify_log_file_real_path(log_parm_value) != CM_SUCCESS) {
        GR_RETURN_IFERR2(
            CM_ERROR, GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "failed to load params, invalid %s", log_param_name));
    }
    return CM_SUCCESS;
}

static status_t gr_init_log_home(gr_config_t *inst_cfg, log_param_t *log_param, char *alarm_dir)
{
    status_t status;
    status = gr_init_log_home_ex(inst_cfg, log_param->log_home, "LOG_HOME", "log");
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }
    status = gr_init_log_home_ex(inst_cfg, alarm_dir, "LOG_HOME", "log/alarm");
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
static status_t gr_load_log_compressed(gr_config_t *inst_cfg, log_param_t *log_param)
{
    char *value = cm_get_config_value(&inst_cfg->config, "LOG_COMPRESSED");
    if (cm_str_equal_ins(value, "TRUE")) {
        log_param->log_compressed = CM_TRUE;
        log_param->log_compress_buf = malloc(CM_LOG_COMPRESS_BUFSIZE);
        if (log_param->log_compress_buf == NULL) {
            log_param->log_compressed = CM_FALSE;
            LOG_RUN_ERR("Failed to alloc compree buf when init log.");
            GR_THROW_ERROR(ERR_GR_INIT_LOGGER_FAILED);
            return CM_ERROR;
        }
    } else if (cm_str_equal_ins(value, "FALSE")) {
        log_param->log_compressed = CM_FALSE;
        log_param->log_compress_buf = NULL;
    } else {
        GR_THROW_ERROR(ERR_GR_INVALID_PARAM, "LOG_COMPRESSED");
        return CM_ERROR;
    }
    LOG_RUN_INF("LOG_COMPRESSED = %u.", log_param->log_compressed);
    return CM_SUCCESS;
}

static status_t gr_init_loggers_inner(gr_config_t *inst_cfg, log_param_t *log_param)
{
    uint32_t val_uint32;

    char *value = cm_get_config_value(&inst_cfg->config, "LOG_FILE_COUNT");
    if (cm_str2uint32(value, &val_uint32) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "LOG_FILE_COUNT");
        return CM_ERROR;
#ifdef OPENGAUSS
    } else if (val_uint32 > CM_MAX_LOG_FILE_COUNT_LARGER) {
#else
    } else if (val_uint32 > CM_MAX_LOG_FILE_COUNT) {
#endif
        CM_THROW_ERROR(ERR_INVALID_PARAM, "LOG_FILE_COUNT");
        return CM_ERROR;
    } else {
        log_param->log_backup_file_count = val_uint32;
        log_param->audit_backup_file_count = val_uint32;
    }

    status_t status = gr_init_log_file(log_param, inst_cfg);
    GR_RETURN_IF_ERROR(status);

    value = cm_get_config_value(&inst_cfg->config, "LOG_LEVEL");
    status = cm_str2uint32(value, (uint32_t *)&log_param->log_level);
    GR_RETURN_IFERR2(status, CM_THROW_ERROR(ERR_INVALID_PARAM, "LOG_LEVEL"));
    if (log_param->log_level > GR_MAX_LOG_LEVEL) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "LOG_LEVEL");
        return CM_ERROR;
    }

    uint32_t audit_val = 0;
    if ((log_param->log_level & LOG_AUDIT_MODIFY_LEVEL) != 0) {
        audit_val |= GR_AUDIT_MODIFY;
    }
    if ((log_param->log_level & LOG_AUDIT_QUERY_LEVEL) != 0) {
        audit_val |= GR_AUDIT_QUERY;
    }
    log_param->audit_level = audit_val;
    return gr_load_log_compressed(inst_cfg, log_param);
}

status_t gr_init_loggers(gr_config_t *inst_cfg, gr_log_def_t *log_def, uint32_t log_def_count, char *name)
{
    char file_name[CM_FULL_PATH_BUFFER_SIZE];
    uint32_t buffer_len = CM_FULL_PATH_BUFFER_SIZE;
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_level = 0;
    char alarm_dir[CM_MAX_LOG_HOME_LEN];
    if (gr_init_log_home(inst_cfg, log_param, alarm_dir) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (gr_init_loggers_inner(inst_cfg, log_param) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (gr_init_log_file(log_param, inst_cfg) != CM_SUCCESS) {
        return CM_ERROR;
    }

    int32_t ret;
    for (size_t i = 0; i < log_def_count; i++) {
        if (log_def[i].log_id == CM_LOG_ALARM) {
            ret = snprintf_s(file_name, buffer_len, (buffer_len - 1), "%s/%s", alarm_dir, log_def[i].log_filename);
        } else {
            ret = snprintf_s(
                file_name, buffer_len, (buffer_len - 1), "%s/%s", log_param->log_home, log_def[i].log_filename);
        }
        GR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
        if (cm_log_init(log_def[i].log_id, file_name) != CM_SUCCESS) {
            return CM_ERROR;
        }
        cm_log_open_compress(log_def[i].log_id, GR_TRUE);
    }
    log_param->log_instance_startup = CM_TRUE;
    cm_init_error_handler(cm_set_log_error);
    status_t status = cm_set_log_module_name(name, (int32_t)strlen(name));
    GR_RETURN_IF_ERROR(status);
    errno_t rc = strcpy_sp(log_param->instance_name, CM_MAX_NAME_LEN, name);
    if (rc != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return CM_ERROR;
    }
    LOG_RUN_INF("gr set log param LOG_LEVEL, param_value = %u", log_param->log_level);
    LOG_RUN_INF("gr set log param AUDIT_LEVEL, param_value = %u", log_param->audit_level);
    return CM_SUCCESS;
}

static void sql_audit_init_assist(
    gr_session_t *session, status_t status, gr_cmd_type_e cmd_type, gr_audit_assist_t *assist)
{
    int32_t ret, tz_hour, tz_min;
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
        GR_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return;
    }

    (void)cm_date2str(
        g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", assist->date + ret, CM_MAX_TIME_STRLEN - (uint32_t)ret);

    // SESSIONID
    assist->sid = (int32_t)session->id;
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
        snprintf_s(assist->return_code_buf, CM_MAX_NUMBER_LEN, CM_MAX_NUMBER_LEN - 1, "GR-%05d", assist->code));
    assist->return_code.len = (uint32_t)strlen(assist->return_code_buf);
    assist->return_code.str[assist->return_code.len] = '\0';
}

static void sql_audit_create_message(
    gr_audit_assist_t *assist, char *resource, char *action, char *log_msg, uint32_t *log_msg_len)
{
    int32_t ret = snprintf_s(log_msg, CM_T2S_LARGER_BUFFER_SIZE, CM_T2S_LARGER_BUFFER_SIZE - 1,
        "SESSIONID:[%u] \"%s\" USER:[%u] \"%s\" HOST:[%u] \"%s\" "
        "RESOURCE:[%u] \"%s\" ACTION:[%u] \"%s\" RETURNCODE:[%u] \"%s\" ",
        assist->session_id.len, assist->session_id.str,     // SESSIONID
        (uint32_t)strlen(assist->db_user), assist->db_user,   // USER
        (uint32_t)strlen(assist->os_host), assist->os_host,   // HOST
        (uint32_t)strlen(resource), resource,                 // RESOURCE
        (uint32_t)strlen(action), action,                     // ACTION
        assist->return_code.len, assist->return_code.str);  // RETURNCODE
    if (SECUREC_UNLIKELY(ret == -1) || (uint32_t)(ret + 1) > CM_T2S_LARGER_BUFFER_SIZE) {
        *log_msg_len = CM_T2S_LARGER_BUFFER_SIZE - 1;
        log_msg[CM_T2S_LARGER_BUFFER_SIZE - 1] = '\0';
        return;
    }

    *log_msg_len = (uint32_t)ret + 1;
    log_msg[*log_msg_len - 1] = '\"';
    log_msg[*log_msg_len] = '\0';
}

static void sql_audit_log(gr_session_t *session, status_t status, uint8 cmd_type)
{
    gr_audit_assist_t assist = {0};
    char *log_msg = cm_get_t2s_addr();
    uint32_t log_msg_len;

    sql_audit_init_assist(session, status, cmd_type, &assist);
    sql_audit_create_message(&assist, session->audit_info.resource, session->audit_info.action, log_msg, &log_msg_len);
    LOG_AUDIT("%s\nLENGTH: \"%u\"\n%s\n", assist.date, log_msg_len, log_msg);
}

void sql_record_audit_log(void *sess, status_t status, uint8 cmd_type)
{
    if (cmd_type >= GR_CMD_QUERY_END) {
        return;
    }
    gr_session_t *session = (gr_session_t *)sess;
    uint32_t audit_mask = cm_log_param_instance()->log_level;
    if ((audit_mask & LOG_AUDIT_MODIFY_LEVEL) == 0 &&
        cmd_type >= GR_CMD_MODIFY_BEGIN && cmd_type < GR_CMD_MODIFY_END) {
        return;
    }
    if ((audit_mask & LOG_AUDIT_QUERY_LEVEL) == 0 &&
        cmd_type >= GR_CMD_QUERY_BEGIN && cmd_type < GR_CMD_QUERY_END) {
        return;
    }
    sql_audit_log(session, status, cmd_type);
}
