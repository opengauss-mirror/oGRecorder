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
 * wrcmd.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/wrcmd.c
 *
 * -------------------------------------------------------------------------
 */

#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#endif

#include "cm_base.h"
#include "cm_config.h"
#include "cm_dlock.h"
#include "cm_list.h"
#include "cm_system.h"
#include "cm_cipher.h"
#include "cm_encrypt.h"
#include "cm_utils.h"
#include "cm_signal.h"
#include "cm_sec_file.h"

#include "wr_errno.h"
#include "wr_defs.h"
#include "wr_malloc.h"
#include "wr_file.h"
#include "wr_io_fence.h"
#include "wr_api.h"
#include "wr_api_impl.h"
#include "wrcmd_encrypt.h"
#include "wr_cli_conn.h"
#include "wr_args_parse.h"
#ifndef WIN32
#include "config.h"
#endif

#ifdef WIN32
#define DEF_WR_VERSION "Windows does not support this feature because it is built using vs."
#endif

// cmd format : cmd subcmd [-f val]
#define CMD_COMMAND_INJECTION_COUNT 22
#define WR_DEFAULT_MEASURE "B"
#define WR_DEFAULT_VG_TYPE 't' /* show vg information in table format by default */

#define VERSION_SHORT       ("-v")
#define VERSION_LONG        ("--version")
#define ALL_SHORT           ("-a")
#define ALL_LONG            ("--all")
#define HELP_SHORT          ("h")
#define HELP_LONG           ("--help")

typedef struct st_wr_print_help_t {
    char fmt;
    uint32_t bytes;
} wr_print_help_t;

wr_conn_t* g_cmd_conn= NULL;  // global connection for wrCmd

wr_conn_t *wr_get_connection_for_cmd()
{
    wr_config_t *inst_cfg = wr_get_g_inst_cfg();
    char server_path[CM_MAX_IP_LEN] = {0};
    errno_t err = sprintf_s(server_path, CM_MAX_IP_LEN, "%s:%u",
                            inst_cfg->params.listen_addr.host, inst_cfg->params.listen_addr.port);
    if (SECUREC_UNLIKELY(err < 0)) {
        WR_PRINT_ERROR("Failed to get server_path.\n");
        return NULL;
    }
    status_t status = wr_enter_api(&g_cmd_conn, server_path);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to get conn.\n");
        return NULL;
    }
    return g_cmd_conn;
}

static status_t cmd_check_cfg_name(const char *name)
{
    uint32_t len = strlen(name);
    for (uint32_t i = 0; i < len; i++) {
        if (!isalpha((int)name[i]) && !isdigit((int)name[i]) && name[i] != '-' && name[i] != '_') {
            WR_PRINT_ERROR("The name's letter should be [alpha|digit|-|_].\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_cfg_value(const char *value)
{
    uint32_t len = strlen(value);
    if (len < 0) {
        WR_PRINT_ERROR("The value is invalid.\n");
        return CM_ERROR;
    }
    for (uint32_t i = 0; i < len; i++) {
        if (!isprint((int)value[i])) {
            WR_PRINT_ERROR("The value's letter should be print-able.\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_cfg_scope(const char *scope)
{
    const char *scope_memory = "memory";
    const char *scope_pfile = "pfile";
    const char *scope_both = "both";
    if (strcmp(scope, scope_memory) != 0 && strcmp(scope, scope_pfile) != 0 && strcmp(scope, scope_both) != 0) {
        WR_PRINT_ERROR("scope should be [%s | %s | %s].\n", scope_memory, scope_pfile, scope_both);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

// ------------------------
// add uni-check function before here
static inline void help_param_wrhome(void)
{
    (void)printf("-D/--WR_HOME <WR_HOME>, [optional], the run path of wrserver, default value is $WR_HOME\n");
}

double wr_convert_size(double size, const char *measure)
{
    double result = size;
    switch (measure[0]) {
        case 'T':
            result /= SIZE_T(1);
            break;
        case 'G':
            result /= SIZE_G(1);
            break;
        case 'M':
            result /= SIZE_M(1);
            break;
        case 'K':
            result /= SIZE_K(1);
            break;
        default:
            break;
    }
    return result;
}

static wr_args_t cmd_ts_args[] = {};

static wr_args_set_t cmd_ts_args_set = {
    cmd_ts_args,
    sizeof(cmd_ts_args) / sizeof(wr_args_t),
    NULL,
};

static void ts_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s ts [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]Show current API invoking time\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
}

static status_t ts_proc(void)
{
    status_t status = CM_SUCCESS;
    wr_conn_t *conn = wr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }

    wr_stat_item_t time_stat[WR_EVT_COUNT];
    status = wr_get_time_stat_on_server(conn, time_stat, WR_EVT_COUNT);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to get time stat.\n");
        return CM_ERROR;
    }
    (void)printf("|      event     |   count   | total_wait_time | avg_wait_time | max_single_time \n");
    (void)printf("+------------------------+-----------+-----------------+---------------+-----------------\n");
    for (int i = 0; i < WR_EVT_COUNT; i++) {
        if (time_stat[i].wait_count == 0) {
            (void)printf("|%-24s|%-11d|%-17d|%-15d|%-17d\n", wr_get_stat_event(i), 0, 0, 0, 0);
            continue;
        }
        (void)printf("|%-24s|%-11lld|%-17lld|%-15lld|%-17lld\n", wr_get_stat_event(i), time_stat[i].wait_count,
            time_stat[i].total_wait_time, time_stat[i].total_wait_time / time_stat[i].wait_count,
            time_stat[i].max_single_time);
    }
    (void)printf("+------------------------+-----------+-----------------+---------------+-----------------\n");
    return CM_SUCCESS;
}

static wr_args_set_t cmd_lscli_args_set = {
    NULL,
    0,
    NULL,
};

static void lscli_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s lscli\n", prog_name);
    (void)printf("[client command] Show information of client\n");
}

static status_t lscli_proc(void)
{
    errno_t errcode;
    wr_cli_info_t cli_info;

    cli_info.cli_pid = cm_sys_pid();
    status_t status = cm_sys_process_start_time(cli_info.cli_pid, &cli_info.start_time);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to get process start time pid %llu.\n", cli_info.cli_pid);
        return CM_ERROR;
    }
    errcode = strncpy_s(
        cli_info.process_name, sizeof(cli_info.process_name), cm_sys_program_name(), strlen(cm_sys_program_name()));
    if (errcode != EOK) {
        WR_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        WR_PRINT_ERROR("Failed to lscli.\n");
        return CM_ERROR;
    }

    (void)printf("%-20s%-20s%-256s\n", "cli_pid", "start_time", "process_name");
    (void)printf("%-20llu%-20lld%-256s\n", cli_info.cli_pid, cli_info.start_time, cli_info.process_name);
    return CM_SUCCESS;
}

static inline char escape_char(char c)
{
    if (c > 0x1f && c < 0x7f) {
        return c;
    } else {
        return '.';
    }
}

bool32 wr_check_software_version(int32_t file_fd, int64_t *offset)
{
    int32_t read_size = 0;
    uint32_t software_version;
    status_t status = cm_read_file(file_fd, &software_version, sizeof(uint32_t), &read_size);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to read software_version");
        return CM_FALSE;
    }
    if (software_version > (uint32_t)WR_SOFTWARE_VERSION) {
        LOG_RUN_ERR("The file software_version which is %u is bigger than the actural software_version which is %u.",
            software_version, (uint32_t)WR_SOFTWARE_VERSION);
        return CM_FALSE;
    }
    *offset += (int64_t)sizeof(uint32_t);
    return CM_TRUE;
}

static wr_args_set_t cmd_encrypt_args_set = {
    NULL,
    0,
    NULL,
};

static void encrypt_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s encrypt\n", prog_name);
    (void)printf("[client command] password encrypt\n");
}

static status_t wr_save_random_file(const uchar *value, int32_t value_len)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    char dir_name[CM_FILE_NAME_BUFFER_SIZE];
    int32_t handle;
    PRTS_RETURN_IFERR(snprintf_s(
        dir_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/wr_protect", g_inst_cfg->home));
    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/wr_protect/%s",
        g_inst_cfg->home, WR_FKEY_FILENAME));
    if (!cm_dir_exist(dir_name)) {
        WR_RETURN_IF_ERROR(cm_create_dir(dir_name));
    }
    if (access(file_name, R_OK | F_OK) == 0) {
        (void)chmod(file_name, S_IRUSR | S_IWUSR);
        WR_RETURN_IF_ERROR(cm_overwrite_file(file_name));
        WR_RETURN_IF_ERROR(cm_remove_file(file_name));
    }
    WR_RETURN_IF_ERROR(
        cm_open_file_ex(file_name, O_SYNC | O_CREAT | O_RDWR | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR, &handle));
    status_t ret = cm_write_file(handle, value, value_len);
    cm_close_file(handle);
    return ret;
}

static status_t encrypt_proc(void)
{
    status_t status;
    char plain[CM_PASSWD_MAX_LEN + 1] = {0};
    status = wr_catch_input_text(plain, CM_PASSWD_MAX_LEN + 1);
    if (status != CM_SUCCESS) {
        (void)(memset_s(plain, CM_PASSWD_MAX_LEN + 1, 0, CM_PASSWD_MAX_LEN + 1));
        WR_PRINT_RUN_ERROR("[ENCRYPT]Failed to encrypt password when catch input.\n");
        return CM_ERROR;
    }
    LOG_RUN_INF("[ENCRYPT]Succeed to encrypt password when catch input.\n");
    cipher_t cipher;
    status = cm_encrypt_pwd((uchar *)plain, (uint32_t)strlen(plain), &cipher);
    if (status != CM_SUCCESS) {
        (void)(memset_s(plain, CM_PASSWD_MAX_LEN + 1, 0, CM_PASSWD_MAX_LEN + 1));
        WR_PRINT_RUN_ERROR("[ENCRYPT]Failed to encrypt password.\n");
        return CM_ERROR;
    }
    LOG_RUN_INF("[ENCRYPT]Succeed to encrypt password.\n");
    (void)(memset_s(plain, CM_PASSWD_MAX_LEN + 1, 0, CM_PASSWD_MAX_LEN + 1));
    status = wr_save_random_file(cipher.rand, RANDOM_LEN + 1);
    if (status != CM_SUCCESS) {
        WR_PRINT_RUN_ERROR("[ENCRYPT]Failed to save random component.\n");
        return CM_ERROR;
    }
    LOG_RUN_INF("[ENCRYPT]Succeed to save random component.\n");
    (void)(memset_s(cipher.rand, RANDOM_LEN + 1, 0, RANDOM_LEN + 1));
    char buf[CM_MAX_SSL_CIPHER_LEN] = {0};
    uint32_t buf_len = CM_MAX_SSL_CIPHER_LEN;
    status = cm_base64_encode((uchar *)&cipher, (uint32_t)sizeof(cipher_t), buf, &buf_len);
    if (status != CM_SUCCESS) {
        WR_PRINT_RUN_ERROR("[ENCRYPT]Failed to encrypt password when encode.\n");
        return CM_ERROR;
    }
    (void)printf("Cipher: \t\t%s\n", buf);
    (void)fflush(stdout);
    LOG_RUN_INF("[ENCRYPT]Succeed to print cipher, length is %u.\n", (uint32_t)strlen(buf));
    return CM_SUCCESS;
}

static wr_args_t cmd_setcfg_args[] = {
    {'n', "name", CM_TRUE, CM_TRUE, cmd_check_cfg_name, NULL, NULL, 0, NULL, NULL, 0},
    {'v', "value", CM_TRUE, CM_TRUE, cmd_check_cfg_value, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "scope", CM_FALSE, CM_TRUE, cmd_check_cfg_scope, NULL, NULL, 0, NULL, NULL, 0},
};
static wr_args_set_t cmd_setcfg_args_set = {
    cmd_setcfg_args,
    sizeof(cmd_setcfg_args) / sizeof(wr_args_t),
    NULL,
};

static void setcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s setcfg <-n name> <-v value> [-s scope]\n", prog_name);
    (void)printf("[client command] set config value by name\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-n/--name <name>, <required>, the config name to set\n");
    (void)printf("-v/--value <value>, <required>, the value of the config name to set\n");
    (void)printf("-s/--scope <scope>, [optional], the scope to save the config\n");
    (void)printf("scope optional values: [memory | pfile | both]. default value is both\n"
                 "Memory indicates that the modification is made in memory and takes effect immediately;\n"
                 "Pfile indicates that the modification is performed in the pfile. \n"
                 "The database must be restarted for the modification to take effect.\n");
}

static status_t setcfg_proc(void)
{
    char *name = cmd_setcfg_args[WR_ARG_IDX_0].input_args;
    char *value = cmd_setcfg_args[WR_ARG_IDX_1].input_args;
    char *scope = cmd_setcfg_args[WR_ARG_IDX_2].input_args != NULL ?
                  cmd_setcfg_args[WR_ARG_IDX_2].input_args : "both";

    wr_conn_t *conn = wr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t status = wr_setcfg_impl(conn, name, value, scope);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to set cfg, name is %s, value is %s.\n", name, value);
    } else {
        WR_PRINT_INF("Succeed to set cfg, name is %s, value is %s.\n", name, value);
    }
    wr_disconnect_ex(conn);
    return status;
}

static wr_args_t cmd_getcfg_args[] = {
    {'n', "name", CM_TRUE, CM_TRUE, cmd_check_cfg_name, NULL, NULL, 0, NULL, NULL, 0},
};
static wr_args_set_t cmd_getcfg_args_set = {
    cmd_getcfg_args,
    sizeof(cmd_getcfg_args) / sizeof(wr_args_t),
    NULL,
};

static void getcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s getcfg <-n name> \n", prog_name);
    (void)printf("[client command] get config value by name\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-n/--name <name>, <required>, the config name to set\n");
}

static status_t getcfg_proc(void)
{
    char *name = cmd_getcfg_args[WR_ARG_IDX_0].input_args;
    wr_conn_t *conn = wr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }
    char value[WR_PARAM_BUFFER_SIZE] = {0};
    status_t status = wr_getcfg_impl(conn, name, value, WR_PARAM_BUFFER_SIZE);
    if (status != CM_SUCCESS) {
        if (strlen(value) != 0 && cm_str_equal_ins(name, "SSL_PWD_CIPHERTEXT")) {
            LOG_RUN_ERR("Failed to get cfg, name is %s, value is ***.\n", name);
            (void)printf("Failed to get cfg, name is %s, value is %s.\n", name, value);
            (void)fflush(stdout);
            wr_print_detail_error();
        } else {
            WR_PRINT_ERROR("Failed to get cfg, name is %s, value is %s.\n", name, (strlen(value) == 0) ? NULL : value);
        }
    } else {
        if (strlen(value) != 0 && cm_str_equal_ins(name, "SSL_PWD_CIPHERTEXT")) {
            LOG_DEBUG_INF("Succeed to get cfg, name is %s, value is ***.\n", name);
            (void)printf("Succeed to get cfg, name is %s, value is %s.\n", name, value);
            (void)fflush(stdout);
        } else {
            WR_PRINT_INF("Succeed to get cfg, name is %s, value is %s.\n", name, (strlen(value) == 0) ? NULL : value);
        }
    }
    wr_disconnect_ex(conn);
    return status;
}

static wr_args_t cmd_getstatus_args[] = {};

static wr_args_set_t cmd_getstatus_args_set = {
    cmd_getstatus_args,
    sizeof(cmd_getstatus_args) / sizeof(wr_args_t),
    NULL,
};

static void getstatus_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s getstatus \n", prog_name);
    (void)printf("[client command] get wr server status\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
}

static status_t getstatus_proc(void)
{
    wr_conn_t *conn = wr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }

    wr_server_status_t wr_status;
    status_t status = wr_get_inst_status_on_server(conn, &wr_status);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to get server status.\n");
    } else {
        WR_PRINT_INF("Server status of instance %u is %s and %s.\nMaster id is %u .\nWR_MAINTAIN is %s.\n",
            wr_status.local_instance_id, wr_status.instance_status, wr_status.server_status, wr_status.master_id,
            (wr_status.is_maintain ? "TRUE" : "FALSE"));
    }
    wr_disconnect_ex(conn);
    return status;
}

static wr_args_t cmd_stopwr_args[] = {};
static wr_args_set_t cmd_stopwr_args_set = {
    cmd_stopwr_args,
    sizeof(cmd_stopwr_args) / sizeof(wr_args_t),
    NULL,
};

static void stopwr_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s stopwr\n", prog_name);
    (void)printf("[client command] stop wr server\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
}

static status_t stopwr_proc(void)
{
    wr_conn_t *conn = wr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t ret = wr_stop_server_impl(conn);
    if (ret != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to stop server.\n");
    } else {
        WR_PRINT_INF("Succeed to stop server.\n");
    }
    wr_disconnect_ex(conn);
    return ret;
}

static wr_args_t cmd_switchover_args[] = {};
static wr_args_set_t cmd_switchover_args_set = {
    cmd_switchover_args,
    sizeof(cmd_switchover_args) / sizeof(wr_args_t),
    NULL,
};

static void switchover_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s stopwr\n", prog_name);
    (void)printf("[client command] stop wr server\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
}

static status_t switchover_proc(void)
{
    wr_conn_t *conn = wr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }
    
    status_t status = wr_set_main_inst_impl(conn);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to switchover server.\n");
    } else {
        WR_PRINT_INF("Succeed to switchover server.\n");
    }
    wr_disconnect_ex(conn);
    return status;
}

static wr_args_t cmd_reload_certs_args[] = {};
static wr_args_set_t cmd_reload_certs_args_set = {
    cmd_reload_certs_args,
    sizeof(cmd_reload_certs_args) / sizeof(wr_args_t),
    NULL,
};

static void reload_certs_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s reload_certs\n", prog_name);
    (void)printf("[client command] reload wr server certs\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
}

static status_t reload_certs_proc(void)
{
    wr_conn_t *conn = wr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t status = wr_reload_certs_impl(conn);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to switchover server.\n");
    } else {
        WR_PRINT_INF("Succeed to switchover server.\n");
    }
    wr_disconnect_ex(conn);
    return status;
}

// clang-format off
wr_admin_cmd_t g_wr_admin_cmd[] = {
    {"ts", ts_help, ts_proc, &cmd_ts_args_set, false},
    {"lscli", lscli_help, lscli_proc, &cmd_lscli_args_set, false},
    {"encrypt", encrypt_help, encrypt_proc, &cmd_encrypt_args_set, true},
    {"setcfg", setcfg_help, setcfg_proc, &cmd_setcfg_args_set, true},
    {"getcfg", getcfg_help, getcfg_proc, &cmd_getcfg_args_set, false},
    {"getstatus", getstatus_help, getstatus_proc, &cmd_getstatus_args_set, false},
    {"stopwr", stopwr_help, stopwr_proc, &cmd_stopwr_args_set, true},
    {"switchover", switchover_help, switchover_proc, &cmd_switchover_args_set, true},
    {"reload_certs", reload_certs_help, reload_certs_proc, &cmd_reload_certs_args_set, false},
};

void clean_cmd()
{
    wr_free_vg_info();
    ga_reset_app_pools();
}

// clang-format on
static void help(char *prog_name, wr_help_type help_type)
{
    (void)printf("Usage:%s [command] [OPTIONS]\n\n", prog_name);
    (void)printf("Usage:%s %s/%s show help information of wrcmd\n", prog_name, HELP_SHORT, HELP_LONG);
    (void)printf("Usage:%s %s/%s show all help information of wrcmd\n", prog_name, ALL_SHORT, ALL_LONG);
    (void)printf("Usage:%s %s/%s show version information of wrcmd\n", prog_name, VERSION_SHORT, VERSION_LONG);
    (void)printf("commands:\n");
    for (uint32_t i = 0; i < sizeof(g_wr_admin_cmd) / sizeof(g_wr_admin_cmd[0]); ++i) {
        g_wr_admin_cmd[i].help(prog_name, help_type);
    }
    (void)printf("\n\n");
}

static status_t execute_one_cmd(int argc, char **argv, uint32_t cmd_idx)
{
    cmd_parse_init(g_wr_admin_cmd[cmd_idx].args_set->cmd_args, g_wr_admin_cmd[cmd_idx].args_set->args_size);
    if (cmd_parse_args(argc, argv, g_wr_admin_cmd[cmd_idx].args_set) != CM_SUCCESS) {
        int32_t code;
        const char *message;
        cm_get_error(&code, &message);
        if (code != 0) {
            WR_PRINT_ERROR("\ncmd %s error:%d %s.\n", g_wr_admin_cmd[cmd_idx].cmd, code, message);
        }
        return CM_ERROR;
    }
    status_t ret = g_wr_admin_cmd[cmd_idx].proc();
    cmd_parse_clean(g_wr_admin_cmd[cmd_idx].args_set->cmd_args, g_wr_admin_cmd[cmd_idx].args_set->args_size);
    return ret;
}

static status_t wr_cmd_append_oper_log(char *log_buf, void *buf, uint32_t *offset)
{
    uint32_t len = (uint32_t)strlen(buf);
    errno_t errcode = memcpy_s(log_buf + *offset, CM_MAX_LOG_CONTENT_LENGTH - *offset, buf, len);
    if (errcode != EOK) {
        LOG_RUN_ERR("Copying buf to log_buf failed.\n");
        return CM_ERROR;
    }
    *offset += len;
    return CM_SUCCESS;
}

static void wr_cmd_oper_log(int argc, char **argv, status_t status)
{
    char log_buf[CM_MAX_LOG_CONTENT_LENGTH] = {0};
    uint32_t offset = 0;

    if (!LOG_OPER_ON) {
        return;
    }

    WR_RETURN_DRIECT_IFERR(wr_cmd_append_oper_log(log_buf, "wrcmd", &offset));

    for (int i = 1; i < argc; i++) {
        WR_RETURN_DRIECT_IFERR(wr_cmd_append_oper_log(log_buf, " ", &offset));
        WR_RETURN_DRIECT_IFERR(wr_cmd_append_oper_log(log_buf, argv[i], &offset));
    }

    char result[WR_MAX_PATH_BUFFER_SIZE];
    int32_t ret = snprintf_s(
        result, WR_MAX_PATH_BUFFER_SIZE, WR_MAX_PATH_BUFFER_SIZE - 1, ". execute result %d.", (int32_t)status);
    if (ret == -1) {
        return;
    }
    WR_RETURN_DRIECT_IFERR(wr_cmd_append_oper_log(log_buf, result, &offset));

    if (offset + 1 > CM_MAX_LOG_CONTENT_LENGTH) {
        WR_PRINT_ERROR("Oper log len %u exceeds max %u.\n", offset, CM_MAX_LOG_CONTENT_LENGTH);
        return;
    }
    log_buf[offset + 1] = '\0';
    cm_write_oper_log(log_buf, offset);
}

static bool32 get_cmd_idx(int argc, char **argv, uint32_t *idx)
{
    for (uint32_t i = 0; i < sizeof(g_wr_admin_cmd) / sizeof(g_wr_admin_cmd[0]); ++i) {
        if (strcmp(g_wr_admin_cmd[i].cmd, argv[WR_ARG_IDX_1]) == 0) {
            *idx = i;
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

bool8 cmd_check_run_interactive(int argc, char **argv)
{
    if (argc < CMD_ARGS_AT_LEAST) {
        return CM_FALSE;
    }
    return CM_FALSE;
}

bool8 cmd_version_and_help(int argc, char **argv)
{
    if (cm_str_equal(argv[1], VERSION_SHORT) || cm_str_equal(argv[1], VERSION_LONG)) {
        (void)printf("wrcmd %s\n", (char *)DEF_WR_VERSION);
        return CM_TRUE;
    }
    if (cm_str_equal(argv[1], ALL_SHORT) || cm_str_equal(argv[1], ALL_LONG)) {
        help(argv[0], WR_HELP_DETAIL);
        return CM_TRUE;
    }
    if (cm_str_equal(argv[1], HELP_SHORT) || cm_str_equal(argv[1], HELP_LONG)) {
        help(argv[0], WR_HELP_SIMPLE);
        return CM_TRUE;
    }
    return CM_FALSE;
}

void print_help_hint()
{
    (void)printf("wrcmd: Try \"wrcmd -h/--help\" for help information.\n");
    (void)printf("wrcmd: Try \"wrcmd -a/--all\" for detailed help information.\n");
}

int32_t execute_help_cmd(int argc, char **argv, uint32_t *idx, bool8 *go_ahead)
{
    if (argc < CMD_ARGS_AT_LEAST) {
        (void)printf("wrcmd: no operation specified.\n");
        print_help_hint();
        *go_ahead = CM_FALSE;
        return EXIT_FAILURE;
    }
    if (cmd_version_and_help(argc, argv)) {
        *go_ahead = CM_FALSE;
        return EXIT_SUCCESS;
    }
    if (!get_cmd_idx(argc, argv, idx)) {
        (void)printf("wrcmd: command(%s) not found!\n", argv[WR_ARG_IDX_1]);
        print_help_hint();
        *go_ahead = CM_FALSE;
        return EXIT_FAILURE;
    }
    if (argc > WR_ARG_IDX_2 &&
        (strcmp(argv[WR_ARG_IDX_2], "-h") == 0 || strcmp(argv[WR_ARG_IDX_2], "--help") == 0)) {
        g_wr_admin_cmd[*idx].help(argv[0], WR_HELP_DETAIL);
        *go_ahead = CM_FALSE;
        return EXIT_SUCCESS;
    }

    *go_ahead = CM_TRUE;
    return EXIT_SUCCESS;
}

status_t execute_cmd(int argc, char **argv, uint32_t idx)
{
    status_t status = execute_one_cmd(argc, argv, idx);
    wr_cmd_oper_log(argc, argv, status);
    return status;
}

static bool32 is_log_necessary(int argc, char **argv)
{
    uint32_t cmd_idx;
    if (get_cmd_idx(argc, argv, &cmd_idx) && g_wr_admin_cmd[cmd_idx].log_necessary) {
        return true;
    }
    return false;
}

static status_t wr_check_user_permit()
{
#ifndef WIN32
    // check root
    if (geteuid() == 0 || getuid() != geteuid()) {
        (void)printf("The root user is not permitted to execute the wrcmd "
                     "and the real uids must be the same as the effective uids.\n");
        (void)fflush(stdout);
        return CM_ERROR;
    }
    if (cm_regist_signal(SIGPIPE, SIG_IGN) != CM_SUCCESS) {
        (void)printf("Can't assign function for SIGPIPE.\n");
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

int main(int argc, char **argv)
{
    WR_RETURN_IF_ERROR(wr_check_user_permit());
    uint32_t idx = 0;
    bool8 go_ahead = CM_TRUE;
    bool8 is_interactive = cmd_check_run_interactive(argc, argv);
    if (!is_interactive) {
        int32_t help_ret = execute_help_cmd(argc, argv, &idx, &go_ahead);
        if (!go_ahead) {
            exit(help_ret);
        }
    }
    wr_config_t *inst_cfg = wr_get_g_inst_cfg();
    status_t ret = wr_set_cfg_dir(NULL, inst_cfg);
    WR_RETURN_IFERR2(ret, WR_PRINT_ERROR("Environment variant WR_HOME not found!\n"));
    ret = wr_load_local_server_config(inst_cfg);
    WR_RETURN_IFERR2(ret, WR_PRINT_ERROR("Failed to load local server config, status(%d).\n", ret));
    ret = cm_start_timer(g_timer());

    WR_RETURN_IFERR2(ret, WR_PRINT_ERROR("Aborted due to starting timer thread.\n"));
    ret = wr_init_loggers(inst_cfg, wr_get_cmd_log_def(), wr_get_cmd_log_def_count(), "wrcmd");
    if (ret != CM_SUCCESS && is_log_necessary(argc, argv)) {
        WR_PRINT_ERROR("%s\nWR init loggers failed!\n", cm_get_errormsg(cm_get_error_code()));
        return ret;
    }

    cm_reset_error();
    ret = execute_cmd(argc, argv, idx);

    clean_cmd();
    return ret;
}
