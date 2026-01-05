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
 * grcmd.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/grcmd.c
 *
 * -------------------------------------------------------------------------
 */

#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
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
#include <errno.h>
#include <string.h>

#include "gr_errno.h"
#include "gr_defs.h"
#include "gr_malloc.h"
#include "gr_file.h"
#include "gr_api.h"
#include "gr_api_impl.h"
#include "gr_cli_conn.h"
#include "gr_args_parse.h"
#include "gr_param_sync.h"
#ifndef WIN32
#include "config.h"
#endif

#ifdef WIN32
#define DEF_GR_VERSION "Windows does not support this feature because it is built using vs."
#endif

// cmd format : cmd subcmd [-f val]
#define CMD_COMMAND_INJECTION_COUNT 22
#define GR_DEFAULT_MEASURE "B"
#define GR_DEFAULT_VG_TYPE 't' /* show vg information in table format by default */

#define VERSION_SHORT       ("-v")
#define VERSION_LONG        ("--version")
#define ALL_SHORT           ("-a")
#define ALL_LONG            ("--all")
#define HELP_SHORT          ("h")
#define HELP_LONG           ("--help")

#define LAST_DAY 2
#define GR_CMD_LEN          2048
#define GR_OPENSSL_KEY_BITS 2048
#define GR_ALL_PERMISSION   0777
#define GR_PERM_DIR         0700
#define GR_PERM_FILE        0400

gr_conn_t* g_cmd_conn= NULL;  // global connection for grcmd

gr_conn_t *gr_get_connection_for_cmd()
{
    gr_config_t *inst_cfg = gr_get_g_inst_cfg();
    char server_path[CM_MAX_IP_LEN] = {0};
    errno_t err = sprintf_s(server_path, CM_MAX_IP_LEN, "%s:%u",
                            inst_cfg->params.listen_addr.host, inst_cfg->params.listen_addr.port);
    if (SECUREC_UNLIKELY(err < 0)) {
        GR_PRINT_ERROR("Failed to get server_path.\n");
        return NULL;
    }
    status_t status = gr_enter_api(&g_cmd_conn, server_path);
    if (status != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to get conn.\n");
        return NULL;
    }
    return g_cmd_conn;
}

static status_t cmd_check_cfg_name(const char *name)
{
    uint32_t len = strlen(name);
    for (uint32_t i = 0; i < len; i++) {
        if (!isalpha((int)name[i]) && !isdigit((int)name[i]) && name[i] != '-' && name[i] != '_') {
            GR_PRINT_ERROR("The name's letter should be [alpha|digit|-|_].\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_cfg_value(const char *value)
{
    uint32_t len = strlen(value);
    if (len < 0) {
        GR_PRINT_ERROR("The value is invalid.\n");
        return CM_ERROR;
    }
    for (uint32_t i = 0; i < len; i++) {
        if (!isprint((int)value[i])) {
            GR_PRINT_ERROR("The value's letter should be print-able.\n");
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
        GR_PRINT_ERROR("scope should be [%s | %s | %s].\n", scope_memory, scope_pfile, scope_both);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static gr_args_t cmd_ts_args[] = {
    {'i', "addr", CM_FALSE, CM_TRUE, check_server_addr_format, NULL, NULL, 0, NULL, NULL, 0},
};

static gr_args_set_t cmd_ts_args_set = {
    cmd_ts_args,
    sizeof(cmd_ts_args) / sizeof(gr_args_t),
    NULL,
};

static void ts_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s ts\n", prog_name);
    (void)printf("[client command]Show current API invoking time\n");
    if (print_flag == GR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-i/--addr <addr>, the value of ip:port\n");
}

static status_t ts_proc(void)
{
    status_t status = CM_SUCCESS;
    const char *addr = cmd_ts_args[GR_ARG_IDX_0].input_args;

    gr_conn_t *conn;
    if (addr == NULL) {
        conn = gr_get_connection_for_cmd();
    } else {
        status = gr_enter_api(&conn, addr);
        if (status != CM_SUCCESS) {
            GR_PRINT_ERROR("Failed to get conn.\n");
            return CM_ERROR;
        }
    }
    if (conn == NULL) {
        return CM_ERROR;
    }

    gr_stat_item_t time_stat[GR_EVT_COUNT];
    status = gr_get_time_stat_on_server(conn, time_stat, GR_EVT_COUNT);
    if (status != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to get time stat.\n");
        return CM_ERROR;
    }
    (void)printf("|      event     |   count   | total_wait_time | avg_wait_time | max_single_time \n");
    (void)printf("+------------------------+-----------+-----------------+---------------+-----------------\n");
    for (int i = 0; i < GR_EVT_COUNT; i++) {
        if (time_stat[i].wait_count == 0) {
            (void)printf("|%-24s|%-11d|%-17d|%-15d|%-17d\n", gr_get_stat_event(i), 0, 0, 0, 0);
            continue;
        }
        (void)printf("|%-24s|%-11lld|%-17lld|%-15lld|%-17lld\n", gr_get_stat_event(i), time_stat[i].wait_count,
            time_stat[i].total_wait_time, time_stat[i].total_wait_time / time_stat[i].wait_count,
            time_stat[i].max_single_time);
    }
    (void)printf("+------------------------+-----------+-----------------+---------------+-----------------\n");
    return CM_SUCCESS;
}

static gr_args_set_t cmd_lscli_args_set = {
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
    gr_cli_info_t cli_info;

    cli_info.cli_pid = cm_sys_pid();
    status_t status = cm_sys_process_start_time(cli_info.cli_pid, &cli_info.start_time);
    if (status != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to get process start time pid %llu.\n", cli_info.cli_pid);
        return CM_ERROR;
    }
    errcode = strncpy_s(
        cli_info.process_name, sizeof(cli_info.process_name), cm_sys_program_name(), strlen(cm_sys_program_name()));
    if (errcode != EOK) {
        GR_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        GR_PRINT_ERROR("Failed to lscli.\n");
        return CM_ERROR;
    }

    (void)printf("%-20s%-20s%-256s\n", "cli_pid", "start_time", "process_name");
    (void)printf("%-20llu%-20lld%-256s\n", cli_info.cli_pid, cli_info.start_time, cli_info.process_name);
    return CM_SUCCESS;
}

static gr_args_t cmd_setcfg_args[] = {
    {'n', "name", CM_TRUE, CM_TRUE, cmd_check_cfg_name, NULL, NULL, 0, NULL, NULL, 0},
    {'v', "value", CM_TRUE, CM_TRUE, cmd_check_cfg_value, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "scope", CM_FALSE, CM_TRUE, cmd_check_cfg_scope, NULL, NULL, 0, NULL, NULL, 0},
    {'i', "addr", CM_FALSE, CM_TRUE, check_server_addr_format, NULL, NULL, 0, NULL, NULL, 0},
};
static gr_args_set_t cmd_setcfg_args_set = {
    cmd_setcfg_args,
    sizeof(cmd_setcfg_args) / sizeof(gr_args_t),
    NULL,
};

static void setcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s setcfg <-n name> <-v value> [-s scope] [-i addr]\n", prog_name);
    (void)printf("[client command] set config value by name\n");
    if (print_flag == GR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-n/--name <name>, <required>, the config name to set\n");
    (void)printf("-v/--value <value>, <required>, the value of the config name to set\n");
    (void)printf("-s/--scope <scope>, [optional], the scope to save the config\n");
    (void)printf("scope optional values: [memory | pfile | both]. default value is both\n"
                 "Memory indicates that the modification is made in memory and takes effect immediately;\n"
                 "Pfile indicates that the modification is performed in the pfile. \n"
                 "The database must be restarted for the modification to take effect.\n");
    (void)printf("-i/--addr <addr>, the value of ip:port\n");
}

static status_t setcfg_proc(void)
{
    char *name = cmd_setcfg_args[GR_ARG_IDX_0].input_args;
    char *value = cmd_setcfg_args[GR_ARG_IDX_1].input_args;
    char *scope = cmd_setcfg_args[GR_ARG_IDX_2].input_args != NULL ?
                  cmd_setcfg_args[GR_ARG_IDX_2].input_args : "both";
    const char *addr = cmd_setcfg_args[GR_ARG_IDX_3].input_args;

    status_t status = CM_SUCCESS;
    gr_conn_t *conn;
    if (addr == NULL) {
        conn = gr_get_connection_for_cmd();
    } else {
        status = gr_enter_api(&conn, addr);
        if (status != CM_SUCCESS) {
            GR_PRINT_ERROR("Failed to get conn.\n");
            return CM_ERROR;
        }
    }
    if (conn == NULL) {
        return CM_ERROR;
    }

    status = gr_setcfg_impl(conn, name, value, scope);
    if (status != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to set cfg, name is %s, value is %s.\n", name, value);
    } else {
        GR_PRINT_INF("Succeed to set cfg, name is %s, value is %s.\n", name, value);
    }
    gr_disconnect_ex(conn);
    return status;
}

static gr_args_t cmd_getcfg_args[] = {
    {'n', "name", CM_TRUE, CM_TRUE, cmd_check_cfg_name, NULL, NULL, 0, NULL, NULL, 0},
    {'i', "addr", CM_FALSE, CM_TRUE, check_server_addr_format, NULL, NULL, 0, NULL, NULL, 0},
};
static gr_args_set_t cmd_getcfg_args_set = {
    cmd_getcfg_args,
    sizeof(cmd_getcfg_args) / sizeof(gr_args_t),
    NULL,
};

static void getcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s getcfg <-n name> [-i addr]\n", prog_name);
    (void)printf("[client command] get config value by name\n");
    if (print_flag == GR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-n/--name <name>, <required>, the config name to set\n");
    (void)printf("-i/--addr <addr>, the value of ip:port\n");
}

static status_t getcfg_proc(void)
{
    gr_conn_t *conn;
    status_t status = CM_SUCCESS;
    char *name = cmd_getcfg_args[GR_ARG_IDX_0].input_args;
    const char *addr = cmd_getcfg_args[GR_ARG_IDX_1].input_args;
    if (addr == NULL) {
        conn = gr_get_connection_for_cmd();
    } else {
        status = gr_enter_api(&conn, addr);
        if (status != CM_SUCCESS) {
            GR_PRINT_ERROR("Failed to get conn.\n");
            return CM_ERROR;
        }
    }
    if (conn == NULL) {
        return CM_ERROR;
    }
    char value[GR_PARAM_BUFFER_SIZE] = {0};
    status = gr_getcfg_impl(conn, name, value, GR_PARAM_BUFFER_SIZE);
    if (status != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to get cfg, name is %s, value is %s.\n", name, (strlen(value) == 0) ? NULL : value);
    } else {
        GR_PRINT_INF("Succeed to get cfg, name is %s, value is %s.\n", name, (strlen(value) == 0) ? NULL : value);
    }
    gr_disconnect_ex(conn);
    return status;
}

static gr_args_t cmd_getstatus_args[] = {
    {'i', "addr", CM_FALSE, CM_TRUE, check_server_addr_format, NULL, NULL, 0, NULL, NULL, 0},
};

static gr_args_set_t cmd_getstatus_args_set = {
    cmd_getstatus_args,
    sizeof(cmd_getstatus_args) / sizeof(gr_args_t),
    NULL,
};

static void getstatus_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s getstatus \n", prog_name);
    (void)printf("[client command] get gr server status\n");
    if (print_flag == GR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-i/--addr <addr>, the value of ip:port\n");
}

static status_t getstatus_proc(void)
{
    gr_conn_t *conn;
    status_t status = CM_SUCCESS;
    const char *addr = cmd_getstatus_args[GR_ARG_IDX_0].input_args;
    if (addr == NULL) {
        conn = gr_get_connection_for_cmd();
    } else {
        status = gr_enter_api(&conn, addr);
        if (status != CM_SUCCESS) {
            GR_PRINT_ERROR("Failed to get conn.\n");
            return CM_ERROR;
        }
    }
    if (conn == NULL) {
        return CM_ERROR;
    }

    gr_server_status_t gr_status;
    status = gr_get_inst_status_on_server(conn, &gr_status);
    if (status != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to get server status.\n");
    } else {
        GR_PRINT_INF("Server status of instance %u is %s and %s.\nMaster id is %u .\nGR_MAINTAIN is %s.\n",
            gr_status.local_instance_id, gr_status.instance_status, gr_status.server_status, gr_status.master_id,
            (gr_status.is_maintain ? "TRUE" : "FALSE"));
    }
    gr_disconnect_ex(conn);
    return status;
}

static gr_args_t cmd_stop_args[] = {
    {'i', "addr", CM_FALSE, CM_TRUE, check_server_addr_format, NULL, NULL, 0, NULL, NULL, 0},
};
static gr_args_set_t cmd_stop_args_set = {
    cmd_stop_args,
    sizeof(cmd_stop_args) / sizeof(gr_args_t),
    NULL,
};

static void stop_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s stop\n", prog_name);
    (void)printf("[client command] stop gr server\n");
    if (print_flag == GR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-i/--addr <addr>, the value of ip:port\n");
}

static status_t stop_proc(void)
{
    gr_conn_t *conn;
    status_t status = CM_SUCCESS;
    const char *addr = cmd_stop_args[GR_ARG_IDX_0].input_args;
    if (addr == NULL) {
        conn = gr_get_connection_for_cmd();
    } else {
        status = gr_enter_api(&conn, addr);
        if (status != CM_SUCCESS) {
            GR_PRINT_ERROR("Failed to get conn.\n");
            return CM_ERROR;
        }
    }
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t ret = gr_stop_server_impl(conn);
    if (ret != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to stop server.\n");
    } else {
        GR_PRINT_INF("Succeed to stop server.\n");
    }
    gr_disconnect_ex(conn);
    return ret;
}

static gr_args_t cmd_switchover_args[] = {
    {'i', "addr", CM_FALSE, CM_TRUE, check_server_addr_format, NULL, NULL, 0, NULL, NULL, 0},
};
static gr_args_set_t cmd_switchover_args_set = {
    cmd_switchover_args,
    sizeof(cmd_switchover_args) / sizeof(gr_args_t),
    NULL,
};

static void switchover_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s stop\n", prog_name);
    (void)printf("[client command] stop gr server\n");
    if (print_flag == GR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-i/--addr <addr>, the value of ip:port\n");
}

static status_t switchover_proc(void)
{
    gr_conn_t *conn;
    status_t status = CM_SUCCESS;
    const char *addr = cmd_switchover_args[GR_ARG_IDX_0].input_args;
    if (addr == NULL) {
        conn = gr_get_connection_for_cmd();
    } else {
        status = gr_enter_api(&conn, addr);
        if (status != CM_SUCCESS) {
            GR_PRINT_ERROR("Failed to get conn.\n");
            return CM_ERROR;
        }
    }
    if (conn == NULL) {
        return CM_ERROR;
    }
    
    status = gr_set_main_inst_impl(conn);
    if (status != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to switchover server.\n");
    } else {
        GR_PRINT_INF("Succeed to switchover server.\n");
    }
    gr_disconnect_ex(conn);
    return status;
}

static gr_args_t cmd_reload_certs_args[] = {};
static gr_args_set_t cmd_reload_certs_args_set = {
    cmd_reload_certs_args,
    sizeof(cmd_reload_certs_args) / sizeof(gr_args_t),
    NULL,
};

static void reload_certs_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s reload_certs\n", prog_name);
    (void)printf("[client command] reload gr server certs\n");
    if (print_flag == GR_HELP_SIMPLE) {
        return;
    }
}

static status_t reload_certs_proc(void)
{
    gr_conn_t *conn = gr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t status = gr_reload_certs_impl(conn);
    if (status != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to reload certs server.\n");
    } else {
        GR_PRINT_INF("Succeed to reload certs server.\n");
    }
    gr_disconnect_ex(conn);
    return status;
}

static gr_args_t cmd_gencert_args[] = {
    {'t', "type", CM_TRUE, CM_TRUE, NULL, NULL, NULL, 0, NULL, NULL, 0},
    {'d', "days", CM_FALSE, CM_TRUE, NULL, NULL, NULL, 0, NULL, NULL, 0},
};

static gr_args_set_t cmd_gencert_args_set = {
    cmd_gencert_args,
    sizeof(cmd_gencert_args) / sizeof(gr_args_t),
    NULL,
};

static void gencert_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s gencert -t <client|server|ca> [-d days]\n", prog_name);
    (void)printf("[command] generate and check certs for client or server\n");
    (void)printf("  -t/--type <client|server>\n");
    (void)printf("  -d/--days <days>  (optional, default: 3650)\n");
}

static int file_exists(const char *filename) {
    return access(filename, F_OK) == 0;
}

/**
 * Read and decrypt password from encrypted file.
 * @param enc_file Full path to the .enc file (e.g., "/path/to/ca.pass.enc")
 * @param plain_pwd Output buffer for decrypted password
 * @param pwd_size Size of output buffer
 * @return CM_SUCCESS on success, CM_ERROR on failure
 */
static status_t decrypt_password_file(const char *enc_file, char *plain_pwd, uint32 pwd_size)
{
    FILE *fp = NULL;
    cipher_t cipher = {0};
    uchar plain[CM_PASSWD_MAX_LEN + 1] = {0};
    uint32 plain_len = 0;
    size_t read_len = 0;
    errno_t ret;

    if (enc_file == NULL || plain_pwd == NULL || pwd_size == 0) {
        GR_PRINT_ERROR("Invalid parameters for decrypt_password_file\n");
        return CM_ERROR;
    }

    /* Open encrypted password file */
    fp = fopen(enc_file, "rb");
    if (fp == NULL) {
        GR_PRINT_ERROR("Failed to open encrypted password file %s: %s\n", enc_file, strerror(errno));
        return CM_ERROR;
    }

    /* Read encrypted password structure */
    read_len = fread(&cipher, 1, sizeof(cipher_t), fp);
    fclose(fp);

    if (read_len != sizeof(cipher_t)) {
        GR_PRINT_ERROR("Failed to read encrypted password file %s, read %zu bytes, expected %zu\n",
            enc_file, read_len, sizeof(cipher_t));
        return CM_ERROR;
    }

    /* Decrypt password */
    plain_len = sizeof(plain);
    if (cm_decrypt_pwd(&cipher, plain, &plain_len) != CM_SUCCESS) {
        (void)memset_s(&cipher, sizeof(cipher), 0, sizeof(cipher));
        GR_PRINT_ERROR("Failed to decrypt password from %s\n", enc_file);
        return CM_ERROR;
    }

    /* Copy decrypted password */
    if (plain_len >= pwd_size) {
        plain_len = pwd_size - 1;
    }
    ret = memcpy_s(plain_pwd, pwd_size, plain, plain_len);
    if (ret != EOK) {
        (void)memset_s(plain, sizeof(plain), 0, sizeof(plain));
        (void)memset_s(&cipher, sizeof(cipher), 0, sizeof(cipher));
        GR_PRINT_ERROR("Failed to copy decrypted password\n");
        return CM_ERROR;
    }
    plain_pwd[plain_len] = '\0';

    /* Clear sensitive data from memory */
    (void)memset_s(plain, sizeof(plain), 0, sizeof(plain));
    (void)memset_s(&cipher, sizeof(cipher), 0, sizeof(cipher));

    return CM_SUCCESS;
}

/**
 * Encrypt plain password file and save as encrypted file.
 * Reads from pass_file (full path with .pass extension), encrypts it, 
 * saves to corresponding .enc file, then removes .pass file.
 * @param pass_file Full path to the .pass file (e.g., "/path/to/server.key.pass")
 */
static status_t encrypt_password_file(const char *pass_file)
{
    char enc_file[CM_MAX_PATH_LEN] = {0};
    FILE *fp = NULL;
    cipher_t cipher = {0};
    uchar plain[CM_PASSWD_MAX_LEN + 1] = {0};
    uint32 plain_len = 0;
    size_t len = 0;

    /* Validate input: must end with .pass */
    if (pass_file == NULL || strlen(pass_file) == 0) {
        GR_PRINT_ERROR("Invalid pass file path: NULL or empty\n");
        return CM_ERROR;
    }

    /* Check if path ends with .pass */
    size_t pass_file_len = strlen(pass_file);
    if (pass_file_len < 5 || strcmp(pass_file + pass_file_len - 5, ".pass") != 0) {
        GR_PRINT_ERROR("Pass file path must end with .pass: %s\n", pass_file);
        return CM_ERROR;
    }

    /* Construct encrypted file path:
     * - For server.key.pass or client.key.pass: generate server.key.enc or client.key.enc
     * - For ca.pass: generate ca.pass.enc
     */
    if (pass_file_len >= 10 && strcmp(pass_file + pass_file_len - 10, ".key.pass") == 0) {
        /* Remove .pass and append .enc: server.key.pass -> server.key.enc */
        if (snprintf_s(enc_file, sizeof(enc_file), sizeof(enc_file) - 1, "%.*s.enc",
                (int)(pass_file_len - 5), pass_file) < 0) {
            GR_PRINT_ERROR("Failed to construct .enc file path for %s\n", pass_file);
            return CM_ERROR;
        }
    } else {
        /* Append .enc to the .pass file: ca.pass -> ca.pass.enc */
        if (snprintf_s(enc_file, sizeof(enc_file), sizeof(enc_file) - 1, "%s.enc", pass_file) < 0) {
            GR_PRINT_ERROR("Failed to construct .enc file path for %s\n", pass_file);
            return CM_ERROR;
        }
    }

    /* Read plain password from .pass file */
    fp = fopen(pass_file, "r");
    if (fp == NULL) {
        /* Plain password file doesn't exist, skip encryption */
        GR_PRINT_ERROR("Plain password file %s doesn't exist, skip encryption\n", pass_file);
        return CM_SUCCESS;
    }

    if (fgets((char *)plain, sizeof(plain), fp) == NULL) {
        fclose(fp);
        GR_PRINT_ERROR("Failed to read password from %s\n", pass_file);
        return CM_ERROR;
    }
    fclose(fp);

    /* Remove trailing newline */
    len = strlen((char *)plain);
    if (len > 0 && plain[len - 1] == '\n') {
        plain[len - 1] = '\0';
        len--;
    }
    plain_len = (uint32)len;

    if (plain_len == 0) {
        (void)memset_s(plain, sizeof(plain), 0, sizeof(plain));
        GR_PRINT_ERROR("Password is empty in %s\n", pass_file);
        return CM_ERROR;
    }

    /* Encrypt password */
    if (cm_encrypt_pwd(plain, plain_len, &cipher) != CM_SUCCESS) {
        (void)memset_s(plain, sizeof(plain), 0, sizeof(plain));
        GR_PRINT_ERROR("Failed to encrypt password from %s\n", pass_file);
        return CM_ERROR;
    }

    /* Clear plain password from memory */
    (void)memset_s(plain, sizeof(plain), 0, sizeof(plain));

    /* Write encrypted password to .enc file (binary format) */
    fp = fopen(enc_file, "wb");
    if (fp == NULL) {
        (void)memset_s(&cipher, sizeof(cipher), 0, sizeof(cipher));
        GR_PRINT_ERROR("Failed to open encrypted file %s for writing: %s\n", enc_file, strerror(errno));
        return CM_ERROR;
    }

    if (fwrite(&cipher, sizeof(cipher_t), 1, fp) != 1) {
        fclose(fp);
        (void)unlink(enc_file);
        (void)memset_s(&cipher, sizeof(cipher), 0, sizeof(cipher));
        GR_PRINT_ERROR("Failed to write encrypted password to %s\n", enc_file);
        return CM_ERROR;
    }
    fclose(fp);

    /* Set file permissions to 400 (read-only for owner) */
    if (chmod(enc_file, S_IRUSR) != 0) {
        GR_PRINT_ERROR("Failed to set permissions on %s: %s\n", enc_file, strerror(errno));
        /* Continue anyway, not critical */
    }

    /* Clear cipher from memory */
    (void)memset_s(&cipher, sizeof(cipher), 0, sizeof(cipher));

    /* Remove plain password file */
    if (unlink(pass_file) != 0) {
        GR_PRINT_ERROR("Failed to remove plain password file %s: %s\n", pass_file, strerror(errno));
        /* Continue anyway, not critical */
    }

    LOG_RUN_INF("Successfully encrypted password file: %s -> %s\n", pass_file, enc_file);
    return CM_SUCCESS;
}

static bool check_root_certs_exist(const char *certs_path) {
    int ret = 0;
    char ca_file[CM_MAX_PATH_LEN] = {0};
    char key_file[CM_MAX_PATH_LEN] = {0};
    char cnf_file[CM_MAX_PATH_LEN] = {0};
    char ca_pass_file[CM_MAX_PATH_LEN] = {0};
    ret = snprintf_s(ca_file, sizeof(ca_file), sizeof(ca_file) - 1, "%s/demoCA/cacert.pem", certs_path);
    GR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    ret = snprintf_s(key_file, sizeof(key_file), sizeof(key_file) - 1, "%s/demoCA/private/cakey.pem", certs_path);
    GR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    ret = snprintf_s(cnf_file, sizeof(cnf_file), sizeof(cnf_file) - 1, "%s/openssl.cnf", certs_path);
    GR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    ret = snprintf_s(ca_pass_file, sizeof(ca_pass_file), sizeof(ca_pass_file) - 1, "%s/ca.pass.enc", certs_path);
    GR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    if (!file_exists(ca_file) || !file_exists(key_file) || !file_exists(cnf_file) || !file_exists(ca_pass_file)) {
        GR_PRINT_ERROR("Root certs files not exist, please check following files: cacert.pem, private/cakey.pem, openssl.cnf, ca.pass.enc.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t prepare_certs_path(const char *certs_path) {
    char cmd[GR_CMD_LEN];
    snprintf(cmd, sizeof(cmd),
        "mkdir -p %s && "
        "[ -f %s/openssl.cnf ] || cp /etc/pki/tls/openssl.cnf %s/. && "
        "cd %s && mkdir -p demoCA demoCA/newcerts demoCA/private && "
        "touch demoCA/index.txt && echo '01'>demoCA/serial && "
        "if [ ! -d demoCA/private ] || [ ! -e demoCA/index.txt ]; then chmod 700 demoCA/private; fi && "
        "sed -i 's/^.*default_md.*$/default_md      = sha256/' openssl.cnf",
        certs_path, certs_path, certs_path, certs_path);
    if (system(cmd) != 0) {
        GR_PRINT_ERROR("Failed to prepare certs path: %s\n", strerror(errno));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t generate_root_cert(const char *certs_path, int days) {
    char cmd[GR_CMD_LEN];
    char pass_file[CM_MAX_PATH_LEN] = {0};
    snprintf(cmd, sizeof(cmd),
        "cd %s && "
        "ca_password=$(openssl rand -base64 32); "
        "export OPENSSL_CONF=%s/openssl.cnf; "
        "echo $ca_password | openssl genrsa -aes256 -passout stdin -out demoCA/private/cakey.pem 2048 && "
        "echo $ca_password | openssl req -new -x509 -passin stdin -days %d -key demoCA/private/cakey.pem -out demoCA/cacert.pem -subj \"/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/CN=CA\" && "
        "cp demoCA/cacert.pem . && "
        "echo $ca_password > ca.pass",
        certs_path, certs_path, days);
    if (system(cmd) != 0) {
        GR_PRINT_ERROR("Failed to generate root cert: %s\n", strerror(errno));
        return CM_ERROR;
    }

    /* Encrypt the CA password file: save as ca.pass.enc and remove ca.pass */
    if (snprintf_s(pass_file, sizeof(pass_file), sizeof(pass_file) - 1, "%s/ca.pass", certs_path) >= 0) {
        if (encrypt_password_file(pass_file) != CM_SUCCESS) {
            (void)unlink(pass_file);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static status_t create_server_certs(const char *certs_path, int days) {
    int ret = 0;
    char cmd[GR_CMD_LEN];
    char key_file[CM_MAX_PATH_LEN] = {0};
    char ca_pass_file[CM_MAX_PATH_LEN] = {0};
    char ca_password[CM_PASSWD_MAX_LEN + 1] = {0};
    char tmp_pass_file[CM_MAX_PATH_LEN] = {0};
    FILE *tmp_fp = NULL;

    if (check_root_certs_exist(certs_path) != CM_SUCCESS) {
        return CM_ERROR;
    }

    /* Decrypt CA password from ca.pass.enc */
    ret = snprintf_s(ca_pass_file, sizeof(ca_pass_file), sizeof(ca_pass_file) - 1, "%s/ca.pass.enc", certs_path);
    GR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);

    if (decrypt_password_file(ca_pass_file, ca_password, sizeof(ca_password)) != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to decrypt CA password from %s, trying plain ca.pass file\n", ca_pass_file);
        return CM_ERROR;
    }

    /* Create temporary password file for shell command */
    ret = snprintf_s(tmp_pass_file, sizeof(tmp_pass_file), sizeof(tmp_pass_file) - 1, "%s/.ca_pass.tmp", certs_path);
    GR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);

    tmp_fp = fopen(tmp_pass_file, "w");
    if (tmp_fp != NULL) {
        if (fprintf(tmp_fp, "%s", ca_password) < 0) {
            GR_PRINT_ERROR("Failed to write CA password to temporary file %s\n", tmp_pass_file);
            fclose(tmp_fp);
            (void)memset_s(ca_password, sizeof(ca_password), 0, sizeof(ca_password));
            return CM_ERROR;
        }
        fclose(tmp_fp);
        if (chmod(tmp_pass_file, S_IRUSR | S_IWUSR) != 0) {
            GR_PRINT_ERROR("Failed to set permissions on temporary file %s: %s\n", tmp_pass_file, strerror(errno));
        }
    } else {
        GR_PRINT_ERROR("Failed to create temporary password file %s: %s\n", tmp_pass_file, strerror(errno));
        (void)memset_s(ca_password, sizeof(ca_password), 0, sizeof(ca_password));
        return CM_ERROR;
    }

    snprintf(cmd, sizeof(cmd),
        "cd %s && "
        "server_password=$(openssl rand -base64 32); "
        "ca_password=$(cat .ca_pass.tmp 2>/dev/null); "
        "if [ -z \"$ca_password\" ]; then echo 'Error: Failed to read CA password from .ca_pass.tmp' >&2; exit 1; fi && "
        "export OPENSSL_CONF=%s/openssl.cnf; "
        "echo $server_password | openssl genrsa -aes256 -passout stdin -out server.key 2048 && "
        "echo $server_password | openssl req -new -key server.key -passin stdin -out server.csr -subj \"/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/CN=server\" && "
        "echo $ca_password | openssl x509 -req -days %d -in server.csr -CA demoCA/cacert.pem -CAkey demoCA/private/cakey.pem -passin stdin -CAcreateserial -out server.crt && "
        "echo $server_password > server.key.pass && "
        "chmod 400 server.crt server.key && echo '00' >demoCA/crlnumber && rm -f .ca_pass.tmp",
        certs_path, certs_path, days);
    if (system(cmd) != 0) {
        GR_PRINT_ERROR("Failed to create server certs: %s\n", strerror(errno));
        return CM_ERROR;
    }

    /* Clear CA password from memory */
    (void)memset_s(ca_password, sizeof(ca_password), 0, sizeof(ca_password));

    /* Encrypt the password file: save as server.key.enc and remove server.key.pass */
    if (snprintf_s(key_file, sizeof(key_file), sizeof(key_file) - 1, "%s/server.key.pass", certs_path) >= 0) {
        if (encrypt_password_file(key_file) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t create_client_certs(const char *certs_path, const char *root_certs_path, int days) {
    int ret = 0;
    char key_file[CM_MAX_PATH_LEN] = {0};
    char cmd[GR_CMD_LEN];
    char ca_pass_file[CM_MAX_PATH_LEN] = {0};
    char ca_password[CM_PASSWD_MAX_LEN + 1] = {0};
    char tmp_pass_file[CM_MAX_PATH_LEN] = {0};
    FILE *tmp_fp = NULL;

    if (check_root_certs_exist(root_certs_path) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (!file_exists(certs_path)) {
        if (mkdir(certs_path, GR_PERM_DIR) != 0) {
            GR_PRINT_ERROR("Failed to create directory %s: %s\n", certs_path, strerror(errno));
            return CM_ERROR;
        }
    }

    /* Decrypt CA password from ca.pass.enc */
    ret = snprintf_s(ca_pass_file, sizeof(ca_pass_file), sizeof(ca_pass_file) - 1, "%s/ca.pass.enc", root_certs_path);
    GR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);

    if (decrypt_password_file(ca_pass_file, ca_password, sizeof(ca_password)) != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to decrypt CA password from %s\n", ca_pass_file);
        return CM_ERROR;
    }

    /* Create temporary password file for shell command */
    ret = snprintf_s(tmp_pass_file, sizeof(tmp_pass_file), sizeof(tmp_pass_file) - 1, "%s/.ca_pass.tmp", root_certs_path);
    GR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);

    tmp_fp = fopen(tmp_pass_file, "w");
    if (tmp_fp != NULL) {
        if (fprintf(tmp_fp, "%s", ca_password) < 0) {
            GR_PRINT_ERROR("Failed to write CA password to temporary file %s\n", tmp_pass_file);
            fclose(tmp_fp);
            (void)memset_s(ca_password, sizeof(ca_password), 0, sizeof(ca_password));
            return CM_ERROR;
        }
        fclose(tmp_fp);
        if (chmod(tmp_pass_file, S_IRUSR | S_IWUSR) != 0) {
            GR_PRINT_ERROR("Failed to set permissions on temporary file %s: %s\n", tmp_pass_file, strerror(errno));
        }
    } else {
        GR_PRINT_ERROR("Failed to create temporary password file %s: %s\n", tmp_pass_file, strerror(errno));
        return CM_ERROR;
    }

    snprintf(cmd, sizeof(cmd),
        "cd %s && "
        "client_password=$(openssl rand -base64 32); "
        "ca_password=$(cat .ca_pass.tmp 2>/dev/null); "
        "if [ -z \"$ca_password\" ]; then echo 'Error: Failed to read CA password from .ca_pass.tmp' >&2; exit 1; fi && "
        "export OPENSSL_CONF=%s/openssl.cnf; "
        "echo $client_password | openssl genrsa -aes256 -passout stdin -out %s/client.key 2048 && "
        "echo $client_password | openssl req -new -key %s/client.key -passin stdin -out %s/client.csr -subj \"/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/CN=client\" && "
        "echo $ca_password | openssl x509 -req -days %d -in %s/client.csr -CA demoCA/cacert.pem -CAkey demoCA/private/cakey.pem -passin stdin -CAcreateserial -out %s/client.crt && "
        "echo $client_password > %s/client.key.pass && if [ \"%s\" != \"%s\" ]; then cat cacert.pem > %s/cacert.pem; fi",
        root_certs_path, root_certs_path, certs_path, certs_path, certs_path, days, certs_path,
        certs_path, certs_path, root_certs_path, certs_path, certs_path);
    if (system(cmd) != 0) {
        GR_PRINT_ERROR("Failed to create client certs: %s\n", strerror(errno));
        return CM_ERROR;
    }

    if (unlink(tmp_pass_file) != 0) {
        GR_PRINT_ERROR("Failed to remove file %s: %s\n", tmp_pass_file, strerror(errno));
        return CM_ERROR;
    }

    /* Clear CA password from memory */
    (void)memset_s(ca_password, sizeof(ca_password), 0, sizeof(ca_password));

    /* Encrypt the password file: save as client.key.enc and remove client.key.pass */
    if (snprintf_s(key_file, sizeof(key_file), sizeof(key_file) - 1, "%s/client.key.pass", certs_path) >= 0) {
        if (encrypt_password_file(key_file) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static status_t check_certs_permission(const char *filename) {
    struct stat file_stat;
    if (stat(filename, &file_stat) != 0) {
        GR_PRINT_ERROR("Failed to get file status for %s: %s\n", filename, strerror(errno));
        return CM_ERROR;
    }

    /* Check if current permissions are already 0400 (read-only for owner) */
    mode_t current_mode = file_stat.st_mode & GR_ALL_PERMISSION;
    if (current_mode == GR_PERM_FILE) {
        /* Permissions are already correct, no need to change */
        return CM_SUCCESS;
    }

    /* Permissions are not 0400, set them to 0400 */
    if (chmod(filename, GR_PERM_FILE) != 0) {
        GR_PRINT_ERROR("Failed to set permissions on file %s: %s\n", filename, strerror(errno));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t get_config_file_path(const char *type, char *config_file_path, size_t path_len) {
    int ret = 0;
    const char *gr_home = getenv("GR_HOME");
    if (!gr_home) {
        printf("Please set GR_HOME environment variable.\n");
        return CM_ERROR;
    }
    if (config_file_path == NULL || path_len == 0) {
        printf("Invalid buffer parameter.\n");
        return CM_ERROR;
    }
    if (strcmp(type, "client") == 0) {
        ret = snprintf_s(config_file_path, path_len, path_len - 1, "%s/%s",
            gr_home, "cfg/gr_cli_inst.ini");
    } else if (strcmp(type, "server") == 0 || strcmp(type, "ca") == 0) {
        ret = snprintf_s(config_file_path, path_len, path_len - 1, "%s/%s",
            gr_home, "cfg/gr_inst.ini");
    }
    if (ret < 0) {
        printf("Failed to get config file path: %s\n", strerror(errno));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t get_ssl_path(const char *config_file_path, char *ssl_conf_path, size_t ssl_conf_path_len) {
    if (config_file_path == NULL || ssl_conf_path == NULL || ssl_conf_path_len == 0) {
        printf("Invalid buffer parameter.\n");
        return CM_ERROR;
    }
    FILE *fp = fopen(config_file_path, "r");
    if (fp == NULL) {
        GR_PRINT_ERROR("Failed to open config file: %s\n", config_file_path);
        return CM_ERROR;
    }
    char line[1024];
    char file_path[CM_MAX_PATH_LEN] = {0};
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        /* Match CLI_SSL_CA with flexible format: "CLI_SSL_CA = value" or "CLI_SSL_CA=value" */
        if (strstr(line, "CLI_SSL_CA") != NULL) {
            char *equal_sign = strchr(line, '=');
            if (equal_sign != NULL) {
                char *value = equal_sign + 1;
                /* Skip leading whitespace */
                while (*value == ' ' || *value == '\t') {
                    value++;
                }
                strncpy(file_path, value, sizeof(file_path) - 1);
                file_path[sizeof(file_path) - 1] = '\0';
                break;
            }
        }
        /* Match SER_SSL_CA with flexible format: "SER_SSL_CA = value" or "SER_SSL_CA=value" */
        if (strstr(line, "SER_SSL_CA") != NULL) {
            char *equal_sign = strchr(line, '=');
            if (equal_sign != NULL) {
                char *value = equal_sign + 1;
                /* Skip leading whitespace */
                while (*value == ' ' || *value == '\t') {
                    value++;
                }
                strncpy(file_path, value, sizeof(file_path) - 1);
                file_path[sizeof(file_path) - 1] = '\0';
                break;
            }
        }
    }
    fclose(fp);

    if (file_path[0] == '\0') {
        return CM_ERROR;
    }

    /* Remove trailing newline, carriage return, and whitespace */
    size_t len = strlen(file_path);
    while (len > 0 && (file_path[len - 1] == '\n' || file_path[len - 1] == '\r' || 
                       file_path[len - 1] == ' ' || file_path[len - 1] == '\t')) {
        file_path[len - 1] = '\0';
        len--;
    }

    /* Extract directory path from file path */
    char *last_slash = strrchr(file_path, '/');
    if (last_slash != NULL) {
        size_t dir_len = last_slash - file_path;
        if (dir_len < ssl_conf_path_len) {
            strncpy(ssl_conf_path, file_path, dir_len);
            ssl_conf_path[dir_len] = '\0';
        } else {
            return CM_ERROR;
        }
    } else {
        /* No slash found, assume current directory */
        if (ssl_conf_path_len > 1) {
            strncpy(ssl_conf_path, ".", ssl_conf_path_len - 1);
            ssl_conf_path[1] = '\0';
        } else {
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static status_t create_client_certs_entry(const char *ssl_path, int days) {
    char cli_ca[CM_MAX_PATH_LEN];
    char cli_key[CM_MAX_PATH_LEN]; 
    char cli_cert[CM_MAX_PATH_LEN]; 
    char cli_crl[CM_MAX_PATH_LEN];
    char cli_enc_key[CM_MAX_PATH_LEN];
    char cli_csr[CM_MAX_PATH_LEN];
    if (snprintf(cli_ca, sizeof(cli_ca), "%s/cacert.pem", ssl_path) >= sizeof(cli_ca) ||
        snprintf(cli_key, sizeof(cli_key), "%s/client.key", ssl_path) >= sizeof(cli_key) ||
        snprintf(cli_cert, sizeof(cli_cert), "%s/client.crt", ssl_path) >= sizeof(cli_cert) ||
        snprintf(cli_crl, sizeof(cli_crl), "%s/client.crl", ssl_path) >= sizeof(cli_crl) ||
        snprintf(cli_csr, sizeof(cli_csr), "%s/client.csr", ssl_path) >= sizeof(cli_csr) ||
        snprintf(cli_enc_key, sizeof(cli_enc_key), "%s/client.key.pass.enc", ssl_path) >= sizeof(cli_enc_key)) {
        GR_PRINT_ERROR("cli_certs_path too long, path buffer overflow!\n");
        return CM_ERROR;
    }

    char root_certs_path[CM_MAX_PATH_LEN] = {0};
    if (get_config_file_path("ca", root_certs_path, sizeof(root_certs_path)) != CM_SUCCESS ||
        root_certs_path[0] == '\0') {
        return CM_ERROR;
    }

    char root_ssl_path[CM_MAX_PATH_LEN] = {0};
    if (get_ssl_path(root_certs_path, root_ssl_path, sizeof(root_ssl_path)) != CM_SUCCESS ||
        root_ssl_path[0] == '\0') {
        GR_PRINT_ERROR("Failed to get ssl path from config file.\n");
        return CM_ERROR;
    }

    if (file_exists(cli_key) || file_exists(cli_cert) || file_exists(cli_crl) ||
        file_exists(cli_enc_key) || file_exists(cli_csr)) {
        GR_PRINT_ERROR("Client certs already exist, please check following client certs whether exist: "
            "client.key, client.crt, client.crl, client.key.pass.enc, client.csr.\n");
        return CM_ERROR;
    }
    if (create_client_certs(ssl_path, root_ssl_path, days) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (!file_exists(cli_ca) || !file_exists(cli_key) || !file_exists(cli_cert) ||
        !file_exists(cli_enc_key) || !file_exists(cli_csr)) {
        GR_PRINT_ERROR("Please check following client certs whether exist: "
            "cacert.pem, client.key, client.crt, client.csr, client.key.pass.enc.\n");
        return CM_ERROR;
    }
    if (check_certs_permission(cli_ca) != CM_SUCCESS || check_certs_permission(cli_key) != CM_SUCCESS ||
        check_certs_permission(cli_cert) != CM_SUCCESS || check_certs_permission(cli_enc_key) != CM_SUCCESS ||
        check_certs_permission(cli_csr) != CM_SUCCESS) {
        return CM_ERROR;
    }

    GR_PRINT_INF("Client certs generated and checked successfully.\n");
    return CM_SUCCESS;
}

static status_t create_server_certs_entry(const char *ssl_path, int days) {
    char ser_ca[CM_MAX_PATH_LEN];
    char ser_key[CM_MAX_PATH_LEN];
    char ser_cert[CM_MAX_PATH_LEN];
    char ser_crl[CM_MAX_PATH_LEN];
    char ser_enc_key[CM_MAX_PATH_LEN];
    char ser_csr[CM_MAX_PATH_LEN];
    if (snprintf(ser_ca, sizeof(ser_ca), "%s/cacert.pem", ssl_path) >= sizeof(ser_ca) ||
        snprintf(ser_key, sizeof(ser_key), "%s/server.key", ssl_path) >= sizeof(ser_key) ||
        snprintf(ser_cert, sizeof(ser_cert), "%s/server.crt", ssl_path) >= sizeof(ser_cert) ||
        snprintf(ser_crl, sizeof(ser_crl), "%s/server.crl", ssl_path) >= sizeof(ser_crl) ||
        snprintf(ser_csr, sizeof(ser_csr), "%s/server.csr", ssl_path) >= sizeof(ser_csr) ||
        snprintf(ser_enc_key, sizeof(ser_enc_key), "%s/server.key.pass.enc", ssl_path) >= sizeof(ser_enc_key)) {
        GR_PRINT_ERROR("ssl_path too long, path buffer overflow!\n");
        return CM_ERROR;
    }

    if (file_exists(ser_key) || file_exists(ser_cert) || file_exists(ser_crl) ||
        file_exists(ser_enc_key) || file_exists(ser_csr)) {
        GR_PRINT_ERROR("Server certs already exist, please check following server certs whether exist: "
            "server.key, server.crt, server.crl, server.key.pass.enc, server.csr.\n");
        return CM_ERROR;
    }
    if (create_server_certs(ssl_path, days) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (check_certs_permission(ser_ca) != CM_SUCCESS || check_certs_permission(ser_key) != CM_SUCCESS||
        check_certs_permission(ser_cert) != CM_SUCCESS || check_certs_permission(ser_enc_key) != CM_SUCCESS ||
        check_certs_permission(ser_csr) != CM_SUCCESS) {
        return CM_ERROR;
    }
    GR_PRINT_INF("Server certs generated and checked successfully.\n");
    return CM_SUCCESS;
}

static status_t generate_root_cert_entry(const char *ssl_path, int days) {
    char demoCA_path[CM_MAX_PATH_LEN];
    char ca_file[CM_MAX_PATH_LEN];
    char ca_key[CM_MAX_PATH_LEN];
    char ca_enc_key[CM_MAX_PATH_LEN];
    if (snprintf_s(ca_file, sizeof(ca_file), sizeof(ca_file) - 1, "%s/cacert.pem", ssl_path) == -1 ||
        snprintf_s(demoCA_path, sizeof(demoCA_path), sizeof(demoCA_path) - 1, "%s/demoCA", ssl_path) == -1 ||
        snprintf_s(ca_key, sizeof(ca_key), sizeof(ca_key) - 1, "%s/demoCA/private/cakey.pem", ssl_path) == -1 ||
        snprintf_s(ca_enc_key, sizeof(ca_enc_key), sizeof(ca_enc_key) - 1, "%s/ca.pass.enc", ssl_path) == -1) {
        GR_PRINT_ERROR("Failed to get path by snprintf_s!\n");
        return CM_ERROR;
    }
    if (file_exists(demoCA_path) || file_exists(ca_file) || file_exists(ca_enc_key)) {
        GR_PRINT_ERROR("CA already exists, failed to gencert.\n");
        return CM_ERROR;
    }
    if (prepare_certs_path(ssl_path) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (generate_root_cert(ssl_path, days) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (check_certs_permission(ca_file) != CM_SUCCESS || check_certs_permission(ca_key) != CM_SUCCESS ||
        check_certs_permission(ca_enc_key) != CM_SUCCESS) {
        return CM_ERROR;
    }
    GR_PRINT_INF("CA certs generated successfully.\n");
    return CM_SUCCESS;
}

static status_t gencert_proc(void)
{
    int days = 0;
    status_t ret = CM_ERROR;
    char *type = cmd_gencert_args[0].input_args;
    char *days_str = cmd_gencert_args[1].input_args;
    if (type == NULL) {
        printf("Please specify -t client or -t server\n");
        return CM_ERROR;
    }
    if (strcmp(type, "client") != 0 && strcmp(type, "server") != 0 && strcmp(type, "ca") != 0) {
        printf("Please specify -t client or -t server or -t ca\n");
        return CM_ERROR;
    }
    if (days_str != NULL) {
        days = atoi(days_str);
        if (days <= 0) {
            printf("Invalid days value: %s\n", days_str);
            return CM_ERROR;
        }
    }
    days = (days != 0) ? days : GR_DEFAULT_CERT_TIME;

    char config_file_path[CM_MAX_PATH_LEN] = {0};
    if (get_config_file_path(type, config_file_path, sizeof(config_file_path)) != CM_SUCCESS ||
        config_file_path[0] == '\0') {
        return CM_ERROR;
    }

    char ssl_path[CM_MAX_PATH_LEN] = {0};
    if (get_ssl_path(config_file_path, ssl_path, sizeof(ssl_path)) != CM_SUCCESS ||
        ssl_path[0] == '\0') {
        printf("Failed to get ssl path from config file: %s\n", config_file_path);
        return CM_ERROR;
    }

    if (strcmp(type, "client") == 0) {
        ret = create_client_certs_entry(ssl_path, days);
    } else if (strcmp(type, "server") == 0) {
        ret = create_server_certs_entry(ssl_path, days);
    } else if (strcmp(type, "ca") == 0) {
        ret = generate_root_cert_entry(ssl_path, days);
    }
    return ret;
}

// add reload for handle server config write to WORM storage
static gr_args_set_t cmd_reload_args_set = {
    NULL,
    0,
    NULL,
};

static void reload_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s reload\n", prog_name);
    (void)printf("[server command] write current config to WORM storage\n");
    if (print_flag == GR_HELP_SIMPLE) {
        return;
    }
}

static status_t reload_proc(void)
{
    gr_conn_t *conn = gr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }
    status_t status = gr_reload_cfg_impl(conn);
    if (status != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to reload (write config to WORM).\n");
    } else {
        GR_PRINT_INF("Succeed to reload (config written to WORM).\n");
    }
    gr_disconnect_ex(conn);
    return status;
}

static gr_args_t cmd_datausage_args[] = {
    {'i', "addr", CM_FALSE, CM_TRUE, check_server_addr_format, NULL, NULL, 0, NULL, NULL, 0},
};

static gr_args_set_t cmd_datausage_args_set = {
    cmd_datausage_args,
    sizeof(cmd_datausage_args) / sizeof(gr_args_t),
    NULL,
};

static void datausage_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s datausage\n", prog_name);
    (void)printf("[client command] reload gr server certs\n");
    if (print_flag == GR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-i/--addr <addr>, the value of ip:port\n");
}

static status_t datausage_proc(void)
{
    status_t status = CM_SUCCESS;
    const double GB = 1073741824.0; // 1 GB in bytes
    const char *addr = cmd_datausage_args[GR_ARG_IDX_0].input_args;
    gr_conn_t *conn;
    if (addr == NULL) {
        conn = gr_get_connection_for_cmd();
    } else {
        status = gr_enter_api(&conn, addr);
        if (status != CM_SUCCESS) {
            GR_PRINT_ERROR("Failed to get conn.\n");
            return CM_ERROR;
        }
    }
    if (conn == NULL) {
        return CM_ERROR;
    }
    gr_disk_usage_info_t info = {0};
    status = gr_get_disk_usage_impl(conn, &info);
    if (status != CM_SUCCESS) {
        GR_PRINT_ERROR("Failed to get disk usage.\n");
    } else {
        double percent = 0.0;
        if (info.total_bytes > 0) {
            percent = (double)info.used_bytes / (double)info.total_bytes * 100.0;
        }
        printf("Total: %.2f GB, Used: %.2f GB, Available: %.2f GB, Usage: %.2f%%\n",
            info.total_bytes / GB,
            info.used_bytes / GB,
            info.available_bytes / GB,
            percent);
    }
    gr_disconnect_ex(conn);
    return status;
}

// clang-format off
gr_admin_cmd_t g_gr_admin_cmd[] = {
    {"ts", ts_help, ts_proc, &cmd_ts_args_set, false},
    {"lscli", lscli_help, lscli_proc, &cmd_lscli_args_set, false},
    {"setcfg", setcfg_help, setcfg_proc, &cmd_setcfg_args_set, true},
    {"getcfg", getcfg_help, getcfg_proc, &cmd_getcfg_args_set, false},
    {"getstatus", getstatus_help, getstatus_proc, &cmd_getstatus_args_set, false},
    {"stop", stop_help, stop_proc, &cmd_stop_args_set, true},
    {"switchover", switchover_help, switchover_proc, &cmd_switchover_args_set, true},
    {"reload_certs", reload_certs_help, reload_certs_proc, &cmd_reload_certs_args_set, false},
    {"gencert", gencert_help, gencert_proc, &cmd_gencert_args_set, true},
    {"reload", reload_help, reload_proc, &cmd_reload_args_set, true},
    {"datausage", datausage_help, datausage_proc, &cmd_datausage_args_set, true},
};

void clean_cmd()
{
}

// clang-format on
static void help(char *prog_name, gr_help_type help_type)
{
    (void)printf("Usage:%s [command] [OPTIONS]\n\n", prog_name);
    (void)printf("Usage:%s %s/%s show help information of grcmd\n", prog_name, HELP_SHORT, HELP_LONG);
    (void)printf("Usage:%s %s/%s show all help information of grcmd\n", prog_name, ALL_SHORT, ALL_LONG);
    (void)printf("Usage:%s %s/%s show version information of grcmd\n", prog_name, VERSION_SHORT, VERSION_LONG);
    (void)printf("commands:\n");
    for (uint32_t i = 0; i < sizeof(g_gr_admin_cmd) / sizeof(g_gr_admin_cmd[0]); ++i) {
        g_gr_admin_cmd[i].help(prog_name, help_type);
    }
    (void)printf("\n\n");
}

static status_t execute_one_cmd(int argc, char **argv, uint32_t cmd_idx)
{
    cmd_parse_init(g_gr_admin_cmd[cmd_idx].args_set->cmd_args, g_gr_admin_cmd[cmd_idx].args_set->args_size);
    if (cmd_parse_args(argc, argv, g_gr_admin_cmd[cmd_idx].args_set) != CM_SUCCESS) {
        int32_t code;
        const char *message;
        cm_get_error(&code, &message);
        if (code != 0) {
            GR_PRINT_ERROR("\ncmd %s error:%d %s.\n", g_gr_admin_cmd[cmd_idx].cmd, code, message);
        }
        return CM_ERROR;
    }
    status_t ret = g_gr_admin_cmd[cmd_idx].proc();
    cmd_parse_clean(g_gr_admin_cmd[cmd_idx].args_set->cmd_args, g_gr_admin_cmd[cmd_idx].args_set->args_size);
    return ret;
}

static status_t gr_cmd_append_oper_log(char *log_buf, void *buf, uint32_t *offset)
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

static void gr_cmd_oper_log(int argc, char **argv, status_t status)
{
    char log_buf[CM_MAX_LOG_CONTENT_LENGTH] = {0};
    uint32_t offset = 0;

    if (!LOG_OPER_ON) {
        return;
    }

    GR_RETURN_DRIECT_IFERR(gr_cmd_append_oper_log(log_buf, "grcmd", &offset));

    for (int i = 1; i < argc; i++) {
        GR_RETURN_DRIECT_IFERR(gr_cmd_append_oper_log(log_buf, " ", &offset));
        GR_RETURN_DRIECT_IFERR(gr_cmd_append_oper_log(log_buf, argv[i], &offset));
    }

    char result[GR_MAX_PATH_BUFFER_SIZE];
    int32_t ret = snprintf_s(
        result, GR_MAX_PATH_BUFFER_SIZE, GR_MAX_PATH_BUFFER_SIZE - 1, ". execute result %d.", (int32_t)status);
    if (ret == -1) {
        return;
    }
    GR_RETURN_DRIECT_IFERR(gr_cmd_append_oper_log(log_buf, result, &offset));

    if (offset + 1 > CM_MAX_LOG_CONTENT_LENGTH) {
        GR_PRINT_ERROR("Oper log len %u exceeds max %u.\n", offset, CM_MAX_LOG_CONTENT_LENGTH);
        return;
    }
    log_buf[offset + 1] = '\0';
    cm_write_oper_log(log_buf, offset);
}

static bool32 get_cmd_idx(int argc, char **argv, uint32_t *idx)
{
    for (uint32_t i = 0; i < sizeof(g_gr_admin_cmd) / sizeof(g_gr_admin_cmd[0]); ++i) {
        if (strcmp(g_gr_admin_cmd[i].cmd, argv[GR_ARG_IDX_1]) == 0) {
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
        (void)printf("grcmd %s\n", (char *)DEF_GR_VERSION);
        return CM_TRUE;
    }
    if (cm_str_equal(argv[1], ALL_SHORT) || cm_str_equal(argv[1], ALL_LONG)) {
        help(argv[0], GR_HELP_DETAIL);
        return CM_TRUE;
    }
    if (cm_str_equal(argv[1], HELP_SHORT) || cm_str_equal(argv[1], HELP_LONG)) {
        help(argv[0], GR_HELP_SIMPLE);
        return CM_TRUE;
    }
    return CM_FALSE;
}

void print_help_hint()
{
    (void)printf("grcmd: Try \"grcmd -h/--help\" for help information.\n");
    (void)printf("grcmd: Try \"grcmd -a/--all\" for detailed help information.\n");
}

int32_t execute_help_cmd(int argc, char **argv, uint32_t *idx, bool8 *go_ahead)
{
    if (argc < CMD_ARGS_AT_LEAST) {
        (void)printf("grcmd: no operation specified.\n");
        print_help_hint();
        *go_ahead = CM_FALSE;
        return EXIT_FAILURE;
    }
    if (cmd_version_and_help(argc, argv)) {
        *go_ahead = CM_FALSE;
        return EXIT_SUCCESS;
    }
    if (!get_cmd_idx(argc, argv, idx)) {
        (void)printf("grcmd: command(%s) not found!\n", argv[GR_ARG_IDX_1]);
        print_help_hint();
        *go_ahead = CM_FALSE;
        return EXIT_FAILURE;
    }
    if (argc > GR_ARG_IDX_2 &&
        (strcmp(argv[GR_ARG_IDX_2], "-h") == 0 || strcmp(argv[GR_ARG_IDX_2], "--help") == 0)) {
        g_gr_admin_cmd[*idx].help(argv[0], GR_HELP_DETAIL);
        *go_ahead = CM_FALSE;
        return EXIT_SUCCESS;
    }

    *go_ahead = CM_TRUE;
    return EXIT_SUCCESS;
}

status_t execute_cmd(int argc, char **argv, uint32_t idx)
{
    status_t status = execute_one_cmd(argc, argv, idx);
    gr_cmd_oper_log(argc, argv, status);
    return status;
}

static bool32 is_log_necessary(int argc, char **argv)
{
    uint32_t cmd_idx;
    if (get_cmd_idx(argc, argv, &cmd_idx) && g_gr_admin_cmd[cmd_idx].log_necessary) {
        return true;
    }
    return false;
}


int main(int argc, char **argv)
{
    uint32_t idx = 0;
    bool8 go_ahead = CM_TRUE;
    bool8 is_interactive = cmd_check_run_interactive(argc, argv);
    if (!is_interactive) {
        int32_t help_ret = execute_help_cmd(argc, argv, &idx, &go_ahead);
        if (!go_ahead) {
            exit(help_ret);
        }
    }
    gr_config_t *inst_cfg = gr_get_g_inst_cfg();
    status_t ret = gr_set_cfg_dir(NULL, inst_cfg);
    GR_RETURN_IFERR2(ret, GR_PRINT_ERROR("Environment variant GR_HOME not found!\n"));
    ret = gr_load_local_server_config(inst_cfg);
    GR_RETURN_IFERR2(ret, GR_PRINT_ERROR("Failed to load local server config, status(%d).\n", ret));
    ret = cm_start_timer(g_timer());

    GR_RETURN_IFERR2(ret, GR_PRINT_ERROR("Aborted due to starting timer thread.\n"));
    ret = gr_init_loggers(inst_cfg, gr_get_cmd_log_def(), gr_get_cmd_log_def_count(), "grcmd");
    if (ret != CM_SUCCESS && is_log_necessary(argc, argv)) {
        GR_PRINT_ERROR("%s\nGR init loggers failed!\n", cm_get_errormsg(cm_get_error_code()));
        return ret;
    }

    cm_reset_error();
    ret = execute_cmd(argc, argv, idx);

    clean_cmd();
    return ret;
}
