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

#include "gr_errno.h"
#include "gr_defs.h"
#include "gr_malloc.h"
#include "gr_file.h"
#include "gr_api.h"
#include "gr_api_impl.h"
#include "gr_cli_conn.h"
#include "gr_args_parse.h"

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

static gr_args_t cmd_ts_args[] = {};

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
}

static status_t ts_proc(void)
{
    status_t status = CM_SUCCESS;
    gr_conn_t *conn = gr_get_connection_for_cmd();
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
};
static gr_args_set_t cmd_setcfg_args_set = {
    cmd_setcfg_args,
    sizeof(cmd_setcfg_args) / sizeof(gr_args_t),
    NULL,
};

static void setcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s setcfg <-n name> <-v value> [-s scope]\n", prog_name);
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
}

static status_t setcfg_proc(void)
{
    char *name = cmd_setcfg_args[GR_ARG_IDX_0].input_args;
    char *value = cmd_setcfg_args[GR_ARG_IDX_1].input_args;
    char *scope = cmd_setcfg_args[GR_ARG_IDX_2].input_args != NULL ?
                  cmd_setcfg_args[GR_ARG_IDX_2].input_args : "both";

    gr_conn_t *conn = gr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t status = gr_setcfg_impl(conn, name, value, scope);
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
};
static gr_args_set_t cmd_getcfg_args_set = {
    cmd_getcfg_args,
    sizeof(cmd_getcfg_args) / sizeof(gr_args_t),
    NULL,
};

static void getcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s getcfg <-n name> \n", prog_name);
    (void)printf("[client command] get config value by name\n");
    if (print_flag == GR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-n/--name <name>, <required>, the config name to set\n");
}

static status_t getcfg_proc(void)
{
    char *name = cmd_getcfg_args[GR_ARG_IDX_0].input_args;
    gr_conn_t *conn = gr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }
    char value[GR_PARAM_BUFFER_SIZE] = {0};
    status_t status = gr_getcfg_impl(conn, name, value, GR_PARAM_BUFFER_SIZE);
    if (status != CM_SUCCESS) {
        if (strlen(value) != 0 && cm_str_equal_ins(name, "SSL_PWD_CIPHERTEXT")) {
            LOG_RUN_ERR("Failed to get cfg, name is %s, value is ***.\n", name);
            (void)printf("Failed to get cfg, name is %s, value is %s.\n", name, value);
            (void)fflush(stdout);
            gr_print_detail_error();
        } else {
            GR_PRINT_ERROR("Failed to get cfg, name is %s, value is %s.\n", name, (strlen(value) == 0) ? NULL : value);
        }
    } else {
        if (strlen(value) != 0 && cm_str_equal_ins(name, "SSL_PWD_CIPHERTEXT")) {
            LOG_DEBUG_INF("Succeed to get cfg, name is %s, value is ***.\n", name);
            (void)printf("Succeed to get cfg, name is %s, value is %s.\n", name, value);
            (void)fflush(stdout);
        } else {
            GR_PRINT_INF("Succeed to get cfg, name is %s, value is %s.\n", name, (strlen(value) == 0) ? NULL : value);
        }
    }
    gr_disconnect_ex(conn);
    return status;
}

static gr_args_t cmd_getstatus_args[] = {};

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
}

static status_t getstatus_proc(void)
{
    gr_conn_t *conn = gr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }

    gr_server_status_t gr_status;
    status_t status = gr_get_inst_status_on_server(conn, &gr_status);
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

static gr_args_t cmd_stop_args[] = {};
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
}

static status_t stop_proc(void)
{
    gr_conn_t *conn = gr_get_connection_for_cmd();
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

static gr_args_t cmd_switchover_args[] = {};
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
}

static status_t switchover_proc(void)
{
    gr_conn_t *conn = gr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }
    
    status_t status = gr_set_main_inst_impl(conn);
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
    (void)printf("\nUsage:%s gencert -t <client|server> [-d days]\n", prog_name);
    (void)printf("[command] generate and check certs for client or server\n");
    (void)printf("  -t/--type <client|server>\n");
    (void)printf("  -d/--days <days>  (optional, default: 3650)\n");
}

static void prepare_certs_path(const char *certs_path) {
    char cmd[GR_CMD_LEN];
    snprintf(cmd, sizeof(cmd),
        "mkdir -p %s && "
        "[ -f %s/openssl.cnf ] || cp /etc/pki/tls/openssl.cnf %s/. && "
        "cd %s && mkdir -p demoCA demoCA/newcerts demoCA/private && "
        "touch demoCA/index.txt && echo '01'>demoCA/serial && "
        "if [ ! -d demoCA/private ] || [ ! -e demoCA/index.txt ]; then chmod 700 demoCA/private; fi && "
        "sed -i 's/^.*default_md.*$/default_md      = sha256/' openssl.cnf",
        certs_path, certs_path, certs_path, certs_path);
    system(cmd);
}

static void generate_root_cert(const char *certs_path, int days) {
    char cmd[GR_CMD_LEN];
    snprintf(cmd, sizeof(cmd),
        "cd %s && "
        "ca_password=$(openssl rand -base64 32); "
        "export OPENSSL_CONF=%s/openssl.cnf; "
        "echo $ca_password | openssl genrsa -aes256 -passout stdin -out demoCA/private/cakey.pem 2048 && "
        "echo $ca_password | openssl req -new -x509 -passin stdin -days %d -key demoCA/private/cakey.pem -out demoCA/cacert.pem -subj \"/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/CN=CA\" && "
        "cp demoCA/cacert.pem . && "
        "echo $ca_password > ca.pass && chmod 400 ca.pass",
        certs_path, certs_path, days);
    system(cmd);
}

static void create_server_certs(const char *certs_path, int days) {
    char cmd[GR_CMD_LEN];
    snprintf(cmd, sizeof(cmd),
        "cd %s && "
        "server_password=$(openssl rand -base64 32); "
        "ca_password=$(cat ca.pass); "
        "export OPENSSL_CONF=%s/openssl.cnf; "
        "echo $server_password | openssl genrsa -aes256 -passout stdin -out server.key 2048 && "
        "echo $server_password | openssl req -new -key server.key -passin stdin -out server.csr -subj \"/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/CN=server\" && "
        "echo $ca_password | openssl x509 -req -days %d -in server.csr -CA demoCA/cacert.pem -CAkey demoCA/private/cakey.pem -passin stdin -CAcreateserial -out server.crt && "
        "echo $server_password | openssl rsa -in server.key -out server.key -passin stdin && "
        "chmod 400 server.* && echo '00' >demoCA/crlnumber",
        certs_path, certs_path, days);
    system(cmd);
}

static void create_client_certs(const char *certs_path, int days) {
    char cmd[GR_CMD_LEN];
    snprintf(cmd, sizeof(cmd),
        "cd %s && "
        "client_password=$(openssl rand -base64 32); "
        "ca_password=$(cat ca.pass); "
        "export OPENSSL_CONF=%s/openssl.cnf; "
        "echo $client_password | openssl genrsa -aes256 -passout stdin -out client.key 2048 && "
        "echo $client_password | openssl req -new -key client.key -passin stdin -out client.csr -subj \"/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/CN=client\" && "
        "echo $ca_password | openssl x509 -req -days %d -in client.csr -CA demoCA/cacert.pem -CAkey demoCA/private/cakey.pem -passin stdin -CAcreateserial -out client.crt && "
        "echo $client_password | openssl rsa -in client.key -out client.key -passin stdin && "
        "chmod 400 client.*",
        certs_path, certs_path, days);
    system(cmd);
}

static void create_server_conf(const char *conf_file, const char *ser_ca, const char *ser_key, const char *ser_cert, const char *ser_crl) {
    // 如果配置文件中已存在相关键，则不重复写入
    FILE *rf = fopen(conf_file, "r");
    int has_ca = 0, has_key = 0, has_cert = 0, has_crl = 0, has_header = 0;
    if (rf) {
        char line[1024];
        while (fgets(line, sizeof(line), rf) != NULL) {
            if (strstr(line, "# ==================== Server SSL Configuration ====================") != NULL) {
                has_header = 1;
            }
            if (strncmp(line, "SER_SSL_CA=", 11) == 0)   has_ca = 1;
            if (strncmp(line, "SER_SSL_KEY=", 12) == 0)  has_key = 1;
            if (strncmp(line, "SER_SSL_CERT=", 13) == 0) has_cert = 1;
            if (strncmp(line, "SER_SSL_CRL=", 12) == 0)  has_crl = 1;
        }
        fclose(rf);
    }
    if (has_ca && has_key && has_cert && has_crl) {
        return; // 已存在全部条目，不再写入
    }
    FILE *fp = fopen(conf_file, "a");
    if (!fp) return;
    if (!has_header) {
        fprintf(fp, "\n# ==================== Server SSL Configuration ====================\n");
        fprintf(fp, "# 服务端SSL配置（自动生成）\n");
    }
    if (!has_ca)   fprintf(fp, "SER_SSL_CA=%s\n", ser_ca);
    if (!has_key)  fprintf(fp, "SER_SSL_KEY=%s\n", ser_key);
    if (!has_cert) fprintf(fp, "SER_SSL_CERT=%s\n", ser_cert);
    if (!has_crl)  fprintf(fp, "SER_SSL_CRL=%s\n", ser_crl);
    fclose(fp);
}

static void create_client_conf(const char *conf_file, const char *cli_ca, const char *cli_key, const char *cli_cert, const char *cli_crl) {
    // 若配置文件已有证书相关键，则不重复写入；否则按需追加缺失项
    int has_ca = 0, has_key = 0, has_cert = 0, has_crl = 0;
    FILE *rf = fopen(conf_file, "r");
    if (rf) {
        char line[1024];
        while (fgets(line, sizeof(line), rf) != NULL) {
            if (strncmp(line, "CLI_SSL_CA=", 11) == 0)   has_ca = 1;
            if (strncmp(line, "CLI_SSL_KEY=", 12) == 0)  has_key = 1;
            if (strncmp(line, "CLI_SSL_CERT=", 13) == 0) has_cert = 1;
            if (strncmp(line, "CLI_SSL_CRL=", 12) == 0)  has_crl = 1;
        }
        fclose(rf);
    }
    if (has_ca && has_key && has_cert) {
        return; // 已存在主要条目，不再写入
    }
    FILE *fp = fopen(conf_file, "a");
    if (!fp) return;
    if (!has_ca)   fprintf(fp, "CLI_SSL_CA=%s\n", cli_ca);
    if (!has_key)  fprintf(fp, "CLI_SSL_KEY=%s\n", cli_key);
    if (!has_cert) fprintf(fp, "CLI_SSL_CERT=%s\n", cli_cert);
    if (!has_crl)  fprintf(fp, "CLI_SSL_CRL=%s\n", cli_crl);
    fclose(fp);
}

static void check_certs_permission(const char *filename) {
    chmod(filename, GR_PERM_FILE);
}

static void check_certs_expired(const char *ca, const char *cert) {
    char cmd[GR_CMD_LEN], buf[GR_CMD_LEN];
    FILE *fp;
    int ca_last = 0, cert_last = 0;

    snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1,
        "openssl x509 -in %s -noout -enddate | cut -d= -f2 | xargs -I {} date -d {} +%%s | xargs -I {} expr {} - $(date +%%s) | xargs -I {} expr {} / 86400",
        ca);
    fp = popen(cmd, "r");
    if (fp && fgets(buf, sizeof(buf), fp)) ca_last = atoi(buf);
    if (fp) pclose(fp);

    snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1,
        "openssl x509 -in %s -noout -enddate | cut -d= -f2 | xargs -I {} date -d {} +%%s | xargs -I {} expr {} - $(date +%%s) | xargs -I {} expr {} / 86400",
        cert);
    fp = popen(cmd, "r");
    if (fp && fgets(buf, sizeof(buf), fp)) cert_last = atoi(buf);
    if (fp) pclose(fp);

    if (ca_last < LAST_DAY) {
        printf("CA will be expired in %d, please renew %s.\n", ca_last, ca);
    }
    if (cert_last < LAST_DAY) {
        printf("CA will be expired in %d, please renew %s.\n", cert_last, cert);
    }
}

static int file_exists(const char *filename) {
    return access(filename, F_OK) == 0;
}

static status_t gencert_proc(void)
{
    const char *gr_home = getenv("GR_HOME");
    if (!gr_home) {
        printf("Please set GR_HOME environment variable.\n");
        return CM_ERROR;
    }
    char *type = cmd_gencert_args[0].input_args;
    char *days_str = cmd_gencert_args[1].input_args;
    int days = 3650;
    if (days_str != NULL) {
        days = atoi(days_str);
        if (days <= 0) {
            printf("Invalid days value: %s\n", days_str);
            return CM_ERROR;
        }
    }
    char certs_path[CM_MAX_PATH_LEN], conf_file[CM_MAX_PATH_LEN];
    if (snprintf(certs_path, sizeof(certs_path), "%s/CA", gr_home) >= sizeof(certs_path)) {
        printf("certs_path too long, path buffer overflow!\n");
        return CM_ERROR;
    }

    if (type == NULL) {
        printf("Please specify -t client or -t server\n");
        return CM_ERROR;
    }

    if (strcmp(type, "client") == 0) {
        if (snprintf(conf_file, sizeof(conf_file), "%s/cfg/gr_cli_inst.ini", gr_home) >= sizeof(conf_file)) {
            printf("conf_file path too long!\n");
            return CM_ERROR;
        }
        char cli_ca[CM_MAX_PATH_LEN], cli_key[CM_MAX_PATH_LEN], cli_cert[CM_MAX_PATH_LEN], cli_crl[CM_MAX_PATH_LEN];
        if (snprintf(cli_ca, sizeof(cli_ca), "%s/cacert.pem", certs_path) >= sizeof(cli_ca) ||
            snprintf(cli_key, sizeof(cli_key), "%s/client.key", certs_path) >= sizeof(cli_key) ||
            snprintf(cli_cert, sizeof(cli_cert), "%s/client.crt", certs_path) >= sizeof(cli_cert) ||
            snprintf(cli_crl, sizeof(cli_crl), "%s/client.crl", certs_path) >= sizeof(cli_crl)) {
            printf("certs_path too long, path buffer overflow!\n");
            return CM_ERROR;
        }
        create_client_certs(certs_path, days);
        create_client_conf(conf_file, cli_ca, cli_key, cli_cert, cli_crl);
        if (!file_exists(cli_ca) || !file_exists(cli_key) || !file_exists(cli_cert)) {
            printf("Please check following client certs whether exist: cacert.pem, client.key, client.crt .\n");
            return CM_ERROR;
        }
        check_certs_permission(cli_ca);
        check_certs_permission(cli_key);
        check_certs_permission(cli_cert);
        check_certs_expired(cli_ca, cli_cert);
        printf("Client certs generated and checked successfully.\n");
    } else if (strcmp(type, "server") == 0) {
        if (snprintf(conf_file, sizeof(conf_file), "%s/cfg/gr_inst.ini", gr_home) >= sizeof(conf_file)) {
            printf("conf_file path too long!\n");
            return CM_ERROR;
        }
        char ser_ca[CM_MAX_PATH_LEN], ser_key[CM_MAX_PATH_LEN], ser_cert[CM_MAX_PATH_LEN], ser_crl[CM_MAX_PATH_LEN];
        if (snprintf(ser_ca, sizeof(ser_ca), "%s/cacert.pem", certs_path) >= sizeof(ser_ca) ||
            snprintf(ser_key, sizeof(ser_key), "%s/server.key", certs_path) >= sizeof(ser_key) ||
            snprintf(ser_cert, sizeof(ser_cert), "%s/server.crt", certs_path) >= sizeof(ser_cert) ||
            snprintf(ser_crl, sizeof(ser_crl), "%s/server.crl", certs_path) >= sizeof(ser_crl)) {
            printf("certs_path too long, path buffer overflow!\n");
            return CM_ERROR;
        }
        // 若已存在demoCA目录，认为已初始化，不再改变其权限或内容
        char demoCA_path[CM_MAX_PATH_LEN];
        if (snprintf_s(demoCA_path, sizeof(demoCA_path), sizeof(demoCA_path) - 1, "%s/demoCA", certs_path) == -1) {
            printf("demoCA_path too long!\n");
            return CM_ERROR;
        }
        if (!file_exists(demoCA_path)) {
            prepare_certs_path(certs_path);
        }
        generate_root_cert(certs_path, days);
        create_server_conf(conf_file, ser_ca, ser_key, ser_cert, ser_crl);
        create_server_certs(certs_path, days);
        if (!file_exists(ser_ca) || !file_exists(ser_key) || !file_exists(ser_cert)) {
            printf("Please check following server certs whether exist: cacert.pem, server.key, server.crt .\n");
            return CM_ERROR;
        }
        check_certs_permission(ser_ca);
        check_certs_permission(ser_key);
        check_certs_permission(ser_cert);
        check_certs_expired(ser_ca, ser_cert);
        printf("Server certs generated and checked successfully.\n");
    } else {
        printf("Unknown type: %s, must be client or server\n", type);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static gr_args_t cmd_datausage_args[] = {};
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
}

static status_t datausage_proc(void)
{
    const double GB = 1073741824.0; // 1 GB in bytes
    gr_conn_t *conn = gr_get_connection_for_cmd();
    if (conn == NULL) {
        return CM_ERROR;
    }
    gr_disk_usage_info_t info = {0};
    status_t status = gr_get_disk_usage_impl(conn, &info);
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
