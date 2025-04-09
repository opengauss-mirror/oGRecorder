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
#include "wrcmd_inq.h"
#include "wrcmd_encrypt.h"
#include "wrcmd_conn_opt.h"
#include "wrcmd_interactive.h"
#include "wr_cli_conn.h"
#ifndef WIN32
#include "config.h"
#endif

#ifdef WIN32
#define DEF_WR_VERSION "Windows does not support this feature because it is built using vs."
#endif

// cmd format : cmd subcmd [-f val]
#define CMD_COMMAND_INJECTION_COUNT 22
#define WR_DEFAULT_MEASURE "B"
#define WR_SUBSTR_UDS_PATH "UDS:"
#define WR_DEFAULT_VG_TYPE 't' /* show vg information in table format by default */
static const char wr_ls_print_flag[] = {'d', '-', 'l'};

typedef struct st_wr_print_help_t {
    char fmt;
    uint32 bytes;
} wr_print_help_t;

// add uni-check function after here
// ------------------------
static status_t cmd_check_flag(const char *input_flag)
{
    uint64 flag;
    status_t ret = cm_str2uint64(input_flag, &flag);
    if (ret != CM_SUCCESS) {
        WR_PRINT_ERROR("The value of flag is invalid.\n");
        return CM_ERROR;
    }
    if (flag != 0 && flag != WR_FILE_FLAG_INNER_INITED) {
        WR_PRINT_ERROR("The value of flag must be 0 or 2147483648(means 0x80000000).\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_length(const char *input_length)
{
    uint64 length;
    status_t ret = cm_str2uint64(input_length, &length);
    if (ret != CM_SUCCESS) {
        WR_PRINT_ERROR("The value of length is invalid.\n");
        return CM_ERROR;
    }
    if ((int64)length < 0) {
        WR_PRINT_ERROR("The value of length must not be a negative number.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_zero_or_one(const char *zero_or_one_str)
{
    uint32 zero_or_one;
    status_t ret = cm_str2uint32(zero_or_one_str, &zero_or_one);
    if (ret != CM_SUCCESS) {
        WR_PRINT_ERROR("The value of zero_or_one is invalid.\n");
        return CM_ERROR;
    }
    if (zero_or_one != 0 && zero_or_one != 1) {
        WR_PRINT_ERROR("The value of zero_or_one should be 0 or 1.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_uds(const char *uds)
{
    const char *uds_prefix = "UDS:";
    /* if uds path only has "UDS:", it is invalid */
    if (strlen(uds) <= strlen(uds_prefix) || memcmp(uds, uds_prefix, strlen(uds_prefix)) != 0) {
        WR_PRINT_ERROR("uds name should start with %s, also it should not be empty.\n", uds_prefix);
        return CM_ERROR;
    }
    return wr_check_path(uds + strlen(uds_prefix));
}

static status_t wr_fetch_uds_path(char *server_path, char *path, char **file)
{
    char *pos = strrchr(server_path, '/');
    if (pos == NULL) {
        *file = server_path;
        path[0] = '.';
        path[1] = '\0';
        return CM_SUCCESS;
    }

    if (pos[1] == 0x00) {
        WR_PRINT_ERROR("the format of UDS is wrong.\n");
        return CM_ERROR;
    }

    if (pos == server_path) {
        *file = (char *)(server_path + 1);
        path[0] = '/';
        path[1] = '\0';
    } else {
        *file = pos;
        errno_t errcode = memcpy_sp(path, (size_t)WR_MAX_PATH_BUFFER_SIZE, server_path, (size_t)(pos - server_path));
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }
        path[(int)(pos - server_path)] = '\0';
    }
    return CM_SUCCESS;
}

static status_t cmd_check_convert_uds_home(const char *input_args, void **convert_result, int *convert_size)
{
    const char *server_path = (const char *)(input_args + strlen(WR_SUBSTR_UDS_PATH));
    char path[WR_MAX_PATH_BUFFER_SIZE];
    char *file = NULL;
    status_t status = wr_fetch_uds_path((char *)server_path, (char *)path, (char **)&file);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Fetch uds path failed.\n");
        return CM_ERROR;
    }

    status = cmd_realpath_home(path, (char **)convert_result, convert_size);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("home realpath failed, home: %s.\n", input_args);
        return status;
    }

    errno_t errcode = strcat_sp((char *)*convert_result, CM_FILE_NAME_BUFFER_SIZE, file);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        free(*convert_result);
        *convert_result = NULL;
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_measure_type(const char *measure)
{
    if (strlen(measure) != 1) {
        WR_PRINT_ERROR("The measure type len should be 1.\n");
        return CM_ERROR;
    }
    if ((measure[0] != 'B' && measure[0] != 'K' && measure[0] != 'M' && measure[0] != 'G' && measure[0] != 'T')) {
        WR_PRINT_ERROR("measure_type error.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t cmd_check_inst_id(const char *inst_str)
{
    uint32 inst_id;
    status_t ret = cm_str2uint32(inst_str, &inst_id);
    if (ret != CM_SUCCESS) {
        WR_PRINT_ERROR("The value of inst_id is invalid.\n");
        return CM_ERROR;
    }
    if (inst_id < WR_MIN_INST_ID || inst_id >= WR_MAX_INST_ID) {
        WR_PRINT_ERROR("The value of inst_id should be in [%u, %u).\n", WR_MIN_INST_ID, WR_MAX_INST_ID);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_inq_type(const char *inq_type)
{
    if (strcmp(inq_type, "lun") != 0 && strcmp(inq_type, "reg") != 0) {
        WR_PRINT_ERROR("The show type should be [lun|reg].\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_offset(const char *offset_str)
{
    int64 offset;
    status_t ret = cm_str2bigint(offset_str, &offset);
    if (ret != CM_SUCCESS) {
        WR_PRINT_ERROR("The value of offset is invalid.\n");
        return CM_ERROR;
    }
    if (offset < 0 || offset % WR_DISK_UNIT_SIZE != 0) {
        WR_PRINT_ERROR("offset must be >= 0 and be align %d.\n", WR_DISK_UNIT_SIZE);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_format(const char *format)
{
    uint32 len = strlen(format);
    if (len == 0) {
        WR_PRINT_ERROR("The value of format is invalid.\n");
        return CM_ERROR;
    }
    if (format[0] != 'c' && format[0] != 'h' && format[0] != 'u' && format[0] != 'l' && format[0] != 's' &&
        format[0] != 'x') {
        WR_PRINT_ERROR("The name's letter of format should be [c|h|u|l|s|x].\n");
        return CM_ERROR;
    }
    if (format[1] != 0x00) {
        WR_PRINT_ERROR("The name's letter of format should be [c|h|u|l|s|x].\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_read_size(const char *read_size_str)
{
    int32 read_size;
    status_t ret = cm_str2int(read_size_str, &read_size);
    if (ret != CM_SUCCESS) {
        WR_PRINT_ERROR("The value of read_size is invalid.\n");
        return CM_ERROR;
    }

    if (read_size < 0) {
        WR_PRINT_ERROR("The read_size should >= 0.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_cfg_name(const char *name)
{
    uint32 len = strlen(name);
    for (uint32 i = 0; i < len; i++) {
        if (!isalpha((int)name[i]) && !isdigit((int)name[i]) && name[i] != '-' && name[i] != '_') {
            WR_PRINT_ERROR("The name's letter should be [alpha|digit|-|_].\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_cfg_value(const char *value)
{
    uint32 len = strlen(value);
    if (len < 0) {
        WR_PRINT_ERROR("The value is invalid.\n");
        return CM_ERROR;
    }
    for (uint32 i = 0; i < len; i++) {
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

static inline void help_param_uds(void)
{
    (void)printf("-U/--UDS <UDS:socket_domain>, [optional], the unix socket path of wrserver, "
                 "default value is UDS:$WR_HOME/.wr_unix_d_socket\n");
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

static void cmd_print_no_path_err()
{
    WR_PRINT_ERROR("Need to input arg [-p|--path] or cd to a path.\n");
}

static wr_args_t cmd_mkdir_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, wr_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'d', "dir_name", CM_TRUE, CM_TRUE, wr_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static wr_args_set_t cmd_mkdir_args_set = {
    cmd_mkdir_args,
    sizeof(cmd_mkdir_args) / sizeof(wr_args_t),
    NULL,
};

static void mkdir_help(const char *prog_name, int print_flag)
{
    if (g_run_interatively) {
        (void)printf("\nUsage:%s mkdir <-d dir_name> [-p path] [-U UDS:socket_domain]\n", prog_name);
    } else {
        (void)printf("\nUsage:%s mkdir <-p path> <-d dir_name> [-U UDS:socket_domain]\n", prog_name);
    }
    (void)printf("[client command]make dir\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, [optional], the name need to add dir\n");
    } else {
        (void)printf("-p/--path <path>, <required>, the name need to add dir\n");
    }
    (void)printf("-d/--dir_name <dir_name>, <required>, the dir name need to be added to path\n");
    help_param_uds();
}

static status_t mkdir_proc(void)
{
    const char *path = cmd_mkdir_args[WR_ARG_IDX_0].input_args;
    if (cmd_mkdir_args[WR_ARG_IDX_0].convert_result != NULL) {
        path = cmd_mkdir_args[WR_ARG_IDX_0].convert_result;
    }
    if (path == NULL) {
        if (g_cur_path[0] == '\0') {
            cmd_print_no_path_err();
            return CM_ERROR;
        }
        path = g_cur_path;
    }

    const char *dir_name = cmd_mkdir_args[WR_ARG_IDX_1].input_args;
    const char *uds_path = cmd_mkdir_args[WR_ARG_IDX_2].input_args;
    wr_conn_t *conn = wr_get_connection_opt(uds_path);
    if (conn == NULL) {
        return CM_ERROR;
    }
    status_t status = wr_vfs_create_impl(conn, dir_name);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to make dir, path is %s, dir name is %s.\n", path, dir_name);
    } else {
        WR_PRINT_INF("Succeed to make dir, path is %s, dir name is %s.\n", path, dir_name);
    }
    return status;
}

#define WR_CMD_TOUCH_ARGS_PATH 0
#define WR_CMD_TOUCH_ARGS_UDS 1
#define WR_CMD_TOUCH_ARGS_FLAG 2
static wr_args_t cmd_touch_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, wr_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
    {'f', "flag", CM_FALSE, CM_TRUE, cmd_check_flag, NULL, NULL, 0, NULL, NULL, 0},
};
static wr_args_set_t cmd_touch_args_set = {
    cmd_touch_args,
    sizeof(cmd_touch_args) / sizeof(wr_args_t),
    NULL,
};

static void touch_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s touch <-p path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]create file\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, <required>, file need to touch\n");
    } else {
        (void)printf("-p/--path <path>, <required>, file need to touch, path must begin with '+'\n");
    }
    (void)printf("-f/--flag <flag>, [optional], file flag need to set\n");
    help_param_uds();
}

static status_t touch_proc(void)
{
    const char *path = cmd_touch_args[WR_CMD_TOUCH_ARGS_PATH].input_args;
    if (cmd_touch_args[WR_CMD_TOUCH_ARGS_PATH].convert_result != NULL) {
        path = cmd_touch_args[WR_CMD_TOUCH_ARGS_PATH].convert_result;
    }

    const char *input_args = cmd_touch_args[WR_CMD_TOUCH_ARGS_UDS].input_args;
    wr_conn_t *conn = wr_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    int64 flag = 0;
    if (cmd_touch_args[WR_CMD_TOUCH_ARGS_FLAG].inputed) {
        status_t status = cm_str2bigint(cmd_touch_args[WR_CMD_TOUCH_ARGS_FLAG].input_args, &flag);
        if (status != CM_SUCCESS) {
            return status;
        }
    }

    status_t status = (status_t)wr_create_file_impl(conn, path, (int32)flag);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to create file, name is %s.\n", path);
    } else {
        WR_PRINT_INF("Succeed to create file, name is %s.\n", path);
    }
    return status;
}

static wr_args_t cmd_ts_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

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
    help_param_uds();
}

static status_t ts_proc(void)
{
    status_t status = CM_SUCCESS;
    const char *input_args = cmd_ts_args[WR_ARG_IDX_0].input_args;
    wr_conn_t *conn = wr_get_connection_opt(input_args);
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

#define WR_CMD_LS_PATH_IDX 0
#define WR_CMD_LS_MEASURE_IDX 1
#define WR_CMD_LS_UDS_IDX 2
#define WR_CMD_LS_MIN_INITED_SIZE 3

static wr_args_t cmd_ls_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, wr_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'m', "measure_type", CM_FALSE, CM_TRUE, cmd_check_measure_type, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
    {'w', "min_inited_size", CM_FALSE, CM_TRUE, cmd_check_zero_or_one, NULL, NULL, 0, NULL, NULL, 0},
};

static wr_args_set_t cmd_ls_args_set = {
    cmd_ls_args,
    sizeof(cmd_ls_args) / sizeof(wr_args_t),
    NULL,
};

static void ls_help(const char *prog_name, int print_flag)
{
    if (g_run_interatively) {
        (void)printf(
            "\nUsage:%s ls [-p path] [-m measure_type] [-w min_inited_size] [-U UDS:socket_domain]\n", prog_name);
    } else {
        (void)printf(
            "\nUsage:%s ls <-p path> [-m measure_type] [-w min_inited_size] [-U UDS:socket_domain]\n", prog_name);
    }
    (void)printf("[client command]Show information of volume group and disk usage space\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, [optional], show information for it\n");
    } else {
        (void)printf("-p/--path <path>, <required>, show information for it\n");
    }
    (void)printf("-m/--measure_type <measure_type>, [optional], B show size by Byte, K show size by kB ,"
                 "M show size by MB ,G show size by GB,  T show size by TB, default show size by Byte\n");
    (void)printf("-w/ --min_inited_size <min_inited_size>, [optional], "
                 "1 show min_inited_size, 0 not show min_inited_size\n");
    help_param_uds();
}

static status_t ls_get_parameter(const char **path, const char **measure, uint32 *show_min_inited_size)
{
    *path = cmd_ls_args[WR_CMD_LS_PATH_IDX].input_args;
    if (cmd_ls_args[WR_CMD_LS_PATH_IDX].convert_result != NULL) {
        *path = cmd_ls_args[WR_CMD_LS_PATH_IDX].convert_result;
    }
    if (*path == NULL) {
        if (g_cur_path[0] == '\0') {
            cmd_print_no_path_err();
            return CM_ERROR;
        }
        *path = g_cur_path;
    }

    char *ls_measure_input_args = cmd_ls_args[WR_CMD_LS_MEASURE_IDX].input_args;
    *measure = ls_measure_input_args != NULL ? ls_measure_input_args : WR_DEFAULT_MEASURE;
    if (cmd_ls_args[WR_CMD_LS_MIN_INITED_SIZE].input_args == NULL) {
        *show_min_inited_size = 0;
    } else {
        status_t status = cm_str2uint32(cmd_ls_args[WR_CMD_LS_MIN_INITED_SIZE].input_args, show_min_inited_size);
        if (status != CM_SUCCESS) {
            WR_PRINT_ERROR("The value of zero_or_one is invalid.\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static void wr_ls_show_base(uint32 show_min_inited_size)
{
    if (show_min_inited_size == 0) {
        (void)printf(
            "%-5s%-20s%-14s %-14s %-64s%-5s%-5s\n", "type", "time", "size", "written_size", "name", "fid", "node_id");
    } else {
        (void)printf("%-5s%-20s%-14s %-14s %-14s %-64s%-5s%-5s\n", "type", "time", "size", "written_size",
            "min_inited_size", "name", "fid", "node_id");
    }
}

static status_t wr_ls_print_node_info(gft_node_t *node, const char *measure, uint32 show_min_inited_size)
{
    char time[512] = {0};
    if (cm_time2str(node->create_time, "YYYY-MM-DD HH24:mi:ss", time, sizeof(time)) != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to get create time of node %s.\n", node->name);
        return CM_ERROR;
    }
    double size = (double)node->size;
    if (node->size != 0) {
        size = wr_convert_size(size, measure);
    }
    char type = wr_ls_print_flag[node->type];
    double written_size = (double)node->written_size;
    if (node->written_size != 0) {
        written_size = wr_convert_size(written_size, measure);
    }
    if (show_min_inited_size == 0) {
        (void)printf("%-5c%-20s%-14.05f %-14.05f %-64s%-5llu%-5llu\n", type, time, size, written_size, node->name,
            node->fid, WR_ID_TO_U64(node->id));
    } else {
        double min_inited_size = node->min_inited_size;
        if (node->min_inited_size != 0) {
            min_inited_size = wr_convert_size((double)node->min_inited_size, measure);
        }
        (void)printf("%-5c%-20s%-14.05f %-14.05f %-14.05f %-64s%-5llu%-5llu\n", type, time, size, written_size,
            min_inited_size, node->name, node->fid, WR_ID_TO_U64(node->id));
    }

    return CM_SUCCESS;
}

static status_t wr_ls_print_file(wr_conn_t *conn, const char *path, const char *measure, uint32 show_min_inited_size)
{
    gft_node_t *node = NULL;
    wr_check_dir_output_t output_info = {&node, NULL, NULL, CM_FALSE};
    WR_RETURN_IF_ERROR(wr_check_dir(conn->session, path, GFT_FILE, &output_info, CM_FALSE));
    if (node == NULL) {
        LOG_DEBUG_INF("Failed to find path %s with the file type", path);
        return CM_ERROR;
    }
    wr_ls_show_base(show_min_inited_size);
    return wr_ls_print_node_info(node, measure, show_min_inited_size);
}

static status_t ls_proc_core(wr_conn_t *conn, const char *path, const char *measure, uint32 show_min_inited_size)
{
    gft_node_t *node = NULL;
    wr_vg_info_item_t *vg_item = NULL;
    char name[WR_MAX_NAME_LEN] = {0};
    status_t status = CM_ERROR;
    bool32 exist = false;
    gft_item_type_t type;
    WR_RETURN_IFERR2(
        wr_find_vg_by_dir(path, name, &vg_item), WR_PRINT_ERROR("Failed to find vg when ls the path %s.\n", path));
    WR_RETURN_IFERR2(
        wr_exist_impl(conn, path, &exist, &type), WR_PRINT_ERROR("Failed to check the path %s exists.\n", path));
    if (!exist) {
        WR_PRINT_ERROR("The path %s is not exist.\n", path);
        return CM_ERROR;
    }
    if (type == GFT_FILE) {
        WR_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session);
        status = wr_ls_print_file(conn, path, measure, show_min_inited_size);
        WR_UNLOCK_VG_META_S(vg_item, conn->session);
        if (status == CM_SUCCESS) {
            WR_PRINT_INF("Succeed to ls file info %s.\n", path);
            return status;
        }
    }
    wr_vfs_t *dir = wr_open_dir_impl(conn, path, CM_TRUE);
    if (dir == NULL) {
        WR_PRINT_ERROR("Failed to open dir %s.\n", path);
        return CM_ERROR;
    }
    wr_ls_show_base(show_min_inited_size);
    while ((node = wr_read_dir_impl(conn, dir, CM_TRUE)) != NULL) {
        status = wr_ls_print_node_info(node, measure, show_min_inited_size);
        if (status != CM_SUCCESS) {
            (void)wr_close_dir_impl(conn, dir);
            return CM_ERROR;
        }
    }
    (void)wr_close_dir_impl(conn, dir);
    WR_PRINT_INF("Succeed to ls dir info %s.\n", path);
    return CM_SUCCESS;
}

static status_t ls_proc(void)
{
    const char *path = NULL;
    const char *measure = NULL;
    uint32 show_min_inited_size = 0;
    status_t status = ls_get_parameter(&path, &measure, &show_min_inited_size);
    if (status != CM_SUCCESS) {
        return status;
    }
    const char *input_args = cmd_ls_args[WR_CMD_LS_UDS_IDX].input_args;
    wr_conn_t *conn = wr_get_connection_opt(input_args);
    if (conn == NULL) {
        WR_PRINT_ERROR("Failed to get uds connection.\n");
        return CM_ERROR;
    }
    status = ls_proc_core(conn, path, measure, show_min_inited_size);
    return status;
}

static wr_args_t cmd_rm_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, wr_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static wr_args_set_t cmd_rm_args_set = {
    cmd_rm_args,
    sizeof(cmd_rm_args) / sizeof(wr_args_t),
    NULL,
};

static void rm_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rm <-p path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]remove device\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, <required>, device path\n");
    } else {
        (void)printf("-p/--path <path>, <required>, device path, must begin with '+'\n");
    }
    help_param_uds();
}

static status_t rm_proc(void)
{
    const char *path = cmd_rm_args[WR_ARG_IDX_0].input_args;
    if (cmd_rm_args[WR_ARG_IDX_0].convert_result != NULL) {
        path = cmd_rm_args[WR_ARG_IDX_0].convert_result;
    }
    status_t status = CM_SUCCESS;
    const char *input_args = cmd_rm_args[WR_ARG_IDX_1].input_args;
    wr_conn_t *conn = wr_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status = wr_remove_file_impl(conn, path);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to remove device %s.\n", path);
    } else {
        WR_PRINT_INF("Succeed to remove device %s.\n", path);
    }
    return status;
}

static wr_args_t cmd_rmdir_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, wr_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'r', "recursive", CM_FALSE, CM_FALSE, NULL, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static wr_args_set_t cmd_rmdir_args_set = {
    cmd_rmdir_args,
    sizeof(cmd_rmdir_args) / sizeof(wr_args_t),
    NULL,
};

static void rmdir_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rmdir <-p path> [-r] [-U UDS:socket_domain path]\n", prog_name);
    (void)printf("[client command] remove dir or with it's contents recursively\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, the name need to remove\n");
    (void)printf("-r/--recursive  [optional], remove dir and it's contents recursively\n");
    help_param_uds();
}

static status_t rmdir_proc(void)
{
    const char *path = cmd_rmdir_args[WR_ARG_IDX_0].input_args;
    if (cmd_rmdir_args[WR_ARG_IDX_0].convert_result != NULL) {
        path = cmd_rmdir_args[WR_ARG_IDX_0].convert_result;
    }

    status_t status = CM_SUCCESS;
    const char *input_args = cmd_rmdir_args[WR_ARG_IDX_2].input_args;
    wr_conn_t *conn = wr_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status = wr_vfs_delete_impl(conn, path);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to rm dir, path is %s.\n", path);
    } else {
        WR_PRINT_INF("Succeed to rm dir, path is %s.\n", path);
    }
    return status;
}

static wr_args_t cmd_inq_args[] = {
    {'t', "inq_type", CM_TRUE, CM_TRUE, cmd_check_inq_type, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "WR_HOME", CM_FALSE, CM_TRUE, cmd_check_wr_home, cmd_check_convert_wr_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static wr_args_set_t cmd_inq_args_set = {
    cmd_inq_args,
    sizeof(cmd_inq_args) / sizeof(wr_args_t),
    NULL,
};

static void inq_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s inq <-t inq_type> [-D WR_HOME]\n", prog_name);
    (void)printf("[raid command] inquiry LUN information or reservations\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-t/--type <inq_type>, <required>, the type need to inquiry, values [lun|reg]"
                 "lun :inquiry LUN information, reg:inquiry reservations\n");
    help_param_wrhome();
}

static status_t inq_proc(void)
{
    return CM_SUCCESS;
}

static wr_args_t cmd_inq_req_args[] = {
    {'i', "inst_id", CM_TRUE, CM_TRUE, cmd_check_inst_id, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "WR_HOME", CM_FALSE, CM_TRUE, cmd_check_wr_home, cmd_check_convert_wr_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static wr_args_set_t cmd_inq_req_args_set = {
    cmd_inq_req_args,
    sizeof(cmd_inq_req_args) / sizeof(wr_args_t),
    NULL,
};

static void inq_reg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s inq_reg <-i inst_id> [-D WR_HOME]\n", prog_name);
    (void)printf("[raid command]check whether the node is registered\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-i/--inst_id <inst_id>, <required>, the id of the host need to reg\n");
    help_param_wrhome();
}

static status_t inq_reg_proc(void)
{
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

static wr_args_t cmd_kickh_args[] = {
    {'i', "inst_id", CM_TRUE, CM_TRUE, cmd_check_inst_id, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "WR_HOME", CM_FALSE, CM_TRUE, cmd_check_wr_home, cmd_check_convert_wr_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static wr_args_set_t cmd_kickh_args_set = {
    cmd_kickh_args,
    sizeof(cmd_kickh_args) / sizeof(wr_args_t),
    NULL,
};

static void kickh_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s kickh <-i inst_id> [-D WR_HOME]\n", prog_name);
    (void)printf("[client command] kick off the host from the array\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-i/--inst_id <inst_id>, <required>, the id of the host need to kick off\n");
    help_param_wrhome();
}

static status_t kickh_proc(void)
{
    return CM_SUCCESS;
}

static wr_args_t cmd_reghl_args[] = {
    {'D', "WR_HOME", CM_FALSE, CM_TRUE, cmd_check_wr_home, cmd_check_convert_wr_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static wr_args_set_t cmd_reghl_args_set = {
    cmd_reghl_args,
    sizeof(cmd_reghl_args) / sizeof(wr_args_t),
    NULL,
};

static void reghl_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s reghl [-D WR_HOME]\n", prog_name);
    (void)printf("[manage command] register host to array\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    help_param_wrhome();
}

static status_t reghl_proc(void)
{
    return CM_SUCCESS;
}

static wr_args_t cmd_unreghl_args[] = {
    {'t', "type", CM_FALSE, CM_TRUE, NULL, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "WR_HOME", CM_FALSE, CM_TRUE, cmd_check_wr_home, cmd_check_convert_wr_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static wr_args_set_t cmd_unreghl_args_set = {
    cmd_unreghl_args,
    sizeof(cmd_unreghl_args) / sizeof(wr_args_t),
    NULL,
};

static void unreghl_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s unreghl [-t type] [-D WR_HOME]\n", prog_name);
    (void)printf("[manage command] unregister host from array\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-t/--type <type>, [optional], value is int, 0 without lock, otherwise with lock\n");
    help_param_wrhome();
}

static status_t unreghl_proc(void)
{
    return CM_SUCCESS;
}

#define WR_CMD_PRINT_BLOCK_SIZE SIZE_K(4)
#define WR_PRINT_RETURN_BYTES 16
#define WR_PRINT_FMT_NUM 6

static wr_args_t cmd_examine_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, wr_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'o', "offset", CM_TRUE, CM_TRUE, cmd_check_offset, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "format", CM_TRUE, CM_TRUE, cmd_check_format, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "read_size", CM_FALSE, CM_TRUE, cmd_check_read_size, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "WR_HOME", CM_FALSE, CM_TRUE, cmd_check_wr_home, cmd_check_convert_wr_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static wr_args_set_t cmd_examine_args_set = {
    cmd_examine_args,
    sizeof(cmd_examine_args) / sizeof(wr_args_t),
    NULL,
};

static void examine_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s examine <-p path> <-o offset> <-f format> [-s read_size] [-D WR_HOME] "
                 "[-U UDS:socket_domain]\n",
        prog_name);
    (void)printf("[client command] display wr file content\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, <required>, device path\n");
    } else {
        (void)printf("-p/--path <path>, <required>, device path, must begin with '+'\n");
    }
    (void)printf("-o/--offset <offset>, <required>, the offset of the file need to examine\n");
    (void)printf("-f/--format <format>, <required>, value is[c|h|u|l|s|x]\n"
                 "c char, h unsigned short, u unsigned int, l unsigned long, s string, x hex.\n");
    (void)printf("-s/--read_size <WR_HOME>, [optional], size to show, default value is 512byte\n");
    help_param_wrhome();
    help_param_uds();
}

static inline char escape_char(char c)
{
    if (c > 0x1f && c < 0x7f) {
        return c;
    } else {
        return '.';
    }
}

static status_t print_buf(const char *o_buf, uint32 buf_size, char format, int64 offset, uint32 read_size)
{
    uint32 pos = 0;
    int16 index = -1;
    wr_print_help_t print_help[] = {{'c', sizeof(char)}, {'h', sizeof(uint16)}, {'u', sizeof(uint32)},
        {'l', sizeof(uint64)}, {'s', sizeof(char)}, {'x', sizeof(uint8)}};

    for (int16 i = 0; i < WR_PRINT_FMT_NUM; i++) {
        if (format == print_help[i].fmt) {
            index = i;
            break;
        }
    }
    if (index == -1) {
        LOG_DEBUG_ERR("Invalid format.\n");
        return CM_ERROR;
    }

    while ((pos + print_help[index].bytes) <= read_size) {
        if (pos % WR_PRINT_RETURN_BYTES == 0) {
            (void)printf("%016llx ", (uint64)offset + pos);
        }

        if (format == 'x') {
            (void)printf("%02x", *(uint8 *)(o_buf + pos));
        } else if (format == 'c') {
            (void)printf("%c", escape_char(*(o_buf + pos)));
        } else if (format == 'h') {
            (void)printf("%5hu", *(uint16 *)(o_buf + pos));
        } else if (format == 'u') {
            (void)printf("%10u", *(uint32 *)(o_buf + pos));
        } else if (format == 'l') {
            (void)printf("%20llu", *(uint64 *)(o_buf + pos));
        } else if (format == 's') {
            (void)printf("%c", escape_char(*(o_buf + pos)));
        }

        pos += print_help[index].bytes;

        if (pos % WR_PRINT_RETURN_BYTES == 0) {
            (void)printf("\n");
        } else {
            if (format != 's') {
                (void)printf(" ");
            }
        }
    }
    if ((read_size / print_help[index].bytes) % (WR_PRINT_RETURN_BYTES / print_help[index].bytes) != 0) {
        (void)printf("\n");
    }

    return CM_SUCCESS;
}

static status_t get_examine_parameter(char **path, int64 *offset, char *fmt)
{
    *path = cmd_examine_args[WR_ARG_IDX_0].input_args;
    if (cmd_examine_args[WR_ARG_IDX_0].convert_result != NULL) {
        *path = cmd_examine_args[WR_ARG_IDX_0].convert_result;
    }

    status_t status = cm_str2bigint(cmd_examine_args[WR_ARG_IDX_1].input_args, offset);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Invalid offset.\n");
        return CM_ERROR;
    }
    *fmt = cmd_examine_args[WR_ARG_IDX_2].input_args[0];
    return CM_SUCCESS;
}

static status_t get_examine_opt_parameter(int32 *read_size)
{
    *read_size = WR_DISK_UNIT_SIZE;
    if (cmd_examine_args[WR_ARG_IDX_3].input_args != NULL) {
        *read_size = (int32)strtol(cmd_examine_args[WR_ARG_IDX_3].input_args, NULL, CM_DEFAULT_DIGIT_RADIX);
    }
    if (*read_size <= 0) {
        LOG_DEBUG_ERR("Invalid read_size.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t print_file_proc(wr_conn_t *conn, int32 handle, int64 offset, int32 read_size, char fmt)
{
#ifndef WIN32
    char o_buf[WR_CMD_PRINT_BLOCK_SIZE] __attribute__((__aligned__(WR_DISK_UNIT_SIZE)));
#else
    char o_buf[WR_CMD_PRINT_BLOCK_SIZE];
#endif
    int32 read_cnt = 0;
    int32 cur_read_size;
    int64 row_aligned_offset = (offset / WR_PRINT_RETURN_BYTES) * WR_PRINT_RETURN_BYTES;
    int64 print_offset = row_aligned_offset - (offset / WR_DISK_UNIT_SIZE) * WR_DISK_UNIT_SIZE;
    int64 offset_shift = offset - row_aligned_offset;

    while (read_cnt < read_size) {
        if (cur_read_size > read_size - read_cnt) {
            cur_read_size = read_size - read_cnt;
        }
        char *buf = o_buf + print_offset;
        uint32 buf_size = (uint32)(sizeof(o_buf) - print_offset);

        CM_RETURN_IFERR_EX(print_buf(buf, buf_size, fmt, offset - offset_shift, (uint32)(cur_read_size - print_offset)),
            LOG_DEBUG_ERR("Failed to print.\n"));

        read_cnt += cur_read_size;
        offset += (cur_read_size - print_offset) - offset_shift;
        print_offset = 0;
        offset_shift = 0;
    }
    return CM_SUCCESS;
}

static int64 adjust_readsize(int64 offset, int32 *read_size, int64 file_size)
{
    int64 unit_aligned_offset = (offset / WR_DISK_UNIT_SIZE) * WR_DISK_UNIT_SIZE;
    int64 new_read_size = *read_size;

    if (unit_aligned_offset != offset) {
        new_read_size += (offset - unit_aligned_offset);
    }

    if (new_read_size + unit_aligned_offset > file_size) {
        if (file_size < unit_aligned_offset) {
            new_read_size = 0;
        } else {
            new_read_size = file_size - unit_aligned_offset;
        }
    }

    if (new_read_size < 0) {
        new_read_size = 0;
    }

    if (new_read_size > INT32_MAX) {
        new_read_size = INT32_MAX;
    }

    *read_size = (int32)new_read_size;
    return unit_aligned_offset;
}

static status_t examine_proc(void)
{
    char *path;
    int64 offset;
    char format;
    int32 read_size = WR_DISK_UNIT_SIZE;
    wr_config_t *inst_cfg = wr_get_g_inst_cfg();

    status_t status = get_examine_parameter(&path, &offset, &format);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = get_examine_opt_parameter(&read_size);
    if (status != CM_SUCCESS) {
        return status;
    }

    char *input_args = cmd_examine_args[WR_ARG_IDX_4].input_args;
    status = set_config_info(input_args, inst_cfg);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to load config info!\n");
        return status;
    }

    wr_conn_t *conn = wr_get_connection_opt(input_args);
    if (conn == NULL) {
        WR_PRINT_ERROR("Failed to get uds connection.\n");
        return CM_ERROR;
    }

    int32 handle;
    status = wr_open_file_impl(conn, path, O_RDONLY, &handle);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to open dir, path is %s.\n", path);
        return CM_ERROR;
    }

    int64 file_size = wr_seek_file_impl(conn, handle, 0, SEEK_END);
    if (file_size == CM_INVALID_INT64) {
        WR_PRINT_ERROR("Failed to seek file %s size.\n", path);
        (void)wr_close_file_impl(conn, handle);
        return CM_ERROR;
    }
    int64 unit_aligned_offset = adjust_readsize(offset, &read_size, file_size);

    unit_aligned_offset = wr_seek_file_impl(conn, handle, unit_aligned_offset, SEEK_SET);
    if (unit_aligned_offset == -1) {
        WR_PRINT_ERROR("Failed to seek file %s.\n", path);
        (void)wr_close_file_impl(conn, handle);
        return CM_ERROR;
    }
    (void)printf("filename is %s, offset is %lld.\n", path, offset);
    status = print_file_proc(conn, handle, offset, read_size, format);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to print file %s.\n", path);
    }
    (void)wr_close_file_impl(conn, handle);
    return status;
}

int32 wr_open_memory_file(const char *file_name)
{
    int32 file_fd;
    uint32 mode = O_RDONLY | O_BINARY;
    char realpath[CM_FILE_NAME_BUFFER_SIZE] = {0};
    if (realpath_file(file_name, realpath, CM_FILE_NAME_BUFFER_SIZE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to find realpath file %s", file_name);
        return -1;
    }
    if (!cm_file_exist(realpath)) {
        WR_THROW_ERROR_EX(ERR_WR_FILE_NOT_EXIST, "%s not exist, please check", realpath);
        return -1;
    }
    if (cm_open_file(realpath, mode, &file_fd) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to open memory file %s", realpath);
        return -1;
    }
    return file_fd;
}

static status_t wr_load_buffer_pool_from_file(int32 file_fd, ga_pool_id_e pool_id)
{
    uint64 total_size;
    int32 read_size;
    status_t status = cm_read_file(file_fd, &total_size, sizeof(uint64), &read_size);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read pool size."));
    char *pool_ft_block_buf = cm_malloc(total_size);
    if (pool_ft_block_buf == NULL) {
        LOG_DEBUG_ERR("Failed to malloc ft block pool.");
        return CM_ERROR;
    }
    ga_pool_t *pool = &g_app_pools[GA_POOL_IDX((uint32)pool_id)];
    if (pool == NULL) {
        CM_FREE_PTR(pool_ft_block_buf);
        LOG_DEBUG_ERR("Failed to get ga pool from file.");
        return CM_ERROR;
    }
    status = cm_read_file(file_fd, pool_ft_block_buf, (int32)total_size, &read_size);
    if (status != CM_SUCCESS) {
        CM_FREE_PTR(pool_ft_block_buf);
        LOG_DEBUG_ERR("Failed to read file.");
        return CM_ERROR;
    }
    pool->addr = pool_ft_block_buf;
    pool->ctrl = (ga_pool_ctrl_t *)pool->addr;
    pool->def = pool->ctrl->def;
    uint32 object_cost = pool->ctrl->def.object_size + (uint32)sizeof(ga_object_map_t);
    uint64 ex_pool_size = (uint64)object_cost * pool->ctrl->def.object_count;
    pool->capacity = CM_ALIGN_512((uint32)sizeof(ga_pool_ctrl_t)) + CM_ALIGN_512(ex_pool_size);
    if (pool->ctrl->ex_count > GA_MAX_EXTENDED_POOLS) {
        LOG_RUN_ERR("Invalid pool info[id=%u]: ex_count is %u, larger than maximum %u", pool_id, pool->ctrl->ex_count,
            GA_MAX_EXTENDED_POOLS);
        return CM_ERROR;
    }
    for (uint32 i = 0; i < pool->ctrl->ex_count; i++) {
        pool->ex_pool_addr[i] = pool_ft_block_buf + pool->capacity + i * ex_pool_size;
    }
    return CM_SUCCESS;
}

static status_t wr_load_wr_ctrl_from_file(int32 file_fd, wr_vg_info_item_t *vg_item)
{
    int32 read_size;
    vg_item->wr_ctrl = cm_malloc(sizeof(wr_ctrl_t));
    if (vg_item->wr_ctrl == NULL) {
        LOG_DEBUG_ERR("Malloc wr_ctrl failed.\n");
        return CM_ERROR;
    }
    status_t status = cm_read_file(file_fd, vg_item->wr_ctrl, sizeof(wr_ctrl_t), &read_size);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read file."));
    return CM_SUCCESS;
}

static status_t wr_load_buffer_cache_from_file(int32 file_fd, wr_vg_info_item_t *vg_item, int64 *offset)
{
    int32 read_size;
    char *buffer = NULL;
    uint64 dir_size = WR_MAX_SEGMENT_NUM * (uint32)sizeof(uint32_t);
    buffer = cm_malloc(sizeof(shm_hashmap_t) + dir_size);
    if (buffer == NULL) {
        LOG_DEBUG_ERR("Malloc failed.\n");
        return CM_ERROR;
    }
    status_t status = cm_read_file(file_fd, buffer, sizeof(shm_hashmap_t), &read_size);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read file."));
    uint32 id = vg_item->id;
    uint32 shm_key = cm_shm_key_of(SHM_TYPE_HASH, id);
    vg_item->buffer_cache = (shm_hashmap_t *)buffer;
    vg_item->buffer_cache->hash_ctrl.dirs = cm_trans_shm_offset_from_malloc(shm_key, buffer + sizeof(shm_hashmap_t));
    vg_item->buffer_cache->shm_id = id;
    vg_item->buffer_cache->hash_ctrl.func = cm_oamap_uint64_compare;
    status = cm_read_file(file_fd, buffer + sizeof(shm_hashmap_t), (int32)dir_size, &read_size);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read file."));
    *offset = *offset + (int64)sizeof(shm_hashmap_t) + (int64)dir_size;
    return CM_SUCCESS;
}

static status_t wr_get_group_num(int32 file_fd, int64 *offset, uint32 *group_num)
{
    int32 read_size = 0;
    status_t status = cm_read_file(file_fd, group_num, sizeof(uint32), &read_size);
    WR_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read group num."));
    *offset += (int64)sizeof(uint32);
    return CM_SUCCESS;
}

bool32 wr_check_software_version(int32 file_fd, int64 *offset)
{
    int32 read_size = 0;
    uint32 software_version;
    status_t status = cm_read_file(file_fd, &software_version, sizeof(uint32), &read_size);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to read software_version");
        return CM_FALSE;
    }
    if (software_version > (uint32)WR_SOFTWARE_VERSION) {
        LOG_DEBUG_ERR("The file software_version which is %u is bigger than the actural software_version which is %u.",
            software_version, (uint32)WR_SOFTWARE_VERSION);
        return CM_FALSE;
    }
    *offset += (int64)sizeof(uint32);
    return CM_TRUE;
}

static wr_args_t cmd_rename_args[] = {
    {'o', "old_name", CM_TRUE, CM_TRUE, wr_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
    {'n', "new_name", CM_TRUE, CM_TRUE, wr_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static wr_args_set_t cmd_rename_args_set = {
    cmd_rename_args,
    sizeof(cmd_rename_args) / sizeof(wr_args_t),
    NULL,
};

static void rename_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rename <-o old_name> <-n new_name> [-U UDS:socket_domain]\n", prog_name);
    if (g_run_interatively) {
        (void)printf("[client command] rename file\n");
    } else {
        (void)printf("[client command] rename file, all file name must begin with '+'\n");
    }
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-o/--old_name <old_name>, <required>, the old file name\n");
    (void)printf("-n/--new_name <new_name>, <required>, the new file name\n");
    help_param_uds();
}

static status_t rename_proc(void)
{
    const char *old_name = cmd_rename_args[WR_ARG_IDX_0].input_args;
    if (cmd_rename_args[WR_ARG_IDX_0].convert_result != NULL) {
        old_name = cmd_rename_args[WR_ARG_IDX_0].convert_result;
    }

    const char *new_name = cmd_rename_args[WR_ARG_IDX_1].input_args;
    if (cmd_rename_args[WR_ARG_IDX_1].convert_result != NULL) {
        new_name = cmd_rename_args[WR_ARG_IDX_1].convert_result;
    }

    status_t status = CM_SUCCESS;
    const char *input_args = cmd_rename_args[WR_ARG_IDX_2].input_args;
    wr_conn_t *conn = wr_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status = wr_rename_file_impl(conn, old_name, new_name);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to rename file, old name is %s, new name is %s.\n", old_name, new_name);
    } else {
        WR_PRINT_INF("Succeed to rename file, old name is %s, new name is %s.\n", old_name, new_name);
    }
    return status;
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

static status_t wr_save_random_file(const uchar *value, int32 value_len)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    char dir_name[CM_FILE_NAME_BUFFER_SIZE];
    int32 handle;
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
    status = cm_encrypt_pwd((uchar *)plain, (uint32)strlen(plain), &cipher);
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
    status = cm_base64_encode((uchar *)&cipher, (uint32)sizeof(cipher_t), buf, &buf_len);
    if (status != CM_SUCCESS) {
        WR_PRINT_RUN_ERROR("[ENCRYPT]Failed to encrypt password when encode.\n");
        return CM_ERROR;
    }
    (void)printf("Cipher: \t\t%s\n", buf);
    (void)fflush(stdout);
    LOG_RUN_INF("[ENCRYPT]Succeed to print cipher, length is %u.\n", (uint32)strlen(buf));
    return CM_SUCCESS;
}

static wr_args_t cmd_setcfg_args[] = {
    {'n', "name", CM_TRUE, CM_TRUE, cmd_check_cfg_name, NULL, NULL, 0, NULL, NULL, 0},
    {'v', "value", CM_TRUE, CM_TRUE, cmd_check_cfg_value, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "scope", CM_FALSE, CM_TRUE, cmd_check_cfg_scope, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static wr_args_set_t cmd_setcfg_args_set = {
    cmd_setcfg_args,
    sizeof(cmd_setcfg_args) / sizeof(wr_args_t),
    NULL,
};

static void setcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s setcfg <-n name> <-v value> [-s scope] [-U UDS:socket_domain]\n", prog_name);
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
    help_param_uds();
}

static status_t setcfg_proc(void)
{
    char *name = cmd_setcfg_args[WR_ARG_IDX_0].input_args;
    char *value = cmd_setcfg_args[WR_ARG_IDX_1].input_args;
    char *scope =
        cmd_setcfg_args[WR_ARG_IDX_2].input_args != NULL ? cmd_setcfg_args[WR_ARG_IDX_2].input_args : "both";

    const char *input_args = cmd_setcfg_args[WR_ARG_IDX_3].input_args;
    wr_conn_t *conn = wr_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t status = wr_setcfg_impl(conn, name, value, scope);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to set cfg, name is %s, value is %s.\n", name, value);
    } else {
        WR_PRINT_INF("Succeed to set cfg, name is %s, value is %s.\n", name, value);
    }
    return status;
}

static wr_args_t cmd_getcfg_args[] = {
    {'n', "name", CM_TRUE, CM_TRUE, cmd_check_cfg_name, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static wr_args_set_t cmd_getcfg_args_set = {
    cmd_getcfg_args,
    sizeof(cmd_getcfg_args) / sizeof(wr_args_t),
    NULL,
};

static void getcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s getcfg <-n name> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] get config value by name\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    (void)printf("-n/--name <name>, <required>, the config name to set\n");
    help_param_uds();
}

static status_t getcfg_proc(void)
{
    char *name = cmd_getcfg_args[WR_ARG_IDX_0].input_args;
    const char *input_args = cmd_getcfg_args[WR_CMD_TOUCH_ARGS_UDS].input_args;
    wr_conn_t *conn = wr_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }
    char value[WR_PARAM_BUFFER_SIZE] = {0};
    status_t status = wr_getcfg_impl(conn, name, value, WR_PARAM_BUFFER_SIZE);
    if (status != CM_SUCCESS) {
        if (strlen(value) != 0 && cm_str_equal_ins(name, "SSL_PWD_CIPHERTEXT")) {
            LOG_DEBUG_ERR("Failed to get cfg, name is %s, value is ***.\n", name);
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
    return status;
}

static wr_args_t cmd_getstatus_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static wr_args_set_t cmd_getstatus_args_set = {
    cmd_getstatus_args,
    sizeof(cmd_getstatus_args) / sizeof(wr_args_t),
    NULL,
};

static void getstatus_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s getstatus [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] get wr server status\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static status_t getstatus_proc(void)
{
    const char *input_args = cmd_getstatus_args[WR_ARG_IDX_0].input_args;
    wr_conn_t *conn = wr_get_connection_opt(input_args);
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
    return status;
}

static wr_args_t cmd_stopwr_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static wr_args_set_t cmd_stopwr_args_set = {
    cmd_stopwr_args,
    sizeof(cmd_stopwr_args) / sizeof(wr_args_t),
    NULL,
};

static void stopwr_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s stopwr [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] stop wr server\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static status_t stopwr_proc(void)
{
    const char *input_args = cmd_stopwr_args[WR_ARG_IDX_0].input_args;
    wr_conn_t *conn = wr_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t status = wr_stop_server_impl(conn);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to stop server.\n");
    } else {
        WR_PRINT_INF("Succeed to stop server.\n");
    }
    wr_conn_opt_exit();
    return status;
}

#define WR_CMD_TRUNCATE_ARGS_PATH 0
#define WR_CMD_TRUNCATE_ARGS_LENGTH 1
#define WR_CMD_TRUNCATE_ARGS_UDS 2

static wr_args_t cmd_truncate_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, wr_cmd_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'l', "length", CM_TRUE, CM_TRUE, cmd_check_length, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static wr_args_set_t cmd_truncate_args_set = {
    cmd_truncate_args,
    sizeof(cmd_truncate_args) / sizeof(wr_args_t),
    NULL,
};

static void truncate_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s truncate <-p path> <-l length> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]truncate file to length\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, <required>, file need to truncate\n");
    } else {
        (void)printf("-p/--path <path>, <required>, file need to truncate, path must begin with '+'\n");
    }
    (void)printf("-l/--length <length>, <required>, length need to truncate\n");
    help_param_uds();
}

static status_t truncate_proc(void)
{
    const char *path = cmd_truncate_args[WR_CMD_TRUNCATE_ARGS_PATH].input_args;
    if (cmd_truncate_args[WR_CMD_TRUNCATE_ARGS_PATH].convert_result != NULL) {
        path = cmd_truncate_args[WR_CMD_TRUNCATE_ARGS_PATH].convert_result;
    }

    int64 length;
    status_t status = cm_str2bigint(cmd_truncate_args[WR_CMD_TRUNCATE_ARGS_LENGTH].input_args, &length);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR(
            "length:%s is not a valid int64.\n", cmd_truncate_args[WR_CMD_TRUNCATE_ARGS_LENGTH].input_args);
        return status;
    }

    const char *input_args = cmd_truncate_args[WR_CMD_TRUNCATE_ARGS_UDS].input_args;
    wr_conn_t *conn = wr_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    int handle;
    status = (status_t)wr_open_file_impl(conn, path, O_RDWR, &handle);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to truncate file, name is %s.\n", path);
        return status;
    }

    status = (status_t)wr_truncate_impl(conn, handle, length);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("Failed to truncate file, name is %s.\n", path);
        (void)wr_close_file_impl(conn, handle);
        return status;
    }
    WR_PRINT_INF("Success to truncate file, name is %s.\n", path);

    (void)wr_close_file_impl(conn, handle);
    return status;
}

// clang-format off
wr_admin_cmd_t g_wr_admin_cmd[] = {
    {"mkdir", mkdir_help, mkdir_proc, &cmd_mkdir_args_set, true},
    {"touch", touch_help, touch_proc, &cmd_touch_args_set, true},
    {"ts", ts_help, ts_proc, &cmd_ts_args_set, false},
    {"ls", ls_help, ls_proc, &cmd_ls_args_set, false},
    {"rm", rm_help, rm_proc, &cmd_rm_args_set, true},
    {"rmdir", rmdir_help, rmdir_proc, &cmd_rmdir_args_set, true},
    {"inq", inq_help, inq_proc, &cmd_inq_args_set, false},
    {"inq_reg", inq_reg_help, inq_reg_proc, &cmd_inq_req_args_set, false},
    {"lscli", lscli_help, lscli_proc, &cmd_lscli_args_set, false},
    {"kickh", kickh_help, kickh_proc, &cmd_kickh_args_set, true},
    {"reghl", reghl_help, reghl_proc, &cmd_reghl_args_set, true},
    {"unreghl", unreghl_help, unreghl_proc, &cmd_unreghl_args_set, true},
    {"examine", examine_help, examine_proc, &cmd_examine_args_set, false},
    {"rename", rename_help, rename_proc, &cmd_rename_args_set, true},
    {"encrypt", encrypt_help, encrypt_proc, &cmd_encrypt_args_set, true},
    {"setcfg", setcfg_help, setcfg_proc, &cmd_setcfg_args_set, true},
    {"getcfg", getcfg_help, getcfg_proc, &cmd_getcfg_args_set, false},
    {"getstatus", getstatus_help, getstatus_proc, &cmd_getstatus_args_set, false},
    {"stopwr", stopwr_help, stopwr_proc, &cmd_stopwr_args_set, true},
    {"truncate", truncate_help, truncate_proc, &cmd_truncate_args_set, true}
};

void clean_cmd()
{
    wr_conn_opt_exit();
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
    if (!g_run_interatively) {
        (void)printf("Usage:%s -i/--interactive run wrcmd interatively\n", prog_name);
    }
    (void)printf("commands:\n");
    for (uint32 i = 0; i < sizeof(g_wr_admin_cmd) / sizeof(g_wr_admin_cmd[0]); ++i) {
        g_wr_admin_cmd[i].help(prog_name, help_type);
    }
    cmd_print_interactive_help(prog_name, help_type);
    (void)printf("\n\n");
}

static status_t execute_one_cmd(int argc, char **argv, uint32 cmd_idx)
{
    cmd_parse_init(g_wr_admin_cmd[cmd_idx].args_set->cmd_args, g_wr_admin_cmd[cmd_idx].args_set->args_size);
    if (cmd_parse_args(argc, argv, g_wr_admin_cmd[cmd_idx].args_set) != CM_SUCCESS) {
        int32 code;
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

static status_t wr_cmd_append_oper_log(char *log_buf, void *buf, uint32 *offset)
{
    uint32 len = (uint32)strlen(buf);
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
    uint32 offset = 0;

    if (!LOG_OPER_ON) {
        return;
    }

    WR_RETURN_DRIECT_IFERR(wr_cmd_append_oper_log(log_buf, "wrcmd", &offset));

    for (int i = 1; i < argc; i++) {
        WR_RETURN_DRIECT_IFERR(wr_cmd_append_oper_log(log_buf, " ", &offset));
        WR_RETURN_DRIECT_IFERR(wr_cmd_append_oper_log(log_buf, argv[i], &offset));
    }

    char result[WR_MAX_PATH_BUFFER_SIZE];
    int32 ret = snprintf_s(
        result, WR_MAX_PATH_BUFFER_SIZE, WR_MAX_PATH_BUFFER_SIZE - 1, ". execute result %d.", (int32)status);
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
    for (uint32 i = 0; i < sizeof(g_wr_admin_cmd) / sizeof(g_wr_admin_cmd[0]); ++i) {
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
    if (cm_str_equal(argv[1], "-i") || cm_str_equal(argv[1], "--interactive")) {
        g_run_interatively = CM_TRUE;
        return CM_TRUE;
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

int32 execute_help_cmd(int argc, char **argv, uint32_t *idx, bool8 *go_ahead)
{
    if (argc < CMD_ARGS_AT_LEAST) {
        if (!g_run_interatively) {
            (void)printf("wrcmd: no operation specified.\n");
            print_help_hint();
        }
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

status_t execute_cmd(int argc, char **argv, uint32 idx)
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
    uint32 idx = 0;
    bool8 go_ahead = CM_TRUE;
    bool8 is_interactive = cmd_check_run_interactive(argc, argv);
    if (!is_interactive) {
        int32 help_ret = execute_help_cmd(argc, argv, &idx, &go_ahead);
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

    do {
        if (g_run_interatively) {
            wr_cmd_run_interactively();
            ret = CM_SUCCESS;
            break;
        }
        cm_reset_error();
        ret = execute_cmd(argc, argv, idx);
    } while (0);

    clean_cmd();
    return ret;
}
