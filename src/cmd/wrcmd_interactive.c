/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * wrcmd_interactive.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/wrcmd_interactive.c
 *
 * -------------------------------------------------------------------------
 */

#include <locale.h>
#include "wrcmd_interactive.h"
#include "wr_malloc.h"
#include "wr_file.h"
#include "wr_interaction.h"
#include "wr_api_impl.h"
#include "wrcmd_conn_opt.h"

#ifndef WIN32
#include <termios.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <wchar.h>
#endif

typedef struct st_wr_cmd_history_list {
    uint32_t nbytes;
    uint32_t nwidths;
    char hist_buf[MAX_CMD_LEN];
} wr_cmd_history_list_t;

static wr_cmd_history_list_t g_hist_list[WR_CMD_MAX_HISTORY_SIZE + 1];

char g_cmd_buf[MAX_CMD_LEN];

bool8 g_run_interatively = CM_FALSE;

char g_cur_path[WR_FILE_PATH_MAX_LENGTH] = {0};

bool8 cmd_check_need_convert_path(const char *input_path, uint32_t *cur_path_len)
{
    if (!g_run_interatively) {
        return CM_FALSE;
    }
    if (input_path[0] == '+') {
        return CM_FALSE;
    }

    *cur_path_len = strlen(g_cur_path);
    if (*cur_path_len == 0) {
        return CM_FALSE;
    }

    return CM_TRUE;
}

status_t cmd_check_convert_path(const char *input_args, void **convert_result, int *convert_size)
{
    status_t ret;
    uint32_t input_path_len;
    uint32_t cur_path_len;
    char *convert_path;
    uint32_t convert_path_len;

    if (!cmd_check_need_convert_path(input_args, &cur_path_len)) {
        return CM_SUCCESS;
    }

    input_path_len = strlen(input_args);
    convert_path_len = cur_path_len + input_path_len + 2;

    *convert_result = cm_malloc(convert_path_len);
    if (*convert_result == NULL) {
        WR_PRINT_ERROR("Malloc failed.\n");
        return CM_ERROR;
    }
    convert_path = (char *)*convert_result;
    securec_check_ret(memcpy_s(convert_path, convert_path_len, g_cur_path, cur_path_len));
    convert_path[cur_path_len] = '/';
    securec_check_ret(
        memcpy_s(convert_path + cur_path_len + 1, convert_path_len - cur_path_len - 1, input_args, input_path_len));
    convert_path[convert_path_len - 1] = '\0';

    ret = wr_check_device_path(convert_path);
    if (ret != CM_SUCCESS) {
        free(*convert_result);
        return ret;
    }

    *convert_size = (int)convert_path_len;
    return CM_SUCCESS;
}

status_t wr_cmd_check_device_path(const char *path)
{
    uint32_t cur_path_len;

    if (cmd_check_need_convert_path(path, &cur_path_len)) {
        return CM_SUCCESS;
    }

    return wr_check_device_path(path);
}

void wr_cmd_exit_proc(int argc, char **args)
{
    if (argc != 2) {
        WR_PRINT_ERROR("args num %d error.\n", argc - 1);
        return;
    }

    exit(EXIT_SUCCESS);
}

status_t wr_cmd_check_path_exist(wr_conn_t *conn, char *path)
{
    bool32 exist = false;
    gft_item_type_t type;

    WR_RETURN_IFERR2(
        wr_exist_impl(conn, path, &exist, &type), WR_PRINT_ERROR("Failed to check the path %s exists.\n", path));
    if (!exist) {
        LOG_RUN_ERR("The path %s is not exist.\n", path);
        return CM_ERROR;
    }
    if (type != GFT_PATH) {
        LOG_RUN_ERR("%s is not a directory.\n", path);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t wr_cmd_check_path(char *path)
{
    status_t status = wr_check_device_path(path);
    if (status != CM_SUCCESS) {
        WR_PRINT_ERROR("check path error.\n");
        return status;
    }

    /* get connection from env of wr_home */
    wr_conn_t *conn = wr_get_connection_opt(NULL);
    if (conn == NULL) {
        WR_PRINT_ERROR("Failed to get uds connection.\n");
        return CM_ERROR;
    }

    status = wr_cmd_check_path_exist(conn, path);
    return status;
}

status_t wr_cmd_format_path(char *org_path, char *out_path_buf, uint32_t out_buf_len, uint32_t *out_path_len)
{
    char *sub_path;
    char *saved = NULL;
    uint32_t sub_path_len;
    uint32_t cur_len = 0;

    if (org_path == NULL || out_path_buf == NULL) {
        return CM_ERROR;
    }

    sub_path = strtok_r(org_path, "/", &saved);
    sub_path_len = strlen(sub_path);
    if (sub_path_len >= out_buf_len) {
        WR_PRINT_ERROR("path is too long.\n");
        return CM_ERROR;
    }
    securec_check_ret(memcpy_s(out_path_buf, out_buf_len, sub_path, sub_path_len));
    cur_len += sub_path_len;

    while (sub_path != NULL) {
        sub_path = strtok_r(NULL, "/", &saved);
        if (sub_path == NULL) {
            break;
        }
        sub_path_len = strlen(sub_path);
        if (cur_len + sub_path_len + 1 >= out_buf_len) {
            WR_PRINT_ERROR("path is too long.\n");
            return CM_ERROR;
        }
        out_path_buf[cur_len] = '/';
        cur_len += 1;
        securec_check_ret(memcpy_s(out_path_buf + cur_len, out_buf_len - cur_len, sub_path, sub_path_len));
        cur_len += sub_path_len;
    }

    out_path_buf[cur_len] = '\0';
    *out_path_len = cur_len;
    return CM_SUCCESS;
}

void wr_cmd_cd_proc(int argc, char **args)
{
    status_t ret;
    char *path;
    char *input_path = args[WR_ARG_IDX_2];
    char format_path[WR_FILE_PATH_MAX_LENGTH] = {0};
    char merged_path[WR_FILE_PATH_MAX_LENGTH] = {0};
    uint32_t path_len;
    uint32_t format_path_len;
    uint32_t cur_path_len = strlen(g_cur_path);

    if (argc != 3) {
        WR_PRINT_ERROR("args num %d error.\n", argc - 1);
        return;
    }

    if (input_path[0] == '/') {
        WR_PRINT_ERROR("path should not start with /\n");
        return;
    }

    ret = wr_cmd_format_path(input_path, format_path, WR_FILE_PATH_MAX_LENGTH, &format_path_len);
    if (ret != CM_SUCCESS) {
        return;
    }

    errno_t err = 0;
    if (input_path[0] == '+') {
        path = format_path;
        path_len = format_path_len;
    } else {
        if (format_path_len + cur_path_len + 1 >= WR_FILE_PATH_MAX_LENGTH) {
            WR_PRINT_ERROR("path is too long.\n");
            return;
        }

        err = memcpy_s(merged_path, WR_FILE_PATH_MAX_LENGTH, g_cur_path, cur_path_len);
        if (err != EOK) {
            WR_PRINT_ERROR("Error occured when copying current working directory, error code is %d.\n", err);
            return;
        }
        merged_path[cur_path_len] = '/';
        err = memcpy_s(
            merged_path + cur_path_len + 1, WR_FILE_PATH_MAX_LENGTH - cur_path_len - 1, format_path, format_path_len);
        if (err != EOK) {
            WR_PRINT_ERROR("Error occured when copying relative path error code is %d.\n", err);
            return;
        }
        path_len = cur_path_len + format_path_len + 1;
        merged_path[path_len] = '\0';
        path = merged_path;
    }

    ret = wr_cmd_check_path(path);
    if (ret != CM_SUCCESS) {
        return;
    }

    err = memcpy_s(g_cur_path, WR_FILE_PATH_MAX_LENGTH, path, path_len + 1);
    if (err != EOK) {
        WR_PRINT_ERROR("Error occured when copying new working directory, error code is %d.\n", err);
    }
}

void wr_cmd_pwd_proc(int argc, char **args)
{
    if (argc != 2) {
        WR_PRINT_ERROR("args num %d error.\n", argc - 1);
        return;
    }

    WR_PRINT_INF("%s\n", g_cur_path);
}

static void wr_cmd_exit_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s exit\n", prog_name);
    (void)printf("[client command] exit wrcmd\n");
}

static void wr_cmd_cd_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s cd <path>\n", prog_name);
    (void)printf("[client command] change the current directory to path\n");
    if (print_flag == WR_HELP_SIMPLE) {
        return;
    }
    (void)printf("path, <required>, the path to change to\n");
}

static void wr_cmd_pwd_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s pwd\n", prog_name);
    (void)printf("[client command] show current directory\n");
}

wr_interactive_cmd_t g_wr_interactive_cmd[] = {
    {"cd", wr_cmd_cd_help, wr_cmd_cd_proc},
    {"pwd", wr_cmd_pwd_help, wr_cmd_pwd_proc},
    {"exit", wr_cmd_exit_help, wr_cmd_exit_proc},
};

static bool32 get_interactive_cmd_idx(int argc, char **argv, uint32_t *idx)
{
    for (uint32_t i = 0; i < sizeof(g_wr_interactive_cmd) / sizeof(g_wr_interactive_cmd[0]); ++i) {
        if (strcmp(g_wr_interactive_cmd[i].cmd, argv[WR_ARG_IDX_1]) == 0) {
            *idx = i;
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static uint32_t wr_cmd_utf8_chr_widths(char *chr, uint32_t c_bytes)
{
    wchar_t wchr;
    uint32_t c_widths = 0;
    (void)mbtowc(&wchr, chr, c_bytes);
#ifndef WIN32
    c_widths = (uint32_t)wcwidth(wchr);
#endif
    return c_widths;
}

void wr_cmd_clean_line(uint32_t line_widths)
{
    uint32_t line_wid = line_widths;
    while (line_wid--) {
        wr_cmd_write(3, "\b \b");
    }
}

int32_t wr_utf8_chr_bytes(uint8 c, uint32_t *bytes)
{
    uint8 chr = c;
    // 1 byte character
    if (chr < WR_UTF8_MULTI_BYTES_MASK) {
        *bytes = 1;
        return CM_SUCCESS;
    }

    // 2-6 bytes character
    *bytes = 0;
    while (chr & WR_UTF8_MULTI_BYTES_MASK) {
        (*bytes)++;
        chr <<= 1;
    }

    // begin with 10xxxxxx is invalid
    if (*bytes >= 2 && *bytes <= 6) {
        return CM_SUCCESS;
    } else {
        *bytes = 1;
        return CM_ERROR;
    }
}

status_t wr_utf8_reverse_str_bytes(const char *str, uint32_t len, uint32_t *bytes)
{
    const char* cur_c = str;

    // 1 byte character
    if (CM_IS_ASCII(*cur_c)) {
        *bytes = 1;
        return CM_SUCCESS;
    }

    // 2-6 bytes character
    *bytes = 1;
    while ((*bytes < len) && IS_VALID_UTF8_CHAR(*cur_c)) {
        (*bytes)++;
        cur_c -= 1;
    }

    return (*bytes >= 2 && *bytes <= 6 && *bytes < len) ? CM_SUCCESS : CM_ERROR;
}

/* Calculate the position and total number of spaces used to space at the end of a line */
void wr_cmd_set_endspace(wr_cmd_history_list_t hist_list, uint32_t ws_col, uint32_t welcome_width,
                       uint32_t *spacenum, bool8 *endspace)
{
    uint32_t offset = 0;
    uint32_t c_bytes = 0;
    uint32_t c_widths = 0;
    uint32_t nwidths = 0;
    uint32_t space_num = 0;

    (void)memset_s(endspace, MAX_CMD_LEN, 0, MAX_CMD_LEN);
    while (offset < hist_list.nbytes) {
        (void)wr_utf8_chr_bytes(hist_list.hist_buf[offset], &c_bytes);
        c_widths = wr_cmd_utf8_chr_widths(hist_list.hist_buf + offset, c_bytes);
        offset += c_bytes;

        if (c_widths == 2 && (nwidths + space_num + welcome_width + 1) % ws_col == 0) {
            space_num++;
            endspace[(nwidths + space_num + welcome_width + 1) / ws_col] = CM_TRUE;
        }
        nwidths += c_widths;
    }
    *spacenum = space_num;
}

void wr_cmd_hist_turn_up(const int *hist_count, int *list_num, uint32_t *nbytes, uint32_t *nwidths, uint32_t ws_col,
                          uint32_t welcome_width, uint32_t *spacenum, bool8 *endspace, char *cmd_buf, uint32_t max_len)
{
    if (*list_num >= *hist_count) {
        return;
    }
    wr_cmd_clean_line(*nwidths + *spacenum);
    (*list_num)++;

    *nbytes = g_hist_list[*list_num].nbytes;
    *nwidths = g_hist_list[*list_num].nwidths;

    errno_t err = memcpy_s(cmd_buf, max_len, g_hist_list[*list_num].hist_buf, *nbytes);
    if (err != EOK) {
        WR_PRINT_ERROR("Error occured when copying historical command.\n");
        return;
    }
    wr_cmd_write(*nbytes, g_hist_list[*list_num].hist_buf);
    wr_cmd_write(2, " \b");
    wr_cmd_set_endspace(g_hist_list[*list_num], ws_col, welcome_width, spacenum, endspace);
}

void wr_cmd_hist_turn_down(int *list_num, uint32_t *nbytes, uint32_t *nwidths, uint32_t ws_col, uint32_t welcome_width,
                            uint32_t *spacenum, bool8 *endspace, char *cmd_buf, uint32_t max_len)
{
    if (*list_num <= 1) {
        return;
    }
    wr_cmd_clean_line(*nwidths + *spacenum);
    (*list_num)--;

    *nbytes = g_hist_list[*list_num].nbytes;
    *nwidths = g_hist_list[*list_num].nwidths;

    errno_t err = memcpy_s(cmd_buf, max_len, g_hist_list[*list_num].hist_buf, *nbytes);
    if (err != EOK) {
        WR_PRINT_ERROR("Error occured when copying historical command.\n");
        return;
    }
    wr_cmd_write(*nbytes, g_hist_list[*list_num].hist_buf);
    wr_cmd_write(2, " \b");
    wr_cmd_set_endspace(g_hist_list[*list_num], ws_col, welcome_width, spacenum, endspace);
}

void wr_cmd_push_history(uint32_t cmd_bytes, uint32_t cmd_width, int *hist_count, char *cmd_buf, uint32_t max_len)
{
    if (cmd_bytes == 0) {
        return;
    }

    if (*hist_count < WR_CMD_MAX_HISTORY_SIZE) {
        *hist_count += 1;
    }
    for (int i = *hist_count; i > 1; i--) {
        (void)memcpy_s(&g_hist_list[i], sizeof(wr_cmd_history_list_t),
                       &g_hist_list[i - 1], sizeof(wr_cmd_history_list_t));
    }
    errno_t err = memcpy_s(g_hist_list[1].hist_buf, MAX_CMD_LEN, cmd_buf, MAX_CMD_LEN);
    if (err != EOK) {
        WR_PRINT_ERROR("Error occured when copying historical command.\n");
        return;
    }
    g_hist_list[1].nbytes = cmd_bytes;
    g_hist_list[1].nwidths = cmd_width;
    return;
}

#ifndef WIN32
void wr_cmd_set_terminal(uint32_t *ws_col, struct termios *oldt)
{
    struct winsize size;
    status_t status = ioctl(STDIN_FILENO, TIOCGWINSZ, &size);
    const uint32_t DEFAULT_WS_COL = 80;
    /* set default ws_col when ioctl fails */
    *ws_col = (status != CM_SUCCESS) ? DEFAULT_WS_COL : size.ws_col;

    struct termios newt;
    (void)tcgetattr(STDIN_FILENO, oldt);
    errno_t err = memcpy_s(&newt, sizeof(newt), oldt, sizeof(newt));
    if (err != EOK) {
        WR_PRINT_ERROR("Error occured when copying termios.\n");
        return;
    }
    newt.c_lflag &= ~(ECHO | ICANON | ECHOE | ECHOK | ECHONL | ICRNL);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &newt); // Set terminal input echo off.
}
#endif

void wr_cmd_handle_backspace(char *cmd_buf, uint32_t *nbytes, uint32_t *nwidths, bool8 *endspace,
                              uint32_t *spacenum, uint32_t ws_col, uint32_t welcome_width)
{
    char chr[WR_UTF8_CHR_SIZE];
    uint32_t c_bytes = 0;
    uint32_t c_widths = 0;
    uint32_t tmp_nbytes = *nbytes;
    uint32_t tmp_nwidths = *nwidths;
    uint32_t tmp_spacenum = *spacenum;

    if (tmp_nbytes == 0) {
        return;
    }

    (void)wr_utf8_reverse_str_bytes(cmd_buf + tmp_nbytes - 1, tmp_nbytes, &c_bytes);
    tmp_nbytes -= c_bytes;
    errno_t err = memcpy_s(chr, WR_UTF8_CHR_SIZE, cmd_buf + tmp_nbytes, c_bytes);
    if (err != EOK) {
        WR_PRINT_ERROR("Error occured when copying command, error code is %d.\n", err);
        return;
    }

    c_widths = wr_cmd_utf8_chr_widths(chr, c_bytes);
    for (int i = c_widths; i > 0; i--) {
        wr_cmd_write(3, "\b \b");
    }
    tmp_nwidths -= c_widths;
    /* When there is a filled in space at the end of the line, one more space should be deleted. */
    if ((tmp_nwidths + tmp_spacenum + welcome_width) % ws_col == 0 && c_widths == 2 &&
        endspace[(tmp_nwidths + tmp_spacenum + welcome_width) / ws_col] == CM_TRUE) {
        endspace[(tmp_nwidths + tmp_spacenum + welcome_width) / ws_col] = CM_FALSE;
        tmp_spacenum--;
        wr_cmd_write(3, "\b \b");
    }

    *nbytes = tmp_nbytes;
    *nwidths = tmp_nwidths;
    *spacenum = tmp_spacenum;
}

void wr_cmd_handle_common_key(int32_t input_key_char, char *cmd_buf, uint32_t *nbytes, uint32_t *nwidths, bool8 *endspace,
                               uint32_t *spacenum, uint32_t ws_col, uint32_t welcome_width)
{
    int32_t key_char = input_key_char;
    char chr[WR_UTF8_CHR_SIZE];
    uint32_t c_bytes = 0;
    uint32_t c_widths = 0;
    uint32_t tmp_nbytes = *nbytes;
    uint32_t tmp_nwidths = *nwidths;
    uint32_t tmp_spacenum = *spacenum;

    (void)wr_utf8_chr_bytes((uint8)key_char, &c_bytes);
    if (tmp_nbytes + c_bytes > MAX_INPUT_LEN) {
        return;
    }
    (void)memset_s(chr, WR_UTF8_CHR_SIZE, key_char, 1);
    for (uint32_t i = 1; i < c_bytes; i++) {
        key_char = getchar();
        (void)memset_s(chr + i, WR_UTF8_CHR_SIZE - i, key_char, 1);
    }
    c_widths = wr_cmd_utf8_chr_widths(chr, c_bytes);
    /* If the char is invisible, skip */
    if (c_widths == -1) {
        return;
    }
    errno_t err = memcpy_s(cmd_buf + tmp_nbytes, MAX_CMD_LEN - tmp_nbytes, chr, c_bytes);
    if (err != EOK) {
        WR_PRINT_ERROR("Error occured when copying command error code is %d.\n", err);
        return;
    }
    tmp_nbytes += c_bytes;
    wr_cmd_write(c_bytes, chr);
    /* UNIX console standard output requires special handling when the cursor is at the end of the line.
       When the end of the line is exactly full of characters, the cursor needs to jump to the next line.
       When there is only one space at the end of the line and the next character is full width, a space
       needs to be filled in. */
    if (((tmp_nwidths + tmp_spacenum + welcome_width + 1) % ws_col == 0 && c_widths == 1) ||
        ((tmp_nwidths + tmp_spacenum + welcome_width + 2) % ws_col == 0 && c_widths == 2)) {
        wr_cmd_write(2, " \b");
    } else if ((tmp_nwidths + tmp_spacenum + welcome_width + 1) % ws_col == 0 && c_widths == 2) {
        tmp_spacenum++;
        endspace[(tmp_nwidths + tmp_spacenum + welcome_width + 1) / ws_col] = CM_TRUE;
    }
    tmp_nwidths += c_widths;

    *nbytes = tmp_nbytes;
    *nwidths = tmp_nwidths;
    *spacenum = tmp_spacenum;
}

bool8 wr_cmd_fgets(int *hist_count, int *list_num, uint32_t welcome_width, char *cmd_buf, uint32_t max_len)
{
    int32_t key_char = 0;
    int32_t direction_key = 0;
    uint32_t nbytes = 0;
    uint32_t nwidths = 0;
    uint32_t spacenum = 0; // Record the number of spaces filled at the end of the line.
    bool8 endspace[MAX_CMD_LEN] = {0}; // Record the line number with space at the end of the line.
    uint32_t ws_col = 0;

#ifndef WIN32
    struct termios oldt;
    wr_cmd_set_terminal(&ws_col, &oldt);
#endif

    while (key_char != CMD_KEY_ASCII_LF && key_char != CMD_KEY_ASCII_CR) {
        key_char = getchar();
        WR_RETURN_STATUS_IF_TRUE((key_char < 0), CM_TRUE);
        switch (key_char) {
            case CMD_KEY_ESCAPE:
                (void)getchar(); // '['
                direction_key = getchar();
                if (direction_key == CMD_KEY_UP) {
                    wr_cmd_hist_turn_up(hist_count, list_num, &nbytes, &nwidths, ws_col, welcome_width, &spacenum,
                                         endspace, cmd_buf, max_len);
                    continue;
                } else if (direction_key == CMD_KEY_DOWN) {
                    wr_cmd_hist_turn_down(list_num, &nbytes, &nwidths, ws_col, welcome_width, &spacenum, endspace,
                                           cmd_buf, max_len);
                    continue;
                } else if (direction_key == CMD_KEY_DEL) {
                    (void)getchar(); // '~'
                } else {
                    continue;
                }

            case CMD_KEY_ASCII_DEL:
            case CMD_KEY_ASCII_BS:
                wr_cmd_handle_backspace(cmd_buf, &nbytes, &nwidths, endspace, &spacenum, ws_col, welcome_width);
                continue;

            case CMD_KEY_ASCII_CR:
            case CMD_KEY_ASCII_LF:
                *list_num = 0;
                wr_cmd_write(1, "\n");
                continue;

            default:
                wr_cmd_handle_common_key(key_char, cmd_buf, &nbytes, &nwidths, endspace, &spacenum,
                                          ws_col, welcome_width);
                continue;
        }
    }

    wr_cmd_push_history(nbytes, nwidths, hist_count, cmd_buf, max_len);
    if (nbytes < max_len) {
        cmd_buf[nbytes] = '\0';
    }

#ifndef WIN32
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &oldt); /* Set terminal input echo on */
#endif
    return CM_FALSE;
}

uint32_t wr_cmd_print_welcome()
{
    bool8 isConnected = wr_get_connection_opt_status();
        uint32_t num = printf("wrcmd%s%s%s%s> ", isConnected ? "@connected" : "",
        strcmp(g_cur_path, "") == CM_SUCCESS ? "" : "(",
        strcmp(g_cur_path, "") == CM_SUCCESS ? "" : g_cur_path,
        strcmp(g_cur_path, "") == CM_SUCCESS ? "" : ")");
    fflush(stdout);
    return num;
}

bool8 wr_exe_interactive_cmd(int argc, char **args)
{
    uint32_t idx;

    if (argc < CMD_ARGS_AT_LEAST) {
        return CM_FALSE;
    }

    if (get_interactive_cmd_idx(argc, args, &idx)) {
        if (argc > WR_ARG_IDX_2 &&
            (strcmp(args[WR_ARG_IDX_2], "-h") == 0 || strcmp(args[WR_ARG_IDX_2], "--help") == 0)) {
            g_wr_interactive_cmd[idx].help(args[0], WR_HELP_DETAIL);
        } else {
            g_wr_interactive_cmd[idx].proc(argc, args);
        }
        return CM_FALSE;
    }

    return CM_TRUE;
}

int wr_cmd_parse_args(char *cmd_buf, char **args, uint32_t max_arg_num)
{
    char *tmpArg;
    char *saved = NULL;
    int argIdx = 1;

    args[0] = "";
    tmpArg = strtok_r(cmd_buf, " ", &saved);
    while (tmpArg != NULL && argIdx < WR_MAX_ARG_NUM) {
        args[argIdx] = tmpArg;
        argIdx++;
        tmpArg = strtok_r(NULL, " ", &saved);
    }

    return argIdx;
}

void cmd_print_interactive_help(char *prog_name, wr_help_type help_type)
{
    if (!g_run_interatively) {
        return;
    }

    for (uint32_t i = 0; i < sizeof(g_wr_interactive_cmd) / sizeof(g_wr_interactive_cmd[0]); ++i) {
        g_wr_interactive_cmd[i].help(prog_name, help_type);
    }
}

void wr_cmd_run_interactively()
{
    uint32_t welcome_width = 0;
    int hist_count = 0;
    int list_num = 0;
    char *args[WR_MAX_ARG_NUM] = {0};
    int argc;
    uint32_t cmd_idx;
    bool8 go_ahead;
    bool8 exit_cmd;
    setlocale(LC_CTYPE, "");

    while (!feof(stdin)) {
        welcome_width = wr_cmd_print_welcome();

        (void)memset_s(g_cmd_buf, MAX_CMD_LEN, 0, MAX_CMD_LEN);
        exit_cmd = wr_cmd_fgets(&hist_count, &list_num, welcome_width, g_cmd_buf, MAX_CMD_LEN);
        if (exit_cmd) {
            break;
        }
        argc = wr_cmd_parse_args(g_cmd_buf, args, WR_MAX_ARG_NUM);

        cm_reset_error();
        go_ahead = wr_exe_interactive_cmd(argc, args);
        if (!go_ahead) {
            continue;
        }

        execute_help_cmd(argc, args, &cmd_idx, &go_ahead);
        if (!go_ahead) {
            continue;
        }

        (void)execute_cmd(argc, args, cmd_idx);
    }
}
