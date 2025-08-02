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
 * wr_args_parse.h
 *
 *
 * IDENTIFICATION
 *    src/common/wr_args_parse.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef WR_ARGS_PARSE_H_
#define WR_ARGS_PARSE_H_

#include "cm_base.h"
#include "wr_ctrl_def.h"

typedef status_t (*cmd_parser_check_args_t)(const char *input_args);
typedef status_t (*cmd_parser_convert_args_t)(const char *input_args, void **convert_result, int *convert_size);
typedef void (*cmd_parser_clean_convert_args_t)(char *convert_result, int convert_size);
typedef struct st_wr_args_t {
    char short_name;                     // args short name
    const char *long_name;               // args long name ,can be null
    int32_t required;                      // CM_TRUE required,  CM_FALSE optional
    int32_t required_args;                 // CM_TRUE required,  CM_FALSE not need
    cmd_parser_check_args_t check_args;  // if want to check input_args, set it, can be NULL
    cmd_parser_convert_args_t convert_args;
    cmd_parser_clean_convert_args_t clean_convert_args;
    int32_t inputed;     // CM_TRUE input-ed by user, CM_FALSE not input
    char *input_args;  // if required_args is CM_TRUE,  should get value from user
    void *convert_result;
    int32_t convert_result_size;
} wr_args_t;

typedef status_t (*cmd_parse_check_t)(wr_args_t *cmd_args_set, int set_size);
typedef struct st_wr_args_set_t {
    wr_args_t *cmd_args;
    int32_t args_size;
    cmd_parse_check_t args_check;
} wr_args_set_t;

typedef void (*wr_admin_help)(const char *prog_name, int print_flag);
typedef status_t (*wr_admin_cmd_proc)(void);
typedef struct st_wr_admin_cmd_t {
    char cmd[CM_MAX_NAME_LEN];
    wr_admin_help help;
    wr_admin_cmd_proc proc;
    wr_args_set_t *args_set;
    bool8 log_necessary;  // Logs are necessary for commands which write disks, and unnecessary for others.
} wr_admin_cmd_t;

typedef enum en_wr_help_type {
    WR_HELP_DETAIL = 0,
    WR_HELP_SIMPLE,
} wr_help_type;

#define WR_ARG_IDX_0 0
#define WR_ARG_IDX_1 1
#define WR_ARG_IDX_2 2
#define WR_ARG_IDX_3 3
#define WR_ARG_IDX_4 4
#define WR_ARG_IDX_5 5
#define WR_ARG_IDX_6 6
#define WR_ARG_IDX_7 7
#define WR_ARG_IDX_8 8
#define WR_ARG_IDX_9 9
#define WR_ARG_IDX_10 10
#define CMD_ARGS_AT_LEAST 2

status_t cmd_parse_args(int argc, char **argv, wr_args_set_t *args_set);
void cmd_parse_init(wr_args_t *cmd_args_set, int set_size);
void cmd_parse_clean(wr_args_t *cmd_args_set, int set_size);
status_t wr_load_local_server_config(wr_config_t *inst_cfg);
status_t wr_check_meta_type(const char *type);
status_t wr_check_meta_id(const char *intput);
status_t cmd_parse_check(wr_args_t *cmd_args_set, int set_size);
#endif