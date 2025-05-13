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
 * wr_log.h
 *
 *
 * IDENTIFICATION
 *    src/log/wr_log.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_LOG_H__
#define __WR_LOG_H__
#include "cm_log.h"
#include "cm_text.h"
#include "wr_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_wr_config wr_config_t;

#define WR_AUDIT_ALL 255

#define WR_AUDIT_MODIFY 0x00000001
#define WR_AUDIT_QUERY 0x00000002

typedef struct st_wr_log_def_t {
    log_type_t log_id;
    char log_filename[WR_MAX_NAME_LEN];
} wr_log_def_t;

typedef struct st_wr_audit_assist {
    char date[CM_MAX_TIME_STRLEN];
    char session_buf[CM_MAX_NUMBER_LEN];
    char return_code_buf[CM_MAX_NUMBER_LEN];
    char os_host[CM_HOST_NAME_BUFFER_SIZE];
    char db_user[CM_NAME_BUFFER_SIZE];

    text_t session_id;
    text_t return_code;

    int32_t sid;
    int32_t code;
    int32_t tz;
} wr_audit_assist_t;

typedef struct st_wr_audit_info {
    char *action;
    char resource[WR_MAX_AUDIT_PATH_LENGTH];
} wr_audit_info_t;

#define WR_LOG_DEBUG_OP(user_fmt_str, ...)              \
    do {                                                 \
        LOG_DEBUG_INF("[OP]" user_fmt_str, ##__VA_ARGS__); \
    } while (0)

static inline void wr_print_detail_error()
{
    int32_t errcode_print;
    const char *errmsg_print = NULL;
    cm_get_error(&errcode_print, &errmsg_print);
    if (errcode_print != 0) {
        (void)printf(" detail reason [%d] : %s\n", errcode_print, errmsg_print);
        (void)fflush(stdout);
    }
    cm_reset_error();
}
#define WR_PRINT_ERROR(fmt, ...)                                                    \
    do {                                                                             \
        (void)printf(fmt, ##__VA_ARGS__);                                            \
        LOG_DEBUG_ERR(fmt, ##__VA_ARGS__);                                           \
        int32_t errcode_print;                                                         \
        const char *errmsg_print = NULL;                                             \
        cm_get_error(&errcode_print, &errmsg_print);                                 \
        if (errcode_print != 0) {                                                    \
            (void)printf(" detail reason [%d] : %s\n", errcode_print, errmsg_print); \
            (void)fflush(stdout);                                                    \
        }                                                                            \
        cm_reset_error();                                                            \
    } while (0)

#define WR_PRINT_RUN_ERROR(fmt, ...)                                                \
    do {                                                                             \
        (void)printf(fmt, ##__VA_ARGS__);                                            \
        LOG_RUN_ERR(fmt, ##__VA_ARGS__);                                             \
        int32_t errcode_print;                                                         \
        const char *errmsg_print = NULL;                                             \
        cm_get_error(&errcode_print, &errmsg_print);                                 \
        if (errcode_print != 0) {                                                    \
            LOG_RUN_ERR(" detail reason [%d] : %s", errcode_print, errmsg_print);    \
            (void)printf(" detail reason [%d] : %s\n", errcode_print, errmsg_print); \
            (void)fflush(stdout);                                                    \
        }                                                                            \
        cm_reset_error();                                                            \
    } while (0)

#define WR_PRINT_INF(fmt, ...)            \
    do {                                   \
        (void)printf(fmt, ##__VA_ARGS__);  \
        (void)fflush(stdout);              \
        LOG_DEBUG_INF(fmt, ##__VA_ARGS__); \
    } while (0)

#define WR_THROW_ERROR(error_no, ...)                                                                                 \
    do {                                                                                                               \
        if (g_wr_error_desc[error_no] != NULL)                                                                        \
            cm_set_error((char *)__FILE_NAME__, (uint32_t)__LINE__, (cm_errno_t)error_no, g_wr_error_desc[error_no],    \
                ##__VA_ARGS__);                                                                                        \
        else                                                                                                           \
            cm_set_error(                                                                                              \
                (char *)__FILE_NAME__, (uint32_t)__LINE__, (cm_errno_t)error_no, g_error_desc[error_no], ##__VA_ARGS__); \
    } while (0)

#define WR_THROW_ERROR_EX(error_no, format, ...)                                                           \
    do {                                                                                                    \
        cm_set_error((char *)__FILE_NAME__, (uint32_t)__LINE__, (cm_errno_t)error_no, format, ##__VA_ARGS__); \
    } while (0)

/*
 * warning id is composed of source + module + object + code
 * source -- DN(10)/CM(11)/OM(12)/DM(20)/WR(30)
 * module -- File(01)/Transaction(02)/HA(03)/Log(04)/Buffer(05)/Space(06)/Server(07)
 * object -- Host Resource(01)/Run Environment(02)/Cluster Status(03)/
 *           Instance Status(04)/Database Status(05)/Database Object(06)
 * code   -- 0001 and so on
 */
/*
 * one warn must modify  warn_id_t
 *                       warn_name_t
 *                       g_warn_id
 *                       g_warning_desc
 */
typedef enum wr_warn_id {
    WARN_WR_SPACEUSAGE_ID = 3006060001,
} wr_warn_id_t;

typedef enum wr_warn_name {
    WARN_WR_SPACEUSAGE, /* wr vg space */
} wr_warn_name_t;

typedef enum { WR_VG_SPACE_ALARM_INIT, WR_VG_SPACE_ALARM_HWM, WR_VG_SPACE_ALARM_LWM} wr_alarm_type_e;

#define WR_ERROR_COUNT 3000
extern const char *g_wr_error_desc[WR_ERROR_COUNT];
extern char *g_wr_warn_desc[];
extern uint32_t g_wr_warn_id[];
status_t wr_init_loggers(wr_config_t *inst_cfg, wr_log_def_t *log_def, uint32_t log_def_count, char *name);
void sql_record_audit_log(void *sess, status_t status, uint8 cmd_type);
wr_log_def_t *wr_get_instance_log_def();
wr_log_def_t *wr_get_cmd_log_def();
uint32_t wr_get_instance_log_def_count();
uint32_t wr_get_cmd_log_def_count();

char *wr_get_print_tab(uint8 level);

#ifdef __cplusplus
}
#endif
#endif
