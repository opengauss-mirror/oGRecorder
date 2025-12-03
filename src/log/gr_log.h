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
 * gr_log.h
 *
 *
 * IDENTIFICATION
 *    src/log/gr_log.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GR_LOG_H__
#define __GR_LOG_H__
#include "cm_log.h"
#include "cm_text.h"
#include "gr_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_gr_config gr_config_t;

#define GR_AUDIT_ALL 255

#define GR_AUDIT_MODIFY 0x00000001
#define GR_AUDIT_QUERY 0x00000002

#define LOG_MAX_FILE_SIZE SIZE_M(1)*256
#define AUDIT_MAX_FILE_SIZE SIZE_M(1)*256
#define LOG_FILE_PERMISSIONS 600
#define LOG_PATH_PERMISSIONS 700

typedef struct st_gr_log_def_t {
    log_type_t log_id;
    char log_filename[GR_MAX_NAME_LEN];
} gr_log_def_t;

typedef struct st_gr_audit_assist {
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
} gr_audit_assist_t;

typedef struct st_gr_audit_info {
    char *action;
    char resource[GR_MAX_AUDIT_PATH_LENGTH];
} gr_audit_info_t;

#define GR_LOG_DEBUG_OP(user_fmt_str, ...)              \
    do {                                                 \
        LOG_DEBUG_INF("[OP]" user_fmt_str, ##__VA_ARGS__); \
    } while (0)

static inline void gr_print_detail_error()
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
#define GR_PRINT_ERROR(fmt, ...)                                                    \
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

#define GR_PRINT_RUN_ERROR(fmt, ...)                                                \
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

#define GR_PRINT_INF(fmt, ...)            \
    do {                                   \
        (void)printf(fmt, ##__VA_ARGS__);  \
        (void)fflush(stdout);              \
        LOG_DEBUG_INF(fmt, ##__VA_ARGS__); \
    } while (0)

#define GR_THROW_ERROR(error_no, ...)                                                                                 \
    do {                                                                                                               \
        if (g_gr_error_desc[error_no] != NULL)                                                                        \
        {                                                                                                            \
            cm_reset_error();                                                                                         \
            cm_set_error((char *)__FILE_NAME__, (uint32_t)__LINE__, (cm_errno_t)error_no, g_gr_error_desc[error_no],    \
                ##__VA_ARGS__);                                                                                        \
        }                                                                                                            \
        else                                                                                                           \
        {                                                                                                            \
            cm_set_error((char *)__FILE_NAME__, (uint32_t)__LINE__, (cm_errno_t)error_no, g_error_desc[error_no],    \
                ##__VA_ARGS__);                                                                                        \
        }                                                                                                            \
    } while (0)

#define GR_THROW_ERROR_EX(error_no, format, ...)                                                           \
    do {                                                                                                    \
        cm_set_error((char *)__FILE_NAME__, (uint32_t)__LINE__, (cm_errno_t)error_no, format, ##__VA_ARGS__); \
    } while (0)

/*
 * warning id is composed of source + module + object + code
 * source -- DN(10)/CM(11)/OM(12)/DM(20)/GR(30)
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
typedef enum gr_warn_id {
    WARN_GR_SPACEUSAGE_ID = 3006060001,
} gr_warn_id_t;

typedef enum gr_warn_name {
    WARN_GR_SPACEUSAGE, /* gr vg space */
} gr_warn_name_t;

typedef enum { GR_VG_SPACE_ALARM_INIT, GR_VG_SPACE_ALARM_HWM, GR_VG_SPACE_ALARM_LWM} gr_alarm_type_e;

#define GR_ERROR_COUNT 3000
extern const char *g_gr_error_desc[GR_ERROR_COUNT];
extern char *g_gr_warn_desc[];
extern uint32_t g_gr_warn_id[];
status_t gr_init_loggers(gr_config_t *inst_cfg, gr_log_def_t *log_def, uint32_t log_def_count, char *name);
void sql_record_audit_log(void *sess, status_t status, uint8 cmd_type);
gr_log_def_t *gr_get_instance_log_def();
gr_log_def_t *gr_get_cmd_log_def();
uint32_t gr_get_instance_log_def_count();
uint32_t gr_get_cmd_log_def_count();


#ifdef __cplusplus
}
#endif
#endif
