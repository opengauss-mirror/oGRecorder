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
 * wr_param_verify.h
 *
 *
 * IDENTIFICATION
 *    src/params/wr_param_verify.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __WR_PARAM_VERIFY_H__
#define __WR_PARAM_VERIFY_H__

#include "cm_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_wr_def {
    config_scope_t scope;
    char name[CM_NAME_BUFFER_SIZE];
    char value[CM_PARAM_BUFFER_SIZE];
} wr_def_t;

status_t wr_verify_log_level(void *lex, void *def);
status_t wr_notify_log_level(void *se, void *item, char *value);
status_t wr_verify_lock_file_path(char *path);
status_t wr_verify_log_file_dir_name(char *log_home);
status_t wr_verify_log_file_real_path(char *log_home);
status_t wr_verify_log_file_size(void *lex, void *def);
status_t wr_notify_log_file_size(void *se, void *item, char *value);
status_t wr_verify_log_backup_file_count(void *lex, void *def);
status_t wr_notify_log_backup_file_count(void *se, void *item, char *value);
status_t wr_verify_audit_backup_file_count(void *lex, void *def);
status_t wr_notify_audit_backup_file_count(void *se, void *item, char *value);
status_t wr_verify_audit_file_size(void *lex, void *def);
status_t wr_notify_audit_file_size(void *se, void *item, char *value);
status_t wr_verify_audit_level(void *lex, void *def);
status_t wr_notify_audit_level(void *se, void *item, char *value);
status_t wr_verify_delay_clean_interval(void *lex, void *def);
status_t wr_notify_delay_clean_interval(void *se, void *item, char *value);
status_t wr_verify_mes_wait_timeout(void *lex, void *def);
status_t wr_notify_mes_wait_timeout(void *se, void *item, char *value);

#ifdef __cplusplus
}
#endif
#endif
