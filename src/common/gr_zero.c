/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * gr_zero.c
 *
 *
 * IDENTIFICATION
 *    src/common/gr_zero.c
 *
 * -------------------------------------------------------------------------
 */
#include "gr_zero.h"
#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#endif
#include "cm_log.h"

static int32_t gr_zero_mmap_fd = 0;
static char *gr_zero_buf = NULL;
static uint32_t gr_zero_buf_len = 0;

status_t gr_init_zero_buf()
{
    uint32_t len = GR_DEFAULT_AU_SIZE;
    char *buf;
#ifndef WIN32
    int32_t fd = open("/dev/zero", O_RDWR);
    if (fd < 0) {
        LOG_RUN_ERR("Failed to open /dev/zero");
        return CM_ERROR;
    }

    buf = (char *)mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (buf == MAP_FAILED) {
        LOG_RUN_ERR("Failed to map /dev/zero, error code :%d", errno);
        (void)close(fd);
        return CM_ERROR;
    }
    gr_zero_mmap_fd = fd;
#else
    buf = (char *)_aligned_malloc(len, GR_DISK_UNIT_SIZE);
    if (buf == NULL) {
        LOG_RUN_ERR("Failed to alloc");
        return CM_ERROR;
    }
    (void)memset_s(buf, len, 0x00, len);
#endif
    gr_zero_buf = buf;
    gr_zero_buf_len = len;
    return CM_SUCCESS;
}

void gr_uninit_zero_buf()
{
#ifndef WIN32
    if (gr_zero_mmap_fd > 0) {
        (void)close(gr_zero_mmap_fd);
        gr_zero_mmap_fd = 0;
    }
#else
    if (gr_zero_buf != NULL) {
        free(gr_zero_buf);
    }
#endif
    gr_zero_buf_len = 0;
    gr_zero_buf = NULL;
}
