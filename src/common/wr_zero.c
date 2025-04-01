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
 * wr_zero.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_zero.c
 *
 * -------------------------------------------------------------------------
 */
#include "wr_zero.h"
#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#endif
#include "cm_log.h"

static int32 wr_zero_mmap_fd = 0;
static char *wr_zero_buf = NULL;
static uint32 wr_zero_buf_len = 0;

status_t wr_init_zero_buf()
{
    uint32 len = WR_DEFAULT_AU_SIZE;
    char *buf = NULL;
#ifndef WIN32
    int32 fd = open("/dev/zero", O_RDWR);
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
    wr_zero_mmap_fd = fd;
#else
    buf = (char *)_aligned_malloc(len, WR_DISK_UNIT_SIZE);
    if (buf == NULL) {
        LOG_RUN_ERR("Failed to alloc");
        return CM_ERROR;
    }
    (void)memset_s(buf, len, 0x00, len);
#endif
    wr_zero_buf = buf;
    wr_zero_buf_len = len;
    return CM_SUCCESS;
}

void wr_uninit_zero_buf()
{
#ifndef WIN32
    if (wr_zero_mmap_fd > 0) {
        (void)close(wr_zero_mmap_fd);
        wr_zero_mmap_fd = 0;
    }
#else
    if (wr_zero_buf != NULL) {
        free(wr_zero_buf);
    }
#endif
    wr_zero_buf_len = 0;
    wr_zero_buf = NULL;
}

char *wr_get_zero_buf()
{
    return wr_zero_buf;
}

uint32 wr_get_zero_buf_len()
{
    return wr_zero_buf_len;
}