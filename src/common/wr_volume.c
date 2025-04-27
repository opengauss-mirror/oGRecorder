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
 * wr_volume.c
 *
 *
 * IDENTIFICATION
 *    src/common/wr_volume.c
 *
 * -------------------------------------------------------------------------
 */
#include "wr_volume.h"
#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif  // !WIN32
#include "wr_file.h"
#include "wr_thv.h"

#ifdef __cplusplus
extern "C" {
#endif

uint64 g_log_offset = WR_INVALID_ID64;
#ifdef WIN32
int32 device_os_error_array[] = {
    EOPNOTSUPP, ETIMEDOUT, ENOSPC, ENOLINK, ENODATA, EILSEQ, ENOMEM, EBUSY, EAGAIN, ENODEV, EOVERFLOW, EIO};
};
#else
int32 device_os_error_array[] = {EOPNOTSUPP, ETIMEDOUT, ENOSPC, ENOLINK, EBADE, ENODATA, EILSEQ, ENOMEM, EBUSY, EAGAIN,
    ENODEV, EREMCHG, ETOOMANYREFS, EOVERFLOW, EIO};
#endif

bool32 wr_is_device_os_error(int32 os_err)
{
    uint8 size = (uint8)sizeof(device_os_error_array) / sizeof(device_os_error_array[0]);
    for (uint8 i = 0; i < size; i++) {
        if (os_err == device_os_error_array[i]) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static inline void wr_open_fail(const char *name)
{
    if (wr_is_device_os_error(cm_get_os_error())) {
        WR_THROW_ERROR(ERR_WR_VOLUME_SYSTEM_IO, name);
        LOG_RUN_ERR("[WR] ABORT OPEN VOLUME RAW, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
            strerror(cm_get_os_error()));
        cm_fync_logfile();
        wr_exit_error();
    } else {
        WR_THROW_ERROR(ERR_WR_VOLUME_OPEN, name, cm_get_os_error());
    }
}

static status_t wr_open_filehandle_raw(const char *name, int flags, volume_handle_t *fd, volume_handle_t *unaligned_fd)
{
    // O_RDWR | O_SYNC | O_DIRECT
    *fd = open(name, flags, 0);
    if (*fd == -1) {
        wr_open_fail(name);
        return CM_ERROR;
    }

    // O_RDWR | O_SYNC
    *unaligned_fd = open(name, WR_NOD_OPEN_FLAG, 0);
    if (*unaligned_fd == -1) {
        wr_open_fail(name);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t wr_open_volume_raw(const char *name, const char *code, int flags, wr_volume_t *volume)
{
    if (wr_open_filehandle_raw(name, flags, &volume->handle, &volume->unaligned_handle) != CM_SUCCESS) {
        return CM_ERROR;
    }
    errno_t ret = snprintf_s(volume->name, WR_MAX_VOLUME_PATH_LEN, WR_MAX_VOLUME_PATH_LEN - 1, "%s", name);
    WR_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    volume->name_p = volume->name;
    return CM_SUCCESS;
}

status_t wr_open_simple_volume_raw(const char *name, int flags, wr_simple_volume_t *volume)
{
    if (wr_open_filehandle_raw(name, flags, &volume->handle, &volume->unaligned_handle) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void wr_close_volume_raw(wr_volume_t *volume)
{
    int ret = close(volume->handle);
    if (ret != 0) {
        LOG_RUN_ERR("failed to close file with handle %d, error code %d", volume->handle, errno);
    }
    ret = close(volume->unaligned_handle);
    if (ret != 0) {
        LOG_RUN_ERR("failed to close file with unaligned_handle %d, error code %d", volume->unaligned_handle, errno);
    }

    if (memset_s(volume, sizeof(wr_volume_t), 0, sizeof(wr_volume_t)) != EOK) {
        cm_panic(0);
    }
    volume->handle = WR_INVALID_HANDLE;
    volume->unaligned_handle = WR_INVALID_HANDLE;
}

void wr_close_simple_volume_raw(wr_simple_volume_t *simple_volume)
{
    (void)close(simple_volume->handle);
    simple_volume->handle = WR_INVALID_HANDLE;
    (void)close(simple_volume->unaligned_handle);
    simple_volume->unaligned_handle = WR_INVALID_HANDLE;
}

uint64 wr_get_volume_size_raw(wr_volume_t *volume)
{
    int64 size = lseek64(volume->handle, 0, SEEK_END);
    if (size == -1) {
        WR_LOG_WITH_OS_MSG("failed to seek file with handle %d", volume->handle);
        if (wr_is_device_os_error(cm_get_os_error())) {
            WR_THROW_ERROR(ERR_WR_VOLUME_SYSTEM_IO, volume->name_p);
            LOG_RUN_ERR("[WR] ABORT GET VOLUME SIZE, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                strerror(cm_get_os_error()));
            cm_fync_logfile();
            wr_exit_error();
        } else {
            WR_THROW_ERROR(ERR_WR_VOLUME_SEEK, volume->name_p, volume->id, cm_get_os_error());
        }
        return WR_INVALID_64;
    }
    return (uint64)size;
}

static status_t wr_try_pread_volume_raw(wr_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *read_size)
{
    *read_size = (int32)pread(volume->handle, buffer, size, (off_t)offset);
    if (*read_size == -1) {
        if (wr_is_device_os_error(cm_get_os_error())) {
            WR_THROW_ERROR(ERR_WR_VOLUME_SYSTEM_IO, volume->name_p);
            LOG_RUN_ERR("[WR] ABORT PREAD VOLUME, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                strerror(cm_get_os_error()));
            cm_fync_logfile();
            wr_exit_error();
        } else {
            WR_THROW_ERROR(ERR_WR_VOLUME_READ, volume->name_p, volume->id, cm_get_os_error());
        }
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static int32 wr_try_pwrite_volume_raw(
    wr_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *written_size)
{
    bool8 aligned_pwrite =
        offset % WR_DISK_UNIT_SIZE == 0 && size % WR_DISK_UNIT_SIZE == 0 && (uint64)buffer % WR_DISK_UNIT_SIZE == 0;
    if (aligned_pwrite) {
        *written_size = (int32)pwrite(volume->handle, buffer, size, (off_t)offset);
        if (*written_size == -1) {
            if (wr_is_device_os_error(cm_get_os_error())) {
                WR_THROW_ERROR(ERR_WR_VOLUME_SYSTEM_IO, volume->name_p);
                LOG_RUN_ERR("[WR] ABORT ALIGNED PWRITE VOLUME, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                    strerror(cm_get_os_error()));
                cm_fync_logfile();
                wr_exit_error();
            } else {
                WR_THROW_ERROR(ERR_WR_VOLUME_WRITE, volume->name_p, volume->id, cm_get_os_error());
            }
            return CM_ERROR;
        }
    } else {
        *written_size = (int32)pwrite(volume->unaligned_handle, buffer, size, (off_t)offset);
        if (*written_size == -1) {
            if (wr_is_device_os_error(cm_get_os_error())) {
                WR_THROW_ERROR(ERR_WR_VOLUME_SYSTEM_IO, volume->name_p);
                LOG_RUN_ERR("[WR] ABORT UNALIGNED PWRITE VOLUME, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                    strerror(cm_get_os_error()));
                cm_fync_logfile();
                wr_exit_error();
            } else {
                WR_THROW_ERROR(ERR_WR_VOLUME_WRITE, volume->name_p, volume->id, cm_get_os_error());
            }
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

typedef struct wr_file_mgr {
    status_t (*open_volume)(const char *name, const char *code, int flags, wr_volume_t *volume);
    status_t (*open_simple_volume)(const char *name, int flags, wr_simple_volume_t *volume);
    void (*close_volume)(wr_volume_t *volume);
    void (*close_simple_volume)(wr_simple_volume_t *simple_volume);
    uint64 (*get_volume_size)(wr_volume_t *volume);
    status_t (*try_pread_volume)(wr_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *read_size);
    int32 (*try_pwrite_volume)(wr_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *written_size);
} file_mgr;

static const file_mgr file_mgr_funcs[] = {
    {wr_open_volume_raw, wr_open_simple_volume_raw, wr_close_volume_raw, wr_close_simple_volume_raw,
        wr_get_volume_size_raw, wr_try_pread_volume_raw, wr_try_pwrite_volume_raw}
};

wr_vg_device_Type_e parse_vg_open_type(const char *name)
{
    return WR_VOLUME_TYPE_RAW;
}

status_t wr_open_volume(const char *name, const char *code, int flags, wr_volume_t *volume)
{
    volume->vg_type = parse_vg_open_type(name);
    return (*(file_mgr_funcs[volume->vg_type].open_volume))(name, code, flags, volume);
}

status_t wr_open_simple_volume(const char *name, int flags, wr_simple_volume_t *volume)
{
    volume->vg_type = parse_vg_open_type(name);
    return (*(file_mgr_funcs[volume->vg_type].open_simple_volume))(name, flags, volume);
}

void wr_close_volume(wr_volume_t *volume)
{
    (*(file_mgr_funcs[volume->vg_type].close_volume))(volume);
}

void wr_close_simple_volume(wr_simple_volume_t *simple_volume)
{
    (*(file_mgr_funcs[simple_volume->vg_type].close_simple_volume))(simple_volume);
}

uint64 wr_get_volume_size(wr_volume_t *volume)
{
    return (*(file_mgr_funcs[volume->vg_type].get_volume_size))(volume);
}

static status_t wr_try_pread_volume(wr_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *read_size)
{
    return (*(file_mgr_funcs[volume->vg_type].try_pread_volume))(volume, offset, buffer, size, read_size);
}

static int32 wr_try_pwrite_volume(wr_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *written_size)
{
    return (*(file_mgr_funcs[volume->vg_type].try_pwrite_volume))(volume, offset, buffer, size, written_size);
}

status_t wr_read_volume(wr_volume_t *volume, int64 offset, void *buf, int32 size)
{
    status_t ret;
    int32 curr_size, total_size;
#ifdef WIN32
    if (wr_seek_volume(volume, offset) != CM_SUCCESS) {
        return CM_ERROR;
    }
#endif
    total_size = 0;

    do {
        curr_size = 0;
#ifdef WIN32
        ret = wr_try_read_volume(volume, (char *)buf + total_size, size - total_size, &curr_size);
#else
        ret =
            wr_try_pread_volume(volume, offset + total_size, (char *)buf + total_size, size - total_size, &curr_size);
#endif
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to read volume %s, begin:%d, volume id:%u, size:%d, offset:%lld, errmsg:%s.",
                volume->name_p, total_size, volume->id, size - total_size, offset, strerror(errno));
            return CM_ERROR;
        }

        if ((curr_size == 0) && (total_size < size)) {
            LOG_RUN_ERR("Read volume %s size error, begin:%d, volume id:%u, size:%d, offset:%lld.", volume->name_p,
                total_size, volume->id, size - total_size, offset);
            return CM_ERROR;
        }

        total_size += curr_size;
    } while (total_size < size);

    return CM_SUCCESS;
}

status_t wr_write_volume(wr_volume_t *volume, int64 offset, const void *buf, int32 size)
{
    status_t ret;
    int32 curr_size, total_size;
#ifdef WIN32
    if (wr_seek_volume(volume, offset) != CM_SUCCESS) {
        LOG_RUN_ERR("failed to seek volume %s , volume id:%u", volume->name_p, volume->id);
        return CM_ERROR;
    }
#endif
    total_size = 0;

    do {
#ifdef WIN32
        ret = wr_try_write_volume(volume, (char *)buf + total_size, size - total_size, &curr_size);
#else
        ret =
            wr_try_pwrite_volume(volume, offset + total_size, (char *)buf + total_size, size - total_size, &curr_size);
#endif
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to write volume %s, begin:%d, volume id:%u,size:%d, offset:%lld, errmsg:%s.",
                volume->name_p, total_size, volume->id, size - total_size, offset, strerror(errno));
            return CM_ERROR;
        }

        total_size += curr_size;
    } while (total_size < size);

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
