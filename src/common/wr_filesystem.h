#ifndef __WR_FILESYSTEM_H__
#define __WR_FILESYSTEM_H__

#include "wr_defs.h"
#include "cm_date.h"
#include "wr_file_def.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t wr_filesystem_mkdir(const char *name, mode_t mode);
status_t wr_filesystem_rmdir(const char *name);
status_t wr_filesystem_touch(const char *name);
status_t wr_filesystem_rm(const char *name);
status_t wr_filesystem_write(int64_t handle, int64_t offset, int64_t size, const char *buf);
status_t wr_filesystem_pread(int64_t handle, int64_t offset, int64_t size, char *buf);
int wr_filesystem_open(const char *file_path);
int wr_filesystem_close(int fd);


#ifdef __cplusplus
}
#endif

#endif
