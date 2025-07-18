#ifndef __WR_FILESYSTEM_H__
#define __WR_FILESYSTEM_H__

#include "wr_defs.h"
#include "cm_date.h"
#include "wr_file_def.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t wr_filesystem_mkdir(const char *name, mode_t mode);
status_t wr_filesystem_rmdir(const char *name, uint64 flag);
status_t wr_filesystem_opendir(const char *name, uint64_t *out_dir);
status_t wr_filesystem_closedir(uint64_t dir);
status_t wr_filesystem_touch(const char *name);
status_t wr_filesystem_rm(const char *name);
status_t wr_filesystem_pwrite(int handle, int64 offset, int64 size, const char *buf, int64 *rel_size);
status_t wr_filesystem_pread(int handle, int64 offset, int64 size, char *buf, int64 *rel_size);
status_t wr_filesystem_query_file_num(uint64_t dir, uint32_t *file_num);
status_t wr_filesystem_query_file_info(uint64_t dir, wr_file_item_t *file_items, uint32_t max_files, uint32_t *file_count, bool is_continue);
status_t wr_filesystem_open(const char *file_path, int flag, int *fd);
status_t wr_filesystem_close(int fd, int need_lock);
status_t wr_filesystem_truncate(int fd, int64 length);
status_t wr_filesystem_stat(const char *name, int64 *offset, int64 *size, wr_file_status_t *mode, time_t *atime);
status_t wr_filesystem_postpone(const char *file_path, const char *time);
status_t wr_filesystem_get_file_end_position(const char *file_path, off_t *end_position);

#ifdef __cplusplus
}
#endif

#endif
