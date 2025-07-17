#include "../fio.h"
#include "../optgroup.h"
#include "../log.h"

#include <errno.h>
#include <string.h>
#include "wr_api.h"
#include <fcntl.h>

// 已经在FIO 340版本验证
struct wr_data {
    wr_instance_handle inst;
    wr_vfs_handle vfs;
    wr_file_handle fh;
    char fname[256];
};

static int fio_wrio_init(struct thread_data *td)
{
    struct wr_data *wd = calloc(1, sizeof(*wd));
    if (!wd)
        return 1;
    td->io_ops_data = wd;
    wr_create_inst("127.0.0.1:19225", &wd->inst);
    wr_vfs_create(wd->inst, "fiofuzz", 0);
    wr_vfs_mount(wd->inst, "fiofuzz", &wd->vfs);
    return 0;
}

static int fio_wrio_open(struct thread_data *td, struct fio_file *f)
{
    struct wr_data *wd = td->io_ops_data;
    snprintf(wd->fname, sizeof(wd->fname), "%s", f->file_name);
    wr_file_create(wd->vfs, wd->fname, NULL);
    return wr_file_open(wd->vfs, wd->fname, O_RDWR | O_SYNC, &wd->fh);
}

static int wrapi_engine_close(struct thread_data *td, struct fio_file *f)
{
    struct wr_data *wd = td->io_ops_data;
    wr_file_close(wd->vfs, &wd->fh, 0);
    return 0;
}

static void fio_wrio_cleanup(struct thread_data *td)
{
    struct wr_data *wd = td->io_ops_data;
    if (wd) {
        wr_vfs_unmount(&wd->vfs);
        wr_delete_inst(wd->inst);
        free(wd);
    }
}

static enum fio_q_status fio_wrio_queue(struct thread_data *td, struct io_u *io)
{
    struct wr_data *wd = td->io_ops_data;
    int ret = 0;
    if (io->ddir == DDIR_READ) {
        ret = wr_file_pread(wd->vfs, wd->fh, io->xfer_buf, io->xfer_buflen, io->offset);
        if (ret < 0) {
            log_err("fio_wrio_queue: read error %d\n", ret);
            return ret;
        }
        io->resid = io->xfer_buflen - ret;
    } else if (io->ddir == DDIR_WRITE) {
        ret = wr_file_pwrite(wd->vfs, &wd->fh, io->xfer_buf, io->xfer_buflen, io->offset);
        if (ret < 0) {
            log_err("fio_wrio_queue: write error %d\n", ret);
            return ret;
        }
        io->resid = io->xfer_buflen - ret;
    } else {
        log_err("fio_wrio_queue: invalid ddir %d\n", io->ddir);
        return -EINVAL;
    }
    return FIO_Q_COMPLETED;
}

struct ioengine_ops ioengine_wrapi = {
    .name           = "wrio",
    .version        = FIO_IOOPS_VERSION,
    .flags          = FIO_SYNCIO,
	.queue          = fio_wrio_queue,
    .init           = fio_wrio_init,
    .cleanup        = fio_wrio_cleanup,
    .open_file      = fio_wrio_open,
    .options        = NULL,
};

static void fio_init fio_wrio_register(void)
{
	register_ioengine(&ioengine_wrapi);
}

static void fio_exit fio_wrio_unregister(void)
{
	unregister_ioengine(&ioengine_wrapi);
}

