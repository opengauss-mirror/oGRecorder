#ifndef __WR_META_H__
#define __WR_META_H__

#include "wr_defs.h"
#include "cm_date.h"
#include "wr_file_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WR_META_MAGIC 0x57524D45
#define WR_META_VERSION 1
#define WR_META_CHECKSUM 0
#define WR_META_RESERVED 0

#define WR_META_BLOCK_SIZE 512

typedef struct wr_meta {
    uint32 magic;
    uint32 version;
    uint32 checksum;
    uint32 reserved;
} wr_meta_t;


#ifdef __cplusplus
}
#endif

#endif
