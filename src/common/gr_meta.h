#ifndef __GR_META_H__
#define __GR_META_H__

#include "gr_defs.h"
#include "cm_date.h"
#include "gr_file_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GR_META_MAGIC 0x57524D45
#define GR_META_VERSION 1
#define GR_META_CHECKSUM 0
#define GR_META_RESERVED 0

#define GR_META_BLOCK_SIZE 512

typedef struct gr_meta {
    uint32_t magic;
    uint32_t version;
    uint32_t checksum;
    uint32_t reserved;
} gr_meta_t;


#ifdef __cplusplus
}
#endif

#endif
