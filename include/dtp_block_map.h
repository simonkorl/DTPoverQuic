#ifndef DTP_BLOCK_MAP_H
#define DTP_BLOCK_MAP_H
#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>
#include "dtp_block.h"
#include "log_helper.h"

//todo multiple connection situation
//{conn:bmap}
typedef struct blockmap{
    uint64_t id;
    block block;

    UT_hash_handle hh;    
} bmap;

bmap * bmap_find(bmap * head,uint64_t id);

// TODO: what if we add duplicate id but different block?
int bmap_add(bmap * head, uint64_t id, block * blk);

int bmap_delete(bmap * head, uint64_t id);

#if defined(__cplusplus)
}
#endif
#endif // DTP_BLOCK_MAP_H