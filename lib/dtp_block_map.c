#include "dtp_block_map.h"

bmap* bmap_find(bmap* head, uint64_t id) {
    bmap *s;
    // s = (bmap *)malloc(sizeof *s);
    HASH_FIND_INT(head,&id,s);
    return s;
}

int bmap_add(bmap * head,uint64_t id,block * blk){ 
    bmap * news;
    
    HASH_FIND_INT(head, &id,news); 

    if (news==NULL){
        news=(bmap *)malloc(sizeof *news);
        news->id=id;
        HASH_ADD_INT(head,id, news);
        return 0;
    } else {
        return -1;
    }
}

int bmap_delete(bmap * blockhash, uint64_t id){
    bmap * aim = bmap_find(blockhash,id);
    if(aim == NULL){
        return -1;
    }

    HASH_DEL(blockhash,aim);
    log_info("Delete block with id %lu",id);
    free(aim->block.buf);
    free(aim);
    
    return 1;
}