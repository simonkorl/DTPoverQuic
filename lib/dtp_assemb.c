#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "dtplayer.h"
#include "dtp_internal.h"
#include "dtp_assemb.h"
 
 
 
int delete_block(bmap * blockhash,uint64_t id){

     
    bmap * aim =find_bmap(blockhash,id);
    if(aim == NULL){
        return -1;
    }

    HASH_DEL(blockhash,aim);
    log_info("Delete block with id %lu",id);
    free(aim->block.buf);
    free(aim);
    
    return 1;
}

int  dtp_assembler_init(dtp_layers_ctx* dtp_ctx,info_assemble_mode mode)
{
    int ret = 0;

    if (dtp_ctx==NULL||dtp_ctx->assemlay_ctx != NULL) {
      
        ret = -1;
    }
    else {
         
        dtp_assem_ctx* assemlay_ctx = ( dtp_sctx*)malloc(sizeof(dtp_assem_ctx));
        
        if (assemlay_ctx == NULL) {
            ret = -1; }
        else {
           
              memset(assemlay_ctx, 0, sizeof( dtp_assem_ctx)); 

              assemlay_ctx->avrddl = 0;
              assemlay_ctx->historyLen = BLOCK_RECORD_LEN;
              assemlay_ctx->historyArray=(rbinfoptr)malloc((assemlay_ctx->historyLen)*sizeof(r_binfo));
              assemlay_ctx->historyCurIndex=0;
              assemlay_ctx->hisCount=0;
              assemlay_ctx->dtpctx=dtp_ctx;
              assemlay_ctx->mode=mode;
            
              dtp_ctx->assemlay_ctx = assemlay_ctx;
        }
    }
    return ret;
}
 
//Automatically set priority and deadline.
 int dtp_assemble_block_auto(dtp_layers_ctx* dtp_ctx, dtp_assem_ctx* assemlay_ctx, block * blk){
    if(assemlay_ctx==NULL||assemlay_ctx->mode==2)
        return -1;
    
    int cout=1;
    if(!blk){
         blk->deadline=max((dtp_ctx->avrddl),dtp_ctx->avrRTT+blk->size/dtp_ctx->bandwidth);
    }
        int i=0;
    if(!blk){
        uint64_t priority=0;
        uint64_t avg=0;
        int i=0;
        //SCAN
        while(i<assemlay_ctx->hisCount){
            avg+=(assemlay_ctx->historyArray[i]).priority;
            i++;
        }

        if (i!=0)
            priority=floor(avg/cout);
        else
            priority=0;
        
        blk->priority=priority;
    }
   
   

    return i;    
}

//Create a block based on the given data,and adds it to the block pool.
int dtp_assemble_block(dtp_layers_ctx* dtp_ctx, dtp_assem_ctx* assemlay_ctx,\
    uint64_t size,      \
    uint64_t priority,  \
    uint64_t deadline,  \
    char * buf,         \
    int is_fragment     \
    ){

    if(dtp_ctx==NULL ||assemlay_ctx ==NULL ||buf==NULL||size<=0){
          DBG_PRINTF("Failed to assemble block\n");
        return -1;
    }
    //create blocks
    block news={0};
    news.id=dtp_ctx->newid;
    dtp_ctx->newid++;
    news.buf=buf;
    news.size=size;
    news.tmode=is_fragment>=1?1:0;
    news.priority=priority;
    news.deadline=deadline;

    if(priority==0||deadline==0){
       int cout=dtp_assemble_block_auto(dtp_ctx,  assemlay_ctx, &news);
       if( cout==-1)
            DBG_PRINTF("Failed to auto ass.Default settings.\n");
    }

    bmap_add(dtp_ctx->block_pool,news.id,&news);
    
    //timestamps in que 
    block_tlinkPtr bhead=dtp_ctx->schelay_ctx->blockinque;
    bhead->data.id=news.id;
    bhead->data.in=getCurrentUsec();

    block_t_link * newinfo=(block_t_link*)malloc(sizeof(block_t_link));
    newinfo->next=bhead;
    newinfo->last=bhead->last;
    bhead->last->next=newinfo;
    bhead->last=newinfo;

    //history array
    assemlay_ctx->historyCurIndex++;
    assemlay_ctx->historyCurIndex=(assemlay_ctx->historyCurIndex)%(assemlay_ctx->historyLen);
    if(assemlay_ctx->hisCount<assemlay_ctx->historyLen)
        assemlay_ctx->hisCount++;

    r_binfo newInfo;
    newInfo.deadline=news.deadline;
    newInfo.size=news.size;
    newInfo.priority=news.priority;

    (assemlay_ctx->historyArray) [ (assemlay_ctx->historyCurIndex) % (assemlay_ctx->historyLen)]=newInfo;
 

    return 1;
}
 
