/* Handling of a _ */
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

 
#include "dtplayer.h"
#include "dtp_assemb.h"
#include "dtp_internal.h"
 
#include "dtp_scheduler.h"


  

 
  

/* init scheduler
peer_addr blockinque left blank
 */
int dtp_scheduler_init(dtp_layers_ctx* dtp_ctx, dtp_trans_mode transport_mode)
{
    int ret = 0;

    if (dtp_ctx->schelay_ctx != NULL) {

        ret = -1;
    }
    else {
      
         dtp_sctx* schelay_ctx = ( dtp_sctx*)malloc(sizeof(dtp_sctx));
        if (schelay_ctx == NULL) {
            ret = -1; }
        else {
           
  
            memset(schelay_ctx, 0, sizeof( dtp_sctx)); 
            schelay_ctx->transport_mode = transport_mode;
            schelay_ctx->dtpctx=dtp_ctx;
        //block in que init
       //     block_t_link * head=(block_t_link *)malloc(sizeof(block_t_link));
         //   head->next = head;
        //    head->last = head;
             
        //    schelay_ctx->blockinque=head;
      
            dtp_ctx->schelay_ctx = schelay_ctx;
            
        }
    }
    return ret;
}


//test no scheduling
void dtplq_disable_sche(dtp_layers_ctx* dtp_ctx)
{
    if (dtp_ctx->schelay_ctx != NULL) {
        free(dtp_ctx->schelay_ctx);
        dtp_ctx->schelay_ctx = NULL;
    }

    printf("ScheOFF\n");
}
int64_t dtplScheCalReaPri( dtp_sctx* sche_ctx, dtp_layers_ctx* dtp_ctx,uint64_t id){

    bmap * cur=find_bmap(dtp_ctx->block_pool,id);
    block_tlinkPtr iter=sche_ctx->blockinque;
    uint64_t time_queue=0;
    
  

    while(iter!=NULL){

        //HASH_FIND()
             if ( iter->data.id==id){
                time_queue=iter->data.in;
                break;
             }

        iter=iter->next;
    }


    if(time_queue==0)
        return -1;

    uint64_t rem=getCurrentUsec()-time_queue;
    iter->data.left=rem;

    int64_t ret=rem+(cur->block.priority)/(cur->block.deadline)+(float)cur->block.size/dtp_ctx->bandwidth+(float)dtp_ctx->avrRTT;
    
    return ret;
    /*
todo:use hash
 
*/
}


//todo:考虑sche binfo queue使用hash
uint64_t dtp_schedule_block(dtp_layers_ctx* dtp_ctx){

     dtp_sctx* sche_ctx=dtp_ctx->schelay_ctx;
    bmap * blocks=dtp_ctx->block_pool;
    bmap * iter,*tmp;
    uint64_t ret=0;
    uint64_t nxtP=0;

    uint64_t nextID_priority=dtplScheCalReaPri(sche_ctx, dtp_ctx,sche_ctx->nxtID);
    HASH_ITER(hh, blocks, iter, tmp) {
         int real=dtplScheCalReaPri(sche_ctx, dtp_ctx,iter->block.id);
         if(real!=-1&&real>nextID_priority){
            ret=iter->block.id;
            sche_ctx->nxtID=ret;
            nextID_priority=real;
         }

  }

  return ret;
}  
 
  
