/*  DTP schedluing layer.Blocks are scheduled before being sent   */
#pragma once
#ifndef DTP_SCHEDULER_H
#define DTP_SCHEDULER_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <time.h>
 


#include "dtp_internal.h"


 
///
/*
typedef struct block {
    char buf[10000];
         time_t t;
    long int ID;u_int16_t size;
 uint8_t priority;
 
    uint32_t deadline;
} block;
*/
 
typedef struct  {
    uint8_t * buf;
    time_t t;
    uint64_t id;
    uint64_t size;
    uint64_t priority;
    uint64_t deadline;
//tmode =1 ,drop the blocks which exceeds the deadline.
//tmode =0 ,transmit as possible as it can.
    uint8_t tmode;  
} block;

//record the timestamp the data comes in at the sender.
typedef struct block_record{
    
    uint64_t id;
   
    uint64_t in; //time in queue ,also used for the arriving timestamps from peer's control STREAM
    uint64_t left;//left time ,compared with ddl

}block_info;
//listnode
typedef struct block_t_link{
    block_info data;
    struct block_t_link * next;
    struct block_t_link * last;
   
}block_t_link,* block_tlinkPtr;
  
//last k informations of blocks
typedef struct rec_block_info{
    uint64_t  size;
    uint64_t  priority;
    uint64_t  deadline;
}r_binfo,* rbinfoptr;

//left for extension
typedef struct dtplayerSchechGis{
    dtp_layers_ctx* dtp_ctx;
 
} dtpl_Cons_context_t;


typedef struct dtp_schedule_layer {
    uint64_t nxtID; // to send
    dtp_layers_ctx * dtpctx;
    block_tlinkPtr blockinque; //link.record the info of the time of the blocks. always points to the header node,cam be blak
 //   rbinfoptr bhistory;
    struct sockaddr_storage peer_addr;
    dtp_trans_mode transport_mode;
    
    
}  dtp_sctx;


//Initialize the scheduler layer.
int dtp_scheduler_init(dtp_layers_ctx* dtp_ctx, dtp_trans_mode transport_mode);


//Test no scheduling
void dtplq_disable_sche(dtp_layers_ctx* dtp_ctx);

//Calculate the real priority in scheduler
int64_t dtplScheCalReaPri( dtp_sctx* sche_ctx, dtp_layers_ctx* dtp_ctx,uint64_t id);


//Calculate all the priority of blocks and choose the id of the most uurgent  one.
uint64_t dtp_schedule_block(dtp_layers_ctx* dtp_ctx);//todo:考虑sche binfo queue使用hash
 



 #if defined(__cplusplus)
}
#endif
#endif