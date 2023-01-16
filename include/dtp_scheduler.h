/*  DTP schedluing layer.Blocks are scheduled before being sent   */
 
#ifndef DTP_SCHEDULER_H
#define DTP_SCHEDULER_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <time.h>
 
#include "dtp_internal.h"
 #include "dtp_structure.h"
//#include "dtp_structure.h"





 
typedef struct dtp_global_ctx dtp_layers_ctx;

  

typedef dtp_traffic_control_ctx dtp_tc_ctx;
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




//record the timestamp the data comes in at the sender.

//listnode

  
//last k informations of blocks





//left for extension
typedef struct dtplayerSchechGis{
    dtp_layers_ctx* dtp_ctx;
 
} dtpl_Cons_context_t;





// Initialize the scheduler layer.
int dtp_scheduler_init(dtp_layers_ctx* dtp_ctx, dtp_trans_mode transport_mode);


//Test no scheduling
void dtplq_disable_sche(dtp_layers_ctx* dtp_ctx);

//Calculate the real priority in scheduler
int64_t dtplScheCalReaPri( dtp_sctx* sche_ctx, dtp_layers_ctx* dtp_ctx,uint64_t id);


//Calculate all the priority of blocks and choose the id of the most uurgent  one.
uint64_t dtp_schedule_block(dtp_layers_ctx* dtp_ctx);//todo:考虑sche binfo queue使用hash
 //for compile?




 #if defined(__cplusplus)
}
#endif
#endif