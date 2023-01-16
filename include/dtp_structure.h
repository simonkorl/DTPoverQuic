#ifndef DTP_STRUCTURE_H
#define DTP_STRUCTURE_H


#include <stdint.h>
#include <stdbool.h> 

#include "quiche.h"
#include "uthash.h"
 


#if defined(__cplusplus)
extern "C" {
#endif


 #define offsetsize_t int32_t

#define MAX_DGRAM_SIZE 1350
typedef struct block_record{
    
    uint64_t id;
   
    uint64_t in; //time in queue ,also used for the arriving timestamps from peer's control STREAM
    uint64_t left;//left time ,compared with ddl

}block_info;


 typedef struct block_t_link{
    block_info data;
    struct block_t_link * next;
    struct block_t_link * last;
   
}block_t_link,* block_tlinkPtr;


typedef enum {
    stream = 1,
    gram = 2,
} dtp_trans_mode;

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


typedef struct blockmap{
    uint64_t id;
    block block;

    UT_hash_handle hh;    

}bmap;


typedef struct {
     
 
    quiche_conn * quic_conn; //current connection
    quiche_conn * connhash;//all the connection hash;
    quiche_config * quic_config;
 
    uint64_t control_streamid;
    offsetsize_t * offset_arrived;
 
    size_t dgram_hdrlen;
    size_t off_array_num;
    uint64_t recv_dgram_num;
    //peer
    uint64_t peer_RTT;

    bmap * recvQueue;
 
    struct sockaddr_storage peer_addr;
    
    int control_stream_id;
    
    dtp_trans_mode transport_mode;
    
 
} dtp_traffic_control_ctx;

typedef dtp_traffic_control_ctx dtp_tc_ctx;

typedef struct dtp_schedule_layer {
    uint64_t nxtID; // to send
 
    block_tlinkPtr blockinque; //link.record the info of the time of the blocks. always points to the header node,cam be blak
 //   rbinfoptr bhistory;
    struct sockaddr_storage peer_addr;
    dtp_trans_mode transport_mode;
    
    
}  dtp_sctx;
typedef enum {
    DTP_BLOCK_INFO_AUTO =1,
    DTP_BLOCK_INFO_MANNUAL =2,
} info_assemble_mode;


typedef struct rec_block_info{
    uint64_t  size;
    uint64_t  priority;
    uint64_t  deadline;
}r_binfo,* rbinfoptr;

typedef struct dtp_assemble_layer_ctx_ {
    //average deadline.
    uint64_t avrddl;
    //Record some of the last blocks.
    uint64_t historyLen;
    rbinfoptr  historyArray;
    //current array index
    uint64_t historyCurIndex;
    uint64_t hisCount;

 

    //auto or mannual or other ways
    info_assemble_mode mode;
    
} dtp_assem_ctx;


struct dtp_global_ctx {
    const char* sni;
    
    quiche_conn * quic_conn;
     dtp_sctx* schelay_ctx;     
    dtp_tc_ctx* tc_ctx;
    
    dtp_assem_ctx * assemlay_ctx;
    
    uint64_t newid; //todo:先前释放的id？grow?
 
    uint64_t avrRTT;    //todo:move to tc_ctx?
    uint64_t bandwidth; 
    uint64_t avrddl;    //dgram level.todo:block level
    bmap * block_pool; //block hash
 
 
    unsigned int do_congestion_control : 1;
};
 
typedef struct dtp_global_ctx dtp_layers_ctx;


#if defined(__cplusplus)
}
#endif

#endif