/*  DTP traffic_control layer.Blocks are sent via tc layer.And it gives back feedback to the peer sender.   */
 
#ifndef DTP_TC_H
#define  DTP_TC_H

#if defined(__cplusplus)
extern "C" {
#endif
#include <time.h>
 
#include "dtplayer.h"
//#include "dtp_assemb.h"
#include "dtp_internal.h"
 
#include "dtp_structure.h"
#define offsetsize_t int32_t
 
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




typedef struct dtp_datagram{
    uint64_t id;
    uint16_t offset;
    uint8_t * payload;
}ddgram;

 
 
//check if dtp conn is closed 
 bool dtp_conn_is_closed(dtp_tc_ctx * tc_ctx);
//send pkt.Contents may be altered.
ssize_t dtp_conn_send(dtp_tc_ctx *tc_ctx, uint8_t *out,size_t out_len);

bool dtp_conn_is_established(dtp_layers_ctx * dtp_ctx);

//Initialize the traffic control layer.
int dtp_tcontroler_init(dtp_layers_ctx* dtp_ctx);


static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len);

static bool validate_token(const uint8_t *token, size_t token_len,
            struct sockaddr_storage *addr, socklen_t addr_len,uint8_t *odcid, size_t *odcid_len) ;

static uint8_t *gen_cid(uint8_t *cid, size_t cid_len) ;
/**/

//validate the connection,
//return -1 => conn doesnt exist , some work needs to be done and need to wait for further data from peer's socket
//1  => connection exists;
int dtp_tc_conn_validate(dtp_tc_ctx * tc_ctx,uint8_t * buf,struct sockaddr_storage * peer_addr,socklen_t peer_addr_len,int socket);//todo ：如何控制粒度 
//send the feeback of current network
//lost pkt
void dtp_tc_control_flow_send(dtp_layers_ctx * dtp_ctx,uint8_t * buf,size_t buflen,bool final_flow_data);

//Check if there is feedback data from control stream
void dtp_tc_control_flow_check(dtp_tc_ctx * tc_ctx);
//Todo :check if the ctx as well as the parameters is not null.
bool dtp_conn_is_established(dtp_layers_ctx * dtp_ctx);


uint64_t dtp_conn_timeout_as_nanos(dtp_tc_ctx *tc_ctx);
//select a block from the pool and send via datagram
ssize_t dtp_conn_send(dtp_tc_ctx *tc_ctx, uint8_t *out,size_t out_len);



//select a block from the pool and send via datagram
ssize_t dtpl_tc_conn_send(dtp_layers_ctx *dtp_ctx); //在使用者眼里，应该可以传入buf就解决掉assemble、发送的问题 //是否提供写buf的能力

//send some block
ssize_t dtpl_tc_conn_block_send(dtp_layers_ctx *dtp_ctx, block * block);
 
//bool quiche_conn_is_closed(quiche_conn *conn);
bool dtp_conn_is_closed(dtp_tc_ctx * tc_ctx);
 

//process the imcoming socket buf;
ssize_t dtp_conn_recv(dtp_tc_ctx * tc_ctx, uint8_t *buf, size_t buf_len,struct sockaddr_storage * peer_addr,socklen_t peer_addr_len);

//extract block bufdata (may be broken when using datagram) from dgram_recv_queue 
int dtp_tc_conn_block_recv(dtp_layers_ctx *dtp_ctx,uint8_t * block_buf );
//parse the buf to get imformations from the peer.
int parse_ddgram_hdr(uint8_t * dgram,uint64_t * id,offsetsize_t * offset,uint64_t * sent_time);



#if defined(__cplusplus)
}
#endif
#endif