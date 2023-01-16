/* Handling of the congestion control,include interacting with quic layer*/
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ev.h>
#include <uthash.h>

 

#include "quiche.h" 

#include <argp.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <errno.h>
#include <stdint.h>
#include "dtplayer.h"
#include "dtp_internal.h"
#include "dtp_assemb.h"
#include "dtp_structure.h"

//usage:
/*
    send blocks 
#include "dtplayer.h"
#include "dtp_internal.h"
#include "dtp_assemb.h"
    typedef struct block {
    char * buf;
    time_t t;
    uint64_t id;
    uint64_t size;
    uint64_t priority;
    uint64_t deadline;

    uint8_t tmode ;
} block;

used for sending blocks to peer via quiche conn

how to extract:
typedef struct dtp_dgram{
    uint64_t id;
    uint16_t offset
   
1.send
    Block is divided equally into several parts,whose size is set 1350.

2.recv
    offset 0 means dgram with block data
    offset -1 means it is the last dgram.(不一定和设定的size相等，当存在块切割交付功能)
    extracted and intergrated into a buffer and handed it to upper layer.

    
}
*/

//initialize tcontroler
//quic_conn and hash、config、block RecvQueue and blockinque left blank.

int dtp_tcontroler_init(dtp_layers_ctx* dtp_ctx)
{//dtp_tc_ctx
    int ret = 0;

    if (dtp_ctx->tc_ctx != NULL) {

        ret = -1;
    }
    else {
      
         dtp_tc_ctx* tc_ctx = ( dtp_tc_ctx*)malloc(sizeof(dtp_tc_ctx));
        if (tc_ctx == NULL) {
            ret = -1; }
        else {
           
  
            memset(tc_ctx, 0, sizeof( dtp_tc_ctx)); 
   
            
            tc_ctx->quic_conn=NULL;
            tc_ctx->connhash=NULL;
            tc_ctx->quic_config=NULL;
           
            tc_ctx->dgram_hdrlen=3*sizeof(uint64_t);//sizeof(id)+sizeof(offset)+sizeof(sent_time);
            tc_ctx->offset_arrived=(offsetsize_t *)malloc(sizeof(offsetsize_t)*tc_ctx->off_array_num);
            tc_ctx->recvQueue=NULL;
            tc_ctx->off_array_num=MAX_BLOCK_SIZE/(MAX_DATAGRAM_SIZE-tc_ctx->dgram_hdrlen)+2; //off =-2 and x.x
           
            tc_ctx->recv_dgram_num=0;
            tc_ctx->peer_RTT=0;
        
            tc_ctx->control_stream_id=8;
            tc_ctx->transport_mode=0;

           
            dtp_ctx->tc_ctx = tc_ctx;
            
        }
    }
    return ret;
}
static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len) {
  memcpy(token, "quiche", sizeof("quiche") - 1);
  memcpy(token + sizeof("quiche") - 1, addr, addr_len);
  memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

  *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

static bool validate_token(const uint8_t *token, size_t token_len,
            struct sockaddr_storage *addr, socklen_t addr_len,uint8_t *odcid, size_t *odcid_len) {
  if ((token_len < sizeof("quiche") - 1) ||
      memcmp(token, "quiche", sizeof("quiche") - 1)) {
    return false;
  }

  token += sizeof("quiche") - 1;
  token_len -= sizeof("quiche") - 1;

  if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
    return false;
  }

  token += addr_len;
  token_len -= addr_len;

  if (*odcid_len < token_len) {
    return false;
  }

  memcpy(odcid, token, token_len);
  *odcid_len = token_len;

  return true;
}

static uint8_t *gen_cid(uint8_t *cid, size_t cid_len) {
  int rng ;
  if (rng < 0) {
    log_error("failed to open /dev/urandom %s", strerror(errno));
    return NULL;
  }

  ssize_t rand_len = read(rng, cid, cid_len);
  if (rand_len < 0) {
    log_error("failed to create connection ID %s", strerror(errno));
    return NULL;
  }

  return cid;
}
/**/
//todo ：如何控制粒度
//validate the connection,
//return -1 => conn doesnt exist , some work needs to be done and need to wait for further data from peer's socket
//1  => connection exists;
int dtp_tc_conn_validate(dtp_tc_ctx * tc_ctx,uint8_t * buf,struct sockaddr_storage * peer_addr,socklen_t peer_addr_len,int socket){

    const int LOCAL_CONN_ID_LEN=10;
    static uint8_t out[MAX_DATAGRAM_SIZE];
    memset(out,0,MAX_DATAGRAM_SIZE);
    int ret=-1;
    uint8_t type;
    uint32_t version;

    uint8_t scid[MAX_DATAGRAM_SIZE];
    size_t scid_len = sizeof(scid);

    uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
    size_t dcid_len = sizeof(dcid);

    uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
    size_t odcid_len = sizeof(odcid);

    uint8_t token[MAX_TOKEN_LEN];
    size_t token_len = sizeof(token);

    int rc =
        quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version, &type, scid,
                           &scid_len, dcid, &dcid_len, token, &token_len);

    if (rc < 0) { 
      log_error("failed to parse header: %d", rc);
    //  ret=DTP_ERR_DONE; 

      return DTP_ERR_DONE;
    }

    //HASH_FIND(hh, tc_ctx->connhash, dcid, dcid_len, tc_ctx->quic_conn);


    if (tc_ctx->quic_conn == NULL) {
      if (!quiche_version_is_supported(version)) {
        log_debug("version negotiation");

        ssize_t written = quiche_negotiate_version(scid, scid_len, dcid,
                                                   dcid_len, out, sizeof(out));

        if (written < 0) {
          log_error("failed to create vneg packet: %zd", written);
          
          return DTP_ERR_DONE;
        }

       // set_tos(conns->ai_family, conns->sock, 5 << 5);
        ssize_t sent = sendto(socket, out, written, 0,
                              (struct sockaddr *)&peer_addr, peer_addr_len);
        if (sent != written) {
          log_error("failed to send %s", strerror(errno));
          return DTP_ERR_DONE;
        }

        log_debug("sent %zd bytes", sent);
         return DTP_ERR_DONE;
      }

      if (token_len == 0) {
        log_debug("stateless retry");

        mint_token(dcid, dcid_len, &peer_addr, peer_addr_len, token,
                   &token_len);

        uint8_t new_cid[LOCAL_CONN_ID_LEN];

        if (gen_cid(new_cid, LOCAL_CONN_ID_LEN) == NULL) {
          
          return DTP_ERR_DONE;
        }

        ssize_t written = quiche_retry(scid, scid_len, dcid, dcid_len, new_cid,
                                       LOCAL_CONN_ID_LEN, token, token_len,
                                       version, out, sizeof(out));

        if (written < 0) {
          log_error("failed to create retry packet: %zd", written);
          return DTP_ERR_DONE;
        }

       // set_tos(conns->ai_family, conns->sock, 5 << 5);
        ssize_t sent = sendto(socket, out, written, 0,
                              (struct sockaddr *)peer_addr, peer_addr_len);
        if (sent != written) {
          log_error("failed to send %s", strerror(errno));
          return DTP_ERR_DONE;
        }

        log_debug("sent %zd bytes", sent);
         return DTP_ERR_DONE;
      }

      if (!validate_token(token, token_len, &peer_addr, peer_addr_len, odcid,
                          &odcid_len)) {
        log_error("invalid address validation token");
        return DTP_ERR_DONE;
      }

      tc_ctx->quic_conn = create_conn(dcid, dcid_len, odcid, odcid_len, &peer_addr,
                            peer_addr_len);

      if (tc_ctx->quic_conn == NULL) {
        return DTP_ERR_DONE;
      }
    }

 
  return 1;
} 
//send the feeback of current network
//lost pkt
void dtp_tc_control_flow_send(dtp_layers_ctx * dtp_ctx,uint8_t * buf,size_t buflen,bool final_flow_data){
  dtp_tc_ctx * tc_ctx=dtp_ctx->tc_ctx;
//  dtp_layers_ctx * dtp_ctx=tc_ctx->dtpctx;
  
   
  memcpy(buf,&(dtp_ctx->avrRTT),sizeof((dtp_ctx->avrRTT)));

  if (quiche_conn_is_established(tc_ctx->quic_conn)){
  ssize_t sent = quiche_conn_stream_send(tc_ctx->quic_conn, tc_ctx->control_stream_id, buf,
                                             sizeof((dtp_ctx->avrRTT)), final_flow_data);

  if (sent != buflen) {
    log_debug("Failed to send feeback_stream %d completely: sent %zd",tc_ctx->control_stream_id, sent);
   }
  } 
  else {
     log_debug("Failed to send feeback_stream %d,conn isn't exist",tc_ctx->control_stream_id);
  }
  

}

//Check and Read the feedback data from peer .
void dtp_tc_control_flow_check(dtp_tc_ctx * tc_ctx){
 
  static uint8_t buf[MAX_BLOCK_SIZE];
  memset(buf, 0, MAX_BLOCK_SIZE);
  uint64_t s = tc_ctx->control_stream_id;
  //quiche_stream_iter *readable = quiche_conn_readable(tc_ctx->quic_conn);

  if(quiche_conn_stream_readable(tc_ctx->quic_conn,s)) {
        
    
        bool fin = false;
        ssize_t recv_len =
            quiche_conn_stream_recv(tc_ctx->quic_conn, s, buf, sizeof(buf), &fin);
        if (recv_len > 0){
          uint64_t p_rtt;
          memcpy(&p_rtt,buf,sizeof(p_rtt));
          tc_ctx->peer_RTT=p_rtt;

          log_debug("Control stream: dgram RTT :%" PRIu64 "  ", p_rtt);
        }
        else
          log_debug("Failed to get data from control stream");
         
        
      }
  //todo:deal with the buf
  //read the control messag
     // quiche_stream_iter_free(readable);


}
//Todo :check if the ctx as well as the parameters is not null.
bool dtp_conn_is_established(dtp_layers_ctx * dtp_ctx){
  
  return (dtp_ctx!=NULL &&dtp_ctx->schelay_ctx!=NULL&&dtp_ctx->tc_ctx!=NULL&&dtp_ctx->assemlay_ctx!=NULL)&&\
  quiche_conn_is_established(dtp_ctx->tc_ctx->quic_conn);
}


uint64_t dtp_conn_timeout_as_nanos(dtp_tc_ctx *tc_ctx){
  return quiche_conn_timeout_as_nanos(tc_ctx->quic_conn);
}
//select a block from the pool and send via datagram
ssize_t dtp_conn_send(dtp_tc_ctx *tc_ctx, uint8_t *out,size_t out_len){

  quiche_send_info send_info;

  return  quiche_conn_send(tc_ctx->quic_conn, *out, out_len,
                          &send_info);
}

//在使用者眼里，应该可以传入buf就解决掉assemble、发送的问题
//是否提供写buf的能力



//send some block
ssize_t dtpl_tc_conn_block_send(dtp_layers_ctx *dtp_ctx, block * block){

    

    if (block==NULL)
        return DTP_ERR_NULL_PTR;
    uint8_t * buf_out=block->buf;
    uint64_t id=block->id;
    uint64_t size=block->size;

    static uint8_t out[MAX_DGRAM_SIZE];
    memset(out,0,MAX_DGRAM_SIZE);
    uint64_t bandwidth=0;
    ssize_t sent=0;
    offsetsize_t offset=0;//off set of the block
    uint64_t priority;
    uint64_t deadline;
    uint64_t sent_time;
    size_t dgram_hdrlen=sizeof(id)+sizeof(offset)+sizeof(sent_time);
    size_t dgram_payloadlen=MAX_DGRAM_SIZE-dgram_hdrlen;

    size_t dgram_num=size/dgram_payloadlen;
    dgram_num=((size%dgram_payloadlen==0)?(dgram_num):(dgram_num+1))+1;
    //divided into grams and send.
    //todo:dgram_size variables in ctx
    size_t dg_counter=0;
    
    while(dg_counter<dgram_num){

            void * curptr=(void *)out;
            memcpy(curptr,&id,sizeof(id));//set id in
            curptr+=sizeof(id);
            memcpy(curptr,&offset,sizeof(offset));//offset in block payload
            curptr+=sizeof(offset);
            sent_time= getCurrentUsec();
            memcpy(curptr,&sent_time,sizeof(sent_time));
            curptr+=sizeof(sent_time);

        if(dg_counter==0){
            //metadgram
            int32_t zerooff=-2;//this is the metadata
            memcpy(curptr-sizeof(offset),&zerooff,sizeof(zerooff));
            memcpy(curptr,&size,sizeof(size));
            curptr+=sizeof(size);
            memcpy(curptr,&priority,sizeof(priority));
            curptr+=sizeof(priority);
            memcpy(curptr,&deadline,sizeof(deadline));
          //todo:reliable tramsmission flag?
        }
        else{
            void * buf_out_ptr=((void *)buf_out)+offset;
            memcpy((void*)curptr,buf_out_ptr,dgram_payloadlen);
            //curptr+=dgram_payloadlen;
            
        }

        //!todo:因队列发送失败，是否不更新，重发 ？
        if (quiche_conn_dgram_max_writable_len(dtp_ctx->quic_conn)>=sizeof(out)){
            sent= quiche_conn_dgram_send(dtp_ctx->quic_conn,out,sizeof(out));
            printf("Log:sents\n %ld",sent);
            dg_counter++;
            offset+=dgram_payloadlen;

            bandwidth+=currentTime()-sent_time;
    }

}
 
    dtp_ctx->bandwidth= (dgram_num*MAX_DATAGRAM_SIZE)/(bandwidth/1000);//byte/ms
  //delete block from hash map and list node

  delete_block(dtp_ctx->block_pool,id);
  block_tlinkPtr linkIter=dtp_ctx->schelay_ctx->blockinque;
  if(linkIter!=NULL){
    while(linkIter->data.id!=id){
        linkIter=linkIter->next;
      }
    //not point to head
    
      block_tlinkPtr last=linkIter->last;
      block_tlinkPtr next=linkIter->next;

      last->next=next;
      next->last=last;

      free(linkIter);

    if(linkIter==dtp_ctx->schelay_ctx->blockinque)
      dtp_ctx->schelay_ctx->blockinque=NULL;
  }
  
 // dtp_ctx->schelay_ctx->blockinque

    return sent;
}
//process the imcoming socket buf;



//select a block from the pool and send via datagram
ssize_t dtpl_tc_conn_send(dtp_layers_ctx *dtp_ctx){

  uint64_t id=dtp_schedule_block( dtp_ctx);
  block * aim_block= find_bmap(dtp_ctx->block_pool,id);
  if( aim_block==NULL)
    return -1;
  return dtpl_tc_conn_block_send(dtp_ctx, aim_block);
}




//bool quiche_conn_is_closed(quiche_conn *conn);
bool dtp_conn_is_closed(dtp_tc_ctx * tc_ctx){

  return quiche_conn_is_closed(tc_ctx->quic_conn);
}
 

//process the imcoming socket buf;
ssize_t dtp_conn_recv(dtp_tc_ctx * tc_ctx, uint8_t *buf, size_t buf_len,struct sockaddr_storage * peer_addr,socklen_t peer_addr_len){

    quiche_recv_info recv_info = {
        (struct sockaddr *)peer_addr,

        peer_addr_len,
    };

    return quiche_conn_recv(tc_ctx->quic_conn, buf, read, &recv_info);
 
}

//extract block bufdata (may be broken when using datagram) from dgram_recv_queue 
int dtp_tc_conn_block_recv(dtp_layers_ctx *dtp_ctx,uint8_t * block_buf ){
  
    if(block_buf == NULL){
        return -1;
    }
    dtp_tc_ctx * tc_ctx=dtp_ctx->tc_ctx;
    
    
    uint64_t total_bytes=0;
    int32_t recv_len=0;
    static uint8_t recv_buf[MAX_DGRAM_SIZE];
    

   // static uint8_t block_buf[BLOCK_SIZE];

    memset(recv_buf,0,MAX_DGRAM_SIZE);
    memset(block_buf,0,MAX_BLOCK_SIZE);

    uint64_t priority=0;
    uint64_t deadline=0;
    uint64_t size=0;

     recv_len=1;
    uint32_t off_ind=0;
    memset(tc_ctx->offset_arrived,0,tc_ctx->off_array_num);
 
    static uint64_t sent_time;
    static uint64_t id=0;
    uint64_t RTT_gap=0;
    offsetsize_t offset=0;

    tc_ctx->recv_dgram_num=0;
 

    for( ;recv_len!=DTP_ERR_DONE;){
        //todo :consider multiple ID situation/ using hash
       recv_len=quiche_conn_dgram_recv(tc_ctx->quic_conn, recv_buf,MAX_DATAGRAM_SIZE);
       total_bytes += recv_len;
       

       if(recv_len!=DTP_ERR_DONE){
            void * curptr=(void *)recv_buf+tc_ctx->dgram_hdrlen;
            parse_ddgram_hdr(recv_buf,&id,&offset,&sent_time);
            //todo:collected and push to queue with correspond ID,to indicate
            //the ID and timestamps via control stream
            //when the queue is not empty,send.
            RTT_gap=RTT_gap+getCurrentUsec()-sent_time;
            tc_ctx->recv_dgram_num++;
            if(offset==-2){//metadata
                memcpy(&size,curptr,sizeof(size));
                curptr+=sizeof(size);
                memcpy(&priority,curptr,sizeof(priority));
                curptr+=sizeof(priority);
                memcpy(&deadline,curptr,sizeof(deadline));
                
               //log_info("Recieve block :%lu ,%s:%s", args.server_ip, args.server_port);
            }
            else{
                void * block_cur_ptr=(void*)block_buf+offset;
                memcpy(block_cur_ptr,curptr,MAX_DATAGRAM_SIZE-tc_ctx->dgram_hdrlen);
            }
             (tc_ctx->offset_arrived)[off_ind]=offset;
       }

     
    }
      uint64_t RTT=RTT_gap/(off_ind+1);
       tc_ctx->peer_RTT=RTT; //each dgram.todo:more stable standard recent RTTs?

    log_info("Recieve block,ID :%lu size : %lu priority :%lu dgram_num:%lu RTT:%lu\n",id,size,priority,off_ind+1);
    return block_buf;
}

int parse_ddgram_hdr(uint8_t * dgram,uint64_t * id,offsetsize_t * offset,uint64_t * sent_time){

    if(id==NULL||offset==NULL||sent_time==NULL)
        return -1;

    void * curptr=(void *)dgram;
     
    memcpy(id,curptr,sizeof(*id));//set id in
    curptr+=sizeof(*id);
    memcpy(offset,curptr,sizeof(*offset));
    curptr+=sizeof(*offset);
    memcpy(sent_time,curptr,sizeof(*sent_time));
    curptr+=sizeof(*offset);
    return 1;
}
/*
used for sending buf 

*/

/*
making connection via quiche
*/