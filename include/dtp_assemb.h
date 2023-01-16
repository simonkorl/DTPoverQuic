/*  DTP assembler layer.Blocks are assembled before being scheduled   */
 
#ifndef DTP_ASSEMB_H
#define DTP_ASSEMB_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "dtplayer.h"
 

#include "dtp_structure.h"
#define BLOCK_RECORD_LEN 10



 
 

/*
int dtp_assemb_input(
    dtp_assem_ctx* reassembly_ctx,
    uint64_t current_time,
    const uint8_t* data,
   
    uint64_t b_id,
    uint64_t offset,
    uint64_t queue_delay,
    uint8_t flags,

    int is_last_fragment,
    size_t data_length,
              
              
              dtpAssMidInfoready_fn ready_fn,
    void * app__ctx);
*/
 

//context


//initialize the layer
int dtp_assembler_init(dtp_layers_ctx* dtp_ctx,info_assemble_mode mode);
//assemble the block automatically
int dtp_assemble_block_auto(dtp_layers_ctx* dtp_ctx, dtp_assem_ctx* assemlay_ctx, block * blk);

delete_block(bmap * blockhash,uint64_t id);
//assemble the block
int dtp_assemble_block(dtp_layers_ctx* dtp_ctx, dtp_assem_ctx* assemlay_ctx,\
    uint64_t size,      \
    uint64_t priority,  \
    uint64_t deadline,  \
    char * buf,         \
    int is_fragment     \
    );


int dtp_assemb_learn_start_point(dtp_assem_ctx* reassembly_ctx,uint64_t start_b_id, uint64_t current_time);


int dtp_assemb_learn_final_obji(dtp_assem_ctx* reassembly_ctx,uint64_t final_b_id);

 
//release
void dtp_assemb_release(dtp_assem_ctx* reassembly_ctx);


#if defined(__cplusplus)
}
#endif

#endif