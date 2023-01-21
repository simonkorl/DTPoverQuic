#ifndef BLOCK_UTIL_H
#define BLOCK_UTIL_H

#include <stdint.h>
#include "dtp_block.h"

const uint64_t QUIC_INFO_STREAM = 3;

struct block_stats {
  quiche_block block_hdr;
  size_t recv_size;
  bool has_hdr;
  bool fin;
  int64_t bct;
};

typedef struct block_stats block_stats;

// encode block info into a buffer as a header
// blockinfo: size: u64, priority: u64, deadline: u64 
size_t encode_block_hdr(uint8_t *buf, size_t max_len, quiche_block block_hdr) {
  if(max_len < sizeof(quiche_block)) {
    return 0;
  }
  memcpy(buf, &block_hdr, sizeof(quiche_block));
  return sizeof(quiche_block);
}

// decode block info from a buffer
// blockinfo: size: u64, priority: u64, deadline: u64 
size_t decode_block_hdr(uint8_t *buf, size_t max_len, quiche_block *block_hdr) {
  if(max_len < sizeof(quiche_block)) {
    return 0;
  }
  memcpy(block_hdr, buf, sizeof(quiche_block));
  if(block_hdr->size == 0 && block_hdr->deadline == 0 && block_hdr->priority == 0) {
    // parse empty hdr
    return 0;
  }
  return sizeof(quiche_block);
}
#endif // BLOCK_UTIL_H