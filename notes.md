# Notes

## dgram buffer in QUIC

If the length of quiche dgram queue is too short (less than the largest block size / payload length in each dgram), without retransmittion machenism, some of the datagram cannot be received, even if they are sent by the server.

Currently, I fix this problem by:

1. Add a deadline-aware finish condition to drain the block data(in fn recv_cb)
2. Remove the metadata dgram and the metadata control flow and add all the metadata of a block in each dgram hdr