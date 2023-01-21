# DTP over QUIC

## Build

Build by calling: 
`cmake -S. -Bbuild && cmake --build build`

## Test

To enable debug_log, you can add `-v 4` after all other options.

### QUIC Version

Test the basic transport function matching block to quic stream.

Use `-q` parameter to enable this test.

```sh
$ cmake -S. -Bbuild && cmake --build build
$ cp aitrans_block.txt examples/cert.crt examples/cert.key examples/rootca.crt ./build
$ cd build
$ ./bin/server 127.0.0.1 5555 aitrans_block.txt -q -l server.log # start the server
$ ./bin/client 127.0.0.1 5555 127.0.0.1 6666 -q -o output.csv -l client.log # start the client
```

### WIP: Dgram version

## Some Q&A

### CPM command doesn't exist

You may get this error if CPM is not downloaded successfully. Please go to github.com and download `cmake/CPM.cmake` into `build/cmake/CPM_{VERSION}.cmake`