// v8 fixture: inter-procedural Heartbleed shape.
//
// caller (handler) does the recv. callee (parse_packet) does the
// memcpy with tainted length extracted from the buffer. Neither
// function alone sees both Source and Sink — only the combined
// inter-procedural view does.
//
// Expected v8 behaviour:
//   - --smt-explore handler --smt-summaries: REACHABLE
//     (recv source synthesises SinkCall event for parse_packet's
//     internal memcpy, lineage walker connects recv.buf → memcpy
//     via call summary)
//
// Without v8 inter-proc taint, parse_packet alone sees no source
// (its buf arg is not a libc Source), so the chain breaks at the
// call boundary.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

__attribute__((noinline))
int parse_packet(char *buf) {
    char dst[64];
    uint16_t len = ((uint16_t)(unsigned char)buf[0] << 8)
                 | ((uint16_t)(unsigned char)buf[1]);
    memcpy(dst, buf + 2, len);
    return (int)dst[0];
}

__attribute__((noinline))
int handler(int sock) {
    char buf[1024];
    recv(sock, buf, sizeof(buf), 0);
    return parse_packet(buf);
}

int main(int argc, char **argv) {
    int s = 0;
    if (argc > 1) s = atoi(argv[1]);
    return handler(s);
}
