// v9 fixture: tainted bytes streamed into fixed stack buffer via
// raw store loop (no libc memcpy/strncpy). Models the
// CVE-2017-14491 extract_name pattern: parser walks input bytes,
// writes them to a fixed-size output buffer, no upper bound on
// the source length.
//
// Expected v9 behaviour:
//   - --smt-explore vuln_loop_store --smt-summaries: REACHABLE
//     via TaintedStore sink on the loop body's `*out++ = ...`.
//
// Without v9 the pattern is invisible: there's no libc sink
// (the store is compiler-emitted), so v8 reports no v0 paths.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

__attribute__((noinline))
int copy_until_zero(unsigned char *src, char *out) {
    while (*src) {
        *out++ = (char)(*src++);
    }
    return 0;
}

__attribute__((noinline))
int vuln_loop_store(int sock) {
    unsigned char buf[1024];
    char dst[64];
    recv(sock, buf, sizeof(buf), 0);
    copy_until_zero(buf, dst);   // OOB write when buf has > 64 nonzero bytes
    return (int)dst[0];
}

int main(int argc, char **argv) {
    int s = 0;
    if (argc > 1) s = atoi(argv[1]);
    return vuln_loop_store(s);
}
