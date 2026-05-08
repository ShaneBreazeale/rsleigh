// Heartbleed-shape fixture: attacker-controlled length extracted from
// packet content, fed to memcpy. This is the dominant real-world CVE
// pattern that rsleigh's static SMT pipeline failed to surface on the
// AX6000 corpus (M2 attempts #1-7).
//
// Expected v7 behaviour:
//   - --smt-candidates SHOULD include a record for vuln_heartbleed
//   - sink_kind = LengthArg
//   - Should the verdict be Reachable? Static-bound filter says no
//     (read.return is bounded by Const(1024), so chain stops there).
//     But the actual `len` is derived from buf[0..2], NOT from
//     read.return. The lineage walker SHOULD still bridge this via
//     region-keyed MemMap (Load(buf+0/+1) is in the same region as
//     recv's tainted buf).
//
// If rsleigh classifies this NotReachable (under v6.W1 strict bound),
// we have a known shape that exposes the recall gap.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

__attribute__((noinline))
int vuln_heartbleed(int sock) {
    char buf[1024];
    char dst[64];

    int n = recv(sock, buf, sizeof(buf), 0);
    if (n < 4) return -1;

    // attacker-controlled length: 16-bit big-endian from packet
    uint16_t len = ((uint16_t)(unsigned char)buf[0] << 8)
                 | ((uint16_t)(unsigned char)buf[1]);

    // BOF: dst is 64 bytes, len can be up to 0xFFFF
    memcpy(dst, buf + 2, len);

    return (int)dst[0];
}

// Also include the simpler variant that v5 W2.D2a should already catch.
__attribute__((noinline))
int vuln_recv_strcpy(int sock) {
    char dst[64];
    char buf[1024];
    recv(sock, buf, sizeof(buf), 0);
    strcpy(dst, buf);
    return dst[0];
}

int main(int argc, char **argv) {
    int s = 0;
    if (argc > 1) s = atoi(argv[1]);
    vuln_heartbleed(s);
    vuln_recv_strcpy(s);
    return 0;
}
