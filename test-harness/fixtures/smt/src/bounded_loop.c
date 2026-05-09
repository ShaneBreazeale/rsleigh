// v11 fixture: BOUNDED copy loop. Helper writes from src into dst
// but stops at a Const upper bound (NOT attacker-controlled).
// This is a classic FP candidate for v10's TaintedStore SAT model:
// the lineage from recv to *out matches the Param→Param shape,
// but the loop iteration is statically capped at 16 bytes — which
// fits any reasonable dst buffer.
//
// Expected v11 behaviour:
//   - --smt-explore safe_handler --smt-summaries: NotReachable.
//
// v10 behaviour (FP — to be fixed by v11.A):
//   - REACHABLE because v9 detector treats this same as the
//     unbounded copy_until_zero case.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

__attribute__((noinline))
void copy_bounded(unsigned char *src, char *out) {
    int i;
    for (i = 0; i < 16; i++) {     // bounded by Const(16)
        out[i] = (char)src[i];
    }
}

__attribute__((noinline))
int safe_handler(int sock) {
    unsigned char buf[1024];
    char dst[64];
    recv(sock, buf, sizeof(buf), 0);
    copy_bounded(buf, dst);   // Const-bounded, not attacker-controllable
    return (int)dst[0];
}

int main(int argc, char **argv) {
    int s = 0;
    if (argc > 1) s = atoi(argv[1]);
    return safe_handler(s);
}
