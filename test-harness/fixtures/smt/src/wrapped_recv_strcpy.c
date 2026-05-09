// SMT v2.V10 fixture: inter-procedural recv -> strcpy through
// caller-supplied buffers (the source and the sink live in
// SEPARATE helpers; the connection is `outer`'s stack buffer).
//
// fill_buf(buf, sock):  recv(sock, buf, 256, 0)
// copy_into(src, dst):  strcpy(dst, src)  (Arg(1) of strcpy = src)
//
// outer(sock) is the analysed entry. With --smt-summaries the
// explorer must:
//   1. Lift fill_buf's recv as a SourceCall at outer's call-site,
//      tainting outer's local `buf`.
//   2. Lift copy_into's strcpy as a SinkCall at outer's call-site,
//      reading outer's local `buf`.
//   3. Lineage-eq sees both events touch the same VarId → SAT
//      proves Reachable.
//
// Without --smt-summaries (v0/v1) outer has no Source/Sink at all
// — both helpers are intra-procedural in their own scope.

#include <string.h>
#include <sys/socket.h>

__attribute__((noinline))
static void fill_buf(char* buf, int sock) {
    recv(sock, buf, 256, 0);
}

__attribute__((noinline))
static void copy_into(const char* src, char* dst) {
    strcpy(dst, src);
}

__attribute__((noinline))
int outer(int sock) {
    char buf[256];
    char dst[16];
    fill_buf(buf, sock);
    copy_into(buf, dst);
    return (int)dst[0];
}

int main(int argc, char** argv) {
    (void)argv;
    return outer(argc);
}
