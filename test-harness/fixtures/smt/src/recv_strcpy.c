// SMT M1 fixture: recv -> strcpy stack-buffer overflow.
//
// `vuln_recv_strcpy` reads attacker bytes from sock into a 256-byte
// staging buf, then strcpy()s them into a 16-byte stack dst. Any
// input >= 16 bytes without an embedded NUL writes past dst.
//
// Expected verdict for M1 SAT prover:
//   source: recv  -> sink: strcpy  (StackBuffer)  Reachable

#include <string.h>
#include <sys/socket.h>

__attribute__((noinline))
int vuln_recv_strcpy(int sock) {
    char buf[256];
    char dst[16];
    recv(sock, buf, sizeof(buf), 0);
    strcpy(dst, buf);
    return (int)dst[0];
}

int main(int argc, char** argv) {
    (void)argv;
    return vuln_recv_strcpy(argc);
}
