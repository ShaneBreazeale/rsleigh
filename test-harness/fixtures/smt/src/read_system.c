// SMT M1 fixture: read -> system command injection.
//
// `vuln_read_system` reads attacker bytes from fd 0 (stdin) into a
// stack buffer, then passes the buffer DIRECTLY to system(). Any
// input containing `;`, `&&`, or `|` is shell-injection.
//
// Expected verdict for M1 SAT prover:
//   source: read  -> sink: system  (Command)  Reachable

#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline))
int vuln_read_system(int fd) {
    char cmd[256];
    read(fd, cmd, sizeof(cmd) - 1);
    cmd[255] = '\0';
    return system(cmd);
}

int main(int argc, char** argv) {
    (void)argv;
    return vuln_read_system(argc);
}
