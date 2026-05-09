// Synthetic CVE corpus: 4 named functions, each modeled after a real CVE pattern.
// Built with -O0 -g so symbols + control flow are preserved.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// CVE-2016-3116 style: command injection via sprintf+system (xauth)
// Source: read() from network. Sink: system(). Tainted: yes. Reachable: yes.
void chansess_x11req_like(int fd) {
    char cookie[256];
    char cmd[512];
    ssize_t n = read(fd, cookie, sizeof(cookie) - 1);
    if (n <= 0) return;
    cookie[n] = 0;
    snprintf(cmd, sizeof(cmd), "xauth add :0 . %s", cookie);
    system(cmd);  // command injection sink
}

// CVE-2013-1813 style: relative path traversal -> stack buffer overflow via strcpy
// Source: argv. Sink: strcpy into fixed stack buf. Reachable: yes.
void mdev_load_like(const char *device_name) {
    char path[64];
    strcpy(path, "/dev/");
    strcat(path, device_name);  // overflow if device_name > 58 bytes
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

// CVE-2015-3294 style: TFTP option parsing OOB read
// Source: recv() into packet. Sink: strchr-style scan past end. Reachable: yes.
int tftp_request_like(const char *pkt, int len) {
    const char *p = pkt + 2;       // skip opcode
    const char *end = pkt + len;
    int mode_ok = 0;
    while (p < end + 32) {          // BUG: should be p < end, scans past buffer
        if (*p == 0) { p++; continue; }
        if (strcmp(p, "octet") == 0) mode_ok = 1;
        p += strlen(p) + 1;          // OOB strlen if no null
    }
    return mode_ok;
}

// Negative control: clean function, no taint.
int safe_add(int a, int b) {
    return a + b;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    if (strcmp(argv[1], "x11") == 0) chansess_x11req_like(0);
    else if (strcmp(argv[1], "mdev") == 0) mdev_load_like(argv[2]);
    else if (strcmp(argv[1], "tftp") == 0) {
        char buf[128];
        int n = read(0, buf, sizeof(buf));
        tftp_request_like(buf, n);
    }
    return safe_add(argc, 0);
}
