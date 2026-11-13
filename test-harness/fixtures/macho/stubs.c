/* Mach-O __stubs naming fixture.
 * Build: clang -O1 -arch x86_64 -o stubs_x86_64 stubs.c
 * Three imports so the stub at index 2 sits at a 6-byte stride, not 8. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) { puts("usage"); return 2; }
    printf("%zu\n", strlen(argv[1]));
    return atoi(argv[1]);
}
