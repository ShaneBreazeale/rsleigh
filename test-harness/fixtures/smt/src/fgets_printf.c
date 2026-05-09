// SMT M1 fixture: fgets -> printf format-string.
//
// `vuln_fgets_printf` reads attacker bytes via fgets into a buffer
// and passes it DIRECTLY as the format argument to printf. Any
// input containing `%n` / `%s` / `%x` is a format-string primitive.
//
// Expected verdict for M1 SAT prover:
//   source: fgets -> sink: printf  (FormatArg)  Reachable

#include <stdio.h>

__attribute__((noinline))
int vuln_fgets_printf(void) {
    char fmt[256];
    fgets(fmt, sizeof(fmt), stdin);
    printf(fmt);
    return (int)fmt[0];
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    return vuln_fgets_printf();
}
