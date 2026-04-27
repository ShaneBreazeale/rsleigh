#include <stdint.h>
#include <stddef.h>

#if defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#define USED __attribute__((used))
#else
#define NOINLINE
#define USED
#endif

struct Pair {
    int32_t x;
    int32_t y;
};

static volatile int32_t sink_i32;
static volatile uint64_t sink_u64;

NOINLINE USED int32_t add_mix(int32_t a, int32_t b) {
    int32_t t = (a * 3) + (b * 5);
    if ((t & 1) != 0) {
        return t - a;
    }
    return t + b;
}

NOINLINE USED int32_t factorial_iter(int32_t n) {
    int32_t acc = 1;
    for (int32_t i = 2; i <= n; i++) {
        acc *= i;
    }
    return acc;
}

NOINLINE USED int32_t classify_score(int32_t score) {
    if (score < 0) {
        return -1;
    }
    if (score < 60) {
        return 0;
    }
    if (score < 90) {
        return 1;
    }
    return 2;
}

NOINLINE USED int32_t sum_until_zero(const int32_t *values, size_t len) {
    int32_t total = 0;
    size_t i = 0;
    while (i < len && values[i] != 0) {
        total += values[i];
        i++;
    }
    return total;
}

NOINLINE USED uint32_t copy_trim(char *dst, const char *src, uint32_t max) {
    uint32_t written = 0;
    while (written + 1 < max && src[written] != '\0' && src[written] != '\n') {
        dst[written] = src[written];
        written++;
    }
    if (max != 0) {
        dst[written] = '\0';
    }
    return written;
}

NOINLINE USED int32_t dispatch_op(int32_t op, int32_t a, int32_t b) {
    switch (op) {
    case 0:
        return a + b;
    case 1:
        return a - b;
    case 2:
        return a ^ b;
    case 3:
        return b == 0 ? 0 : a / b;
    default:
        return -99;
    }
}

NOINLINE USED int32_t fib_rec(int32_t n) {
    if (n <= 1) {
        return n;
    }
    return fib_rec(n - 1) + fib_rec(n - 2);
}

NOINLINE USED int32_t struct_accum(struct Pair *pairs, size_t len) {
    int32_t total = 0;
    for (size_t i = 0; i < len; i++) {
        total += pairs[i].x;
        total -= pairs[i].y;
    }
    return total;
}

int main(int argc, char **argv) {
    int32_t values[] = {1, 2, 3, 0, 4};
    struct Pair pairs[] = {{5, 1}, {7, 2}};
    char dst[32];

    sink_i32 = add_mix(argc, 7);
    sink_i32 += factorial_iter(5);
    sink_i32 += classify_score(argc * 10);
    sink_i32 += sum_until_zero(values, 5);
    sink_u64 = copy_trim(dst, argc > 1 ? argv[1] : "default\n", sizeof(dst));
    sink_i32 += dispatch_op(argc & 3, 8, 2);
    sink_i32 += fib_rec(6);
    sink_i32 += struct_accum(pairs, 2);

    return (int)(sink_i32 + (int32_t)sink_u64);
}
