#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// 1. Simple — should optimize to single instruction
int add(int a, int b) { return a + b; }
int max_val(int a, int b) { return a > b ? a : b; }
int abs_val(int x) { return x < 0 ? -x : x; }

// 2. Tail call candidate
int factorial_tail(int n, int acc) {
    if (n <= 1) return acc;
    return factorial_tail(n - 1, n * acc);
}
int factorial(int n) { return factorial_tail(n, 1); }

// 3. Loop that should vectorize or unroll
int dot_product(const int* a, const int* b, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

// 4. Pointer chasing with early exit
int find_char(const char* s, char c) {
    for (int i = 0; s[i] != '\0'; i++) {
        if (s[i] == c) return i;
    }
    return -1;
}

// 5. Bitfield manipulation
uint32_t count_bits(uint32_t x) {
    uint32_t count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}

// 6. Division by constant (compiler generates multiply+shift)
int divide_by_7(int x) { return x / 7; }
int modulo_10(int x) { return x % 10; }

// 7. Nested loops
void matrix_add(int* dst, const int* a, const int* b, int rows, int cols) {
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) {
            dst[r * cols + c] = a[r * cols + c] + b[r * cols + c];
        }
    }
}

// 8. Bubble sort (complex control flow + swaps)
void bubble_sort(int* arr, int len) {
    for (int i = 0; i < len - 1; i++) {
        for (int j = 0; j < len - 1 - i; j++) {
            if (arr[j] > arr[j + 1]) {
                int tmp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = tmp;
            }
        }
    }
}

// 9. String processing
int count_words(const char* s) {
    int count = 0;
    int in_word = 0;
    while (*s) {
        if (*s == ' ' || *s == '\t' || *s == '\n') {
            in_word = 0;
        } else if (!in_word) {
            in_word = 1;
            count++;
        }
        s++;
    }
    return count;
}

// 10. Recursive with multiple returns
int gcd(int a, int b) {
    if (b == 0) return a;
    return gcd(b, a % b);
}

int main(int argc, char** argv) {
    printf("add(3,4) = %d\n", add(3, 4));
    printf("max(5,3) = %d\n", max_val(5, 3));
    printf("abs(-7) = %d\n", abs_val(-7));
    printf("factorial(6) = %d\n", factorial(6));

    int a[] = {1,2,3,4};
    int b[] = {5,6,7,8};
    printf("dot = %d\n", dot_product(a, b, 4));
    printf("find('l' in 'hello') = %d\n", find_char("hello", 'l'));
    printf("bits(0xFF) = %d\n", count_bits(0xFF));
    printf("42/7 = %d\n", divide_by_7(42));
    printf("42%%10 = %d\n", modulo_10(42));

    int m[4] = {0};
    int ma[4] = {1,2,3,4};
    int mb[4] = {5,6,7,8};
    matrix_add(m, ma, mb, 2, 2);
    printf("matrix[0] = %d\n", m[0]);

    int arr[] = {4,2,7,1,3};
    bubble_sort(arr, 5);
    printf("sorted[0] = %d\n", arr[0]);

    printf("words = %d\n", count_words("hello world foo"));
    printf("gcd(12,8) = %d\n", gcd(12, 8));
    return 0;
}
