#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1. Simple arithmetic
int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }

// 2. Recursion with conditional
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

// 3. Loop with array access
int sum_array(int* arr, int len) {
    int total = 0;
    for (int i = 0; i < len; i++) {
        total += arr[i];
    }
    return total;
}

// 4. String processing with pointers
int string_length(const char* s) {
    int len = 0;
    while (*s != '\0') {
        len++;
        s++;
    }
    return len;
}

// 5. Struct-like stack layout
typedef struct {
    int x, y;
} Point;

int manhattan_distance(Point* a, Point* b) {
    int dx = a->x - b->x;
    int dy = a->y - b->y;
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;
    return dx + dy;
}

// 6. Switch/case
const char* day_name(int day) {
    switch (day) {
        case 0: return "Sunday";
        case 1: return "Monday";
        case 2: return "Tuesday";
        case 3: return "Wednesday";
        case 4: return "Thursday";
        case 5: return "Friday";
        case 6: return "Saturday";
        default: return "Unknown";
    }
}

// 7. Linked list traversal
typedef struct Node {
    int value;
    struct Node* next;
} Node;

int list_sum(Node* head) {
    int sum = 0;
    while (head != NULL) {
        sum += head->value;
        head = head->next;
    }
    return sum;
}

// 8. Binary search
int binary_search(int* arr, int len, int target) {
    int lo = 0, hi = len - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (arr[mid] == target) return mid;
        if (arr[mid] < target) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;
}

// 9. Function pointers
typedef int (*BinOp)(int, int);
int apply(BinOp op, int a, int b) { return op(a, b); }

// 10. Main exercising everything
int main(int argc, char** argv) {
    printf("add(3,4) = %d\n", add(3, 4));
    printf("factorial(6) = %d\n", factorial(6));

    int nums[] = {1, 2, 3, 4, 5};
    printf("sum = %d\n", sum_array(nums, 5));
    printf("strlen = %d\n", string_length("hello world"));

    Point a = {3, 7}, b = {1, 2};
    printf("manhattan = %d\n", manhattan_distance(&a, &b));
    printf("day = %s\n", day_name(3));

    printf("apply(add,5,6) = %d\n", apply(add, 5, 6));

    int sorted[] = {2, 5, 8, 12, 16, 23, 38, 56, 72, 91};
    printf("search(23) = %d\n", binary_search(sorted, 10, 23));

    return 0;
}
