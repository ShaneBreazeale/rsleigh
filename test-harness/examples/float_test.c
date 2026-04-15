#include <stdio.h>
#include <math.h>

double dot_product(double *a, double *b, int n) {
    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

float lerp(float a, float b, float t) {
    return a + t * (b - a);
}

int main() {
    double a[] = {1.0, 2.0, 3.0};
    double b[] = {4.0, 5.0, 6.0};
    double result = dot_product(a, b, 3);
    printf("dot product: %f\n", result);

    float x = lerp(1.0f, 5.0f, 0.5f);
    printf("lerp: %f\n", (double)x);

    double y = sin(3.14159) + cos(1.0);
    printf("trig: %f\n", y);
    return 0;
}
