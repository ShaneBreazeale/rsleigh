struct node { struct node *next; int size; long count; };

int add(int left, int right) { int total = left + right; return total; }

long walk(struct node *head)
{
    long sum = 0;
    while (head) {
        sum += head->count;
        head = head->next;
    }
    return sum;
}

void _start(void)
{
    struct node n = {0, 4, 7};
    volatile long r = add(1, 2) + walk(&n);
    (void)r;
    for (;;) {}
}
