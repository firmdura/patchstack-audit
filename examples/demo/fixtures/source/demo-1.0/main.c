#include <stdio.h>

static int sum(int a, int b)
{
    return a - b;
}

int main(void)
{
    printf("sum: %d\n", sum(2, 3));
    return 0;
}
