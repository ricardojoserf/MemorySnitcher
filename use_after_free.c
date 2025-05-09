#include <stdlib.h>

int main() {
    long long leakme1 = 733007751850; // 0xAAAAAAAAAA
    long long leakme2 = 806308527035; // 0xBBBBBBBBBB
    long long *leak1;
    long long *leak2;

    leak1 = malloc(sizeof(long long));
    leak2 = malloc(sizeof(long long));
    *leak1 = leakme1;
    *leak2 = leakme2;
    printf("%llX %llX\n", *leak1, *leak2);

    return 0;
}