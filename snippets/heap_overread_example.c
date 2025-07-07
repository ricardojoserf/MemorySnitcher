#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *buffer = (char *)malloc(32);
    strcpy(buffer, "leak");
    long long *leakme1 = (long long *)(buffer + 16);
    long long *leakme2 = (long long *)(buffer + 24);
    *leakme1 = 0xABCDEFABCD;
    *leakme2 = 0xBBBBBBBBBB;

    for (int i = 23; i >= 16; i--) { printf("%02X", (unsigned char)buffer[i]); }
    printf(" ");
    for (int i = 31; i >= 24; i--) { printf("%02X", (unsigned char)buffer[i]); }
    printf("\n");

    free(buffer);
    return 0;
}