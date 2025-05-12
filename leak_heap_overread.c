#include <windows.h>
#include <stdio.h>

int main() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");

    char *buffer = (char *)malloc(32);
    strcpy(buffer, "leak");
    long long *leakme1 = (long long *)(buffer + 16);
    long long *leakme2 = (long long *)(buffer + 24);
    // long long leakme1 = 733007751850; // 0xAAAAAAAAAA
    // long long leakme2 = 806308527035; // 0xBBBBBBBBBB
    *leakme1 = hNtdll;
    *leakme2 = pNtReadVirtualMemory;

    for (int i = 23; i >= 16; i--) { printf("%02X", (unsigned char)buffer[i]); }
    printf(" ");
    for (int i = 31; i >= 24; i--) { printf("%02X", (unsigned char)buffer[i]); }
    printf("\n");

    return 0;
}