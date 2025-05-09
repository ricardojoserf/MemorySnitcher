#include <windows.h>
#include <stdlib.h>

int main() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
    
    long long leakme1 = (long long) hNtdll;
    long long leakme2 = (long long) pNtReadVirtualMemory;
    long long *leak1;
    long long *leak2;

    leak1 = malloc(sizeof(long long));
    leak2 = malloc(sizeof(long long));
    *leak1 = leakme1;
    *leak2 = leakme2;
    printf("%llX %llX\n", *leak1, *leak2);
    
    return 0;
}