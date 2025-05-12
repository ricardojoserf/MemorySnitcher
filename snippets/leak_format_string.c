#include <windows.h>
#include <stdio.h>

int main() {    
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
    
    // long long leakme1 = 733007751850; // 0xAAAAAAAAAA
    // long long leakme2 = 806308527035; // 0xBBBBBBBBBB
    long long leakme1 = (long long) hNtdll;
    long long leakme2 = (long long) pNtReadVirtualMemory;
    char input[100];
    sprintf(input, "%p %p %p %p\n");
    printf(input);

    return 0;
}