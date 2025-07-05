#include <windows.h>
#include <stdio.h>

int main() {
   HMODULE hNtdll = LoadLibraryA("ntdll.dll");
   FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
   
   char *buffer = (char *)malloc(32);
   strcpy(buffer, "leak");
   uintptr_t *leakme1 = (uintptr_t *)(buffer + 16);
   *leakme1 = (uintptr_t)pNtReadVirtualMemory;
   
   for (int i = 23; i >= 16; i--) { printf("%02X", (unsigned char)buffer[i]); }
   
   return 0;
}