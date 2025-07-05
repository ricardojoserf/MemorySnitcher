#include <windows.h>
#include <stdio.h>

int main() {
   HMODULE hNtdll = LoadLibraryA("ntdll.dll");
   FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
   
   char buffer[8] = "leak";
   long long leakme1 = (long long) pNtReadVirtualMemory;
   unsigned char *ptr = (unsigned char *)buffer;
   
   for (int i = 23; i >= 16; i--) { printf("%02X", ptr[i]); }
   
   return 0;
}