# MemorySnitcher

Using a purposefully vulnerable application to leak the address of NtReadVirtualMemory, removing the need to use any Kernel32 function for API resolution in your malicious application.


## Motivation

Last months, I have made public some tools which use "only" lower-level functions in the ntdll.dll library. This DLL contains the lowest level functions in user mode because it interacts directly with ntoskrnl.exe, which is kernel mode.

Some of these projects have been:

- NativeDump and TrickDump

- NativeBypassCredGuard

- NativeTokenImpersonate

- NativeNtdllRemap

However, it bothered me to have all the necessary functions in the import table of the binary, because this could hint towards the true intentions of the compiled binary - you know, importing NtOpenProcessToken and NtAdjustPrivilegesToken might look suspicious :)

To solve this, I decided to use dynamic API resolution by creating functions mimicking GetModuleHandle and GetProcAddress. As a short reminder, GetModuleHandle returns the address of a loaded DLL given the library name (LoadLibrary works too but I would only use it if the DLL is not already loaded in the process) and GetProcAddress returns the address of a function given the DLL address and the function name. The ntdll.dll library is always the first DLL to get loaded in a process and it gets always loaded, so we can simplify this problem to GetModuleHandle + GetProcAddress when we work with NTAPIs.

By walking the PEB it is possible to get this functionality using custom implementations, and you can do it using only functions in ntdll.dll:

- CustomGetModuleHandle requires NtQueryInformationProcess and NtReadVirtualMemory

- CustomGetProcAddress requires only NtReadVirtualMemory

The problem here: you need some way to resolve at least ntdll.dll address and NtReadVirtualMemory. With those 2 addresses, you can use CustomGetProcAddress to get the function address of any function in ntdll.dll. Or, resolving NtQueryInformationProcess, you can use CustomGetProcAddress to get the base address of any DLL using CustomGetModuleHandle, in case you are not sticking to using only NTAPIs (understandable hahaha).

In C, it would look something like this:

```
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress((HMODULE)hNtdll, "NtReadVirtualMemory");
NtQueryInformationProcess = (NtQueryInformationProcessFn)CustomGetProcAddress(hNtdll, "NtQueryInformationProcess");
```

Taking into account that the function structure is defined earlier in the code:

```
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
NtQueryInformationProcessFn NtQueryInformationProcess;
NtReadVirtualMemoryFn NtReadVirtualMemory;
```

And with these lines of code we would have GetModuleHandle and GetProcAddress in the import table, very suspicious. Let's fire up PE-BEAR and see what the table looks like:

![img1](...nativentdllremap_import_table.png)

There are 17 imported functions from Kernel32.dll, the first 2 functions are GetModuleHandleA and GetProcAddress. What about the other 15 functions? I created a very simple program:

```
#include <iostream>

int main(int argc, char* argv[]) {
    printf("Test");
    return 0;
}
```

And the same 15 functions appear in the import table, so it is not related to our code (it is just the CRT!):

![img2](...printf_program_import_table.png) 


## Easiest approach

These addresses are just numbers, so they can be hardcoded or sent to the program as an input parameter. 

For example, we can create a program to print these addresses: 

```
#include <iostream>
#include <windows.h>

int main(int argc, char* argv[]) {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
    printf("[+] ntdll.dll address: \t\t0x%p\n", hNtdll);
    printf("[+] NtReadVirtualMemory address: \t0x%p\n", pNtReadVirtualMemory);
    return 0;
}
```

Hardcoding the values, the previous code would look like this now:

```
HMODULE hNtdll = (HMODULE)0x00007FFABF8B0000;
NtReadVirtualMemory = (NtReadVirtualMemoryFn)0x00007FFABF94D7B0;
NtQueryInformationProcess = (NtQueryInformationProcessFn)CustomGetProcAddress(hNtdll, "NtQueryInformationProcess");
``` 

Using input parameters, the previous code would look like this now:

``` 
``` 

With this, the import table would not include these addresses. Success!(?)
