# MemorySnitcher

## TL;DR - Does a poorly-coded application get detected?

- I use dynamic API resolution to avoid functions to appear in the import table of the binary, but it requires at least the ntdll.dll library and the *NtReadVirtualMemory* function addresses.

- Using a separate application which just prints these addresses might look suspicious.

- The proposal is using an application with any vulnerability which leaks memory addresses (on purpose).
<br>

## Motivation

Last months, I have made public some tools which use "only" lower-level functions in the ntdll.dll library. This DLL contains the lowest level functions in user mode because it interacts directly with ntoskrnl.exe, which is already kernel mode.

Some of these projects have been:

- [NativeDump](https://github.com/ricardojoserf/NativeDump) and [TrickDump](https://github.com/ricardojoserf/TrickDump): To dump the LSASS process.

- [NativeBypassCredGuard](https://github.com/ricardojoserf/NativeBypassCredGuard): To patch Credential Guard.

- [NativeTokenImpersonate](https://github.com/ricardojoserf/NativeTokenImpersonate): To impersonate tokens.

- [NativeNtdllRemap](https://github.com/ricardojoserf/NativeNtdllRemap): Remap ntdll.dll using a suspended process.


However, it bothered me to have all the necessary functions in the import table of the binary, because this could hint towards the true intentions of the compiled binary - you know, importing NtOpenProcessToken and NtAdjustPrivilegesToken might look suspicious :)

To solve this, I decided to use dynamic API resolution by creating functions mimicking GetModuleHandle and GetProcAddress. As a short reminder, GetModuleHandle returns the address of a loaded DLL given the library name (LoadLibrary works too but I would only use it if the DLL is not already loaded in the process) and GetProcAddress returns the address of a function given the DLL address and the function name. """The ntdll.dll library is always the first DLL to get loaded in a process and it gets always loaded, so we can simplify this problem to GetModuleHandle + GetProcAddress when we work with NTAPIs."""

By walking the PEB it is possible to get this functionality using custom implementations, and you can do it using only functions in ntdll.dll:

- CustomGetModuleHandle requires NtQueryInformationProcess and NtReadVirtualMemory

- CustomGetProcAddress requires only NtReadVirtualMemory

The problem here: you need some way to resolve at least ntdll.dll address and NtReadVirtualMemory. With those 2 addresses, you can use CustomGetProcAddress to get the function address of any function in ntdll.dll. Or, resolving NtQueryInformationProcess, you can use CustomGetProcAddress to get the base address of any DLL using CustomGetModuleHandle, in case you are not sticking to using only NTAPIs (understandable hahaha).

In C, first the function delegates are defined:

```
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

NtQueryInformationProcessFn NtQueryInformationProcess;
NtReadVirtualMemoryFn NtReadVirtualMemory;
```

Then, resolving the function *NtQueryInformationProcess* would look like this:

```
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress((HMODULE)hNtdll, "NtReadVirtualMemory");
NtQueryInformationProcess = (NtQueryInformationProcessFn)CustomGetProcAddress(hNtdll, "NtQueryInformationProcess");
```

With this code we would have *GetModuleHandleA* and *GetProcAddress* in the import table, very suspicious. Let's run PE-BEAR and see what the table looks like:

![it1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/nativentdllremap_import_table.png)


There are 17 imported functions from Kernel32.dll, the first 2 functions are those functions. Regarding the other 15 functions, I created a very simple program to test if these always appear:

```
#include <iostream>

int main(int argc, char* argv[]) {
    printf("Test");
    return 0;
}
```

And the same 15 functions appear in the import table, so it is not related to our code:

![it2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/printf_program_import_table.png)


This means the binary was compiled with the C Runtime (CRT) included, which embeds the necessary runtime support directly into the executable. There are many blogs about compiling without CRT and it is not my goal to do this: if I get only these functions in the import table I think it will be good enough.  


<br>

## Easiest approach

These addresses are just numbers, so there are some silly methods to use them, but these will change for every system. First, let's print the values: 

```
#include <iostream>
#include <windows.h>

int main(int argc, char* argv[]) {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
    printf("[+] ntdll.dll address: \t\t\t0x%p\n", hNtdll);
    printf("[+] NtReadVirtualMemory address: \t0x%p\n", pNtReadVirtualMemory);
    return 0;
}
```

![ra](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/read_addresses.png)


We can simply hardcode the values in the code, making the previous code to look like this now:

```
HMODULE hNtdll = (HMODULE)0x00007FFABF8B0000;
NtReadVirtualMemory = (NtReadVirtualMemoryFn)0x00007FFABF94D7B0;
NtQueryInformationProcess = (NtQueryInformationProcessFn)CustomGetProcAddress(hNtdll, "NtQueryInformationProcess");
``` 

Or we can use input parameters:

```
int main(int argc, char* argv[]) {
    if (argc == 3) {
        char* endptr1;
        char* endptr2;
        uintptr_t ntdllAddr = (uintptr_t)strtoull(argv[1], &endptr1, 0);
        uintptr_t ntrvmAddr = (uintptr_t)strtoull(argv[2], &endptr2, 0);            
        HMODULE hNtdll = (HMODULE)ntdllAddress;
        NtReadVirtualMemory = (NtReadVirtualMemoryFn)ntrvmAddress;
        NtQueryInformationProcess = (NtQueryInformationProcessFn)CustomGetProcAddress(hNtdll, "NtQueryInformationProcess");
        ...
    }
}
``` 

With this, the import table would not include these addresses. Success! 

![rav](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/read_addresses_virustotal_1.png)


Or maybe not xD


<br>

## A tree in the forest: Moar code!

Probably the code does too much for so little lines of code, so I will rely on AI to create the most generic Task management program:

```
Give me the code for a C++ application of at least 300 lines that under no circumstances could be considered malicious by an antivirus or EDR. For example, a Task management program
```

The code prompts the user to press a key from 1 to 6, we will add a secret option 33:

```
switch (choice) {
    case 1: addTask(); break;
    ...
    case 33: test(); break;
    case 0: cout << "Exiting...\n"; break;
    default: cout << "Invalid choice. Try again.\n";
}
```

The called function will print the addresses:

```
void test() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
    printf("0x%p\t0x%p\n", hNtdll, pNtReadVirtualMemory);
    return;
}
```

![tm](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_1.png)


VirusTotal shows there are many less detections:

![tmv](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_1_virustotal.png)


Using AI we can generate a new function every time we want! So we could bypass static analysis with a technique like this.


<br>


## Leaking addresses: Vulnerable code on purpose

Once the previous technique is explained to the Blue Team, (I guess) they could create rules to detect it! So, what if instead of printing it, we create a program which leaks the addresses "by mistake"? Can AV and EDR solutions detect this? This is a honest question, I do not know the answer xD


### 1. Format String Vulnerability

This simple code should leak the 0xAAAAAAAAAA and 0xBBBBBBBBBB values in the "leakme1" and "leakme2" variable:

```c
#include <stdio.h>

int main() {
    long long leakme1 = 733007751850; // 0xAAAAAAAAAA
    long long leakme2 = 806308527035; // 0xBBBBBBBBBB
    char input[100];
    sprintf(input, "%p %p %p %p\n");
    printf(input);
    
    return 0;
}
```

Compile it like this:

```
cl /Fe:format_string.exe format_string.c /Od /Zi /RTC1
```

And execute it:

![fs1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/format_string_1.png)


The values are leaked! Now it is time to implement this to leak the addresses:

```c
#include <windows.h>
#include <stdio.h>

int main() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
    
    long long leakme1 = (long long) hNtdll;
    long long leakme2 = (long long) pNtReadVirtualMemory;
    char input[100];
    sprintf(input, "%p %p %p %p\n");
    printf(input);

    return 0;
}
```

Compile it again and get the addresses:

```
cl /Fe:format_string_addresses.exe format_string_addresses.c /Od /Zi /RTC1
```


![fs2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/format_string_2.png)


<br>

### 2. Use-After-Free

This simple code should leak the 0xAAAAAAAAAA and 0xBBBBBBBBBB values in the "leakme1" and "leakme2" variable:

```c
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
```

Compile it like this:

```
cl /Fe:use_after_free.exe use_after_free.c /Od /Zi /RTC1
```

And execute it:

![uaf1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/use_after_free_1.png)


The values are leaked! Now it is time to implement this to leak the addresses:

```c
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
```

Compile it again and get the addresses:

```
cl /Fe:use_after_free_addresses.exe use_after_free_addresses.c /Od /Zi /RTC1
```


![uaf2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/use_after_free_2.png)

<br>


### 3. Buffer Over-read (Heartbleed-like)

This simple code should leak the 0xAAAAAAAAAA and 0xBBBBBBBBBB values in the "leakme1" and "leakme2" variable:

```c
#include <stdio.h>

int main() {
    char buffer[8] = "leak";
    long long leakme1 = 733007751850; // 0xAAAAAAAAAA
    long long leakme2 = 806308527035; // 0xBBBBBBBBBB
    unsigned char *ptr = (unsigned char *)buffer;
    
    for (int i = 23; i >= 16; i--) { printf("%02X", ptr[i]); }
    printf(" ");
    for (int i = 31; i >= 24; i--) { printf("%02X", ptr[i]); }
    printf("\n");
    
    return 0;
}
```

Compile it like this:

```
cl /Fe:overread.exe overread.c /Od /Zi /RTC1
```

And execute it:

![or1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/overread_1.png)


The values are leaked! Now it is time to implement this to leak the addresses:

```c
#include <windows.h>
#include <stdio.h>

int main() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
    
    char buffer[8] = "leak";
    long long leakme1 = (long long) hNtdll;
    long long leakme2 = (long long) pNtReadVirtualMemory;
    unsigned char *ptr = (unsigned char *)buffer;

    for (int i = 23; i >= 16; i--) { printf("%02X", ptr[i]); }
    printf(" ");
    for (int i = 31; i >= 24; i--) { printf("%02X", ptr[i]); }
    printf("\n");
    
    return 0;
}
```

Compile it again and get the addresses:

```
cl /Fe:overread_addresses.exe overread_addresses.c /Od /Zi /RTC1
```


![or2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/overread_2.png)


<br>