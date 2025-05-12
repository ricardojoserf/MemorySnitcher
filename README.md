# MemorySnitcher

## TL;DR

- Using dynamic API resolution to avoid functions to appear in the IAT still requires the ntdll.dll and *NtReadVirtualMemory* addresses.

- A separate application which just prints these addresses looks suspicious.

- Using an application with any vulnerability which leaks memory addresses (on purpose) seems to go undetected.


<br>


## Motivation

Last months, I have made public some tools which use "only" lower-level functions in the ntdll.dll library, also known as NTAPIs. This DLL contains the lowest level functions in user-mode because it interacts directly with *ntoskrnl.exe*, which is already kernel-mode.

Some of these projects have been [NativeDump](https://github.com/ricardojoserf/NativeDump) and [TrickDump](https://github.com/ricardojoserf/TrickDump) to dump the LSASS process; [NativeBypassCredGuard](https://github.com/ricardojoserf/NativeBypassCredGuard) to patch Credential Guard; [NativeTokenImpersonate](https://github.com/ricardojoserf/NativeTokenImpersonate) to impersonate tokens and [NativeNtdllRemap](https://github.com/ricardojoserf/NativeNtdllRemap) to remap ntdll.dll.

It bothered me to have all the necessary functions in the Import Address Table (IAT) of the binary, because this could hint towards the true intentions of the compiled binary, so I implemented dynamic API resolution. However, using it, I could not avoid calling *GetModuleHandle* and *GetProcAddress* - and these are not ntdll.dll functions!

<br>

## ntdll.dll and NtReadVirtualMemory for API resolution

To use dynamic API resolution, I created functions mimicking *GetModuleHandle* and *GetProcAddress*. *GetModuleHandle* returns the address of a loaded DLL given the library name (*LoadLibrary* works too but I would only use it if the DLL is not already loaded in the process) and *GetProcAddress* returns the address of a function given the DLL address and the function name. 

By walking the PEB, it is possible to do this using only functions in ntdll.dll:

- Custom implementation of *GetProcAddress* requires only *NtReadVirtualMemory*.

- Custom implementation of *GetModuleHandle* requires *NtReadVirtualMemory*, *NtQueryInformationProcess* and *RtlUnicodeStringToAnsiString*.

The problem: you need some way to resolve at least ntdll.dll and *NtReadVirtualMemory*. With those 2 addresses, you can use your custom *GetProcAddress* to get the function address of any function in ntdll.dll. 

And, resolving *NtQueryInformationProcess* and *RtlUnicodeStringToAnsiString*, you can use your custom *GetModuleHandle* to get the base address of any DLL, in case you are not sticking to using only NTAPIs.

The way I did it until now is:

```c
#include <windows.h>

// First, the function delegates are defined at the top of the program:
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

NtQueryInformationProcessFn NtQueryInformationProcess;
NtReadVirtualMemoryFn NtReadVirtualMemory;

int main() {
    // NTAPI
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress((HMODULE)hNtdll, "NtReadVirtualMemory");
    void* pNtapi = CustomGetProcAddress(hNtdll, "NtClose");
    
    // Function in other DLL
    NtQueryInformationProcess = (NtQueryInformationProcessFn)CustomGetProcAddress(hNtdll, "NtQueryInformationProcess");
    RtlUnicodeStringToAnsiString = (RtlUnicodeStringToAnsiStringFn)CustomGetProcAddress(hNtdll, "RtlUnicodeStringToAnsiString");
    uintptr_t hDLL = CustomGetModuleHandle((HANDLE)(-1), "kernel32.dll");
    void* pFunction = CustomGetProcAddress(hDLL, "CloseHandle");
    ...
}
```

- First, NtReadVirtualMemory address is calculated using *GetModuleHandleA* and *GetProcAddress*. The ntdll.dll library is the first one to get loaded in any process, so you would not need *LoadLibrary*.

- *NtQueryInformationProcess* and *RtlUnicodeStringToAnsiString* get resolved with the custom implementation of *GetProcAddress*, using ntdll.dll base address.

- Then, any function address in any DLL can be calculated dynamically using the custom implementation of *GetModuleHandle*.

From this code, we find we only call *GetModuleHandleA* once to get ntdll.dll address; and *GetProcAddress* once to get *NtReadVirtualMemory* address. The rest of addresses can be calculated dynamically!

The problem is, even if we only call them once, we would have *GetModuleHandleA* and *GetProcAddress* functions in the Import Address Table of the binary, which can be considered suspicious. 

Let's check it with PE-BEAR:

![it1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/nativentdllremap_import_table.png)

There are 17 imported functions from Kernel32.dll, the first 2 in the list are the suspicious-looking ones. 

Regarding the other 15 functions, these appear because the binary was compiled with the C Runtime (CRT) included, which embeds the necessary runtime support directly into the executable. I created a very simple program to test it, and those same 15 functions appear in the IAT:

![it2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/printf_program_import_table.png)

There are many blogs about compiling without CRT so I will not do it here (also, maybe not having any function in the IAT looks even worse).

These 2 addresses are just numbers, so could be hardcoded or used as input arguments to the program. But, how can we get these values?

<br>


## Approach 1: Print the addresses directly

The easiest way to obtain these addreses is just to print them: 

```c
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

But it does not look very OPSEC-like:

![rav](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/read_addresses_virustotal_1.png)

However, these addresses are just numbers, so there are some silly methods to use them. 

Their values will change for every system reboot, so hardcoding them is not useful, but we can use the output from a program like *read_addresses.exe* as input parameters for our program.

The file *resolve.c* contains the code to resolve the function in any DLL given four parameters: the DLL containing that function, the function name, ntdll.dll address and *NtReadVirtualMemory* address.

![r1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/resolve_1.png)

We could not find an stealthy way to resolve these 2 addresses, but we know it is enough to send these 2 addresses as parameters to a program, and with that the program can resolve any function. Without any extra function in the IAT! 

<br>


## Approach 2: Moar code!

Probably the code does too much for so little lines of code, so I will rely on AI to create the most generic application (a Task Manager):

```
Give me the code for a C++ application of at least 300 lines that under no circumstances could be considered malicious by an antivirus or EDR. For example, a Task management program
```

The code prompts the user to press a key from 1 to 6, we will add a secret option 33:

```c
switch (choice) {
    case 1: addTask(); break;
    ...
    case 33: test(); break;
    case 0: cout << "Exiting...\n"; break;
    default: cout << "Invalid choice. Try again.\n";
}
```

The called function will print the addresses:

```c
void test() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
    printf("0x%p\t0x%p\n", hNtdll, pNtReadVirtualMemory);
    return;
}
```

```
cl /Fe:taskmanager_print_addresses.exe taskmanager_print_addresses.cpp /Od /Zi /RTC1
```

![tm](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_1.png)


VirusTotal shows there are many less detections:

![tmv](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_1_virustotal.png)


Using AI we can generate a new program every time we want, as huge and useless as needed! So we could bypass static analysis with a technique like this.

<br>


## Approach 3: Address leak by design

Once the previous technique is explained to the Blue Team, (I guess) they could create rules to detect it! So, what if instead of printing it, we create a program which leaks the addresses "by mistake"? 

Can AV and EDR solutions detect this? This is a honest question, I do not know the answer xD


### 3.1. Format String Vulnerability

This simple code should leak the 0xAAAAAAAAAA and 0xBBBBBBBBBB values in the "leakme1" and "leakme2" variables:

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
cl /Fe:leak_format_string.exe leak_format_string.c /Od /Zi /RTC1
```

And execute it:

![fs1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/format_string_1.png)

The values are leaked! Now it is time to leak the addresses:

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

![fs2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/format_string_2.png)

Let's add it to the Task Management code, which calls this function using the secret code 33. Compile *taskmanager_format_string.c* and run it:

```
cl /Fe:taskmanager_format_string.exe taskmanager_format_string.cpp /Od /Zi /RTC1
```

![tm2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_2.png)

Now it looks much more OPSEC-safe:

![tm2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/memorysnitcher/task_manager_2_virustotal.png)

The rest of the examples offered similar results. If you compile the programs and upload them to Virustotal you might find it is flagged by some vendors, so create a new useless application using AI!

<br>


### 3.2. Stack Over-read

This simple code should leak the 0xAAAAAAAAAA and 0xBBBBBBBBBB values in the "leakme1" and "leakme2" variables:

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
cl /Fe:leak_stack_overread.exe leak_stack_overread.c /Od /Zi /RTC1
```

And execute it:

![or1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/overread_1.png)

The values are leaked! Now it is time to leak the addresses:

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

![or2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/overread_2.png)

Let's add it to the Task Management code, which calls this function using the secret code 33. Compile *taskmanager_stack_overread.c* and run it:

```
cl /Fe:taskmanager_stack_overread.exe taskmanager_stack_overread.cpp /Od /Zi /RTC1
```

![tm3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_3.png)

<br>


### 3.3. Heap override

This simple code should leak the 0xAAAAAAAAAA and 0xBBBBBBBBBB values in the "leakme1" and "leakme2" variables:

```c
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
```

Compile it like this:

```
cl /Fe:leak_heap_overread.exe leak_heap_overread.c /Od /Zi /RTC1
```

And execute it:

![hor1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/heap_overread_1.png)


The values are leaked! Now it is time to leak the addresses:

```c
#include <windows.h>
#include <stdio.h>

int main() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");

    char *buffer = (char *)malloc(32);
    strcpy(buffer, "leak");
    long long *leakme1 = (long long *)(buffer + 16);
    long long *leakme2 = (long long *)(buffer + 24);
    *leakme1 = hNtdll;
    *leakme2 = pNtReadVirtualMemory;

    for (int i = 23; i >= 16; i--) { printf("%02X", (unsigned char)buffer[i]); }
    printf(" ");
    for (int i = 31; i >= 24; i--) { printf("%02X", (unsigned char)buffer[i]); }
    printf("\n");

    return 0;
}
```

Compile it again and get the addresses:

![hor2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/heap_overread_2.png)


Let's add it to the Task Management code, which calls this function using the secret code 33. Compile *taskmanager_heao_overread.c* and run it:

```
cl /Fe:taskmanager_heap_overread.exe taskmanager_heap_overread.cpp /Od /Zi /RTC1
```

![tm4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_4.png)

<br>
