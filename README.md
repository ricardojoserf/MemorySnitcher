# MemorySnitcher

## TL;DR

- I use dynamic API resolution to avoid functions to appear in the Import Address Table of the binary, but it requires at least the ntdll.dll library and the *NtReadVirtualMemory* function addresses.

- Using a separate application which just prints these addresses might look suspicious.

- The proposal is using an application with any vulnerability which leaks memory addresses (on purpose).

- Does a poorly-coded application get detected?


<br>

## Motivation

Last months, I have made public some tools which use "only" lower-level functions in the ntdll.dll library, also known as NTAPIs. This DLL contains the lowest level functions in user mode because it interacts directly with ntoskrnl.exe, which is already kernel mode.

Some of these projects have been:

- [NativeDump](https://github.com/ricardojoserf/NativeDump) and [TrickDump](https://github.com/ricardojoserf/TrickDump): To dump the LSASS process.

- [NativeBypassCredGuard](https://github.com/ricardojoserf/NativeBypassCredGuard): To patch Credential Guard.

- [NativeTokenImpersonate](https://github.com/ricardojoserf/NativeTokenImpersonate): To impersonate tokens.

- [NativeNtdllRemap](https://github.com/ricardojoserf/NativeNtdllRemap): Remap ntdll.dll using a suspended process.


However, it bothered me to have all the necessary functions in the Import Address Table (IAT) of the binary, because this could hint towards the true intentions of the compiled binary - you know, importing *NtOpenProcessToken* and *NtAdjustPrivilegesToken* might look suspicious :)

To solve this, I decided to use dynamic API resolution by creating functions mimicking *GetModuleHandle* and *GetProcAddress*. *GetModuleHandle* returns the address of a loaded DLL given the library name (*LoadLibrary* works too but I would only use it if the DLL is not already loaded in the process) and *GetProcAddress* returns the address of a function given the DLL address and the function name. 

By walking the PEB, it is possible to get this functionality with custom implementations and using only functions in ntdll.dll:

- Custom implementation of *GetModuleHandle* requires *NtQueryInformationProcess* and *NtReadVirtualMemory*

- Custom implementation of *CustomGetProcAddress* requires only *NtReadVirtualMemory*

The problem: you need some way to resolve at least ntdll.dll and *NtReadVirtualMemory*. With those 2 addresses, you can use CustomGetProcAddress to get the function address of any function in ntdll.dll. Or, resolving *NtQueryInformationProcess*, you can use CustomGetProcAddress to get the base address of any DLL using CustomGetModuleHandle, in case you are not sticking to using only NTAPIs.

The ntdll.dll library is always the first DLL to get loaded in a process and it gets always loaded, so we can use *GetModuleHandle* without the need for *LoadLibrary*.

In C, the function delegates are defined at the top of the program:

```
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

NtQueryInformationProcessFn NtQueryInformationProcess;
NtReadVirtualMemoryFn NtReadVirtualMemory;
```

Then, the code to resolve the function *NtReadVirtualMemory* address is added to the main function:

```
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress((HMODULE)hNtdll, "NtReadVirtualMemory");
```

After this, *NtQueryInformationProcess* would get resolved and then any function in any DLL. But we would have *GetModuleHandleA* and *GetProcAddress* in the IAT, which is suspicious. 

Let's run PE-BEAR and check this:

![it1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/nativentdllremap_import_table.png)


There are 17 imported functions from Kernel32.dll, the first 2 in the list are the suspicious-looking ones. 

Regarding the other 15 functions, these appear because the binary was compiled with the C Runtime (CRT) included, which embeds the necessary runtime support directly into the executable. 

I created a very simple program to test it, simply printing a message to the console, and those same 15 functions appear in the IAT:

![it2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/printf_program_import_table.png)


There are many blogs about compiling without CRT and it is not my goal to do this. Also, maybe not having any function in the IAT looks even worse!

<br>

## Approach 1: Print the addresses

The easiest way to obtain these addreses is just to print them: 

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

But it does not look very OPSEC-like:

![rav](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/read_addresses_virustotal_1.png)

However, these addresses are just numbers, so there are some silly methods to use them. 

Their values will change for every system reboot, so hardcoding them is not useful, but we can use the output from a program like *read_addresses.exe* as input parameters for our program.

The file *resolve.c* contains the code to resolve the function in any DLL given four parameters: the DLL containing that function, the function name, ntdll.dll address and *NtReadVirtualMemory* address.

```c
```

![r1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/resolve_1.png)

We could not find an stealthy way to resolve these 2 addresses, but we know it is enough to send these 2 addresses as parameters to a program, and with that the program can resolve any function. Without functions in the IAT! 

<br>


## Approach 2: Moar code!

Probably the code does too much for so little lines of code, so I will rely on AI to create the most generic application (a Task Manager):

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


Using AI we can generate a new program every time we want, as huge and useless as needed! So we could bypass static analysis with a technique like this.


<br>

## Approach 3: Address leak by design

Once the previous technique is explained to the Blue Team, (I guess) they could create rules to detect it! So, what if instead of printing it, we create a program which leaks the addresses "by mistake"? 

Can AV and EDR solutions detect this? This is a honest question, I do not know the answer xD


### 1. Format String Vulnerability

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
cl /Fe:leak_formatstring.exe leak_formatstring.c /Od /Zi /RTC1
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


Let's add it to the Task Management code, which calls this function using the secret code 331:

```c
```

<br>

### 2. Buffer Over-read (Heartbleed-like)

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
cl /Fe:leak_overread.exe leak_overread.c /Od /Zi /RTC1
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


Let's add it to the Task Management code, which calls this function using the secret code 332:

```c
```

<br>

### Heap override

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *buffer = (char *)malloc(8);
    strcpy(buffer, "leak");  // Copiamos un string pequeño

    // Variables ahora también en heap (simulando datos sensibles contiguos)
    long long *leakme1 = (long long *)malloc(sizeof(long long));
    long long *leakme2 = (long long *)malloc(sizeof(long long));
    *leakme1 = 0xAAAAAAAAAA;
    *leakme2 = 0xBBBBBBBBBB;

    // Lectura más allá del final del buffer
    unsigned char *ptr = (unsigned char *)buffer;
    for (int i = 16; i < 24; i++) {
        printf("%02X", ptr[i]);
    }
    printf(" ");
    for (int i = 24; i < 32; i++) {
        printf("%02X", ptr[i]);
    }
    printf("\n");

    // Limpieza
    free(buffer);
    free(leakme1);
    free(leakme2);

    return 0;
}
```

### Stack/Heap Leak via Format String

```
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Heap variable
    long long *leakme_heap = (long long *)malloc(sizeof(long long));
    *leakme_heap = 0xABCDEFABCD;

    // Stack variable
    long long leakme_stack = 0xDEADBEEFDEAD;

    // Vulnerable format string usage
    char input[100];
    sprintf(input, "%p %p %p %p %p %p %p %p\n");  // Controlled format string
    printf(input);  // Unsafe: input is used directly as format string

    free(leakme_heap);
    return 0;
}
```
