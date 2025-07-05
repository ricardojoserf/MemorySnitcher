# MemorySnitcher

## TL;DR

- Using dynamic API resolution to avoid functions appearing in the IAT requires only the *NtReadVirtualMemory* address.

- A separate application which just prints the address may look suspicious.

- Using an application with any vulnerability which leaks memory addresses (on purpose) may be stealthier.


----------------------------------------------------------

<br>

## Index

1. [Motivation](#motivation)

2. [ntdll.dll and NtReadVirtualMemory](#ntdlldll-and-ntreadvirtualmemory-for-api-resolution)

3. [Approach 1: Print the address](#approach-1-print-the-address)

4. [Approach 2: More code!](#approach-2-more-code)

5. [Approach 3: Address leak by design](#approach-3-address-leak-by-design)

   - [Leak 1: Format String Vulnerability](#leak-1-format-string-vulnerability)

   - [Leak 2: Stack Over-read](#leak-2-stack-over-read)

   - [Leak 3: Heap override](#leak-3-heap-override)

6. [Putting it into practice: NativeBypassCredGuard example](#putting-it-into-practice-nativebypasscredguard-example)

7. [Conclusion](#conclusion)

<br>




## Motivation

Over the last few months, I have made public some tools that use "only" low-level functions in the ntdll.dll library, also known as NTAPIs. This DLL contains the lowest level functions in user-mode because it interacts directly with *ntoskrnl.exe*, which is already kernel-mode.

Some of these projects have been [NativeDump](https://github.com/ricardojoserf/NativeDump) and [TrickDump](https://github.com/ricardojoserf/TrickDump) to dump the LSASS process; [NativeBypassCredGuard](https://github.com/ricardojoserf/NativeBypassCredGuard) to patch Credential Guard; [NativeTokenImpersonate](https://github.com/ricardojoserf/NativeTokenImpersonate) to impersonate tokens and [NativeNtdllRemap](https://github.com/ricardojoserf/NativeNtdllRemap) to remap ntdll.dll.

It bothered me to have all the necessary functions in the Import Address Table (IAT) of the binary, because this could hint at the true intentions of the compiled binary, so I implemented dynamic API resolution. However, using it, I could not avoid calling *GetModuleHandle* or *LoadLibrary* and *GetProcAddress* - which are part of kernel32.dll, not ntdll.dll!

<br>

## ntdll.dll and NtReadVirtualMemory for API resolution

To use dynamic API resolution, I created functions mimicking *GetModuleHandle* and *GetProcAddress*. *GetModuleHandle* returns the address of a loaded DLL given the library name (*LoadLibrary* works too, but I would only use it if the DLL is not already loaded in the process) and *GetProcAddress* returns the address of a function given the DLL address and the function name. 

By walking the PEB, it is possible to do this using only functions in ntdll.dll:

- Custom implementation of *GetProcAddress* requires only *NtReadVirtualMemory*.

- Custom implementation of *GetModuleHandle* requires *NtReadVirtualMemory*, *NtQueryInformationProcess* and *RtlUnicodeStringToAnsiString*.

The problem: you need some way to resolve at least *NtReadVirtualMemory*, and for that you need the address of ntdll.dll. With those two addresses, you can use your custom implementation of *GetProcAddress* to get the function address of any function in ntdll.dll. 

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

- First, NtReadVirtualMemory address is calculated using *GetModuleHandleA* and *GetProcAddress*. The ntdll.dll library is the first one to get loaded in any process, so there is no need for *LoadLibrary*.

- *NtQueryInformationProcess* and *RtlUnicodeStringToAnsiString* get resolved with the custom implementation of *GetProcAddress*, using ntdll.dll base address.

- Then, any function address in any DLL can be calculated dynamically using the custom implementation of *GetModuleHandle*.

<br>

From this code, we find we only call *GetModuleHandleA* once to get ntdll.dll address; and *GetProcAddress* once to get *NtReadVirtualMemory* address. The rest of the addresses can be calculated dynamically!

The problem is, even if we only call them once, we would have *GetModuleHandleA* and *GetProcAddress* functions in the Import Address Table of the binary, which can be considered suspicious. Let's verify it using PE-BEAR:

![it1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/nativentdllremap_import_table.png)

There are 17 imported functions from Kernel32.dll, the first 2 in the list are the suspicious-looking ones. 

Regarding the other 15 functions, these appear because the binary was compiled with the C Runtime (CRT) included, which embeds the necessary runtime support directly into the executable. I created a very simple program to test it, and those same 15 functions appear in the IAT:

![it2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/printf_program_import_table.png)

There are many blogs about compiling without CRT so I will not do it here (also, maybe not having any function in the IAT looks even worse).

<br>

After some tests, I found that the ntdll.dll base address can be bruteforced given the *NtReadVirtualMemory* address. For example, if the function address is 0x7FFE5424D7B0, the module's base address can be any value from 0x7FFE54100000 to 0x7FFE542D0000. So I created a small script to test all addresses like 0x7FFE54100000, 0x7FFE54120000,... , 0x7FFE541F0000, 0x7FFE54200000, 0x7FFE54210000,... , 0x7FFE542F0000.   

The file *resolve.c* contains the code to resolve the function in any DLL given three parameters: 

- The DLL containing that function

- The function name

- The *NtReadVirtualMemory* address.

![r1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/resolve_1.png)


<br>


## Approach 1: Print the address

The easiest way to obtain the addresses is just to print it: 

```c
#include <iostream>
#include <windows.h>

int main(int argc, char* argv[]) {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
    printf("[+] NtReadVirtualMemory address: \t0x%p\n", pNtReadVirtualMemory);
    return 0;
}
```

![ra](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/read_addresses.png)

It is straightforward, but not very OPSEC-safe:

![rav](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/read_addresses_virustotal_1.png)

The function address value will change for every system and reboot, so hardcoding it is not useful, but we can use the output from a program like *read_addresses.exe* as input parameters for a program such as *resolve.exe*.

<br>



## Approach 2: More code!

The code probably does too much for so few lines of code, so I will rely on AI to create the most generic application (a Task Management program):

```
Give me the code for a C++ application of at least 300 lines that under no circumstances could be considered malicious by an antivirus or EDR. For example, a Task management program
```

The code prompts the user to press a key from 1 to 6, but we will add a secret option 33:

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
    printf("0x%p\n", pNtReadVirtualMemory);
    return;
}
```

Compile [taskmanager_print_addresses.cpp](https://github.com/ricardojoserf/MemorySnitcher/blob/main/taskmanager_print_addresses.cpp) using "x64 Native Tools Command Prompt for VS" and run it:

```
cl /Fe:taskmanager_print_addresses.exe taskmanager_print_addresses.cpp /Od /Zi /RTC1
```

![tm](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_1.png)


VirusTotal shows there are many less detections:

![tmv](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_1_virustotal.png)


Using AI we can generate a new program every time we want, as huge and useless as needed, allowing us to bypass static analysis with this technique.

<br>




## Approach 3: Address leak by design

Once the previous technique is explained to the Blue Team, (I guess) they could create rules to detect it! So, what if instead of printing it, we create a program which leaks the addresses "by mistake" (but not really)? Will AV and EDR solutions detect this?


<br>

### Leak 1: Format String Vulnerability

This code should leak the 0xAAAAAAAAAA and 0xBBBBBBBBBB values in the "leakme1" and "leakme2" variables:

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

Compile it using "x64 Native Tools Command Prompt for VS" and execute it:

```
cl /Fe:format_string.exe leak_format_string.c /Od /Zi /RTC1
```

![fs1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/format_string_1.png)

The values are leaked! Now it is time to leak the function address:

```c
#include <windows.h>
#include <stdio.h>

int main() {
   HMODULE hNtdll = LoadLibraryA("ntdll.dll");
   FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
   
   long long leakme1 = (long long) pNtReadVirtualMemory;
   char input[100];
   sprintf(input, "%p %p %p %p\n");
   printf(input);
   
   return 0;
}
```

The previous simple code snippet is available [in the snippets folder](https://github.com/ricardojoserf/MemorySnitcher/blob/main/snippets/leak_format_string.c), compile it again and get the addresses:

```
cl /Fe:format_string_addresses.exe leak_format_string.c /Od /Zi /RTC1
```

![fs2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/format_string_2.png)

Let's add it to the Task Management code, which invokes this function when the secret code 33 is selected. Compile [taskmanager_format_string.cpp](https://github.com/ricardojoserf/MemorySnitcher/blob/main/taskmanager_format_string.cpp) and run it:

```
cl /Fe:taskmanager_format_string.exe taskmanager_format_string.cpp /Od /Zi /RTC1
```

![tm2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_2.png)

Now it looks much more OPSEC-safe:

![tm2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/memorysnitcher/task_manager_2_virustotal.png)

The rest of the examples offered similar results. If you compile the programs and upload them to Virustotal you might find it is flagged by some vendors, so create a new useless application using AI!

<br>




### Leak 2: Stack Over-read

This code should leak the 0xAAAAAAAAAA and 0xBBBBBBBBBB values in the "leakme1" and "leakme2" variables:

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

Compile it using the following command and execute it:

```
cl /Fe:overread.exe leak_stack_overread.c /Od /Zi /RTC1
```

![or1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/overread_1.png)

The values are leaked! Now it is time to leak the function address:

```c
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
```

The previous simple code snippet is available [in the snippets folder](https://github.com/ricardojoserf/MemorySnitcher/blob/main/snippets/leak_stack_overread.c), compile it again and get the addresses:

```
cl /Fe:overread_addresses.exe leak_stack_overread.c /Od /Zi /RTC1
```

![or2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/overread_2.png)

Let's add it to the Task Management code, which invokes this function when the secret code 33 is selected. Compile [taskmanager_stack_overread.cpp](https://github.com/ricardojoserf/MemorySnitcher/blob/main/taskmanager_stack_overread.cpp) and run it:

```
cl /Fe:taskmanager_stack_overread.exe taskmanager_stack_overread.cpp /Od /Zi /RTC1
```

![tm3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_3.png)

<br>




### Leak 3: Heap override

This code should leak the 0xAAAAAAAAAA and 0xBBBBBBBBBB values in the "leakme1" and "leakme2" variables:

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

Compile it using the following command and execute it:

```
cl /Fe:heap_overread.exe leak_heap_overread.c /Od /Zi /RTC1
```

![hor1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/heap_overread_1.png)

The values are leaked! Now it is time to leak the function address:

```c
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
```

The previous simple code snippet is available [in the snippets folder](https://github.com/ricardojoserf/MemorySnitcher/blob/main/snippets/leak_heap_overread.c), compile it again and get the addresses:

```
cl /Fe:heap_overread_addresses.exe leak_heap_overread.c /Od /Zi /RTC1
```

![hor2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/heap_overread_2.png)


Let's add it to the Task Management code, which invokes this function when the secret code 33 is selected. Compile [taskmanager_heap_overread.cpp](https://github.com/ricardojoserf/MemorySnitcher/blob/main/taskmanager_heap_overread.cpp) and run it:

```
cl /Fe:taskmanager_heap_overread.exe taskmanager_heap_overread.cpp /Od /Zi /RTC1
```

![tm4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/task_manager_4.png)

<br>




## Putting it into practice: NativeBypassCredGuard example

Once we get the leaked addresses, what can we do? Well we can update tools like [NativeBypassCredGuard](https://github.com/ricardojoserf/NativeBypassCredGuard), whose original version resolves function addresses like this:

```
void initializeFunctions() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress((HMODULE)hNtdll, "NtReadVirtualMemory");
    NtQueryInformationProcess = (NtQueryInformationProcessFn)CustomGetProcAddress(hNtdll, "NtQueryInformationProcess");
    NtClose = (NtCloseFn)CustomGetProcAddress(hNtdll, "NtClose");
    NtOpenProcessToken = (NtOpenProcessTokenFn)CustomGetProcAddress(hNtdll, "NtOpenProcessToken");
    NtAdjustPrivilegesToken = (NtAdjustPrivilegesTokenFn)CustomGetProcAddress(hNtdll, "NtAdjustPrivilegesToken");
    NtGetNextProcess = (NtGetNextProcessFn)CustomGetProcAddress(hNtdll, "NtGetNextProcess");
    NtCreateFile = (NtCreateFileFn)CustomGetProcAddress(hNtdll, "NtCreateFile");
    NtReadFile = (NtReadFileFn)CustomGetProcAddress(hNtdll, "NtReadFile");
    NtWriteVirtualMemory = (NtWriteVirtualMemoryFn)CustomGetProcAddress(hNtdll, "NtWriteVirtualMemory");
    NtTerminateProcess = (NtTerminateProcessFn)CustomGetProcAddress(hNtdll, "NtTerminateProcess");
    NtProtectVirtualMemory = (NtProtectVirtualMemoryFn)CustomGetProcAddress(hNtdll, "NtProtectVirtualMemory");
    NtCreateUserProcess = (NtCreateUserProcessFn)CustomGetProcAddress(hNtdll, "NtCreateUserProcess");
    RtlCreateProcessParametersEx = (RtlCreateProcessParametersExFn)CustomGetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
    RtlDestroyProcessParameters = (RtlDestroyProcessParametersFn)CustomGetProcAddress(hNtdll, "RtlDestroyProcessParameters");
    RtlAllocateHeap = (RtlAllocateHeapFn)CustomGetProcAddress(hNtdll, "RtlAllocateHeap");
    RtlFreeHeap = (RtlFreeHeapFn)CustomGetProcAddress(hNtdll, "RtlFreeHeap");
    RtlInitUnicodeString = (RtlInitUnicodeStringFn)CustomGetProcAddress(hNtdll, "RtlInitUnicodeString");
}
```

The updated version, [NativeBypassCredGuard_Updated.cpp](https://github.com/ricardojoserf/MemorySnitcher/blob/main/NativeBypassCredGuard_Updated.cpp), requires two additional input arguments corresponding to the necessary addresses:

```
int main(int argc, char* argv[]) {
   uintptr_t func_address =  (uintptr_t)strtoull(argv[1], NULL, 16);
   NtReadVirtualMemory = (NtReadVirtualMemoryFn)func_address;
   uintptr_t hNtdll = (uintptr_t) get_ntdll_base_address(argv[1]);
   initializeFunctions(hNtdll, func_address);
   ...
}
```

And the function initializeFunctions will now take these two values:

```
void initializeFunctions(uintptr_t hNtdllPtr, uintptr_t NtReadVirtualMemoryPtr) {
    HMODULE hNtdll = (HMODULE)hNtdllPtr; // Instead of LoadLibrary
    NtReadVirtualMemory = (NtReadVirtualMemoryFn)NtReadVirtualMemoryPtr; // Instead of GetProcAddress 

    NtQueryInformationProcess = (NtQueryInformationProcessFn)CustomGetProcAddress(hNtdll, "NtQueryInformationProcess");
    NtClose = (NtCloseFn)CustomGetProcAddress(hNtdll, "NtClose");
    NtOpenProcessToken = (NtOpenProcessTokenFn)CustomGetProcAddress(hNtdll, "NtOpenProcessToken");
    NtAdjustPrivilegesToken = (NtAdjustPrivilegesTokenFn)CustomGetProcAddress(hNtdll, "NtAdjustPrivilegesToken");
    NtGetNextProcess = (NtGetNextProcessFn)CustomGetProcAddress(hNtdll, "NtGetNextProcess");
    NtCreateFile = (NtCreateFileFn)CustomGetProcAddress(hNtdll, "NtCreateFile");
    NtReadFile = (NtReadFileFn)CustomGetProcAddress(hNtdll, "NtReadFile");
    NtWriteVirtualMemory = (NtWriteVirtualMemoryFn)CustomGetProcAddress(hNtdll, "NtWriteVirtualMemory");
    NtTerminateProcess = (NtTerminateProcessFn)CustomGetProcAddress(hNtdll, "NtTerminateProcess");
    NtProtectVirtualMemory = (NtProtectVirtualMemoryFn)CustomGetProcAddress(hNtdll, "NtProtectVirtualMemory");
    NtCreateUserProcess = (NtCreateUserProcessFn)CustomGetProcAddress(hNtdll, "NtCreateUserProcess");
    RtlCreateProcessParametersEx = (RtlCreateProcessParametersExFn)CustomGetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
    RtlDestroyProcessParameters = (RtlDestroyProcessParametersFn)CustomGetProcAddress(hNtdll, "RtlDestroyProcessParameters");
    RtlAllocateHeap = (RtlAllocateHeapFn)CustomGetProcAddress(hNtdll, "RtlAllocateHeap");
    RtlFreeHeap = (RtlFreeHeapFn)CustomGetProcAddress(hNtdll, "RtlFreeHeap");
    RtlInitUnicodeString = (RtlInitUnicodeStringFn)CustomGetProcAddress(hNtdll, "RtlInitUnicodeString");
}
```


First, the address is leaked using the dummy program with the heap overread vulnerability:

![nbcg0](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/nbcg_0.png)


Next, we attempt to run it using the address to find it still works:

```
cl /Fe:NativeBypassCredGuard_Updated.exe NativeBypassCredGuard_Updated.cpp
```

![nbcg1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/nbcg_1.png)


Finally, analyze it with PE-Bear to find *GetProcAddress*, *GetModuleHandle* and *LoadLibrary* are missing... Success!!!

![nbcg2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/memorysnitcher/nbcg_2.png)

<br>



## Conclusion

In summary, dynamically resolving NTAPI functions without relying on the Import Address Table remains a tricky problem due to the chicken-and-egg issue of needing *NtReadVirtualMemory* upfront. 

Directly printing the addresses is the simplest approach but easily raises suspicion and detection risks.

By embedding the address leak inside a seemingly benign, large application, either through intentional vulnerabilities like format string bugs, stack over-reads, or heap overrides, we can covertly expose the address of this function. This technique seems to effectively bypass many static detection mechanisms and can be adapted with autogenerated code to evade heuristic and signature-based detections.

Incorporating this strategy into tools, in this case NativeBypassCredGuard, shows how this could help to make API resolution stealthier because common APIs needed for it such as *GetProcAddress*, *GetModuleHandle* and *LoadLibrary* are not present in the Import Address Table of the binary.
