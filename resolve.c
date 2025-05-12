#include <windows.h>
#include <stdio.h>

typedef enum   _PROCESSINFOCLASS { ProcessBasicInformation = 0 } PROCESSINFOCLASS;
typedef struct _UNICODE_STRING { USHORT Length, MaximumLength; PWSTR Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _STRING { USHORT Length; USHORT MaximumLength; PCHAR Buffer; } ANSI_STRING, * PANSI_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* RtlUnicodeStringToAnsiStringFn)(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);

NtQueryInformationProcessFn NtQueryInformationProcess;
NtReadVirtualMemoryFn NtReadVirtualMemory;
RtlUnicodeStringToAnsiStringFn RtlUnicodeStringToAnsiString;


// Read 8-bytes remotely: NtReadVirtualMemory
PVOID ReadRemoteIntPtr(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[8];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        printf("[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
        return NULL;
    }
    long long value = *(long long*)buff;
    return (PVOID)value;
}


// Read Unicode string remotely: NtReadVirtualMemory + RtlUnicodeStringToAnsiString
char* ReadRemoteWStr(HANDLE hProcess, PVOID mem_address) {
    // Read Unicode string
    if (!hProcess || !mem_address) {
        return (char*)"";
    }
    BYTE buff[512] = { 0 };
    SIZE_T bytesRead = 0;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) { // if (ntstatus != 0) {
        printf("[-] NtReadVirtualMemory failed (0x%X) at 0x%p\n", ntstatus, mem_address);
        return (char*)"<unknown>";
    }
    if (bytesRead < 2) {
        return (char*)"<unknown>";
    }

    // Convert wide char to multi-byte
    static char output[256];
    UNICODE_STRING uniStr;
    ANSI_STRING ansiStr;
    uniStr.Length = (USHORT)wcsnlen((wchar_t*)buff, 256) * sizeof(wchar_t);
    uniStr.MaximumLength = uniStr.Length + sizeof(wchar_t);
    uniStr.Buffer = (wchar_t*)buff;
    ansiStr.Length = 0;
    ansiStr.MaximumLength = sizeof(output);
    ansiStr.Buffer = output;
    NTSTATUS status = RtlUnicodeStringToAnsiString(&ansiStr, &uniStr, FALSE);
    if (status == 0) {
        if (ansiStr.Length < sizeof(output)) {
            output[ansiStr.Length] = '\0';
        }
        else {
            output[sizeof(output) - 1] = '\0';
        }
    }
    return output;
}


// Read remote 16-bytes address - NtReadVirtualMemory
uintptr_t ReadRemoteUintptr_t(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[16];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(uintptr_t), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        printf("[-] Error calling NtReadVirtualMemory (ReadRemoteUintptr_t). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
        return 0;
    }

    uintptr_t value = *(uintptr_t*)buff;
    return value;
}


// Custom implementation for GetModuleHandle - NtQueryInformationProcess + NtReadVirtualMemory + RtlUnicodeStringToAnsiString
uintptr_t CustomGetModuleHandle(HANDLE hProcess, const char* dll_name) {
    int process_basic_information_size = 48;
    int peb_offset = 0x8;
    int ldr_offset = 0x18;
    int inInitializationOrderModuleList_offset = 0x30;
    int flink_dllbase_offset = 0x20;
    int flink_buffer_fulldllname_offset = 0x40;
    int flink_buffer_offset = 0x50;

    BYTE pbi_byte_array[48];
    void* pbi_addr = (void*)pbi_byte_array;
    ULONG ReturnLength;

    NTSTATUS ntstatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi_addr, process_basic_information_size, &ReturnLength);
    if (ntstatus != 0) {
        printf("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return NULL;
    }

    void* peb_pointer = (void*)((uintptr_t)pbi_addr + peb_offset);
    void* pebaddress = *(void**)peb_pointer;
    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);
    if ((long long)ldr_adress == 0) {
        printf("[-] PEB structure is not readable.\n");
        exit(0);
    }
    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_adress + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

    uintptr_t dll_base = (uintptr_t)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);

        dll_base = (uintptr_t)ReadRemoteUintptr_t(hProcess, (void*)((uintptr_t)next_flink + flink_dllbase_offset));

        void* buffer = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        char* base_dll_name = ReadRemoteWStr(hProcess, buffer);

        if (stricmp(base_dll_name, dll_name) == 0) {
            return dll_base;
        }
        next_flink = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + 0x10));
    }

    return 0;
}


// Custom implementation for GetProcAddress - NtReadVirtualMemory
void* CustomGetProcAddress(void* pDosHdr, const char* func_name) {
    int exportrva_offset = 136;
    HANDLE hProcess = (HANDLE)-1;
    DWORD e_lfanew_value = 0;
    SIZE_T aux = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + 0x3C, &e_lfanew_value, sizeof(e_lfanew_value), &aux);
    WORD sizeopthdr_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + 20, &sizeopthdr_value, sizeof(sizeopthdr_value), &aux);
    DWORD exportTableRVA_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + exportrva_offset, &exportTableRVA_value, sizeof(exportTableRVA_value), &aux);
    if (exportTableRVA_value != 0) {
        DWORD numberOfNames_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x18, &numberOfNames_value, sizeof(numberOfNames_value), &aux);
        DWORD addressOfFunctionsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x1C, &addressOfFunctionsVRA_value, sizeof(addressOfFunctionsVRA_value), &aux);
        DWORD addressOfNamesVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x20, &addressOfNamesVRA_value, sizeof(addressOfNamesVRA_value), &aux);
        DWORD addressOfNameOrdinalsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x24, &addressOfNameOrdinalsVRA_value, sizeof(addressOfNameOrdinalsVRA_value), &aux);
        void* addressOfFunctionsRA = (BYTE*)pDosHdr + addressOfFunctionsVRA_value;
        void* addressOfNamesRA = (BYTE*)pDosHdr + addressOfNamesVRA_value;
        void* addressOfNameOrdinalsRA = (BYTE*)pDosHdr + addressOfNameOrdinalsVRA_value;
        for (int i = 0; i < numberOfNames_value; i++) {
            DWORD functionAddressVRA = 0;
            NtReadVirtualMemory(hProcess, addressOfNamesRA, &functionAddressVRA, sizeof(functionAddressVRA), &aux);
            void* functionAddressRA = (BYTE*)pDosHdr + functionAddressVRA;
            char functionName[256];
            NtReadVirtualMemory(hProcess, functionAddressRA, functionName, strlen(func_name) + 1, &aux);
            if (strcmp(functionName, func_name) == 0) {
                WORD ordinal = 0;
                NtReadVirtualMemory(hProcess, addressOfNameOrdinalsRA, &ordinal, sizeof(ordinal), &aux);
                void* functionAddress;
                NtReadVirtualMemory(hProcess, (BYTE*)addressOfFunctionsRA + ordinal * 4, &functionAddress, sizeof(functionAddress), &aux);
                uintptr_t maskedFunctionAddress = (uintptr_t)functionAddress & 0xFFFFFFFF;
                return (BYTE*)pDosHdr + (DWORD_PTR)maskedFunctionAddress;
            }
            addressOfNamesRA = (BYTE*)addressOfNamesRA + 4;
            addressOfNameOrdinalsRA = (BYTE*)addressOfNameOrdinalsRA + 2;
        }
    }
    return NULL;
}


int main(int argc, char* argv[]) {
    if (argc < 5) {
        printf("Usage: %s <ntdll_addr> <ntrvm_addr> <dll_name> <function_name>\n", argv[0]);
        return 1;
    }

    uintptr_t ntdll_address = strtoull(argv[1], NULL, 0);
    uintptr_t func_address = strtoull(argv[2], NULL, 0);
    HMODULE hNtdll = (HMODULE)ntdll_address;
    NtReadVirtualMemory = (NtReadVirtualMemoryFn)func_address;
        
    if (stricmp(argv[3], "ntdll.dll") == 0) {
        const char* func_name = argv[4];
        
        void* pFunc = CustomGetProcAddress(hNtdll, func_name);
        printf("[+] NTAPI address: \t0x%p\n", pFunc);
    }

    else {
        const char* dll_name = argv[3];
        const char* func_name = argv[4];
        
        NtQueryInformationProcess = (NtQueryInformationProcessFn)CustomGetProcAddress(hNtdll, "NtQueryInformationProcess");
        RtlUnicodeStringToAnsiString = (RtlUnicodeStringToAnsiStringFn)CustomGetProcAddress(hNtdll, "RtlUnicodeStringToAnsiString");
        HANDLE currentProcess = (HANDLE)(-1);
        uintptr_t hDLL = CustomGetModuleHandle(currentProcess, dll_name);
        void* pFunction = CustomGetProcAddress(hDLL, func_name);
        printf("[+] DLL Address: \t0x%p\n", hDLL);
        printf("[+] Function Address: \t0x%p\n", pFunction);
    }

    FreeLibrary(hNtdll);
    return 0;
}