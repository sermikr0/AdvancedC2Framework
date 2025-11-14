#include "../../include/common.h"

bool CheckRAM() {
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    
    // Less than 4GB = likely VM
    return (memStatus.ullTotalPhys < (4ULL * 1024 * 1024 * 1024));
}

bool CheckCPU() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    // Less than 2 CPUs = likely VM
    return (si.dwNumberOfProcessors < 2);
}

bool CheckUptime() {
    // Less than 10 minutes = fresh VM
    return (GetTickCount64() < 600000);
}

bool CheckRecentFiles() {
    char recentPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recentPath);
    
    WIN32_FIND_DATAA findData;
    std::string searchPath = std::string(recentPath) + "\\*";
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    
    int fileCount = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                fileCount++;
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    
    // Less than 10 recent files = likely VM
    return (fileCount < 10);
}

bool CheckMouseMovement() {
    POINT pt1, pt2;
    GetCursorPos(&pt1);
    Sleep(500);
    GetCursorPos(&pt2);
    
    // No mouse movement = automated environment
    return (pt1.x == pt2.x && pt1.y == pt2.y);
}

bool CheckVMProcesses() {
    const char* vmProcesses[] = {
        "vmsrvc.exe", "vmusrvc.exe", "vboxservice.exe", "vboxtray.exe",
        "vmtoolsd.exe", "vmwareuser.exe", "vmacthlp.exe", "qemu-ga.exe"
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (const char* vmProc : vmProcesses) {
                if (_stricmp(pe32.szExeFile, vmProc) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return false;
}

bool IsSandbox() {
    int detectionCount = 0;
    
    if (CheckRAM()) detectionCount++;
    if (CheckCPU()) detectionCount++;
    if (CheckUptime()) detectionCount++;
    if (CheckRecentFiles()) detectionCount++;
    if (CheckVMProcesses()) detectionCount++;
    
    // If 3+ indicators = sandbox
    return (detectionCount >= 3);
}   