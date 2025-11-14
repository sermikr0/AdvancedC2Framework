#include "../../include/common.h"

void HideConsole() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
}

void EvasiveSleep(DWORD ms) {
    DWORD start = GetTickCount();
    volatile double result = 0;
    
    // CPU-intensive work to evade emulation
    for (int i = 0; i < 1000000; i++) {
        result += sqrt((double)i);
    }
    
    DWORD elapsed = GetTickCount() - start;
    if (ms > elapsed) {
        Sleep(ms - elapsed);
    }
}

std::string GetExecutablePath() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    return std::string(path);
}

bool IsElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    
    return isElevated;
}

void RandomDelay() {
    srand((unsigned)time(NULL));
    int delay = 5000 + (rand() % 10000); // 5-15 seconds
    EvasiveSleep(delay);
}