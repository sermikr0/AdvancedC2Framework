#include "../../include/common.h"

bool InstallRegistryPersistence(const char* execPath, const char* name) {
    HKEY hKey;
    const char* regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    if (RegOpenKeyExA(HKEY_CURRENT_USER, regPath, 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    LONG result = RegSetValueExA(hKey, name, 0, REG_SZ, 
        (BYTE*)execPath, (DWORD)strlen(execPath) + 1);

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

bool RemoveRegistryPersistence(const char* name) {
    HKEY hKey;
    const char* regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    if (RegOpenKeyExA(HKEY_CURRENT_USER, regPath, 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    LONG result = RegDeleteValueA(hKey, name);
    RegCloseKey(hKey);
    
    return (result == ERROR_SUCCESS);
}