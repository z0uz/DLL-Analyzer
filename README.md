# 🔍 Advanced DLL/EXE Analyzer - Malware Analysis & Reverse Engineering Toolkit

**⚠️ Legal Notice:** Use these tools only for legitimate reverse engineering, malware analysis, and security research purposes on software you own or have explicit permission to analyze.

---

## 🚀 **NEW FEATURES - POWERFUL MALWARE ANALYSIS CAPABILITIES**

### 🎯 **Interactive Analysis Mode**
- **Quick Security Assessment** - Instant risk scoring (0-100)
- **18 Detailed Analysis Options** - Deep dive into every aspect
- **Real-time Threat Detection** - Identify malware immediately
- **Windows Console Compatible** - No encoding issues

### 🔓 **Advanced Unpacking Capabilities**
- **UPX Detection & Unpacking** - Automatically unpack UPX-packed malware
- **Packed Section Analysis** - Find hidden code regions
- **Entry Point Analysis** - Locate real malicious code
- **Hidden String Extraction** - Extract strings from packed regions
- **Entropy Distribution** - Visualize packed vs unpacked areas

### 🌐 **Network Threat Intelligence**
- **186+ URL Extraction** - Find all C&C servers
- **IP Address Discovery** - Direct connection endpoints
- **Registry Key Analysis** - Persistence mechanisms
- **API Pattern Detection** - Anti-analysis techniques

### 🛡️ **Security Risk Assessment**
- **Critical Risk Scoring** - 80/100 for dangerous files
- **Timeline Analysis** - Future timestamp detection
- **Certificate Verification** - Digital signature analysis
- **Code Pattern Analysis** - Anti-debug, anti-VM, anti-sandbox

## 📦 **Installation**

```bash
# Clone the repository
git clone https://github.com/yourusername/dll-analyzer.git
cd dll-analyzer

# Install dependencies
pip install -r requirements.txt
pip install capstone  # For advanced disassembly
```

### **Requirements**
```
pefile>=2023.2.7
capstone>=4.0.2
python>=3.7
```

---

## 🎮 **Usage Examples**

### **🔥 Interactive Mode (NEW!)**
```bash
# Interactive analysis with menu-driven options
python dll_analyzer.py "suspicious_file.exe"

# Example output:
# QUICK SECURITY ASSESSMENT
# • Risk Score: 80/100
# • Risk Level: CRITICAL  
# • Action: DO NOT EXECUTE - Analyze in isolated sandbox
# • Packed: Yes WARNING
# • Signed: No WARNING
# • URLs Found: 186 WARNING
```

### **📊 Quick Analysis**
```bash
# Basic DLL analysis
python dll_analyzer.py C:\Windows\System32\kernel32.dll

# Export to JSON
python dll_analyzer.py "malware.exe" -o analysis.json -f json

# Export to text report
python dll_analyzer.py "malware.exe" -o report.txt -f txt
```

### **🎯 Targeted Analysis**
```bash
# Extract only strings
python dll_analyzer.py "file.exe" --strings-only

# Extract only exports
python dll_analyzer.py "file.dll" --exports-only

# Extract only imports
python dll_analyzer.py "file.dll" --imports-only
```

---

## 🔧 **Interactive Analysis Options**

When you run the tool in interactive mode, you'll see this menu:

```
DETAILED ANALYSIS OPTIONS:
1. Show all embedded URLs
2. Analyze suspicious imports
3. Show dependency details
4. Extract and analyze strings
5. Check for .NET metadata
6. Show file hashes for malware checking
7. Analyze entropy distribution
8. Detect packing algorithms
9. Extract IP addresses
10. Analyze code patterns (anti-analysis)
11. File timeline analysis
12. Certificate analysis
13. Attempt UPX unpacking
14. Analyze packed sections
15. Extract hidden strings
16. Entry point analysis
17. Generate comprehensive security report
18. Exit
```

---

## 🚨 **Real-World Malware Analysis**

### **Critical Risk Detection Example:**
```
FINAL ASSESSMENT:
• Security Score: 80/100
• Risk Level: CRITICAL
• Action: DO NOT EXECUTE - Analyze in isolated sandbox

ISSUES FOUND:
   1. Packed/obfuscated executable
   2. No digital signature
   3. High number of embedded URLs (186)
   4. Suspicious future timestamp

RECOMMENDATIONS:
   • Unpack using UPX or manual unpacking
   • Decompile with dnSpy to view source
   • Investigate embedded URLs
   • Submit to VirusTotal for malware analysis
   • Run in sandbox (Cuckoo, Any.Run)
```

## Tools Included

### 1. dll_analyzer.py (ENHANCED)
**Advanced malware analysis tool with:**
- **Interactive Mode** - Menu-driven analysis
- **Security Scoring** - 0-100 risk assessment
- **Unpacking Capabilities** - UPX detection and extraction
- **Network Intelligence** - URL/IP extraction
- **Threat Detection** - Anti-analysis techniques
- **Timeline Analysis** - Timestamp anomalies
- **Certificate Analysis** - Digital signature verification
- **Entropy Analysis** - Packed region detection
- **Hidden String Extraction** - Extract from packed areas
- **Entry Point Analysis** - Find real malicious code

### 2. disassembler.py
Advanced analysis tool with:
- Function disassembly (requires Capstone)
- Pattern recognition
- Import heuristics analysis
- Section entropy analysis
- Function signature generation
- Suspicious API detection

---

## 🔍 **Advanced Features**

### **🔓 Unpacking Analysis**
- **UPX Detection**: Automatically detects UPX-packed malware
- **Manual Unpacking**: Attempts to extract original code
- **Entry Point Analysis**: Finds real malicious code location
- **Packed Sections**: Identifies hidden/encrypted regions

### **🌐 Network Intelligence**
- **URL Extraction**: Finds all HTTP/HTTPS endpoints
- **IP Discovery**: Direct connection endpoints
- **C&C Detection**: Command & Control server identification
- **Protocol Analysis**: HTTP, WebSocket, custom protocols

### **🛡️ Threat Detection**
- **Anti-Analysis**: Detects debuggers, VMs, sandboxes
- **Persistence**: Registry, services, scheduled tasks
- **Evasion**: Sleep delays, time checks, API hooks
- **Injection**: Process injection, DLL injection

### **📊 Risk Assessment**
- **Security Scoring**: 0-100 risk assessment
- **Timeline Analysis**: Future timestamp detection
- **Certificate Analysis**: Digital signature verification
- **Entropy Analysis**: Packed vs unpacked regions

---

## 📋 **Output Formats**

### **JSON Format**
```json
{
  "dll_info": {
    "file_path": "malware.exe",
    "machine_type": "AMD64",
    "is_64bit": true,
    "file_size": 1024576
  },
  "characteristics": {
    "is_packed": true,
    "is_signed": false,
    "is_dotnet": false,
    "has_high_entropy": true
  },
  "embedded_urls": [
    "https://api.chatgpt[.]malware[.]com/update",
    "https://c2-server[.]xyz/heartbeat"
  ],
  "ip_addresses": [
    "203.0.113.45",
    "198.51.100.23"
  ],
  "security_score": 80,
  "risk_level": "CRITICAL"
}
```

### **Text Report Format**
Human-readable reports with:
- **Security Assessment Summary**
- **Detailed Technical Analysis**
- **Recommendations for Next Steps**
- **Threat Intelligence Indicators**

---

## 🎯 **Use Cases**

### **🔒 Malware Analysis**
- **Sandbox Pre-analysis**: Quick triage before sandbox
- **Threat Intelligence**: Extract IOCs and indicators
- **Family Identification**: Compare with known malware
- **Behavior Prediction**: Anticipate malware actions

### **🔍 Reverse Engineering**
- **API Analysis**: Understand software dependencies
- **Function Discovery**: Find exported functions
- **Import Analysis**: See what libraries are used
- **Structure Analysis**: Understand PE file layout

### **🛡️ Security Research**
- **Vulnerability Research**: Find security issues
- **Digital Forensics**: Analyze suspicious files
- **Incident Response**: Quick malware identification
- **Security Auditing**: Verify file authenticity

---

## ⚠️ **Ethical Guidelines**

1. **Only analyze software you own** or have explicit permission
2. **Respect license agreements** and terms of service
3. **Follow local laws** and regulations
4. **Use for educational purposes** and legitimate security research
5. **Do not distribute** copyrighted material
6. **Analyze malware in isolated environments** only

---

## 🔧 **Dependencies**

- **pefile**: PE file format parsing
- **capstone**: Disassembly framework (optional for advanced features)
- **Python 3.7+**: Core runtime requirement

---

## 🐛 **Troubleshooting**

### **Common Issues**
1. **"DLL not found"**: Check file path and permissions
2. **"Access denied"**: Run as administrator for system files
3. **"Capstone not available"**: Install with `pip install capstone`
4. **"Invalid PE file"**: Verify file is a valid Windows DLL/EXE
5. **"Unicode errors"**: Tool handles Windows console encoding

### **Tips**
- **Use absolute paths** for system files
- **Run as admin** for system DLL analysis
- **Large files** may take time to analyze
- **Export results** for large analyses
- **Use interactive mode** for suspicious files

---

## 🚀 **Advanced Usage**

### **Python API**
```python
from dll_analyzer import DLLAnalyzer

# Create analyzer instance
analyzer = DLLAnalyzer("suspicious.exe")

# Load and analyze
analyzer.load_dll()
results = analyzer.full_analysis()

# Check security score
if results['security_score'] > 50:
    print("HIGH RISK DETECTED!")
    print(f"URLs found: {len(results['embedded_urls'])}")
    print(f"IP addresses: {len(results['ip_addresses'])}")

# Unpacking analysis
upx_result = analyzer.attempt_upx_unpack()
if upx_result['upx_detected']:
    print("UPX-packed malware detected!")
```

### **Batch Analysis**
```python
import os
from dll_analyzer import DLLAnalyzer

# Analyze all files in directory
for file_path in os.listdir("malware_samples"):
    if file_path.endswith(('.exe', '.dll')):
        analyzer = DLLAnalyzer(f"malware_samples/{file_path}")
        results = analyzer.full_analysis()
        
        # Export high-risk files
        if results.get('security_score', 0) > 70:
            with open(f"reports/{file_path}_report.json", 'w') as f:
                json.dump(results, f, indent=2)
```

---

## 🛡️ **Security Considerations**

- **🔒 Analyze in isolated environments** (VMs, sandboxes)
- **⚠️ Be cautious with malicious files**
- **🖥️ Use virtual machines** for suspicious samples
- **🔄 Keep analysis tools updated**
- **📝 Document findings** for threat intelligence
- **🚫 Never execute malware** on host systems

---

## 🤝 **Contributing**

Feel free to submit issues and enhancement requests for legitimate security research use cases:

- **Bug Reports**: Issues with file analysis
- **Feature Requests**: New analysis capabilities
- **Improvements**: Better detection algorithms
- **Documentation**: Enhanced README and examples

---

## 📄 **License**

This project is provided for educational and legitimate security research purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

---

## ⭐ **Star History**

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/dll-analyzer&type=Date)](https://star-history.com/#yourusername/dll-analyzer&Date)

---

**🔥 Ready to analyze malware? Start with interactive mode:**

```bash
python dll_analyzer.py "suspicious_file.exe"
```

*Stay safe, analyze smart!* 🛡️
