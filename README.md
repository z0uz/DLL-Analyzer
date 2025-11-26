# 🔍 Advanced DLL/EXE Analyzer - Professional Malware Analysis & Reverse Engineering Toolkit

**⚠️ Legal Notice:** Use these tools only for legitimate reverse engineering, malware analysis, and security research purposes on software you own or have explicit permission to analyze.

---

## 🚀 **PROFESSIONAL EDITION - ENTERPRISE-GRADE FEATURES**

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

### 🏗️ **NEW PROFESSIONAL ARCHITECTURE**
- **Configuration Management** - Centralized settings with JSON persistence
- **Professional Logging** - Rotating logs with security event tracking
- **Plugin System** - Extensible architecture for custom analysis
- **Database Storage** - SQLite for persistent analysis results
- **Web Dashboard** - Flask-based interface for visualization
- **Testing Framework** - Automated unit and integration tests
- **Build Automation** - Windows batch scripts for development

---

## 📦 **Installation**

### **Windows (Recommended)**
```cmd
# Clone the repository
git clone https://github.com/yourusername/dll-analyzer.git
cd dll-analyzer

# Install with development dependencies
.\build.bat install-dev

# Or install manually
pip install -r requirements.txt
pip install -e .
```

### **Linux/Mac**
```bash
# Clone the repository
git clone https://github.com/yourusername/dll-analyzer.git
cd dll-analyzer

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

### **Requirements**
```
pefile>=2023.2.7
capstone>=4.0.2
Flask>=2.3.0
python>=3.7
```

---

## 🎮 **Quick Start**

### **🔥 Interactive Mode (Easiest)**
```cmd
# Windows
.\build.bat run

# Linux/Mac
python dll_analyzer.py

# Example output:
# QUICK SECURITY ASSESSMENT
# • Risk Score: 80/100
# • Risk Level: CRITICAL  
# • Action: DO NOT EXECUTE - Analyze in isolated sandbox
# • Packed: Yes WARNING
# • Signed: No WARNING
# • URLs Found: 186 WARNING
```

### **🌐 Web Dashboard**
```cmd
# Start web interface
.\build.bat web

# Open browser to http://localhost:5000
# Features:
# - Real-time analysis results
# - IOC search and filtering
# - Export capabilities (JSON/CSV)
# - Statistics and reporting
```

### **📊 Command Line Analysis**
```cmd
# Basic DLL analysis
python dll_analyzer.py "C:\Windows\System32\kernel32.dll"

# Export to JSON
python dll_analyzer.py "malware.exe" -o analysis.json -f json

# Export to text report
python dll_analyzer.py "malware.exe" -o report.txt -f txt

# Targeted analysis
python dll_analyzer.py "file.exe" --strings-only
python dll_analyzer.py "file.dll" --exports-only
python dll_analyzer.py "file.dll" --imports-only
```

---

## 🛠️ **Development Commands**

### **Windows Build System**
```cmd
# Development setup
.\build.bat install-dev

# Run tests
.\build.bat test

# Code formatting
.\build.bat format

# Linting
.\build.bat lint

# Clean project
.\build.bat clean

# Security audit
.\build.bat security-audit

# Create plugin
.\build.bat create-plugin

# Performance benchmark
.\build.bat benchmark
```

### **Linux/Mac Makefile**
```bash
# Development setup
make install-dev

# Run tests
make test

# Code formatting
make format

# Clean project
make clean
```

---

## 🔧 **Professional Features**

### **📈 Configuration Management**
```python
from config import config

# Access settings
max_size = config.get('analysis.max_file_size')
risk_threshold = config.get('security.risk_threshold_high')

# Update settings
config.set('analysis.enable_deep_analysis', True)
config.save_config()
```

### **📝 Professional Logging**
```python
from logger import logger

# Log analysis events
logger.log_analysis_start(file_path, file_size)
logger.log_security_event("suspicious_import", {"function": "CreateRemoteThread"})
logger.error("Analysis failed", exception=e, context={"file": file_path})
```

### **🔌 Plugin Development**
```python
from plugin_system import AnalysisPlugin

class CustomPlugin(AnalysisPlugin):
    @property
    def name(self):
        return "custom_plugin"
    
    def analyze(self, pe_file, config):
        return {"custom_result": "analysis_data"}
```

### **💾 Database Integration**
```python
from database import AnalysisDatabase

# Store analysis results
db = AnalysisDatabase()
analysis_id = db.store_analysis(results)

# Search IOCs
ioc_results = db.search_iocs("malicious.com")

# Get statistics
stats = db.get_statistics()
```

---

## 🌐 **Web Interface Features**

### **Dashboard**
- **Real-time Statistics** - Analysis overview and trends
- **Recent Analyses** - Latest processed files
- **Risk Distribution** - Visual risk level breakdown
- **IOC Search** - Search for indicators across all analyses

### **Analysis Details**
- **Comprehensive Reports** - Full analysis breakdown
- **Export Options** - JSON, CSV, and text formats
- **Plugin Results** - Custom plugin analysis data
- **Timeline View** - Analysis history and trends

---

## 🧪 **Testing Framework**

### **Unit Tests**
```cmd
# Run all tests
.\build.bat test

# Run specific test
python -m pytest tests.py::TestDLLAnalyzer::test_file_loading

# Coverage report
python -m pytest tests.py --cov=. --cov-report=html
```

### **Integration Tests**
- Real PE file analysis
- Database operations
- Plugin system validation
- Web interface testing

---

## 🔌 **Plugin System**

### **Available Plugins**
- **Entropy Analysis** - Advanced entropy calculation and visualization
- **YARA Rules** - Malware pattern matching (requires yara-python)
- **Custom Plugins** - Easy plugin development framework

### **Creating Plugins**
```cmd
# Create plugin template
.\build.bat create-plugin

# Edit plugins/custom_plugin.py
# Plugin automatically loads on next run
```

---

## 📊 **Output Formats**

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
    "https://api.malware[.]com/update"
  ],
  "ip_addresses": [
    "203.0.113.45"
  ],
  "security_score": 80,
  "risk_level": "CRITICAL",
  "plugin_results": {
    "entropy_analysis": {
      "average_entropy": 7.2,
      "packed_sections": [".text"]
    }
  }
}
```

---

## 🎯 **Use Cases**

### **🔒 Malware Analysis**
- **Sandbox Pre-analysis** - Quick triage before sandbox
- **Threat Intelligence** - Extract IOCs and indicators
- **Family Identification** - Compare with known malware
- **Behavior Prediction** - Anticipate malware actions

### **🔍 Reverse Engineering**
- **API Analysis** - Understand software dependencies
- **Function Discovery** - Find exported functions
- **Import Analysis** - See what libraries are used
- **Structure Analysis** - Understand PE file layout

### **🛡️ Security Research**
- **Vulnerability Research** - Find security issues
- **Digital Forensics** - Analyze suspicious files
- **Incident Response** - Quick malware identification
- **Security Auditing** - Verify file authenticity

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

### **Core**
- **pefile**: PE file format parsing
- **capstone**: Disassembly framework
- **Python 3.7+**: Core runtime requirement

### **Web Interface**
- **Flask**: Web framework
- **Jinja2**: Template engine

### **Development**
- **pytest**: Testing framework
- **black**: Code formatting
- **flake8**: Linting
- **mypy**: Type checking

### **Optional**
- **yara-python**: YARA rule matching
- **sphinx**: Documentation generation

---

## 🐛 **Troubleshooting**

### **Common Issues**
1. **"DLL not found"**: Check file path and permissions
2. **"Access denied"**: Run as administrator for system files
3. **"Capstone not available"**: Install with `pip install capstone`
4. **"Invalid PE file"**: Verify file is a valid Windows DLL/EXE
5. **"Unicode errors"**: Tool handles Windows console encoding
6. **"Web interface not starting"**: Check port 5000 availability

### **Windows Specific**
- Use `.\build.bat` commands instead of `make`
- Run PowerShell/CMD as Administrator for system files
- Check Windows Defender exclusions for malware analysis

---

## 🚀 **Advanced Usage**

### **Python API**
```python
from dll_analyzer import DLLAnalyzer
from database import AnalysisDatabase
from plugin_system import PluginManager

# Create analyzer instance
analyzer = DLLAnalyzer("suspicious.exe")
analyzer.load_dll()
results = analyzer.full_analysis()

# Store in database
db = AnalysisDatabase()
analysis_id = db.store_analysis(results)

# Run plugins
plugin_manager = PluginManager()
plugin_results = plugin_manager.run_all_plugins(analyzer.pe, config.config)
```

### **Batch Analysis**
```python
import os
from dll_analyzer import DLLAnalyzer

# Analyze all files in directory
for file_path in os.listdir("malware_samples"):
    if file_path.endswith(('.exe', '.dll')):
        analyzer = DLLAnalyzer(f"malware_samples/{file_path}")
        analyzer.load_dll()
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

### **Development Setup**
```cmd
git clone https://github.com/yourusername/dll-analyzer.git
cd dll-analyzer
.\build.bat install-dev
```

### **Contributing Guidelines**
- **Bug Reports**: Issues with file analysis
- **Feature Requests**: New analysis capabilities
- **Plugin Development**: Custom analysis modules
- **Documentation**: Enhanced README and examples
- **Testing**: Additional test cases

### **Code Quality**
- Follow PEP 8 style guidelines
- Add unit tests for new features
- Update documentation
- Use `.\build.bat format` before commits

---

## 📄 **License**

This project is provided for educational and legitimate security research purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

---

## ⭐ **Professional Features Summary**

- ✅ **Enterprise-grade logging** with rotation
- ✅ **Persistent database** storage
- ✅ **Extensible plugin** architecture
- ✅ **Web dashboard** interface
- ✅ **Automated testing** framework
- ✅ **Professional configuration** management
- ✅ **Cross-platform compatibility**
- ✅ **Comprehensive documentation**

---

**🔥 Ready to analyze malware? Start with the web dashboard:**

```cmd
.\build.bat web
# Open http://localhost:5000
```

*Stay safe, analyze smart!* 🛡️
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
