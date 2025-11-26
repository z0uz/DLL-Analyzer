#!/usr/bin/env python3
"""
DLL Analyzer Tool
For educational and legitimate reverse engineering purposes only
"""

import os
import sys
import struct
import pefile
from typing import Dict, List, Optional, Tuple
import argparse
import json
import re
from datetime import datetime
import math
import hashlib

class DLLAnalyzer:
    def __init__(self, dll_path: str):
        self.dll_path = dll_path
        self.pe = None
        self.analysis_results = {}
        
    def load_dll(self) -> bool:
        """Load and parse the DLL file"""
        try:
            self.pe = pefile.PE(self.dll_path)
            return True
        except Exception as e:
            print(f"Error loading DLL: {e}")
            return False
    
    def get_dll_info(self) -> Dict:
        """Extract basic DLL information"""
        if not self.pe:
            return {}
        
        info = {
            'file_path': self.dll_path,
            'file_size': os.path.getsize(self.dll_path),
            'machine': self.pe.FILE_HEADER.Machine,
            'timestamp': self.pe.FILE_HEADER.TimeDateStamp,
            'characteristics': self.pe.FILE_HEADER.Characteristics,
            'entry_point': self.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'image_base': self.pe.OPTIONAL_HEADER.ImageBase,
            'dll_characteristics': self.pe.OPTIONAL_HEADER.DllCharacteristics
        }
        
        # Machine type mapping
        machine_types = {
            0x014c: 'i386',
            0x0200: 'IA64',
            0x8664: 'AMD64'
        }
        info['machine_type'] = machine_types.get(info['machine'], 'Unknown')
        
        return info
    
    def get_exported_functions(self) -> List[Dict]:
        """Extract exported functions"""
        exports = []
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports
        
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append({
                    'name': exp.name.decode('utf-8', errors='ignore'),
                    'ordinal': exp.ordinal,
                    'address': exp.address,
                    'forwarded': exp.forwarder is not None
                })
        
        return sorted(exports, key=lambda x: x['name'])
    
    def get_imported_functions(self) -> List[Dict]:
        """Extract imported functions and DLLs"""
        imports = []
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            
            for imp in entry.imports:
                func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
                
                imports.append({
                    'dll': dll_name,
                    'function': func_name,
                    'ordinal': imp.ordinal,
                    'address': imp.address,
                    'hint': imp.hint
                })
        
        return imports
    
    def get_sections(self) -> List[Dict]:
        """Extract section information"""
        sections = []
        
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            sections.append({
                'name': section_name,
                'virtual_address': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_address': section.PointerToRawData,
                'raw_size': section.SizeOfRawData,
                'characteristics': section.Characteristics,
                'entropy': section.get_entropy()
            })
        
        return sections
    
    def analyze_strings(self, min_length: int = 4) -> List[str]:
        """Extract printable strings from the DLL"""
        strings = []
        
        try:
            with open(self.dll_path, 'rb') as f:
                data = f.read()
                
            current_string = ""
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""
            
            if len(current_string) >= min_length:
                strings.append(current_string)
                
        except Exception as e:
            print(f"Error extracting strings: {e}")
        
        return strings
    
    def get_version_info(self) -> Dict:
        """Extract version information if available"""
        version_info = {}
        
        try:
            if hasattr(self.pe, 'VS_VERSIONINFO'):
                for fileinfo in self.pe.FileInfo:
                    if hasattr(fileinfo, 'Key') and fileinfo.Key.decode('utf-8') == 'StringFileInfo':
                        for st in fileinfo.StringTable:
                            for entry in st.entries.items():
                                version_info[entry[0].decode('utf-8')] = entry[1].decode('utf-8')
        except Exception as e:
            # Version info extraction failed, return empty dict
            pass
        
        return version_info
    
    def full_analysis(self) -> Dict:
        """Perform complete DLL analysis with all enhanced features"""
        if not self.load_dll():
            return {}
        
        self.analysis_results = {
            'dll_info': self.get_dll_info(),
            'exports': self.get_exported_functions(),
            'imports': self.get_imported_functions(),
            'sections': self.get_sections(),
            'strings': self.analyze_strings(),
            'version_info': self.get_version_info(),
            'characteristics': self.analyze_dll_characteristics(),
            'dependencies': self.analyze_dependencies(),
            'metadata': self.analyze_file_metadata(),
            'embedded_urls': self.extract_embedded_urls(),
            'entropy_analysis': self.analyze_entropy_distribution(),
            'packing_analysis': self.detect_packing_algorithms(),
            'ip_addresses': self.extract_ip_addresses(),
            'code_patterns': self.analyze_code_patterns(),
            'timeline_analysis': self.analyze_file_timeline(),
            'certificate_analysis': self.extract_certificates(),
            'upx_unpack': self.attempt_upx_unpack(),
            'packed_sections': self.analyze_packed_sections(),
            'hidden_strings': self.extract_hidden_strings(),
            'entry_point_analysis': self.analyze_entry_point()
        }
        
        return self.analysis_results
    
    def export_report(self, output_file: str, format_type: str = 'json'):
        """Export analysis results to file"""
        if format_type.lower() == 'json':
            with open(output_file, 'w') as f:
                json.dump(self.analysis_results, f, indent=2)
        elif format_type.lower() == 'txt':
            with open(output_file, 'w') as f:
                self._write_text_report(f)
        else:
            raise ValueError("Unsupported format. Use 'json' or 'txt'")
    
    def _write_text_report(self, file):
        """Write formatted text report with explanations"""
        file.write("=== DLL Analysis Report ===\n\n")
        
        # DLL Info
        info = self.analysis_results.get('dll_info', {})
        file.write("DLL BASIC INFORMATION:\n")
        file.write("=" * 50 + "\n")
        
        machine_types = {
            0x014c: '32-bit (x86)',
            0x0200: 'IA64 (Itanium)',
            0x8664: '64-bit (x64)'
        }
        
        file.write(f"File: {os.path.basename(info.get('file_path', 'Unknown'))}\n")
        file.write(f"Size: {info.get('file_size', 0):,} bytes ({info.get('file_size', 0) / 1024:.1f} KB)\n")
        file.write(f"Architecture: {machine_types.get(info.get('machine'), 'Unknown')}\n")
        file.write(f"Build Date: {self._format_timestamp(info.get('timestamp', 0))}\n")
        file.write(f"Entry Point: 0x{info.get('entry_point', 0):08x} (where execution starts)\n")
        file.write(f"Image Base: 0x{info.get('image_base', 0):08x} (preferred memory location)\n")
        file.write("\n")
        
        # Exports
        exports = self.analysis_results.get('exports', [])
        file.write(f"EXPORTED FUNCTIONS ({len(exports)} total):\n")
        file.write("=" * 50 + "\n")
        file.write("These are the functions this DLL provides to other programs:\n\n")
        
        # Categorize exports by type
        api_categories = self._categorize_functions(exports)
        
        for category, functions in api_categories.items():
            if functions:
                file.write(f"{category} ({len(functions)} functions):\n")
                for func in functions[:5]:  # Show first 5 of each category
                    file.write(f"   * {func['name']} - Address: 0x{func['address']:08x}\n")
                if len(functions) > 5:
                    file.write(f"   ... and {len(functions) - 5} more\n")
                file.write("\n")
        
        # Imports
        imports = self.analysis_results.get('imports', [])
        file.write(f"IMPORTED FUNCTIONS ({len(imports)} total):\n")
        file.write("=" * 50 + "\n")
        file.write("These are the external functions this DLL needs from other DLLs:\n\n")
        
        # Group imports by DLL
        import_groups = {}
        for imp in imports:
            dll_name = imp['dll']
            if dll_name not in import_groups:
                import_groups[dll_name] = []
            import_groups[dll_name].append(imp)
        
        for dll_name, functions in sorted(import_groups.items()):
            file.write(f"From {dll_name} ({len(functions)} functions):\n")
            for func in functions[:3]:  # Show first 3 from each DLL
                file.write(f"   * {func['function']}\n")
            if len(functions) > 3:
                file.write(f"   ... and {len(functions) - 3} more\n")
            file.write("\n")
        
        # Sections
        sections = self.analysis_results.get('sections', [])
        file.write(f"MEMORY SECTIONS ({len(sections)} total):\n")
        file.write("=" * 50 + "\n")
        file.write("These are the different parts of the DLL in memory:\n\n")
        
        for section in sections:
            section_type = self._explain_section(section['name'], section['characteristics'])
            entropy_desc = self._explain_entropy(section['entropy'])
            
            file.write(f"{section['name']} ({section_type}):\n")
            file.write(f"   * Memory Address: 0x{section['virtual_address']:08x}\n")
            file.write(f"   * Size: {section['virtual_size']:,} bytes\n")
            file.write(f"   * Entropy: {section['entropy']:.2f} ({entropy_desc})\n")
            file.write("\n")
        
        # Version Info
        version_info = self.analysis_results.get('version_info', {})
        if version_info:
            file.write(f"VERSION INFORMATION:\n")
            file.write("=" * 50 + "\n")
            for key, value in version_info.items():
                file.write(f"* {key}: {value}\n")
            file.write("\n")
        
        # Security Analysis
        file.write(f"SECURITY ANALYSIS:\n")
        file.write("=" * 50 + "\n")
        
        # Suspicious functions
        suspicious_imports = self._find_suspicious_imports(imports)
        if suspicious_imports:
            file.write("WARNING: Potentially Suspicious Functions Found:\n")
            for category, functions in suspicious_imports.items():
                if functions:
                    file.write(f"   * {category}: {', '.join(functions[:5])}\n")
                    if len(functions) > 5:
                        file.write(f"     ... and {len(functions) - 5} more\n")
        else:
            file.write("OK: No obviously suspicious functions detected\n")
        
        file.write("\n")
        
        # Summary
        file.write(f"SUMMARY:\n")
        file.write("=" * 50 + "\n")
        file.write(f"• Total Functions Exported: {len(exports)}\n")
        file.write(f"• Total Functions Imported: {len(imports)}\n")
        file.write(f"• Dependencies: {len(import_groups)} other DLLs\n")
        file.write(f"• Memory Sections: {len(sections)}\n")
        file.write(f"• Architecture: {machine_types.get(info.get('machine'), 'Unknown')}\n")
        
        # Risk Assessment
        risk_score = self._calculate_risk_score(imports, sections)
        file.write(f"• Risk Assessment: {risk_score['level']} ({risk_score['score']}/100)\n")
        if risk_score['concerns']:
            file.write("• Concerns: " + ", ".join(risk_score['concerns']) + "\n")
        
        # Enhanced Analysis Sections
        file.write("\n")
        
        # DLL Characteristics
        characteristics = self.analysis_results.get('characteristics', {})
        file.write("DLL CHARACTERISTICS:\n")
        file.write("=" * 50 + "\n")
        file.write(f"• File Type: {'DLL' if characteristics.get('is_dll') else 'EXE'}\n")
        file.write(f"• Architecture: {'64-bit' if characteristics.get('is_64bit') else '32-bit'}\n")
        file.write(f"• Has Exports: {'Yes' if characteristics.get('has_exports') else 'No'}\n")
        file.write(f"• Has Imports: {'Yes' if characteristics.get('has_imports') else 'No'}\n")
        file.write(f"• Has Resources: {'Yes' if characteristics.get('has_resources') else 'No'}\n")
        file.write(f"• Has Debug Info: {'Yes' if characteristics.get('has_debug_info') else 'No'}\n")
        file.write(f"• Is .NET Assembly: {'Yes' if characteristics.get('is_dotnet') else 'No'}\n")
        file.write(f"• Is Packed: {'Yes' if characteristics.get('is_packed') else 'No'}\n")
        file.write(f"• Is Digitally Signed: {'Yes' if characteristics.get('is_signed') else 'No'}\n")
        
        capabilities = characteristics.get('capabilities', [])
        if capabilities:
            file.write(f"\n• Capabilities: {', '.join(capabilities)}\n")
        
        file.write("\n")
        
        # Dependency Analysis
        dependencies = self.analysis_results.get('dependencies', {})
        file.write("DEPENDENCY ANALYSIS:\n")
        file.write("=" * 50 + "\n")
        file.write(f"• Total Dependencies: {dependencies.get('total_dependencies', 0)}\n")
        file.write(f"• System DLLs: {dependencies.get('system_dlls', 0)}\n")
        file.write(f"• Third-Party DLLs: {dependencies.get('third_party_dlls', 0)}\n")
        
        # Show high-risk dependencies
        deps_data = dependencies.get('dependencies', {})
        high_risk_deps = [name for name, data in deps_data.items() if data.get('risk_level') == 'HIGH']
        medium_risk_deps = [name for name, data in deps_data.items() if data.get('risk_level') == 'MEDIUM']
        
        if high_risk_deps:
            file.write(f"• High-Risk Dependencies: {', '.join(high_risk_deps[:5])}\n")
        if medium_risk_deps:
            file.write(f"• Medium-Risk Dependencies: {', '.join(medium_risk_deps[:5])}\n")
        
        file.write("\n")
        
        # File Metadata
        metadata = self.analysis_results.get('metadata', {})
        file.write("FILE METADATA:\n")
        file.write("=" * 50 + "\n")
        
        file_info = metadata.get('file_info', {})
        if file_info:
            file.write(f"• File Size: {file_info.get('size', 0):,} bytes\n")
            file.write(f"• MD5: {file_info.get('md5', 'N/A')}\n")
            file.write(f"• SHA1: {file_info.get('sha1', 'N/A')}\n")
            file.write(f"• SHA256: {file_info.get('sha256', 'N/A')}\n")
        
        company_info = metadata.get('company_info', {})
        if company_info:
            file.write(f"\n• Company: {company_info.get('company_name', 'Unknown')}\n")
            file.write(f"• Product: {company_info.get('product_name', 'Unknown')}\n")
            file.write(f"• File Version: {company_info.get('file_version', 'Unknown')}\n")
            file.write(f"• Description: {company_info.get('description', 'Unknown')}\n")
        
        compile_info = metadata.get('compile_info', {})
        if compile_info:
            file.write(f"\n• Compile Time: {compile_info.get('compile_time', 'Unknown')}\n")
        
        signature_info = metadata.get('digital_signature', {})
        if signature_info:
            file.write(f"\n• Digital Signature: {'Valid' if signature_info.get('is_signed') else 'None'}\n")
        
        file.write("\n")
        
        # Embedded URLs
        urls = self.analysis_results.get('embedded_urls', [])
        if urls:
            file.write("EMBEDDED URLS:\n")
            file.write("=" * 50 + "\n")
            file.write(f"• Found {len(urls)} embedded URLs:\n")
            for url in urls[:10]:  # Show first 10 URLs
                file.write(f"  - {url}\n")
            if len(urls) > 10:
                file.write(f"  ... and {len(urls) - 10} more\n")
            file.write("\n")
        
        # Advanced Security Assessment
        file.write("ADVANCED SECURITY ASSESSMENT:\n")
        file.write("=" * 50 + "\n")
        
        security_score = 0
        security_issues = []
        
        # Check for suspicious characteristics
        if characteristics.get('is_packed'):
            security_score += 25
            security_issues.append("File appears to be packed/obfuscated")
        
        if characteristics.get('is_dotnet'):
            security_score += 5
            security_issues.append(".NET assembly (may be decompilable)")
        
        if not characteristics.get('is_signed') and len(exports) > 10:
            security_score += 10
            security_issues.append("Unsigned file with many exports")
        
        if high_risk_deps:
            security_score += 20
            security_issues.append(f"Uses {len(high_risk_deps)} high-risk dependencies")
        
        if urls:
            security_score += 15
            security_issues.append("Contains embedded URLs")
        
        # Determine overall security level
        if security_score >= 50:
            security_level = "CRITICAL"
        elif security_score >= 30:
            security_level = "HIGH"
        elif security_score >= 15:
            security_level = "MEDIUM"
        else:
            security_level = "LOW"
        
        file.write(f"• Security Score: {security_score}/100\n")
        file.write(f"• Security Level: {security_level}\n")
        if security_issues:
            file.write("• Security Issues:\n")
            for issue in security_issues:
                file.write(f"  - {issue}\n")
        
        file.write("\n")
        
        # Recommendations
        file.write("SECURITY RECOMMENDATIONS:\n")
        file.write("=" * 50 + "\n")
        
        recommendations = []
        
        if characteristics.get('is_packed'):
            recommendations.append("Analyze in sandboxed environment due to packing")
        
        if not characteristics.get('is_signed'):
            recommendations.append("Verify file authenticity before use")
        
        if high_risk_deps:
            recommendations.append("Review high-risk dependencies")
        
        if urls:
            recommendations.append("Investigate embedded URLs for potential C&C servers")
        
        if suspicious_imports.get('Network Communication'):
            recommendations.append("Monitor network activity if executed")
        
        if suspicious_imports.get('Process Manipulation'):
            recommendations.append("Run with limited privileges")
        
        if not recommendations:
            recommendations.append("File appears to be standard system DLL")
        
        for i, rec in enumerate(recommendations, 1):
            file.write(f"{i}. {rec}\n")
    
    def _format_timestamp(self, timestamp: int) -> str:
        """Convert PE timestamp to readable date"""
        if timestamp == 0:
            return "Unknown"
        try:
            # PE timestamps are seconds since Jan 1, 1970
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime("%B %d, %Y at %I:%M %p")
        except:
            return "Invalid timestamp"
    
    def _categorize_functions(self, functions: List[Dict]) -> Dict[str, List[Dict]]:
        """Categorize functions by their purpose"""
        categories = {
            'File Operations': [],
            'Memory Management': [],
            'Process/Thread': [],
            'Network': [],
            'Registry': [],
            'String Operations': [],
            'Graphics/GUI': [],
            'System/Kernel': [],
            'Math/Utility': [],
            'Other': []
        }
        
        file_keywords = ['CreateFile', 'OpenFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'FindFile', 'CopyFile', 'MoveFile']
        memory_keywords = ['VirtualAlloc', 'VirtualFree', 'VirtualProtect', 'HeapAlloc', 'HeapFree', 'GlobalAlloc', 'LocalAlloc']
        process_keywords = ['CreateProcess', 'OpenProcess', 'TerminateProcess', 'CreateThread', 'GetCurrentProcess']
        network_keywords = ['Socket', 'Connect', 'Bind', 'Listen', 'Send', 'Recv', 'WSA', 'Internet']
        registry_keywords = ['RegOpen', 'RegCreate', 'RegSetValue', 'RegDelete', 'RegQuery', 'RegClose']
        string_keywords = ['lstr', 'strcpy', 'strcmp', 'strlen', 'CharTo', 'MultiByte']
        graphics_keywords = ['CreateWindow', 'Draw', 'Paint', 'Bitmap', 'Icon', 'Cursor', 'Font']
        system_keywords = ['GetSystem', 'SetSystem', 'Kernel', 'Device', 'Driver']
        math_keywords = ['sin', 'cos', 'tan', 'sqrt', 'abs', 'pow', 'log']
        
        for func in functions:
            name = func['name'].lower()
            categorized = False
            
            for keyword in file_keywords:
                if keyword.lower() in name:
                    categories['File Operations'].append(func)
                    categorized = True
                    break
            
            if not categorized:
                for keyword in memory_keywords:
                    if keyword.lower() in name:
                        categories['Memory Management'].append(func)
                        categorized = True
                        break
            
            if not categorized:
                for keyword in process_keywords:
                    if keyword.lower() in name:
                        categories['Process/Thread'].append(func)
                        categorized = True
                        break
            
            if not categorized:
                for keyword in network_keywords:
                    if keyword.lower() in name:
                        categories['Network'].append(func)
                        categorized = True
                        break
            
            if not categorized:
                for keyword in registry_keywords:
                    if keyword.lower() in name:
                        categories['Registry'].append(func)
                        categorized = True
                        break
            
            if not categorized:
                for keyword in string_keywords:
                    if keyword.lower() in name:
                        categories['String Operations'].append(func)
                        categorized = True
                        break
            
            if not categorized:
                for keyword in graphics_keywords:
                    if keyword.lower() in name:
                        categories['Graphics/GUI'].append(func)
                        categorized = True
                        break
            
            if not categorized:
                for keyword in system_keywords:
                    if keyword.lower() in name:
                        categories['System/Kernel'].append(func)
                        categorized = True
                        break
            
            if not categorized:
                for keyword in math_keywords:
                    if keyword.lower() in name:
                        categories['Math/Utility'].append(func)
                        categorized = True
                        break
            
            if not categorized:
                categories['Other'].append(func)
        
        return categories
    
    def _explain_section(self, name: str, characteristics: int) -> str:
        """Explain what a section does based on its name and characteristics"""
        name_lower = name.lower().rstrip('\x00')
        
        # Common section types
        section_explanations = {
            '.text': 'Executable code (the actual program instructions)',
            '.data': 'Initialized data (global variables and constants)',
            '.rdata': 'Read-only data (strings, constants, import tables)',
            '.bss': 'Uninitialized data (variables that start as zero)',
            '.reloc': 'Relocation information (for fixing addresses)',
            '.rsrc': 'Resources (icons, bitmaps, version info)',
            '.tls': 'Thread-local storage (data unique to each thread)',
            '.debug': 'Debug information',
            '.pdata': 'Exception handling information',
            '.idata': 'Import directory (external function references)',
            '.edata': 'Export directory (functions this DLL provides)'
        }
        
        return section_explanations.get(name_lower, f'Unknown section type (name: {name})')
    
    def _explain_entropy(self, entropy: float) -> str:
        """Explain what entropy means for this section"""
        if entropy < 3.0:
            return "Very low - mostly empty or repetitive data"
        elif entropy < 5.0:
            return "Low - likely structured data or uncompressed code"
        elif entropy < 6.5:
            return "Normal - typical for executable code"
        elif entropy < 7.5:
            return "High - possibly compressed or encrypted"
        else:
            return "Very high - likely packed, compressed, or encrypted"
    
    def _find_suspicious_imports(self, imports: List[Dict]) -> Dict[str, List[str]]:
        """Find potentially suspicious imported functions"""
        suspicious = {
            'Keylogging': [],
            'Network Communication': [],
            'Process Manipulation': [],
            'File Hiding': [],
            'Registry Manipulation': [],
            'Anti-Analysis': []
        }
        
        keylog_keywords = ['GetAsyncKeyState', 'GetKeyboardState', 'SetWindowsHookEx', 'keybd_event']
        network_keywords = ['Socket', 'Connect', 'Send', 'Recv', 'InternetConnect', 'HttpSendRequest']
        process_keywords = ['CreateProcess', 'OpenProcess', 'TerminateProcess', 'WriteProcessMemory', 'CreateRemoteThread']
        file_keywords = ['SetFileAttributes', 'DeleteFile', 'MoveFile', 'CreateFile', 'FindFirstFile']
        registry_keywords = ['RegSetValue', 'RegCreateKey', 'RegDeleteValue', 'RegOpenKey']
        anti_analysis_keywords = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugString']
        
        for imp in imports:
            func_name = imp['function'].lower()
            
            for keyword in keylog_keywords:
                if keyword.lower() in func_name:
                    suspicious['Keylogging'].append(imp['function'])
            
            for keyword in network_keywords:
                if keyword.lower() in func_name:
                    suspicious['Network Communication'].append(imp['function'])
            
            for keyword in process_keywords:
                if keyword.lower() in func_name:
                    suspicious['Process Manipulation'].append(imp['function'])
            
            for keyword in file_keywords:
                if keyword.lower() in func_name:
                    suspicious['File Hiding'].append(imp['function'])
            
            for keyword in registry_keywords:
                if keyword.lower() in func_name:
                    suspicious['Registry Manipulation'].append(imp['function'])
            
            for keyword in anti_analysis_keywords:
                if keyword.lower() in func_name:
                    suspicious['Anti-Analysis'].append(imp['function'])
        
        return suspicious
    
    def _calculate_risk_score(self, imports: List[Dict], sections: List[Dict]) -> Dict:
        """Calculate a comprehensive risk assessment score"""
        score = 0
        concerns = []
        
        suspicious_imports = self._find_suspicious_imports(imports)
        
        # Score based on suspicious imports
        for category, functions in suspicious_imports.items():
            if functions:
                if category == 'Keylogging':
                    score += 30
                    concerns.append("Keylogging functions")
                elif category == 'Network Communication':
                    score += 15
                    concerns.append("Network functions")
                elif category == 'Process Manipulation':
                    score += 20
                    concerns.append("Process manipulation")
                elif category == 'Anti-Analysis':
                    score += 25
                    concerns.append("Anti-analysis techniques")
        
        # Score based on high entropy sections (possible packing)
        high_entropy_sections = [s for s in sections if s['entropy'] > 7.0]
        if high_entropy_sections:
            score += 20
            concerns.append("High entropy sections (possibly packed)")
        
        # Determine risk level
        if score >= 60:
            level = "HIGH RISK"
        elif score >= 30:
            level = "MEDIUM RISK"
        elif score >= 10:
            level = "LOW RISK"
        else:
            level = "VERY LOW RISK"
        
        return {
            'score': min(score, 100),
            'level': level,
            'concerns': concerns
        }
    
    def analyze_dll_characteristics(self) -> Dict:
        """Analyze DLL characteristics and capabilities"""
        characteristics = {
            'is_dll': False,
            'is_exe': False,
            'is_driver': False,
            'is_64bit': False,
            'is_32bit': False,
            'has_exports': False,
            'has_imports': False,
            'has_resources': False,
            'has_debug_info': False,
            'has_tls': False,
            'is_dotnet': False,
            'is_packed': False,
            'is_signed': False,
            'capabilities': []
        }
        
        if not self.pe:
            return characteristics
        
        # Check file type
        if hasattr(self.pe, 'FILE_HEADER'):
            characteristics['is_dll'] = self.pe.FILE_HEADER.Characteristics & 0x2000 != 0
            characteristics['is_exe'] = self.pe.FILE_HEADER.Characteristics & 0x2002 == 0x0002
            characteristics['is_driver'] = self.pe.FILE_HEADER.Characteristics & 0x2000 != 0 and self.pe.OPTIONAL_HEADER.Subsystem == 1
        
        # Check architecture
        characteristics['is_64bit'] = self.pe.FILE_HEADER.Machine == 0x8664
        characteristics['is_32bit'] = self.pe.FILE_HEADER.Machine == 0x014c
        
        # Check sections
        if hasattr(self.pe, 'sections'):
            section_names = [s.Name.decode('utf-8', errors='ignore').rstrip('\x00') for s in self.pe.sections]
            characteristics['has_exports'] = '.edata' in section_names or hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT')
            characteristics['has_imports'] = '.idata' in section_names or hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT')
            characteristics['has_resources'] = '.rsrc' in section_names
            characteristics['has_debug_info'] = '.debug' in section_names
            characteristics['has_tls'] = '.tls' in section_names
            
            # Check for .NET
            is_dotnet = False
            for s in self.pe.sections:
                if s.Name.decode('utf-8', errors='ignore').rstrip('\x00') == '.text':
                    try:
                        if b'CLR' in s.get_data()[:200]:
                            is_dotnet = True
                            break
                    except:
                        pass
            characteristics['is_dotnet'] = is_dotnet
        
        # Check for packing
        high_entropy_sections = [s for s in self.pe.sections if s.get_entropy() > 7.5]
        characteristics['is_packed'] = len(high_entropy_sections) > 0
        
        # Check for digital signature
        characteristics['is_signed'] = hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY')
        
        # Determine capabilities
        if characteristics['has_imports']:
            imports = self.get_imported_functions()
            capabilities = self._determine_capabilities(imports)
            characteristics['capabilities'] = capabilities
        
        return characteristics
    
    def _determine_capabilities(self, imports: List[Dict]) -> List[str]:
        """Determine DLL capabilities based on imports"""
        capabilities = []
        
        import_names = [imp['function'].lower() for imp in imports]
        
        # Network capabilities
        network_funcs = ['socket', 'connect', 'bind', 'listen', 'send', 'recv', 'wsa', 'internet', 'http', 'ftp']
        if any(func in ' '.join(import_names) for func in network_funcs):
            capabilities.append("Network Communication")
        
        # File system capabilities
        file_funcs = ['createfile', 'openfile', 'readfile', 'writefile', 'deletefile', 'findfile']
        if any(func in ' '.join(import_names) for func in file_funcs):
            capabilities.append("File System Access")
        
        # Registry capabilities
        registry_funcs = ['regopen', 'regcreate', 'regsetvalue', 'regdelete', 'regquery']
        if any(func in ' '.join(import_names) for func in registry_funcs):
            capabilities.append("Registry Access")
        
        # Process capabilities
        process_funcs = ['createprocess', 'openprocess', 'terminateprocess', 'writereadprocessmemory']
        if any(func in ' '.join(import_names) for func in process_funcs):
            capabilities.append("Process Manipulation")
        
        # Memory capabilities
        memory_funcs = ['virtualalloc', 'virtualprotect', 'heapalloc', 'globalalloc']
        if any(func in ' '.join(import_names) for func in memory_funcs):
            capabilities.append("Memory Management")
        
        # Crypto capabilities
        crypto_funcs = ['crypt', 'encrypt', 'decrypt', 'hash', 'signature']
        if any(func in ' '.join(import_names) for func in crypto_funcs):
            capabilities.append("Cryptographic Operations")
        
        # GUI capabilities
        gui_funcs = ['createwindow', 'messagebox', 'dialog', 'button', 'menu']
        if any(func in ' '.join(import_names) for func in gui_funcs):
            capabilities.append("GUI Interface")
        
        # Service capabilities
        service_funcs = ['openservice', 'createservice', 'startservice', 'stopservice']
        if any(func in ' '.join(import_names) for func in service_funcs):
            capabilities.append("Windows Services")
        
        return capabilities
    
    def analyze_dependencies(self) -> Dict:
        """Analyze DLL dependencies and their relationships"""
        if not self.load_dll():
            return {}
        
        imports = self.get_imported_functions()
        
        # Group imports by DLL
        dll_groups = {}
        for imp in imports:
            dll_name = imp['dll']
            if dll_name not in dll_groups:
                dll_groups[dll_name] = []
            dll_groups[dll_name].append(imp)
        
        # Analyze each dependency
        dependency_analysis = {}
        for dll_name, functions in dll_groups.items():
            analysis = {
                'dll_name': dll_name,
                'function_count': len(functions),
                'function_types': self._categorize_import_functions(functions),
                'is_system_dll': self._is_system_dll(dll_name),
                'is_microsoft_dll': self._is_microsoft_dll(dll_name),
                'risk_level': self._assess_dll_risk(dll_name, functions)
            }
            dependency_analysis[dll_name] = analysis
        
        return {
            'total_dependencies': len(dll_groups),
            'system_dlls': len([d for d in dll_groups.keys() if self._is_system_dll(d)]),
            'third_party_dlls': len([d for d in dll_groups.keys() if not self._is_system_dll(d)]),
            'dependencies': dependency_analysis
        }
    
    def _categorize_import_functions(self, functions: List[Dict]) -> Dict[str, int]:
        """Categorize imported functions by type"""
        categories = {
            'File': 0, 'Registry': 0, 'Network': 0, 'Process': 0,
            'Memory': 0, 'String': 0, 'GUI': 0, 'System': 0, 'Crypto': 0, 'Other': 0
        }
        
        for func in functions:
            name = func['function'].lower()
            
            if any(keyword in name for keyword in ['createfile', 'openfile', 'readfile', 'writefile']):
                categories['File'] += 1
            elif any(keyword in name for keyword in ['regopen', 'regcreate', 'regsetvalue']):
                categories['Registry'] += 1
            elif any(keyword in name for keyword in ['socket', 'connect', 'send', 'recv']):
                categories['Network'] += 1
            elif any(keyword in name for keyword in ['createprocess', 'openprocess', 'terminateprocess']):
                categories['Process'] += 1
            elif any(keyword in name for keyword in ['virtualalloc', 'heapalloc', 'globalalloc']):
                categories['Memory'] += 1
            elif any(keyword in name for keyword in ['strcpy', 'strcmp', 'strlen', 'char']):
                categories['String'] += 1
            elif any(keyword in name for keyword in ['createwindow', 'messagebox', 'dialog']):
                categories['GUI'] += 1
            elif any(keyword in name for keyword in ['getsystem', 'kernel', 'device']):
                categories['System'] += 1
            elif any(keyword in name for keyword in ['crypt', 'encrypt', 'decrypt', 'hash']):
                categories['Crypto'] += 1
            else:
                categories['Other'] += 1
        
        return categories
    
    def _is_system_dll(self, dll_name: str) -> bool:
        """Check if DLL is a system DLL"""
        system_paths = ['system32', 'syswow64', 'windows']
        dll_lower = dll_name.lower()
        
        # Common system DLL patterns
        system_dlls = [
            'kernel32', 'user32', 'gdi32', 'advapi32', 'shell32', 'ole32', 'oleaut32',
            'comctl32', 'comdlg32', 'wininet', 'ws2_32', 'msvcrt', 'ntdll',
            'api-ms-win-', 'ext-ms-win-', 'ucrtbase', 'vcruntime'
        ]
        
        return any(pattern in dll_lower for pattern in system_dlls)
    
    def _is_microsoft_dll(self, dll_name: str) -> bool:
        """Check if DLL is from Microsoft"""
        microsoft_patterns = ['microsoft', 'ms-', 'windows', 'system', 'kernel']
        dll_lower = dll_name.lower()
        
        return any(pattern in dll_lower for pattern in microsoft_patterns)
    
    def _assess_dll_risk(self, dll_name: str, functions: List[Dict]) -> str:
        """Assess risk level of a dependency DLL"""
        if self._is_system_dll(dll_name):
            return "LOW"
        
        # Check for suspicious functions
        suspicious_count = 0
        for func in functions:
            name = func['function'].lower()
            if any(keyword in name for keyword in ['hook', 'inject', 'keylog', 'debug', 'monitor']):
                suspicious_count += 1
        
        if suspicious_count > 3:
            return "HIGH"
        elif suspicious_count > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def extract_embedded_urls(self) -> List[str]:
        """Extract embedded URLs from the DLL"""
        urls = []
        
        try:
            with open(self.dll_path, 'rb') as f:
                data = f.read()
            
            # URL patterns
            url_patterns = [
                rb'http[s]?://[^\s<>"]+',
                rb'ftp://[^\s<>"]+',
                rb'www\.[^\s<>"]+\.[a-zA-Z]{2,}',
                rb'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"]*'
            ]
            
            import re
            for pattern in url_patterns:
                matches = re.findall(pattern, data)
                for match in matches:
                    try:
                        url = match.decode('utf-8', errors='ignore')
                        if len(url) > 10 and '.' in url:
                            urls.append(url)
                    except:
                        pass
        
        except Exception as e:
            pass
        
        return list(set(urls))  # Remove duplicates
    
    def analyze_file_metadata(self) -> Dict:
        """Extract and analyze file metadata"""
        metadata = {
            'file_info': {},
            'digital_signature': {},
            'compile_info': {},
            'company_info': {}
        }
        
        if not self.pe:
            return metadata
        
        try:
            # Basic file info
            metadata['file_info'] = {
                'size': os.path.getsize(self.dll_path),
                'md5': self._calculate_file_hash('md5'),
                'sha1': self._calculate_file_hash('sha1'),
                'sha256': self._calculate_file_hash('sha256')
            }
            
            # Version info
            version_info = self.get_version_info()
            if version_info:
                metadata['company_info'] = {
                    'company_name': version_info.get('CompanyName', 'Unknown'),
                    'product_name': version_info.get('ProductName', 'Unknown'),
                    'file_version': version_info.get('FileVersion', 'Unknown'),
                    'product_version': version_info.get('ProductVersion', 'Unknown'),
                    'copyright': version_info.get('LegalCopyright', 'Unknown'),
                    'original_filename': version_info.get('OriginalFilename', 'Unknown'),
                    'description': version_info.get('FileDescription', 'Unknown')
                }
            
            # Compile timestamp
            if hasattr(self.pe, 'FILE_HEADER'):
                timestamp = self.pe.FILE_HEADER.TimeDateStamp
                metadata['compile_info'] = {
                    'compile_time': self._format_timestamp(timestamp),
                    'timestamp': timestamp
                }
            
            # Digital signature check
            metadata['digital_signature'] = {
                'is_signed': hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'),
                'signature_size': len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Data) if hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY') else 0
            }
        
        except Exception as e:
            pass
        
        return metadata
    
    def _calculate_file_hash(self, algorithm: str) -> str:
        """Calculate file hash using specified algorithm"""
        try:
            with open(self.dll_path, 'rb') as f:
                data = f.read()
            
            if algorithm.lower() == 'md5':
                return hashlib.md5(data).hexdigest()
            elif algorithm.lower() == 'sha1':
                return hashlib.sha1(data).hexdigest()
            elif algorithm.lower() == 'sha256':
                return hashlib.sha256(data).hexdigest()
            else:
                return "Unknown algorithm"
        
        except:
            return "Error calculating hash"
    
    def analyze_entropy_distribution(self) -> Dict:
        """Analyze entropy distribution across the file"""
        try:
            with open(self.dll_path, 'rb') as f:
                data = f.read()
            
            # Calculate entropy for different chunks
            chunk_size = 1024  # 1KB chunks
            entropies = []
            
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                if len(chunk) > 0:
                    entropy = self._calculate_entropy(chunk)
                    entropies.append(entropy)
            
            # Statistics
            avg_entropy = sum(entropies) / len(entropies) if entropies else 0
            max_entropy = max(entropies) if entropies else 0
            min_entropy = min(entropies) if entropies else 0
            
            # Find high entropy regions
            high_entropy_threshold = 7.0
            high_entropy_regions = []
            current_region = None
            
            for i, entropy in enumerate(entropies):
                if entropy > high_entropy_threshold:
                    if current_region is None:
                        current_region = {'start': i * chunk_size, 'end': (i + 1) * chunk_size, 'max_entropy': entropy}
                    else:
                        current_region['end'] = (i + 1) * chunk_size
                        current_region['max_entropy'] = max(current_region['max_entropy'], entropy)
                else:
                    if current_region is not None:
                        high_entropy_regions.append(current_region)
                        current_region = None
            
            if current_region is not None:
                high_entropy_regions.append(current_region)
            
            return {
                'average_entropy': avg_entropy,
                'max_entropy': max_entropy,
                'min_entropy': min_entropy,
                'high_entropy_regions': high_entropy_regions,
                'total_chunks': len(entropies),
                'chunk_size': chunk_size
            }
        
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in freq.values():
            p = count / data_len
            entropy -= p * math.log2(p)
        
        return entropy
    
    def detect_packing_algorithms(self) -> Dict:
        """Detect common packing/obfuscation algorithms"""
        try:
            with open(self.dll_path, 'rb') as f:
                data = f.read()
            
            packers_detected = []
            packer_signatures = {
                'UPX': [b'UPX0', b'UPX1', b'UPX2', b'UPX!'],
                'PECompact': [b'PECompact', b'PEC2'],
                'ASPack': [b'ASPack', b'ASPack 2.12'],
                'FSG': [b'FSG', b'FSG 1.0', b'FSG 2.0'],
                'MEW': [b'MEW', b'MEWS'],
                'Petite': [b'Petite', b'petite'],
                'Neolite': [b'Neolite', b'NEOLITE'],
                'WinUpack': [b'WinUpack', b'WinUP'],
                'tElock': [b'tElock', b'tE!', b'Elock'],
                'Exe32Pack': [b'Exe32Pack', b'E32P'],
                'Yoda': [b'Yoda', b'YodaProt'],
                'PESpin': [b'PESpin', b'SPIN'],
                'Themida': [b'Themida', b'WinLicense'],
                'Obsidium': [b'Obsidium', b'OBSD'],
                'Enigma': [b'Enigma', b'ENIGMA']
            }
            
            for packer, signatures in packer_signatures.items():
                for sig in signatures:
                    if sig in data:
                        packers_detected.append(packer)
                        break
            
            # Check for high entropy sections (indicative of packing)
            sections = self.get_sections()
            high_entropy_sections = [s for s in sections if s['entropy'] > 7.5]
            
            # Check for small import table (common in packed files)
            imports = self.get_imported_functions()
            few_imports = len(imports) < 5
            
            # Check for single section
            single_section = len(sections) <= 3
            
            return {
                'detected_packers': packers_detected,
                'high_entropy_sections': len(high_entropy_sections),
                'few_imports': few_imports,
                'single_section': single_section,
                'likely_packed': len(packers_detected) > 0 or len(high_entropy_sections) > 0
            }
        
        except Exception as e:
            return {'error': str(e)}
    
    def extract_ip_addresses(self) -> List[str]:
        """Extract IP addresses from the file"""
        try:
            with open(self.dll_path, 'rb') as f:
                data = f.read()
            
            # IP address patterns
            ip_patterns = [
                rb'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # IPv4
                rb'\[([0-9a-fA-F:]+)\]',  # IPv6 in brackets
                rb'([0-9a-fA-F:]{2,})',  # IPv6 (basic)
            ]
            
            ips = []
            for pattern in ip_patterns:
                matches = re.findall(pattern, data)
                for match in matches:
                    try:
                        ip = match.decode('utf-8', errors='ignore')
                        if self._is_valid_ip(ip):
                            ips.append(ip)
                    except:
                        pass
            
            return list(set(ips))  # Remove duplicates
        
        except:
            return []
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            # Basic IPv4 validation
            if '.' in ip:
                parts = ip.split('.')
                if len(parts) == 4:
                    for part in parts:
                        num = int(part)
                        if num < 0 or num > 255:
                            return False
                    return True
            
            # Basic IPv6 validation (simplified)
            if ':' in ip:
                return len(ip) > 3 and all(c in '0123456789abcdefABCDEF:' for c in ip)
            
            return False
        except:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        try:
            if '.' in ip:
                parts = ip.split('.')
                first = int(parts[0])
                second = int(parts[1])
                
                # 10.0.0.0/8
                if first == 10:
                    return True
                
                # 172.16.0.0/12
                if first == 172 and 16 <= second <= 31:
                    return True
                
                # 192.168.0.0/16
                if first == 192 and second == 168:
                    return True
                
                # 127.0.0.0/8 (localhost)
                if first == 127:
                    return True
            
            return False
        except:
            return False
    
    def analyze_code_patterns(self) -> Dict:
        """Analyze code patterns and instructions"""
        try:
            patterns = {
                'anti_debug': [],
                'anti_vm': [],
                'anti_sandbox': [],
                'persistence': [],
                'evasion': [],
                'cryptography': [],
                'network': [],
                'injection': []
            }
            
            with open(self.dll_path, 'rb') as f:
                data = f.read()
            
            # Anti-debugging patterns
            anti_debug_patterns = [
                b'IsDebuggerPresent',
                b'CheckRemoteDebuggerPresent',
                b'NtQueryInformationProcess',
                b'NtSetInformationThread',
                b'OutputDebugString',
                b'DebugActiveProcess',
                b'NtDebugActiveProcess'
            ]
            
            # Anti-VM patterns
            anti_vm_patterns = [
                b'VMware',
                b'VirtualBox',
                b'QEMU',
                b'Xen',
                b'Hyper-V',
                b'KVM',
                b'Parallels',
                b'Sandbox',
                b'Cuckoo',
                b'JoeBox',
                b'ThreatAnalyzer'
            ]
            
            # Anti-sandbox patterns
            anti_sandbox_patterns = [
                b'SbieDll',
                b'Sandboxie',
                b'wireshark',
                b'procmon',
                b'tcpview',
                b'process explorer',
                b'sysinternals'
            ]
            
            # Persistence mechanisms
            persistence_patterns = [
                b'RegSetValue',
                b'RegCreateKey',
                b'CreateService',
                b'StartService',
                b'SetWindowsHookEx',
                b'WritePrivateProfileString',
                b'ScheduleJob',
                b'CreateJobObject'
            ]
            
            # Evasion techniques
            evasion_patterns = [
                b'Sleep',
                b'GetTickCount',
                b'QueryPerformanceCounter',
                b'timeGetTime',
                b'GetLocalTime',
                b'GetSystemTime',
                b'NtQuerySystemTime'
            ]
            
            # Cryptography patterns
            crypto_patterns = [
                b'CryptEncrypt',
                b'CryptDecrypt',
                b'CryptCreateHash',
                b'CryptDeriveKey',
                b'CryptGenKey',
                b'CryptAcquireContext',
                b'CryptImportKey',
                b'CryptExportKey'
            ]
            
            # Network patterns
            network_patterns = [
                b'WSAStartup',
                b'Socket',
                b'Connect',
                b'Send',
                b'Recv',
                b'InternetOpen',
                b'InternetConnect',
                b'HttpOpenRequest',
                b'HttpSendRequest'
            ]
            
            # Injection patterns
            injection_patterns = [
                b'WriteProcessMemory',
                b'CreateRemoteThread',
                b'VirtualAllocEx',
                b'QueueUserAPC',
                b'NtQueueApcThread',
                b'RtlCreateUserThread',
                b'CreateProcessInternalW'
            ]
            
            # Check for patterns
            for pattern in anti_debug_patterns:
                if pattern in data:
                    patterns['anti_debug'].append(pattern.decode('utf-8', errors='ignore'))
            
            for pattern in anti_vm_patterns:
                if pattern in data:
                    patterns['anti_vm'].append(pattern.decode('utf-8', errors='ignore'))
            
            for pattern in anti_sandbox_patterns:
                if pattern in data:
                    patterns['anti_sandbox'].append(pattern.decode('utf-8', errors='ignore'))
            
            for pattern in persistence_patterns:
                if pattern in data:
                    patterns['persistence'].append(pattern.decode('utf-8', errors='ignore'))
            
            for pattern in evasion_patterns:
                if pattern in data:
                    patterns['evasion'].append(pattern.decode('utf-8', errors='ignore'))
            
            for pattern in crypto_patterns:
                if pattern in data:
                    patterns['cryptography'].append(pattern.decode('utf-8', errors='ignore'))
            
            for pattern in network_patterns:
                if pattern in data:
                    patterns['network'].append(pattern.decode('utf-8', errors='ignore'))
            
            for pattern in injection_patterns:
                if pattern in data:
                    patterns['injection'].append(pattern.decode('utf-8', errors='ignore'))
            
            return patterns
        
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_file_timeline(self) -> Dict:
        """Analyze file timeline and metadata"""
        try:
            file_stat = os.stat(self.dll_path)
            
            # File system timestamps
            creation_time = datetime.fromtimestamp(file_stat.st_ctime)
            modification_time = datetime.fromtimestamp(file_stat.st_mtime)
            access_time = datetime.fromtimestamp(file_stat.st_atime)
            
            # PE timestamp
            pe_timestamp = 0
            if self.pe and hasattr(self.pe, 'FILE_HEADER'):
                pe_timestamp = self.pe.FILE_HEADER.TimeDateStamp
                pe_compile_time = datetime.fromtimestamp(pe_timestamp)
            else:
                pe_compile_time = None
            
            # Analyze timestamp anomalies
            anomalies = []
            
            # Check for future timestamps
            now = datetime.now()
            if pe_compile_time and pe_compile_time > now:
                anomalies.append(f"Future PE timestamp: {pe_compile_time}")
            
            # Check for old timestamps
            if pe_compile_time and pe_compile_time < datetime(1990, 1, 1):
                anomalies.append(f"Suspicious old PE timestamp: {pe_compile_time}")
            
            # Check for timestamp inconsistencies
            if pe_compile_time:
                time_diff = abs((pe_compile_time - modification_time).total_seconds())
                if time_diff > 365 * 24 * 3600:  # More than 1 year difference
                    anomalies.append(f"Large timestamp discrepancy: PE={pe_compile_time}, FS={modification_time}")
            
            return {
                'file_creation': creation_time.strftime('%Y-%m-%d %H:%M:%S'),
                'file_modification': modification_time.strftime('%Y-%m-%d %H:%M:%S'),
                'file_access': access_time.strftime('%Y-%m-%d %H:%M:%S'),
                'pe_compile_time': pe_compile_time.strftime('%Y-%m-%d %H:%M:%S') if pe_compile_time else None,
                'pe_timestamp': pe_timestamp,
                'timestamp_anomalies': anomalies,
                'file_age_days': (now - creation_time).days
            }
        
        except Exception as e:
            return {'error': str(e)}
    
    def extract_certificates(self) -> Dict:
        """Extract digital certificate information"""
        try:
            if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
                return {'signed': False, 'certificates': []}
            
            certificates = []
            security_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            
            if security_dir.Size == 0:
                return {'signed': False, 'certificates': []}
            
            # Parse certificate directory
            cert_data = self.pe.get_data(security_dir.VirtualAddress, security_dir.Size)
            
            # Extract certificate info (simplified)
            cert_info = {
                'size': security_dir.Size,
                'virtual_address': security_dir.VirtualAddress,
                'has_certificate': True,
                'certificate_data': cert_data[:100].hex() if len(cert_data) > 100 else cert_data.hex()
            }
            
            certificates.append(cert_info)
            
            return {
                'signed': True,
                'certificates': certificates,
                'total_cert_size': security_dir.Size
            }
        
        except Exception as e:
            return {'error': str(e), 'signed': False}
    
    def attempt_upx_unpack(self) -> Dict:
        """Attempt to detect and unpack UPX-packed files"""
        try:
            with open(self.dll_path, 'rb') as f:
                data = f.read()
            
            # Check for UPX signatures
            upx_signatures = [b'UPX0', b'UPX1', b'UPX2', b'UPX!']
            is_upx_packed = any(sig in data for sig in upx_signatures)
            
            if not is_upx_packed:
                return {'upx_detected': False, 'unpacked': False}
            
            # Try to find UPX section
            upx_section = None
            if hasattr(self.pe, 'sections'):
                for section in self.pe.sections:
                    section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                    if 'UPX' in section_name:
                        upx_section = section
                        break
            
            result = {
                'upx_detected': True,
                'upx_section_found': upx_section is not None,
                'unpacked': False,
                'unpacked_data': None,
                'original_entry_point': None,
                'new_entry_point': None
            }
            
            # Try to find original entry point
            if upx_section:
                # UPX typically stores the original EP at the end of the first section
                try:
                    # Look for UPX unpacking stub
                    section_data = upx_section.get_data()
                    if len(section_data) > 100:
                        # Try to find the original EP pattern
                        for i in range(len(section_data) - 4):
                            # Look for potential EP (simple heuristic)
                            if section_data[i:i+4] == b'\x68\x00\x00\x00\x00':  # push 0
                                potential_ep = i + 5
                                if potential_ep < len(section_data):
                                    result['original_entry_point'] = f"0x{potential_ep:08x}"
                                    break
                except:
                    pass
            
            # Attempt manual unpacking (simplified)
            try:
                # This is a very basic unpacking attempt
                # In reality, you'd need more sophisticated unpacking logic
                unpacked_data = self._simple_upx_unpack_attempt(data)
                if unpacked_data:
                    result['unpacked'] = True
                    result['unpacked_data'] = unpacked_data[:500].hex()  # First 500 bytes as hex
                    result['unpacked_size'] = len(unpacked_data)
            except:
                pass
            
            return result
        
        except Exception as e:
            return {'error': str(e), 'upx_detected': False}
    
    def _simple_upx_unpack_attempt(self, data: bytes) -> Optional[bytes]:
        """Simple UPX unpacking attempt (very basic)"""
        try:
            # Look for UPX unpacking stub patterns
            upx_patterns = [
                b'UPX!',  # UPX signature
                b'\x60\x9A\xE8',  # Common UPX prologue
                b'\xBE\x00\x10\x00\x00'  # UPX data section start
            ]
            
            for pattern in upx_patterns:
                offset = data.find(pattern)
                if offset != -1:
                    # Found potential UPX data, try to extract
                    # This is very simplified - real unpacking is much more complex
                    start = max(0, offset - 1000)
                    end = min(len(data), offset + 10000)
                    return data[start:end]
            
            return None
        except:
            return None
    
    def analyze_packed_sections(self) -> Dict:
        """Deep analysis of packed/obfuscated sections"""
        try:
            sections = self.get_sections()
            packed_analysis = {
                'high_entropy_sections': [],
                'suspicious_sections': [],
                'potential_code_caves': [],
                'unpacking_suggestions': []
            }
            
            for section in sections:
                section_name = section['name']
                entropy = section['entropy']
                size = section['size']
                virtual_address = section['virtual_address']
                
                # High entropy analysis
                if entropy > 7.0:
                    packed_analysis['high_entropy_sections'].append({
                        'name': section_name,
                        'entropy': entropy,
                        'size': size,
                        'virtual_address': f"0x{virtual_address:08x}",
                        'likely_packed': True
                    })
                
                # Suspicious section names
                suspicious_names = ['.upx', '.packed', '.adata', '.text', '.rsrc']
                if any(susp in section_name.lower() for susp in suspicious_names):
                    if entropy > 6.0:
                        packed_analysis['suspicious_sections'].append({
                            'name': section_name,
                            'entropy': entropy,
                            'reason': f"High entropy ({entropy:.2f}) in suspicious section"
                        })
                
                # Look for code caves (unused space in sections)
                if size > 0x1000 and entropy < 1.0:  # Large, low entropy section
                    packed_analysis['potential_code_caves'].append({
                        'name': section_name,
                        'size': size,
                        'virtual_address': f"0x{virtual_address:08x}",
                        'potential_cave_size': size // 2
                    })
            
            # Generate unpacking suggestions
            if packed_analysis['high_entropy_sections']:
                packed_analysis['unpacking_suggestions'].append(
                    "High entropy sections detected - likely packed. Try UPX unpacking or manual unpacking."
                )
            
            if packed_analysis['suspicious_sections']:
                packed_analysis['unpacking_suggestions'].append(
                    "Suspicious section names with high entropy - manual analysis recommended."
                )
            
            if not packed_analysis['high_entropy_sections'] and not packed_analysis['suspicious_sections']:
                packed_analysis['unpacking_suggestions'].append(
                    "No obvious packing detected - file may be obfuscated or encrypted."
                )
            
            return packed_analysis
        
        except Exception as e:
            return {'error': str(e)}
    
    def extract_hidden_strings(self) -> Dict:
        """Extract strings from packed/hidden regions"""
        try:
            with open(self.dll_path, 'rb') as f:
                data = f.read()
            
            # Extract strings from high entropy regions
            entropy_analysis = self.analyze_entropy_distribution()
            hidden_strings = {
                'total_strings_found': 0,
                'suspicious_strings': [],
                'url_like_strings': [],
                'registry_keys': [],
                'file_paths': [],
                'api_calls': []
            }
            
            # Define patterns
            patterns = {
                'urls': rb'(https?://[^\s\x00-\x1f\x7f-\x9f]+|ftp://[^\s\x00-\x1f\x7f-\x9f]+)',
                'registry': rb'(HKEY_[A-Z_]+|\\\\.*\\[A-Za-z0-9_\-\.]+)',
                'file_paths': rb'([A-Za-z]:\\\\[^\\x00-\x1f\\x7f-\\x9f]+|\\\\[^\\x00-\x1f\\x7f-\\x9f]+)',
                'apis': rb'([A-Za-z][A-Za-z0-9]*[A-Z][a-z][A-Za-z0-9]*)'
            }
            
            # Extract all printable strings
            all_strings = re.findall(rb'[\x20-\x7E]{4,}', data)
            hidden_strings['total_strings_found'] = len(all_strings)
            
            # Categorize strings
            for string_bytes in all_strings:
                try:
                    string = string_bytes.decode('utf-8', errors='ignore')
                    
                    # URLs
                    if re.match(rb'https?://', string_bytes) or re.match(rb'ftp://', string_bytes):
                        hidden_strings['url_like_strings'].append(string)
                    
                    # Registry keys
                    if b'HKEY_' in string_bytes or (b'\\\\' in string_bytes and b'\\' in string_bytes[2:]):
                        hidden_strings['registry_keys'].append(string)
                    
                    # File paths
                    if (b':\\\\' in string_bytes) or (b'\\\\\\\\' in string_bytes):
                        hidden_strings['file_paths'].append(string)
                    
                    # API calls (heuristic)
                    if len(string) > 5 and any(c.isupper() for c in string[1:]) and any(c.islower() for c in string[1:]):
                        if string[0].isupper() and any(word in string for word in ['Get', 'Set', 'Create', 'Delete', 'Open', 'Close', 'Read', 'Write']):
                            hidden_strings['api_calls'].append(string)
                    
                    # Suspicious strings
                    suspicious_keywords = ['password', 'key', 'secret', 'token', 'api', 'crypt', 'decode', 'unpack', 'inject', 'shell']
                    if any(keyword in string.lower() for keyword in suspicious_keywords):
                        hidden_strings['suspicious_strings'].append(string)
                
                except:
                    continue
            
            # Remove duplicates and limit results
            for key in hidden_strings:
                if key != 'total_strings_found':
                    hidden_strings[key] = list(set(hidden_strings[key]))[:20]  # Limit to 20 unique items
            
            return hidden_strings
        
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_entry_point(self) -> Dict:
        """Analyze the entry point for unpacking clues"""
        try:
            if not self.pe:
                return {'error': 'PE file not loaded'}
            
            entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = self.pe.OPTIONAL_HEADER.ImageBase
            actual_entry = image_base + entry_point
            
            analysis = {
                'entry_point_offset': f"0x{entry_point:08x}",
                'entry_point_va': f"0x{actual_entry:08x}",
                'image_base': f"0x{image_base:08x}",
                'entry_section': None,
                'entry_bytes': None,
                'disassembly_hint': None
            }
            
            # Find which section contains the entry point
            if hasattr(self.pe, 'sections'):
                for section in self.pe.sections:
                    if (section.VirtualAddress <= entry_point < 
                        section.VirtualAddress + section.SizeOfRawData):
                        analysis['entry_section'] = {
                            'name': section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                            'virtual_address': f"0x{section.VirtualAddress:08x}",
                            'size': section.SizeOfRawData,
                            'entropy': section.get_entropy()
                        }
                        break
            
            # Get bytes at entry point
            try:
                entry_data = self.pe.get_data(entry_point, min(32, self.pe.OPTIONAL_HEADER.SizeOfImage - entry_point))
                analysis['entry_bytes'] = entry_data.hex()
                
                # Simple disassembly hints
                if entry_data.startswith(b'\x60') or entry_data.startswith(b'\x9C'):
                    analysis['disassembly_hint'] = "Possible packed code (pushad/pushfd)"
                elif entry_data.startswith(b'\xE9'):
                    analysis['disassembly_hint'] = "Jump instruction - possible unpacking stub"
                elif entry_data.startswith(b'\xB8'):
                    analysis['disassembly_hint'] = "Move immediate - possible unpacking stub"
                else:
                    analysis['disassembly_hint'] = "Unknown entry pattern"
            except:
                analysis['entry_bytes'] = "Unable to read entry point bytes"
            
            return analysis
        
        except Exception as e:
            return {'error': str(e)}

def main():
    parser = argparse.ArgumentParser(description='DLL Analyzer Tool')
    parser.add_argument('dll_path', help='Path to DLL file')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-f', '--format', choices=['json', 'txt'], default='json', help='Output format')
    parser.add_argument('--strings-only', action='store_true', help='Extract strings only')
    parser.add_argument('--exports-only', action='store_true', help='Extract exports only')
    parser.add_argument('--imports-only', action='store_true', help='Extract imports only')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.dll_path):
        print(f"Error: DLL file not found: {args.dll_path}")
        return 1
    
    analyzer = DLLAnalyzer(args.dll_path)
    
    if args.strings_only:
        if analyzer.load_dll():
            strings = analyzer.analyze_strings()
            for s in strings:
                print(s)
    elif args.exports_only:
        if analyzer.load_dll():
            exports = analyzer.get_exported_functions()
            for exp in exports:
                print(f"{exp['name']} (Ordinal: {exp['ordinal']}, Address: 0x{exp['address']:08x})")
    elif args.imports_only:
        if analyzer.load_dll():
            imports = analyzer.get_imported_functions()
            for imp in imports:
                print(f"{imp['dll']}: {imp['function']}")
    else:
        results = analyzer.full_analysis()
        
        # Quick risk assessment
        characteristics = results.get('characteristics', {})
        metadata = results.get('metadata', {})
        urls = results.get('embedded_urls', [])
        
        print("\n" + "="*60)
        print("QUICK SECURITY ASSESSMENT")
        print("="*60)
        
        risk_score = 0
        if characteristics.get('is_packed'): risk_score += 25
        if not characteristics.get('is_signed'): risk_score += 15
        if len(urls) > 10: risk_score += 20
        
        print(f"• Risk Score: {risk_score}/100")
        print(f"• Packed: {'Yes WARNING' if characteristics.get('is_packed') else 'No'}")
        print(f"• Signed: {'Yes' if characteristics.get('is_signed') else 'No WARNING'}")
        print(f"• URLs Found: {len(urls)} {'WARNING' if len(urls) > 10 else ''}")
        print(f"• Dependencies: {results.get('dependencies', {}).get('total_dependencies', 0)}")
        
        # Show suspicious indicators
        suspicious_imports = analyzer._find_suspicious_imports(results.get('imports', []))
        has_suspicious = any(suspicious_imports.values())
        
        if has_suspicious:
            print("WARNING: Contains suspicious imports")
        
        compile_time = metadata.get('compile_info', {}).get('compile_time', '')
        if '2049' in compile_time:
            print("WARNING: Suspicious future timestamp detected!")
        
        print("\n" + "="*60)
        print("DETAILED ANALYSIS OPTIONS")
        print("="*60)
        print("1. Show all embedded URLs")
        print("2. Analyze suspicious imports") 
        print("3. Show dependency details")
        print("4. Extract and analyze strings")
        print("5. Check for .NET metadata")
        print("6. Show file hashes for malware checking")
        print("7. Analyze entropy distribution")
        print("8. Detect packing algorithms")
        print("9. Extract IP addresses")
        print("10. Analyze code patterns (anti-analysis)")
        print("11. File timeline analysis")
        print("12. Certificate analysis")
        print("13. Attempt UPX unpacking")
        print("14. Analyze packed sections")
        print("15. Extract hidden strings")
        print("16. Entry point analysis")
        print("17. Generate comprehensive security report")
        print("18. Exit")
        
        while True:
            try:
                choice = input("\nSelect analysis option (1-18): ").strip()
                
                if choice == '1':
                    print(f"\nEMBEDDED URLS ({len(urls)} total):")
                    print("="*50)
                    # Clean and filter URLs
                    clean_urls = []
                    for url in urls:
                        clean_url = ''.join(c for c in url if ord(c) >= 32 and ord(c) <= 126)
                        if len(clean_url) > 10 and ('.' in clean_url or 'http' in clean_url):
                            clean_urls.append(clean_url)
                    
                    clean_urls = list(set(clean_urls))[:20]  # Remove duplicates, show first 20
                    
                    for i, url in enumerate(clean_urls, 1):
                        print(f"{i:2d}. {url}")
                
                elif choice == '2':
                    print(f"\nSUSPICIOUS IMPORTS ANALYSIS:")
                    print("="*50)
                    
                    if suspicious_imports:
                        for category, functions in suspicious_imports.items():
                            if functions:
                                print(f"\n{category.upper()}:")
                                for func in functions[:5]:
                                    print(f"   • {func}")
                    else:
                        print("No obviously suspicious imports found")
                
                elif choice == '3':
                    deps = results.get('dependencies', {})
                    print(f"\nDEPENDENCY ANALYSIS:")
                    print("="*50)
                    print(f"• Total Dependencies: {deps.get('total_dependencies', 0)}")
                    print(f"• System DLLs: {deps.get('system_dlls', 0)}")
                    print(f"• Third-Party DLLs: {deps.get('third_party_dlls', 0)}")
                    
                    deps_data = deps.get('dependencies', {})
                    for name, data in list(deps_data.items())[:10]:
                        risk_level = data.get('risk_level', 'UNKNOWN')
                        print(f"   [{risk_level}] {name} ({data.get('function_count', 0)} functions)")
                
                elif choice == '4':
                    strings = results.get('strings', [])
                    print(f"\nSTRING ANALYSIS:")
                    print("="*50)
                    print(f"• Total strings: {len(strings)}")
                    
                    # Find interesting strings
                    interesting = []
                    for s in strings:
                        if len(s) > 15 and len(s) < 100:
                            if any(char in s for char in ['.', '/', '\\', ':', 'http']):
                                interesting.append(s)
                    
                    print(f"• Interesting strings: {len(interesting)}")
                    for s in interesting[:15]:
                        print(f"   • {s}")
                
                elif choice == '5':
                    print(f"\n.NET METADATA:")
                    print("="*50)
                    if characteristics.get('is_dotnet'):
                        print("Yes - .NET Assembly detected")
                        print("💡 Can be decompiled with dnSpy, ILSpy, or dotPeek")
                    else:
                        print("No - Not a .NET assembly")
                    
                    imports = results.get('imports', [])
                    dotnet_imports = [imp for imp in imports if 'mscoree' in imp['dll'].lower()]
                    if dotnet_imports:
                        print(f"\n.NET IMPORTS:")
                        for imp in dotnet_imports:
                            print(f"   • {imp['dll']}: {imp['function']}")
                
                elif choice == '6':
                    file_info = metadata.get('file_info', {})
                    print(f"\nFILE HASHES FOR MALWARE CHECKING:")
                    print("="*50)
                    if file_info:
                        print(f"• MD5:    {file_info.get('md5', 'N/A')}")
                        print(f"• SHA1:   {file_info.get('sha1', 'N/A')}")
                        print(f"• SHA256: {file_info.get('sha256', 'N/A')}")
                    
                    print(f"\nCHECK THESE HASHES ON:")
                    print("• VirusTotal: https://www.virustotal.com/")
                    print("• Hybrid Analysis: https://www.hybrid-analysis.com/")
                
                elif choice == '7':
                    entropy = results.get('entropy_analysis', {})
                    print(f"\nENTROPY DISTRIBUTION ANALYSIS:")
                    print("="*50)
                    
                    if 'error' in entropy:
                        print(f"Error: {entropy['error']}")
                    else:
                        print(f"• Average Entropy: {entropy.get('average_entropy', 0):.2f}")
                        print(f"• Max Entropy: {entropy.get('max_entropy', 0):.2f}")
                        print(f"• Min Entropy: {entropy.get('min_entropy', 0):.2f}")
                        print(f"• Total Chunks: {entropy.get('total_chunks', 0)}")
                        
                        high_entropy_regions = entropy.get('high_entropy_regions', [])
                        if high_entropy_regions:
                            print(f"\nHIGH ENTROPY REGIONS ({len(high_entropy_regions)}):")
                            for i, region in enumerate(high_entropy_regions[:5], 1):
                                start = region.get('start', 0)
                                end = region.get('end', 0)
                                max_e = region.get('max_entropy', 0)
                                print(f"   {i}. Offset 0x{start:08x}-0x{end:08x} (Max: {max_e:.2f})")
                            if len(high_entropy_regions) > 5:
                                print(f"   ... and {len(high_entropy_regions) - 5} more")
                
                elif choice == '8':
                    packing = results.get('packing_analysis', {})
                    print(f"\nPACKING ALGORITHM DETECTION:")
                    print("="*50)
                    
                    if 'error' in packing:
                        print(f"Error: {packing['error']}")
                    else:
                        detected_packers = packing.get('detected_packers', [])
                        if detected_packers:
                            print(f"DETECTED PACKERS:")
                            for packer in detected_packers:
                                print(f"   • {packer}")
                        else:
                            print("No known packers detected")
                        
                        print(f"\nPACKING INDICATORS:")
                        print(f"• High Entropy Sections: {packing.get('high_entropy_sections', 0)}")
                        print(f"• Few Imports: {'Yes' if packing.get('few_imports') else 'No'}")
                        print(f"• Single Section: {'Yes' if packing.get('single_section') else 'No'}")
                        print(f"• Likely Packed: {'Yes WARNING' if packing.get('likely_packed') else 'No'}")
                
                elif choice == '9':
                    ips = results.get('ip_addresses', [])
                    print(f"\nIP ADDRESS EXTRACTION:")
                    print("="*50)
                    
                    if ips:
                        print(f"FOUND {len(ips)} IP ADDRESSES:")
                        for i, ip in enumerate(ips[:20], 1):
                            print(f"   {i:2d}. {ip}")
                        if len(ips) > 20:
                            print(f"   ... and {len(ips) - 20} more")
                        
                        # Categorize IPs
                        private_ips = []
                        public_ips = []
                        for ip in ips:
                            if self._is_private_ip(ip):
                                private_ips.append(ip)
                            else:
                                public_ips.append(ip)
                        
                        print(f"\nIP CATEGORIES:")
                        print(f"• Private IPs: {len(private_ips)}")
                        print(f"• Public IPs: {len(public_ips)}")
                        
                        if public_ips:
                            print(f"WARNING: PUBLIC IPs (potential C&C): {public_ips[:5]}")
                    else:
                        print("No IP addresses found")
                
                elif choice == '10':
                    patterns = results.get('code_patterns', {})
                    print(f"\nCODE PATTERN ANALYSIS:")
                    print("="*50)
                    
                    if 'error' in patterns:
                        print(f"Error: {patterns['error']}")
                    else:
                        categories = [
                            ('Anti-Debug', 'anti_debug'),
                            ('Anti-VM', 'anti_vm'),
                            ('Anti-Sandbox', 'anti_sandbox'),
                            ('Persistence', 'persistence'),
                            ('Evasion', 'evasion'),
                            ('Cryptography', 'cryptography'),
                            ('Network', 'network'),
                            ('Injection', 'injection')
                        ]
                        
                        for display_name, key in categories:
                            items = patterns.get(key, [])
                            if items:
                                print(f"\n{display_name.upper()} ({len(items)}):")
                                for item in items[:3]:
                                    print(f"   • {item}")
                                if len(items) > 3:
                                    print(f"   ... and {len(items) - 3} more")
                            else:
                                print(f"{display_name}: None detected")
                
                elif choice == '11':
                    timeline = results.get('timeline_analysis', {})
                    print(f"\nFILE TIMELINE ANALYSIS:")
                    print("="*50)
                    
                    if 'error' in timeline:
                        print(f"Error: {timeline['error']}")
                    else:
                        print(f"\nFILE TIMESTAMPS:")
                        print(f"• File Creation: {timeline.get('file_creation', 'Unknown')}")
                        print(f"• File Modification: {timeline.get('file_modification', 'Unknown')}")
                        print(f"• File Access: {timeline.get('file_access', 'Unknown')}")
                        print(f"• PE Compile Time: {timeline.get('pe_compile_time', 'Unknown')}")
                        print(f"• File Age: {timeline.get('file_age_days', 0)} days")
                        
                        anomalies = timeline.get('timestamp_anomalies', [])
                        if anomalies:
                            print(f"\nTIMESTAMP ANOMALIES:")
                            for anomaly in anomalies:
                                print(f"   • {anomaly}")
                        else:
                            print(f"\nNo timestamp anomalies detected")
                
                elif choice == '12':
                    certs = results.get('certificate_analysis', {})
                    print(f"\nCERTIFICATE ANALYSIS:")
                    print("="*50)
                    
                    if 'error' in certs:
                        print(f"Error: {certs['error']}")
                    else:
                        if certs.get('signed'):
                            print(f"YES - FILE IS DIGITALLY SIGNED")
                            print(f"• Certificate Size: {certs.get('total_cert_size', 0)} bytes")
                            
                            cert_list = certs.get('certificates', [])
                            for i, cert in enumerate(cert_list, 1):
                                print(f"\nCERTIFICATE {i}:")
                                print(f"   • Size: {cert.get('size', 0)} bytes")
                                print(f"   • Virtual Address: 0x{cert.get('virtual_address', 0):08x}")
                                print(f"   • Data Preview: {cert.get('certificate_data', '')[:50]}...")
                        else:
                            print("NO - FILE IS NOT DIGITALLY SIGNED")
                            print("WARNING: Unsigned files pose higher security risk")
                
                elif choice == '13':
                    upx = results.get('upx_unpack', {})
                    print(f"\nUPX UNPACKING ATTEMPT:")
                    print("="*50)
                    
                    if 'error' in upx:
                        print(f"Error: {upx['error']}")
                    else:
                        print(f"• UPX Detected: {'Yes' if upx.get('upx_detected') else 'No'}")
                        print(f"• UPX Section Found: {'Yes' if upx.get('upx_section_found') else 'No'}")
                        print(f"• Unpacked Successfully: {'Yes' if upx.get('unpacked') else 'No'}")
                        
                        if upx.get('original_entry_point'):
                            print(f"• Original Entry Point: {upx.get('original_entry_point')}")
                        
                        if upx.get('unpacked_data'):
                            print(f"• Unpacked Data Size: {upx.get('unpacked_size', 0)} bytes")
                            print(f"• Unpacked Data Preview: {upx.get('unpacked_data', '')[:100]}...")
                        
                        if not upx.get('upx_detected'):
                            print("\nThis file is not UPX-packed.")
                            print("Try option 14 for general packing analysis.")
                
                elif choice == '14':
                    packed = results.get('packed_sections', {})
                    print(f"\nPACKED SECTIONS ANALYSIS:")
                    print("="*50)
                    
                    if 'error' in packed:
                        print(f"Error: {packed['error']}")
                    else:
                        high_entropy = packed.get('high_entropy_sections', [])
                        suspicious = packed.get('suspicious_sections', [])
                        code_caves = packed.get('potential_code_caves', [])
                        
                        print(f"• High Entropy Sections: {len(high_entropy)}")
                        for section in high_entropy[:5]:
                            print(f"   - {section['name']} (Entropy: {section['entropy']:.2f})")
                        
                        print(f"\n• Suspicious Sections: {len(suspicious)}")
                        for section in suspicious[:3]:
                            print(f"   - {section['name']}: {section['reason']}")
                        
                        print(f"\n• Potential Code Caves: {len(code_caves)}")
                        for cave in code_caves[:3]:
                            print(f"   - {cave['name']}: ~{cave['potential_cave_size']} bytes available")
                        
                        suggestions = packed.get('unpacking_suggestions', [])
                        if suggestions:
                            print(f"\nUNPACKING SUGGESTIONS:")
                            for i, suggestion in enumerate(suggestions, 1):
                                print(f"   {i}. {suggestion}")
                
                elif choice == '15':
                    hidden = results.get('hidden_strings', {})
                    print(f"\nHIDDEN STRINGS EXTRACTION:")
                    print("="*50)
                    
                    if 'error' in hidden:
                        print(f"Error: {hidden['error']}")
                    else:
                        print(f"• Total Strings Found: {hidden.get('total_strings_found', 0)}")
                        
                        suspicious = hidden.get('suspicious_strings', [])
                        urls = hidden.get('url_like_strings', [])
                        registry = hidden.get('registry_keys', [])
                        file_paths = hidden.get('file_paths', [])
                        apis = hidden.get('api_calls', [])
                        
                        if suspicious:
                            print(f"\nSUSPICIOUS STRINGS ({len(suspicious)}):")
                            for s in suspicious[:10]:
                                print(f"   - {s}")
                        
                        if urls:
                            print(f"\nHIDDEN URLS ({len(urls)}):")
                            for url in urls[:5]:
                                print(f"   - {url}")
                        
                        if registry:
                            print(f"\nREGISTRY KEYS ({len(registry)}):")
                            for key in registry[:5]:
                                print(f"   - {key}")
                        
                        if file_paths:
                            print(f"\nFILE PATHS ({len(file_paths)}):")
                            for path in file_paths[:5]:
                                print(f"   - {path}")
                        
                        if apis:
                            print(f"\nAPI CALLS ({len(apis)}):")
                            for api in apis[:5]:
                                print(f"   - {api}")
                
                elif choice == '16':
                    entry = results.get('entry_point_analysis', {})
                    print(f"\nENTRY POINT ANALYSIS:")
                    print("="*50)
                    
                    if 'error' in entry:
                        print(f"Error: {entry['error']}")
                    else:
                        print(f"• Entry Point Offset: {entry.get('entry_point_offset', 'Unknown')}")
                        print(f"• Entry Point VA: {entry.get('entry_point_va', 'Unknown')}")
                        print(f"• Image Base: {entry.get('image_base', 'Unknown')}")
                        
                        entry_section = entry.get('entry_section')
                        if entry_section:
                            print(f"\nENTRY SECTION:")
                            print(f"• Name: {entry_section.get('name', 'Unknown')}")
                            print(f"• Virtual Address: {entry_section.get('virtual_address', 'Unknown')}")
                            print(f"• Size: {entry_section.get('size', 0)} bytes")
                            print(f"• Entropy: {entry_section.get('entropy', 0):.2f}")
                        
                        entry_bytes = entry.get('entry_bytes')
                        if entry_bytes:
                            print(f"\nENTRY POINT BYTES:")
                            print(f"• First 32 bytes: {entry_bytes}")
                        
                        hint = entry.get('disassembly_hint')
                        if hint:
                            print(f"\nDISASSEMBLY HINT:")
                            print(f"• {hint}")
                        
                        print(f"\nUNPACKING CLUES:")
                        if entry_section and entry_section.get('entropy', 0) > 7.0:
                            print("• High entropy at entry point - likely packed")
                        if hint and "packed" in hint.lower():
                            print("• Entry point pattern suggests packed code")
                        if entry_bytes and entry_bytes.startswith('60'):
                            print("• pushad instruction - common in unpacking stubs")
                
                elif choice == '17':
                    print(f"\nCOMPREHENSIVE SECURITY REPORT:")
                    print("="*50)
                    
                    security_score = 0
                    issues = []
                    
                    if characteristics.get('is_packed'):
                        security_score += 25
                        issues.append("Packed/obfuscated executable")
                    
                    if not characteristics.get('is_signed'):
                        security_score += 15
                        issues.append("No digital signature")
                    
                    if len(urls) > 10:
                        security_score += 20
                        issues.append(f"High number of embedded URLs ({len(urls)})")
                    
                    if has_suspicious:
                        security_score += 30
                        issues.append("Contains suspicious function imports")
                    
                    if '2049' in compile_time:
                        security_score += 20
                        issues.append("Suspicious future timestamp")
                    
                    if security_score >= 70:
                        risk_level = "CRITICAL"
                        action = "DO NOT EXECUTE - Analyze in isolated sandbox"
                    elif security_score >= 50:
                        risk_level = "HIGH"
                        action = "High suspicion - Sandbox analysis recommended"
                    elif security_score >= 30:
                        risk_level = "MEDIUM"
                        action = "Proceed with caution - Verify source"
                    else:
                        risk_level = "LOW"
                        action = "Appears safe but verify authenticity"
                    
                    print(f"\nFINAL ASSESSMENT:")
                    print(f"• Security Score: {security_score}/100")
                    print(f"• Risk Level: {risk_level}")
                    print(f"• Action: {action}")
                    
                    if issues:
                        print(f"\nISSUES FOUND:")
                        for i, issue in enumerate(issues, 1):
                            print(f"   {i}. {issue}")
                    
                    print(f"\nRECOMMENDATIONS:")
                    if characteristics.get('is_packed'):
                        print("   • Unpack using UPX or manual unpacking")
                    if characteristics.get('is_dotnet'):
                        print("   • Decompile with dnSpy to view source")
                    if len(urls) > 0:
                        print("   • Investigate embedded URLs")
                    if security_score >= 50:
                        print("   • Submit to VirusTotal for malware analysis")
                        print("   • Run in sandbox (Cuckoo, Any.Run)")
                
                elif choice == '18':
                    print("\nAnalysis complete.")
                    break
                
                else:
                    print("Invalid choice. Please select 1-18.")
            
            except KeyboardInterrupt:
                print("\nAnalysis interrupted.")
                break
            except Exception as e:
                print(f"\nError: {e}")
        
        if args.output:
            analyzer.export_report(args.output, args.format)
            print(f"\nReport exported to: {args.output}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
