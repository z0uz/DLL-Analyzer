#!/usr/bin/env python3
"""
Advanced DLL Disassembler and Analysis Tool
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

# Try to import capstone for disassembly
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    print("Warning: Capstone not available. Install with: pip install capstone")

class AdvancedDLLAnalyzer:
    def __init__(self, dll_path: str):
        self.dll_path = dll_path
        self.pe = None
        self.cs = None
        self.is_64bit = False
        
    def load_dll(self) -> bool:
        """Load and parse the DLL file"""
        try:
            self.pe = pefile.PE(self.dll_path)
            self.is_64bit = self.pe.FILE_HEADER.Machine == 0x8664
            
            if CAPSTONE_AVAILABLE:
                if self.is_64bit:
                    self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
                else:
                    self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            
            return True
        except Exception as e:
            print(f"Error loading DLL: {e}")
            return False
    
    def disassemble_function(self, address: int, size: int = 100) -> List[Dict]:
        """Disassemble code at given address"""
        if not self.cs or not self.pe:
            return []
        
        try:
            # Get raw data at the address
            section = self.pe.get_section_by_rva(address)
            if not section:
                return []
            
            offset = address - section.VirtualAddress
            data = section.get_data()[offset:offset+size]
            
            instructions = []
            for insn in self.cs.disasm(data, address):
                instructions.append({
                    'address': hex(insn.address),
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str,
                    'size': insn.size,
                    'bytes': insn.bytes.hex()
                })
            
            return instructions
        except Exception as e:
            print(f"Error disassembling at 0x{address:08x}: {e}")
            return []
    
    def analyze_function_patterns(self) -> Dict:
        """Analyze common function patterns"""
        patterns = {
            'entry_points': [],
            'api_calls': [],
            'string_references': [],
            'loops': [],
            'conditions': []
        }
        
        if not self.pe:
            return patterns
        
        # Find entry points
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name and exp.address:
                    patterns['entry_points'].append({
                        'name': exp.name.decode('utf-8', errors='ignore'),
                        'address': exp.address
                    })
        
        # Analyze strings for API references
        strings = self.extract_strings()
        api_patterns = [
            r'CreateFile', r'OpenFile', r'ReadFile', r'WriteFile',
            r'Registry', r'RegOpen', r'RegCreate', r'RegSetValue',
            r'Socket', r'Connect', r'Bind', r'Listen',
            r'VirtualAlloc', r'VirtualProtect', r'VirtualFree',
            r'LoadLibrary', r'GetProcAddress', r'CreateThread'
        ]
        
        for string in strings:
            for pattern in api_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    patterns['api_calls'].append(string)
        
        return patterns
    
    def extract_strings(self, min_length: int = 4) -> List[str]:
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
    
    def analyze_imports_heuristics(self) -> Dict:
        """Analyze imports for suspicious patterns"""
        imports_analysis = {
            'total_imports': 0,
            'unique_dlls': set(),
            'suspicious_apis': [],
            'network_apis': [],
            'file_apis': [],
            'registry_apis': [],
            'crypto_apis': [],
            'process_apis': []
        }
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports_analysis
        
        suspicious_categories = {
            'network_apis': [r'socket', r'connect', r'bind', r'listen', r'send', r'recv', r'WSA'],
            'file_apis': [r'CreateFile', r'OpenFile', r'ReadFile', r'WriteFile', r'DeleteFile'],
            'registry_apis': [r'RegOpen', r'RegCreate', r'RegSetValue', r'RegDelete'],
            'crypto_apis': [r'Crypt', r'Encrypt', r'Decrypt', r'Hash', r'Signature'],
            'process_apis': [r'CreateProcess', r'OpenProcess', r'TerminateProcess', r'VirtualAlloc']
        }
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
            imports_analysis['unique_dlls'].add(dll_name)
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore').lower()
                    imports_analysis['total_imports'] += 1
                    
                    # Categorize APIs
                    for category, patterns in suspicious_categories.items():
                        for pattern in patterns:
                            if re.search(pattern, func_name, re.IGNORECASE):
                                imports_analysis[category].append(func_name)
        
        # Convert sets to lists for JSON serialization
        imports_analysis['unique_dlls'] = list(imports_analysis['unique_dlls'])
        
        return imports_analysis
    
    def analyze_sections_entropy(self) -> List[Dict]:
        """Analyze section entropy for packed/encrypted content"""
        sections_analysis = []
        
        if not self.pe:
            return sections_analysis
        
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            entropy = section.get_entropy()
            
            # High entropy might indicate packing/encryption
            is_suspicious = entropy > 7.0
            
            sections_analysis.append({
                'name': section_name,
                'entropy': entropy,
                'is_suspicious': is_suspicious,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'characteristics': hex(section.Characteristics)
            })
        
        return sections_analysis
    
    def generate_function_signatures(self) -> List[Dict]:
        """Generate function signatures for exported functions"""
        signatures = []
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return signatures
        
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and exp.address:
                # Try to disassemble the function prologue
                instructions = self.disassemble_function(exp.address, 20)
                
                signature = {
                    'name': exp.name.decode('utf-8', errors='ignore'),
                    'ordinal': exp.ordinal,
                    'address': exp.address,
                    'prologue': instructions[:5],  # First 5 instructions
                    'estimated_size': self._estimate_function_size(exp.address)
                }
                
                signatures.append(signature)
        
        return signatures
    
    def _estimate_function_size(self, address: int) -> int:
        """Estimate function size by looking for common patterns"""
        if not self.pe:
            return 0
        
        try:
            section = self.pe.get_section_by_rva(address)
            if not section:
                return 0
            
            offset = address - section.VirtualAddress
            data = section.get_data()[offset:]
            
            # Look for common function endings (ret, jmp, etc.)
            for i in range(0, min(len(data), 1000), 1):
                if data[i] in [0xC3, 0xC2, 0xCB, 0xCA]:  # ret instructions
                    return i + 1
                elif data[i] == 0xE9 and i < len(data) - 4:  # jmp
                    return i + 5
            
            return 100  # Default size if no ending found
        except:
            return 0
    
    def comprehensive_analysis(self) -> Dict:
        """Perform comprehensive DLL analysis"""
        if not self.load_dll():
            return {}
        
        return {
            'dll_info': self._get_dll_info(),
            'function_signatures': self.generate_function_signatures(),
            'patterns': self.analyze_function_patterns(),
            'imports_analysis': self.analyze_imports_heuristics(),
            'sections_entropy': self.analyze_sections_entropy(),
            'strings': self.extract_strings()
        }
    
    def _get_dll_info(self) -> Dict:
        """Extract basic DLL information"""
        if not self.pe:
            return {}
        
        info = {
            'file_path': self.dll_path,
            'file_size': os.path.getsize(self.dll_path),
            'machine': self.pe.FILE_HEADER.Machine,
            'is_64bit': self.is_64bit,
            'timestamp': self.pe.FILE_HEADER.TimeDateStamp,
            'entry_point': self.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'image_base': self.pe.OPTIONAL_HEADER.ImageBase
        }
        
        return info

def main():
    parser = argparse.ArgumentParser(description='Advanced DLL Disassembler')
    parser.add_argument('dll_path', help='Path to DLL file')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-f', '--format', choices=['json', 'txt'], default='json', help='Output format')
    parser.add_argument('--disassemble', help='Disassemble function at address (hex)')
    parser.add_argument('--entropy-threshold', type=float, default=7.0, help='Entropy threshold for suspicious sections')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.dll_path):
        print(f"Error: DLL file not found: {args.dll_path}")
        return 1
    
    analyzer = AdvancedDLLAnalyzer(args.dll_path)
    
    if args.disassemble:
        if analyzer.load_dll():
            address = int(args.disassemble, 16)
            instructions = analyzer.disassemble_function(address)
            for insn in instructions:
                print(f"{insn['address']}: {insn['mnemonic']} {insn['op_str']}")
    else:
        results = analyzer.comprehensive_analysis()
        print(json.dumps(results, indent=2))
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nReport exported to: {args.output}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
