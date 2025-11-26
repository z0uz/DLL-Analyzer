#!/usr/bin/env python3
"""
Automated testing framework for DLL Analyzer
"""

import unittest
import tempfile
import os
import sys
import struct
from unittest.mock import Mock, patch
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from dll_analyzer import DLLAnalyzer
    from config import Config, config
    from database import AnalysisDatabase
    from plugin_system import PluginManager, AnalysisPlugin
    from logger import logger
except ImportError as e:
    print(f"Warning: Could not import modules: {e}")

class TestDLLAnalyzer(unittest.TestCase):
    """Test cases for DLL Analyzer core functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, 'test.dll')
        self.create_test_pe_file()
        
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def create_test_pe_file(self):
        """Create a minimal PE file for testing"""
        # Create a simple PE header structure
        pe_header = b'MZ\x90\x00' + b'\x00' * 58  # DOS header
        pe_header += struct.pack('<I', 0x3C000000)  # PE offset
        
        # PE signature
        pe_signature = b'PE\x00\x00'
        
        # COFF header
        coff_header = struct.pack('<H', 0x8664)  # Machine (AMD64)
        coff_header += struct.pack('<H', 1)       # NumberOfSections
        coff_header += struct.pack('<I', 0)       # TimeDateStamp
        coff_header += struct.pack('<I', 0)       # PointerToSymbolTable
        coff_header += struct.pack('<I', 0)       # NumberOfSymbols
        coff_header += struct.pack('<H', 0)       # SizeOfOptionalHeader
        coff_header += struct.pack('<H', 0)       # Characteristics
        
        # Optional header (minimal)
        optional_header = struct.pack('<H', 0x10b)  # Magic
        optional_header += b'\x00' * 22            # Skip to AddressOfEntryPoint
        optional_header += struct.pack('<I', 0x1000)  # AddressOfEntryPoint
        optional_header += b'\x00' * 100           # Rest of optional header
        
        # Section header
        section_header = b'.text\x00\x00\x00' + b'\x00' * 8  # Name
        section_header += struct.pack('<I', 0x1000)  # VirtualSize
        section_header += struct.pack('<I', 0x1000)  # VirtualAddress
        section_header += struct.pack('<I', 0x200)   # SizeOfRawData
        section_header += struct.pack('<I', 0x400)   # PointerToRawData
        section_header += b'\x00' * 16              # Rest of section header
        
        # Section data (some dummy code)
        section_data = b'\x90\x90\x90\xC3' + b'\x00' * 196
        
        # Write to file
        with open(self.test_file, 'wb') as f:
            f.write(pe_header + pe_signature + coff_header + optional_header + section_header + section_data)
    
    def test_file_loading(self):
        """Test PE file loading"""
        analyzer = DLLAnalyzer(self.test_file)
        result = analyzer.load_dll()
        self.assertTrue(result)
        self.assertIsNotNone(analyzer.pe)
    
    def test_basic_info_extraction(self):
        """Test basic file information extraction"""
        analyzer = DLLAnalyzer(self.test_file)
        analyzer.load_dll()
        info = analyzer.get_dll_info()
        
        self.assertIn('file_path', info)
        self.assertIn('file_size', info)
        self.assertIn('machine', info)
        self.assertEqual(info['file_path'], self.test_file)
    
    def test_invalid_file_handling(self):
        """Test handling of invalid PE files"""
        invalid_file = os.path.join(self.test_dir, 'invalid.txt')
        with open(invalid_file, 'w') as f:
            f.write('Not a PE file')
        
        analyzer = DLLAnalyzer(invalid_file)
        result = analyzer.load_dll()
        self.assertFalse(result)

class TestConfig(unittest.TestCase):
    """Test configuration management"""
    
    def test_default_config_loading(self):
        """Test loading default configuration"""
        test_config = Config()
        self.assertIsNotNone(test_config.config)
        self.assertIn('analysis', test_config.config)
        self.assertIn('security', test_config.config)
    
    def test_config_get_set(self):
        """Test configuration get/set operations"""
        test_config = Config()
        
        # Test getting existing value
        max_size = test_config.get('analysis.max_file_size')
        self.assertIsInstance(max_size, int)
        
        # Test setting new value
        test_config.set('test.value', 'test_data')
        self.assertEqual(test_config.get('test.value'), 'test_data')
        
        # Test getting non-existent value with default
        self.assertEqual(test_config.get('non.existent', 'default'), 'default')

class TestDatabase(unittest.TestCase):
    """Test database functionality"""
    
    def setUp(self):
        """Set up test database"""
        self.test_db = tempfile.mktemp(suffix='.db')
        self.db = AnalysisDatabase(self.test_db)
    
    def tearDown(self):
        """Clean up test database"""
        if os.path.exists(self.test_db):
            os.unlink(self.test_db)
    
    def test_database_initialization(self):
        """Test database table creation"""
        # Should not raise any exceptions
        self.db.init_database()
    
    def test_analysis_storage(self):
        """Test storing and retrieving analysis data"""
        test_data = {
            'file_path': '/test/file.dll',
            'file_hash': 'abcd1234',
            'file_size': 1024,
            'security_score': 50,
            'risk_level': 'MEDIUM',
            'embedded_urls': ['http://example.com'],
            'ip_addresses': ['192.168.1.1']
        }
        
        analysis_id = self.db.store_analysis(test_data)
        self.assertIsInstance(analysis_id, int)
        self.assertGreater(analysis_id, 0)
        
        # Retrieve analysis
        retrieved = self.db.get_analysis('abcd1234')
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved['file_hash'], 'abcd1234')
    
    def test_ioc_search(self):
        """Test IOC searching functionality"""
        test_data = {
            'file_path': '/test/file.dll',
            'file_hash': 'test123',
            'file_size': 1024,
            'security_score': 80,
            'risk_level': 'HIGH',
            'embedded_urls': ['http://malicious.com'],
            'ip_addresses': ['192.168.1.100']
        }
        
        self.db.store_analysis(test_data)
        
        # Search for IOC
        results = self.db.search_iocs('malicious.com')
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]['ioc_value'], 'http://malicious.com')

class TestPluginSystem(unittest.TestCase):
    """Test plugin system functionality"""
    
    def test_plugin_loading(self):
        """Test plugin loading from directory"""
        plugin_dir = tempfile.mkdtemp()
        
        # Create a test plugin
        plugin_code = '''
from plugin_system import AnalysisPlugin

class TestPlugin(AnalysisPlugin):
    @property
    def name(self):
        return "test_plugin"
    
    @property
    def version(self):
        return "1.0.0"
    
    @property
    def description(self):
        return "Test plugin for unit testing"
    
    def analyze(self, pe_file, config):
        return {"test_result": "success"}
'''
        
        plugin_file = os.path.join(plugin_dir, 'test_plugin.py')
        with open(plugin_file, 'w') as f:
            f.write(plugin_code)
        
        try:
            plugin_manager = PluginManager(plugin_dir)
            plugins = plugin_manager.list_plugins()
            
            # Should have loaded our test plugin
            plugin_names = [p['name'] for p in plugins]
            self.assertIn('test_plugin', plugin_names)
            
        finally:
            import shutil
            shutil.rmtree(plugin_dir, ignore_errors=True)
    
    def test_plugin_execution(self):
        """Test plugin execution"""
        from plugin_system import EntropyAnalysisPlugin
        
        # Create mock PE file
        mock_pe = Mock()
        mock_pe.sections = []
        
        plugin = EntropyAnalysisPlugin()
        result = plugin.analyze(mock_pe, {})
        
        self.assertIn('sections', result)
        self.assertIn('average_entropy', result)

class TestLogger(unittest.TestCase):
    """Test logging functionality"""
    
    def test_logger_creation(self):
        """Test logger initialization"""
        from logger import DLLAnalyzerLogger
        
        test_log_file = tempfile.mktemp(suffix='.log')
        logger = DLLAnalyzerLogger('test_logger', test_log_file)
        
        # Should not raise exceptions
        logger.info("Test message")
        logger.error("Error message")
        
        # Check if log file was created
        self.assertTrue(os.path.exists(test_log_file))
        
        # Clean up
        if os.path.exists(test_log_file):
            os.unlink(test_log_file)

def run_integration_tests():
    """Run integration tests with real PE files"""
    print("Running integration tests...")
    
    # Test with system DLL if available
    system_dlls = [
        r'C:\Windows\System32\kernel32.dll',
        r'C:\Windows\System32\user32.dll',
        r'C:\Windows\System32\advapi32.dll'
    ]
    
    for dll_path in system_dlls:
        if os.path.exists(dll_path):
            print(f"Testing with {dll_path}...")
            try:
                analyzer = DLLAnalyzer(dll_path)
                if analyzer.load_dll():
                    info = analyzer.get_dll_info()
                    print(f"  ✓ Successfully analyzed {info.get('file_size', 0)} bytes")
                else:
                    print(f"  ✗ Failed to load {dll_path}")
            except Exception as e:
                print(f"  ✗ Error analyzing {dll_path}: {e}")

if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [TestDLLAnalyzer, TestConfig, TestDatabase, TestPluginSystem, TestLogger]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Run integration tests if unit tests pass
    if result.wasSuccessful():
        print("\n" + "="*50)
        run_integration_tests()
    
    print(f"\nTests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
