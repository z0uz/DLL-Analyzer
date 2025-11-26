#!/usr/bin/env python3
"""
Plugin system for DLL Analyzer extensibility
"""

import os
import sys
import importlib.util
import inspect
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Type
from pathlib import Path

class AnalysisPlugin(ABC):
    """Base class for analysis plugins"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Plugin description"""
        pass
    
    @abstractmethod
    def analyze(self, pe_file, config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform plugin analysis"""
        pass
    
    def get_dependencies(self) -> List[str]:
        """Return list of required dependencies"""
        return []
    
    def is_compatible(self, pe_file) -> bool:
        """Check if plugin is compatible with the PE file"""
        return True

class PluginManager:
    """Manager for loading and executing analysis plugins"""
    
    def __init__(self, plugin_directory: str = "plugins"):
        self.plugin_directory = plugin_directory
        self.plugins: Dict[str, AnalysisPlugin] = {}
        self.load_plugins()
    
    def load_plugins(self) -> None:
        """Load all plugins from the plugin directory"""
        if not os.path.exists(self.plugin_directory):
            os.makedirs(self.plugin_directory, exist_ok=True)
            return
        
        for filename in os.listdir(self.plugin_directory):
            if filename.endswith('.py') and not filename.startswith('__'):
                plugin_path = os.path.join(self.plugin_directory, filename)
                try:
                    self._load_plugin_from_file(plugin_path)
                except Exception as e:
                    print(f"Warning: Failed to load plugin {filename}: {e}")
    
    def _load_plugin_from_file(self, plugin_path: str) -> None:
        """Load a single plugin from file"""
        spec = importlib.util.spec_from_file_location(
            os.path.basename(plugin_path)[:-3], plugin_path
        )
        
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load spec from {plugin_path}")
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Find plugin classes in the module
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, AnalysisPlugin) and 
                obj is not AnalysisPlugin and 
                not inspect.isabstract(obj)):
                
                plugin_instance = obj()
                self.plugins[plugin_instance.name] = plugin_instance
                print(f"Loaded plugin: {plugin_instance.name} v{plugin_instance.version}")
    
    def get_plugin(self, name: str) -> Optional[AnalysisPlugin]:
        """Get a plugin by name"""
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[Dict[str, str]]:
        """List all loaded plugins"""
        return [
            {
                "name": plugin.name,
                "version": plugin.version,
                "description": plugin.description
            }
            for plugin in self.plugins.values()
        ]
    
    def run_plugin(self, name: str, pe_file, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run a specific plugin"""
        plugin = self.get_plugin(name)
        if not plugin:
            return None
        
        if not plugin.is_compatible(pe_file):
            return {"error": f"Plugin {name} is not compatible with this file"}
        
        try:
            return plugin.analyze(pe_file, config)
        except Exception as e:
            return {"error": f"Plugin {name} failed: {str(e)}"}
    
    def run_all_plugins(self, pe_file, config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Run all compatible plugins"""
        results = {}
        
        for name, plugin in self.plugins.items():
            if plugin.is_compatible(pe_file):
                try:
                    result = plugin.analyze(pe_file, config)
                    results[name] = result
                except Exception as e:
                    results[name] = {"error": str(e)}
        
        return results

# Example plugin implementations
class YARARulePlugin(AnalysisPlugin):
    """Example YARA rule matching plugin"""
    
    @property
    def name(self) -> str:
        return "yara_rules"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def description(self) -> str:
        "Matches YARA rules against the PE file"
    
    def analyze(self, pe_file, config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze PE file with YARA rules"""
        # This would integrate with YARA library
        return {
            "matches": [],
            "rules_checked": 0,
            "threat_indicators": []
        }
    
    def get_dependencies(self) -> List[str]:
        return ["yara-python"]

class EntropyAnalysisPlugin(AnalysisPlugin):
    """Enhanced entropy analysis plugin"""
    
    @property
    def name(self) -> str:
        return "entropy_analysis"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def description(self) -> str:
        "Advanced entropy analysis with visualization"
    
    def analyze(self, pe_file, config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform advanced entropy analysis"""
        import math
        
        entropy_data = []
        
        if hasattr(pe_file, 'sections'):
            for section in pe_file.sections:
                try:
                    section_data = section.get_data()
                    if len(section_data) > 0:
                        entropy = self._calculate_entropy(section_data)
                        entropy_data.append({
                            "section": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                            "entropy": entropy,
                            "size": len(section_data),
                            "is_packed": entropy > 7.0
                        })
                except Exception:
                    continue
        
        return {
            "sections": entropy_data,
            "average_entropy": sum(s["entropy"] for s in entropy_data) / len(entropy_data) if entropy_data else 0,
            "packed_sections": [s for s in entropy_data if s["is_packed"]]
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in frequency.values():
            p = count / data_len
            entropy -= p * math.log2(p)
        
        return entropy
