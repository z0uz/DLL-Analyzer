#!/usr/bin/env python3
"""
Configuration management for DLL Analyzer
"""

import os
import json
from typing import Dict, Any
from pathlib import Path

class Config:
    """Configuration manager for DLL Analyzer"""
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = self._load_default_config()
        self.load_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            "analysis": {
                "max_file_size": 100 * 1024 * 1024,  # 100MB
                "timeout_seconds": 300,
                "enable_deep_analysis": True,
                "extract_strings": True,
                "min_string_length": 4,
                "entropy_threshold": 7.0
            },
            "security": {
                "risk_threshold_high": 70,
                "risk_threshold_medium": 40,
                "check_signatures": True,
                "check_timestamps": True,
                "check_packing": True
            },
            "output": {
                "default_format": "json",
                "include_raw_data": False,
                "pretty_print": True,
                "output_directory": "analysis_results"
            },
            "network": {
                "enable_url_extraction": True,
                "enable_ip_extraction": True,
                "url_regex_patterns": [
                    r'https?://[^\s<>"{}|\\^`[\]]',
                    r'ftp://[^\s<>"{}|\\^`[\]]',
                    r'smtp://[^\s<>"{}|\\^`[\]]'
                ],
                "ip_regex_patterns": [
                    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ]
            },
            "plugins": {
                "enabled": True,
                "plugin_directory": "plugins",
                "auto_load": True
            },
            "logging": {
                "level": "INFO",
                "file": "dll_analyzer.log",
                "max_size": 10 * 1024 * 1024,  # 10MB
                "backup_count": 5
            }
        }
    
    def load_config(self) -> None:
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                self._merge_config(self.config, file_config)
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")
    
    def save_config(self) -> None:
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def _merge_config(self, base: Dict, update: Dict) -> None:
        """Recursively merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, key_path: str, default=None):
        """Get configuration value using dot notation (e.g., 'analysis.max_file_size')"""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        keys = key_path.split('.')
        config = self.config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value

# Global configuration instance
config = Config()
