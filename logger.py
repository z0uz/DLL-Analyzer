#!/usr/bin/env python3
"""
Professional logging system for DLL Analyzer
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

class DLLAnalyzerLogger:
    """Enhanced logger for DLL Analyzer with rotation and formatting"""
    
    def __init__(self, name: str = "dll_analyzer", log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Create formatters
        self.detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        
        self.simple_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(self.simple_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler with rotation
        if log_file:
            self._setup_file_handler(log_file)
    
    def _setup_file_handler(self, log_file: str) -> None:
        """Setup rotating file handler"""
        try:
            # Ensure log directory exists
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Rotating file handler (10MB max, 5 backups)
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(self.detailed_formatter)
            self.logger.addHandler(file_handler)
            
        except Exception as e:
            self.logger.error(f"Failed to setup file handler: {e}")
    
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message with optional context"""
        if kwargs:
            context = " | ".join([f"{k}={v}" for k, v in kwargs.items()])
            message = f"{message} | {context}"
        self.logger.debug(message)
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message with optional context"""
        if kwargs:
            context = " | ".join([f"{k}={v}" for k, v in kwargs.items()])
            message = f"{message} | {context}"
        self.logger.info(message)
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message with optional context"""
        if kwargs:
            context = " | ".join([f"{k}={v}" for k, v in kwargs.items()])
            message = f"{message} | {context}"
        self.logger.warning(message)
    
    def error(self, message: str, exception: Optional[Exception] = None, **kwargs) -> None:
        """Log error message with optional exception and context"""
        if exception:
            message = f"{message} | Exception: {str(exception)}"
        
        if kwargs:
            context = " | ".join([f"{k}={v}" for k, v in kwargs.items()])
            message = f"{message} | {context}"
        
        self.logger.error(message, exc_info=True)
    
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message"""
        if kwargs:
            context = " | ".join([f"{k}={v}" for k, v in kwargs.items()])
            message = f"{message} | {context}"
        self.logger.critical(message)
    
    def log_analysis_start(self, file_path: str, file_size: int) -> None:
        """Log analysis start with file info"""
        self.info(f"Starting analysis", file=file_path, size=f"{file_size:,} bytes")
    
    def log_analysis_complete(self, file_path: str, duration: float, risk_score: int) -> None:
        """Log analysis completion with metrics"""
        self.info(f"Analysis complete", file=file_path, 
                 duration=f"{duration:.2f}s", risk_score=risk_score)
    
    def log_security_event(self, event_type: str, details: dict) -> None:
        """Log security-related events"""
        self.warning(f"Security event", type=event_type, **details)

# Global logger instance
logger = DLLAnalyzerLogger()
