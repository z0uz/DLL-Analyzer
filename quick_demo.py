#!/usr/bin/env python3
"""
Quick demo to populate web dashboard with sample data
"""

import os
import sys
from dll_analyzer import DLLAnalyzer
from database import AnalysisDatabase
from config import config

def populate_sample_data():
    """Create sample analysis data for web dashboard"""
    
    # Sample system DLLs to analyze
    sample_dlls = [
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\System32\user32.dll", 
        r"C:\Windows\System32\advapi32.dll"
    ]
    
    db = AnalysisDatabase()
    
    for dll_path in sample_dlls:
        if os.path.exists(dll_path):
            print(f"Analyzing {os.path.basename(dll_path)}...")
            
            try:
                analyzer = DLLAnalyzer(dll_path)
                if analyzer.load_dll():
                    # Get analysis results
                    results = analyzer.full_analysis()
                    
                    # Add file hash for database
                    import hashlib
                    with open(dll_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    
                    results['file_hash'] = file_hash
                    results['file_path'] = dll_path
                    
                    # Store in database
                    analysis_id = db.store_analysis(results)
                    print(f"✓ Stored analysis ID: {analysis_id}")
                    
                else:
                    print(f"✗ Failed to load {dll_path}")
                    
            except Exception as e:
                print(f"✗ Error analyzing {dll_path}: {e}")
    
    print("\n📊 Web dashboard populated!")
    print("Start with: .\build.bat web")
    print("Visit: http://localhost:5000")

if __name__ == "__main__":
    populate_sample_data()
