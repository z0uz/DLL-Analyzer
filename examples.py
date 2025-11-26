#!/usr/bin/env python3
"""
DLL Analyzer API Examples and Usage Patterns
"""

import os
import json
from typing import Dict, Any
from dll_analyzer import DLLAnalyzer
from database import AnalysisDatabase
from plugin_system import PluginManager
from config import config
from logger import logger

def basic_analysis_example():
    """Example: Basic file analysis"""
    print("=== Basic Analysis Example ===")
    
    # Analyze a file
    file_path = "C:\\Windows\\System32\\kernel32.dll"
    analyzer = DLLAnalyzer(file_path)
    
    if analyzer.load_dll():
        # Get basic information
        info = analyzer.get_dll_info()
        print(f"File: {info['file_path']}")
        print(f"Size: {info['file_size']:,} bytes")
        print(f"Machine: {info['machine']}")
        
        # Perform full analysis
        results = analyzer.full_analysis()
        print(f"Security Score: {results.get('security_score', 0)}/100")
        print(f"Risk Level: {results.get('risk_level', 'UNKNOWN')}")
    else:
        print(f"Failed to load: {file_path}")

def batch_analysis_example():
    """Example: Analyzing multiple files"""
    print("\n=== Batch Analysis Example ===")
    
    # Directory to analyze
    directory = "C:\\Windows\\System32"
    file_extensions = ['.dll', '.exe']
    
    results = []
    analyzed_count = 0
    
    for filename in os.listdir(directory):
        if any(filename.lower().endswith(ext) for ext in file_extensions):
            file_path = os.path.join(directory, filename)
            
            try:
                analyzer = DLLAnalyzer(file_path)
                if analyzer.load_dll():
                    result = analyzer.quick_analysis()
                    result['file_path'] = file_path
                    results.append(result)
                    analyzed_count += 1
                    
                    # Stop after 10 files for demo
                    if analyzed_count >= 10:
                        break
            except Exception as e:
                print(f"Error analyzing {filename}: {e}")
    
    # Sort by risk score
    results.sort(key=lambda x: x.get('security_score', 0), reverse=True)
    
    print(f"Analyzed {len(results)} files")
    for result in results[:5]:  # Top 5 highest risk
        print(f"{os.path.basename(result['file_path'])}: {result.get('security_score', 0)}/100")

def database_integration_example():
    """Example: Using database for persistent storage"""
    print("\n=== Database Integration Example ===")
    
    # Initialize database
    db = AnalysisDatabase()
    
    # Analyze and store results
    file_path = "C:\\Windows\\System32\\user32.dll"
    analyzer = DLLAnalyzer(file_path)
    
    if analyzer.load_dll():
        results = analyzer.full_analysis()
        
        # Add file hash for database storage
        import hashlib
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        results['file_hash'] = file_hash
        
        # Store in database
        analysis_id = db.store_analysis(results)
        print(f"Stored analysis with ID: {analysis_id}")
        
        # Retrieve from database
        stored = db.get_analysis(file_hash)
        if stored:
            print(f"Retrieved: {stored['file_path']} (Score: {stored['security_score']})")
        
        # Search for IOCs
        if results.get('embedded_urls'):
            ioc_results = db.search_iocs(results['embedded_urls'][0])
            print(f"IOC search results: {len(ioc_results)} matches")

def plugin_usage_example():
    """Example: Using the plugin system"""
    print("\n=== Plugin System Example ===")
    
    # Initialize plugin manager
    plugin_manager = PluginManager()
    
    # List available plugins
    plugins = plugin_manager.list_plugins()
    print("Available plugins:")
    for plugin in plugins:
        print(f"  - {plugin['name']} v{plugin['version']}: {plugin['description']}")
    
    # Analyze with plugins
    file_path = "C:\\Windows\\System32\\advapi32.dll"
    analyzer = DLLAnalyzer(file_path)
    
    if analyzer.load_dll():
        # Run all compatible plugins
        plugin_results = plugin_manager.run_all_plugins(analyzer.pe, config.config)
        
        print("Plugin Results:")
        for plugin_name, result in plugin_results.items():
            if 'error' not in result:
                print(f"  {plugin_name}: ✓ Success")
            else:
                print(f"  {plugin_name}: ✗ {result['error']}")

def configuration_example():
    """Example: Using configuration management"""
    print("\n=== Configuration Management Example ===")
    
    # Access configuration values
    max_file_size = config.get('analysis.max_file_size')
    risk_threshold = config.get('security.risk_threshold_high')
    
    print(f"Max file size: {max_file_size:,} bytes")
    print(f"High risk threshold: {risk_threshold}")
    
    # Update configuration
    config.set('analysis.enable_deep_analysis', True)
    config.set('custom.setting', 'custom_value')
    
    # Save configuration
    config.save_config()
    print("Configuration saved")

def logging_example():
    """Example: Professional logging usage"""
    print("\n=== Logging Example ===")
    
    # Log analysis events
    logger.info("Starting DLL Analyzer examples")
    
    file_path = "test_file.dll"
    file_size = 1024
    
    logger.log_analysis_start(file_path, file_size)
    
    # Simulate analysis
    import time
    time.sleep(0.1)
    
    duration = 0.1
    risk_score = 45
    
    logger.log_analysis_complete(file_path, duration, risk_score)
    
    # Log security events
    logger.log_security_event("suspicious_import", {
        "function": "CreateRemoteThread",
        "library": "kernel32.dll",
        "confidence": 80
    })
    
    # Log errors
    logger.error("Test error message", exception=None, context={"file": file_path})
    
    print("Check dll_analyzer.log for detailed logs")

def web_api_example():
    """Example: Using the web API"""
    print("\n=== Web API Example ===")
    
    # Note: This assumes the web interface is running
    import requests
    
    base_url = "http://localhost:5000"
    
    try:
        # Get dashboard statistics
        response = requests.get(f"{base_url}/")
        if response.status_code == 200:
            print("Web interface accessible")
        
        # Search for IOCs (example)
        response = requests.get(f"{base_url}/api/search?q=kernel32")
        if response.status_code == 200:
            results = response.json()
            print(f"Found {len(results)} IOC matches")
        
    except requests.exceptions.ConnectionError:
        print("Web interface not running. Start with: python web_interface.py")

def advanced_analysis_workflow():
    """Example: Complete professional analysis workflow"""
    print("\n=== Advanced Analysis Workflow ===")
    
    # Step 1: Configuration
    config.set('analysis.enable_deep_analysis', True)
    config.set('security.check_signatures', True)
    
    # Step 2: Initialize components
    db = AnalysisDatabase()
    plugin_manager = PluginManager()
    
    # Step 3: Analyze file
    file_path = input("Enter file path to analyze (or press Enter for demo): ").strip()
    
    if not file_path or not os.path.exists(file_path):
        file_path = "C:\\Windows\\System32\\kernel32.dll"
        print(f"Using demo file: {file_path}")
    
    # Step 4: Perform analysis
    logger.info(f"Starting advanced analysis of {file_path}")
    
    analyzer = DLLAnalyzer(file_path)
    if not analyzer.load_dll():
        print("Failed to load file")
        return
    
    # Basic analysis
    basic_results = analyzer.full_analysis()
    
    # Plugin analysis
    plugin_results = plugin_manager.run_all_plugins(analyzer.pe, config.config)
    
    # Combine results
    comprehensive_results = {
        **basic_results,
        'plugin_results': plugin_results,
        'analysis_timestamp': logger.logger.handlers[0].formatter.formatTime(logger.logger.makeRecord(
            '', 0, '', 0, '', (), None
        )) if logger.logger.handlers else ''
    }
    
    # Step 5: Store results
    import hashlib
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    comprehensive_results['file_hash'] = file_hash
    analysis_id = db.store_analysis(comprehensive_results)
    
    # Step 6: Generate report
    report_file = f"analysis_report_{os.path.basename(file_path)}.json"
    with open(report_file, 'w') as f:
        json.dump(comprehensive_results, f, indent=2, default=str)
    
    # Step 7: Display summary
    print(f"\nAnalysis Complete!")
    print(f"File: {file_path}")
    print(f"Security Score: {comprehensive_results.get('security_score', 0)}/100")
    print(f"Risk Level: {comprehensive_results.get('risk_level', 'UNKNOWN')}")
    print(f"Analysis ID: {analysis_id}")
    print(f"Report saved: {report_file}")
    
    # Step 8: Recommendations
    score = comprehensive_results.get('security_score', 0)
    if score > 70:
        print("\n⚠️  HIGH RISK DETECTED!")
        print("Recommendations:")
        print("- Analyze in isolated sandbox")
        print("- Submit to VirusTotal")
        print("- Check embedded URLs and IPs")
        print("- Verify digital signature")
    elif score > 40:
        print("\n⚡ MEDIUM RISK")
        print("Recommendations:")
        print("- Review imports and exports")
        print("- Check file timestamps")
        print("- Verify publisher")
    else:
        print("\n✅ LOW RISK")
        print("File appears to be legitimate")

def main():
    """Run all examples"""
    print("DLL Analyzer Professional Examples")
    print("=" * 50)
    
    try:
        basic_analysis_example()
        batch_analysis_example()
        database_integration_example()
        plugin_usage_example()
        configuration_example()
        logging_example()
        web_api_example()
        advanced_analysis_workflow()
        
    except KeyboardInterrupt:
        print("\nExamples interrupted by user")
    except Exception as e:
        print(f"\nError running examples: {e}")
    
    print("\n" + "=" * 50)
    print("Examples complete! Check the generated files and logs.")

if __name__ == "__main__":
    main()
