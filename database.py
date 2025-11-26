#!/usr/bin/env python3
"""
Database support for DLL Analyzer analysis storage
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

class AnalysisDatabase:
    """SQLite database for storing and retrieving analysis results"""
    
    def __init__(self, db_path: str = "analysis_results.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self) -> None:
        """Initialize database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    security_score INTEGER,
                    risk_level TEXT,
                    analysis_data TEXT,
                    file_metadata TEXT,
                    UNIQUE(file_hash)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER,
                    ioc_type TEXT NOT NULL,
                    ioc_value TEXT NOT NULL,
                    confidence INTEGER,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES analyses (id)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS plugins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER,
                    plugin_name TEXT NOT NULL,
                    plugin_version TEXT,
                    plugin_result TEXT,
                    execution_time REAL,
                    FOREIGN KEY (analysis_id) REFERENCES analyses (id)
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_file_hash ON analyses (file_hash)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs (ioc_value)
            ''')
            
            conn.commit()
    
    def store_analysis(self, analysis_data: Dict[str, Any]) -> int:
        """Store analysis results in database"""
        file_hash = analysis_data.get('file_hash', '')
        file_path = analysis_data.get('file_path', '')
        file_size = analysis_data.get('file_size', 0)
        security_score = analysis_data.get('security_score', 0)
        risk_level = analysis_data.get('risk_level', 'UNKNOWN')
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if analysis already exists
            cursor.execute('SELECT id FROM analyses WHERE file_hash = ?', (file_hash,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing analysis
                cursor.execute('''
                    UPDATE analyses SET 
                        file_path = ?, file_size = ?, security_score = ?, 
                        risk_level = ?, analysis_date = CURRENT_TIMESTAMP,
                        analysis_data = ?, file_metadata = ?
                    WHERE file_hash = ?
                ''', (
                    file_path, file_size, security_score, risk_level,
                    json.dumps(analysis_data), json.dumps(analysis_data.get('metadata', {})),
                    file_hash
                ))
                analysis_id = existing[0]
            else:
                # Insert new analysis
                cursor.execute('''
                    INSERT INTO analyses 
                    (file_path, file_hash, file_size, security_score, risk_level, analysis_data, file_metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_path, file_hash, file_size, security_score, risk_level,
                    json.dumps(analysis_data), json.dumps(analysis_data.get('metadata', {}))
                ))
                analysis_id = cursor.lastrowid
            
            # Store IOCs
            self._store_iocs(cursor, analysis_id, analysis_data)
            
            # Store plugin results
            self._store_plugin_results(cursor, analysis_id, analysis_data)
            
            conn.commit()
            return analysis_id
    
    def _store_iocs(self, cursor, analysis_id: int, analysis_data: Dict[str, Any]) -> None:
        """Store indicators of compromise"""
        iocs = []
        
        # Extract URLs
        for url in analysis_data.get('embedded_urls', []):
            iocs.append(('url', url, 80))
        
        # Extract IP addresses
        for ip in analysis_data.get('ip_addresses', []):
            iocs.append(('ip', ip, 70))
        
        # Extract suspicious imports
        for imp in analysis_data.get('suspicious_imports', []):
            iocs.append(('import', imp, 60))
        
        # Clear existing IOCs for this analysis
        cursor.execute('DELETE FROM iocs WHERE analysis_id = ?', (analysis_id,))
        
        # Insert new IOCs
        for ioc_type, ioc_value, confidence in iocs:
            cursor.execute('''
                INSERT INTO iocs (analysis_id, ioc_type, ioc_value, confidence)
                VALUES (?, ?, ?, ?)
            ''', (analysis_id, ioc_type, ioc_value, confidence))
    
    def _store_plugin_results(self, cursor, analysis_id: int, analysis_data: Dict[str, Any]) -> None:
        """Store plugin execution results"""
        plugin_results = analysis_data.get('plugin_results', {})
        
        # Clear existing plugin results
        cursor.execute('DELETE FROM plugins WHERE analysis_id = ?', (analysis_id,))
        
        # Insert plugin results
        for plugin_name, result in plugin_results.items():
            cursor.execute('''
                INSERT INTO plugins (analysis_id, plugin_name, plugin_version, plugin_result)
                VALUES (?, ?, ?, ?)
            ''', (
                analysis_id, plugin_name, 
                result.get('version', '1.0.0'),
                json.dumps(result)
            ))
    
    def get_analysis(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve analysis by file hash"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM analyses WHERE file_hash = ?
            ''', (file_hash,))
            
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    def search_iocs(self, ioc_value: str) -> List[Dict[str, Any]]:
        """Search for analyses containing specific IOC"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT a.*, i.ioc_type, i.ioc_value, i.confidence
                FROM analyses a
                JOIN iocs i ON a.id = i.analysis_id
                WHERE i.ioc_value LIKE ?
                ORDER BY a.analysis_date DESC
            ''', (f'%{ioc_value}%',))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_recent_analyses(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent analyses"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM analyses 
                ORDER BY analysis_date DESC 
                LIMIT ?
            ''', (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total analyses
            cursor.execute('SELECT COUNT(*) FROM analyses')
            total_analyses = cursor.fetchone()[0]
            
            # Risk level distribution
            cursor.execute('''
                SELECT risk_level, COUNT(*) as count 
                FROM analyses 
                GROUP BY risk_level
            ''')
            risk_distribution = dict(cursor.fetchall())
            
            # High-risk files
            cursor.execute('SELECT COUNT(*) FROM analyses WHERE security_score > 70')
            high_risk_count = cursor.fetchone()[0]
            
            # Unique IOCs
            cursor.execute('SELECT COUNT(DISTINCT ioc_value) FROM iocs')
            unique_iocs = cursor.fetchone()[0]
            
            return {
                'total_analyses': total_analyses,
                'risk_distribution': risk_distribution,
                'high_risk_count': high_risk_count,
                'unique_iocs': unique_iocs
            }
    
    def export_analysis(self, analysis_id: int, format: str = 'json') -> str:
        """Export analysis in specified format"""
        analysis = self.get_analysis_by_id(analysis_id)
        if not analysis:
            return ""
        
        if format.lower() == 'json':
            return json.dumps(analysis, indent=2, default=str)
        elif format.lower() == 'csv':
            # Simple CSV export
            return self._export_to_csv(analysis)
        else:
            return str(analysis)
    
    def get_analysis_by_id(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        """Get analysis by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM analyses WHERE id = ?', (analysis_id,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
    
    def _export_to_csv(self, analysis: Dict[str, Any]) -> str:
        """Export analysis to CSV format"""
        csv_lines = []
        csv_lines.append("Field,Value")
        
        for key, value in analysis.items():
            if isinstance(value, (str, int, float)):
                csv_lines.append(f"{key},{value}")
        
        return '\n'.join(csv_lines)
