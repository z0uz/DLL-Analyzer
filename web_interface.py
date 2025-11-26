#!/usr/bin/env python3
"""
Web interface for DLL Analyzer results visualization
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import json
from datetime import datetime
from typing import Dict, List, Any
from database import AnalysisDatabase
from config import config

app = Flask(__name__)
db = AnalysisDatabase()

@app.route('/')
def index():
    """Main dashboard page"""
    stats = db.get_statistics()
    recent_analyses = db.get_recent_analyses(10)
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         recent_analyses=recent_analyses)

@app.route('/analysis/<int:analysis_id>')
def analysis_detail(analysis_id: int):
    """Detailed analysis view"""
    analysis = db.get_analysis_by_id(analysis_id)
    if not analysis:
        return "Analysis not found", 404
    
    # Parse JSON data
    if analysis.get('analysis_data'):
        analysis['analysis_data'] = json.loads(analysis['analysis_data'])
    if analysis.get('file_metadata'):
        analysis['file_metadata'] = json.loads(analysis['file_metadata'])
    
    return render_template('analysis_detail.html', analysis=analysis)

@app.route('/api/search')
def search_iocs():
    """API endpoint for searching IOCs"""
    query = request.args.get('q', '')
    if len(query) < 3:
        return jsonify({'error': 'Query too short'})
    
    results = db.search_iocs(query)
    return jsonify(results)

@app.route('/api/export/<int:analysis_id>')
def export_analysis(analysis_id: int):
    """Export analysis in various formats"""
    format_type = request.args.get('format', 'json')
    analysis_data = db.export_analysis(analysis_id, format_type)
    
    if not analysis_data:
        return "Analysis not found", 404
    
    filename = f"analysis_{analysis_id}.{format_type}"
    
    if format_type.lower() == 'json':
        return analysis_data, 200, {
            'Content-Type': 'application/json',
            'Content-Disposition': f'attachment; filename={filename}'
        }
    else:
        return analysis_data, 200, {
            'Content-Type': 'text/plain',
            'Content-Disposition': f'attachment; filename={filename}'
        }

def create_templates():
    """Create HTML templates for the web interface"""
    templates_dir = 'templates'
    os.makedirs(templates_dir, exist_ok=True)
    
    # Dashboard template
    dashboard_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DLL Analyzer Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
        .recent-analyses { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .analysis-item { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .risk-high { border-left: 5px solid #e74c3c; }
        .risk-medium { border-left: 5px solid #f39c12; }
        .risk-low { border-left: 5px solid #27ae60; }
        .btn { background: #3498db; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #2980b9; }
    </style>
</head>
<body>
    <div class="header">
        <h1>DLL Analyzer Dashboard</h1>
        <p>Malware Analysis & Reverse Engineering Toolkit</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-number">{{ stats.total_analyses }}</div>
            <div>Total Analyses</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{{ stats.high_risk_count }}</div>
            <div>High Risk Files</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{{ stats.unique_iocs }}</div>
            <div>Unique IOCs</div>
        </div>
    </div>
    
    <div class="recent-analyses">
        <h2>Recent Analyses</h2>
        {% for analysis in recent_analyses %}
        <div class="analysis-item risk-{{ analysis.risk_level.lower() }}">
            <h3>{{ analysis.file_path }}</h3>
            <p>Score: {{ analysis.security_score }}/100 | Risk: {{ analysis.risk_level }}</p>
            <p>Date: {{ analysis.analysis_date }}</p>
            <a href="/analysis/{{ analysis.id }}" class="btn">View Details</a>
        </div>
        {% endfor %}
    </div>
</body>
</html>
    """
    
    # Analysis detail template
    detail_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analysis Details - DLL Analyzer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .detail-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .risk-badge { padding: 5px 10px; border-radius: 4px; color: white; font-weight: bold; }
        .risk-critical { background: #e74c3c; }
        .risk-high { background: #f39c12; }
        .risk-medium { background: #f1c40f; }
        .risk-low { background: #27ae60; }
        .btn { background: #3498db; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin: 5px; }
        .btn:hover { background: #2980b9; }
        .json-viewer { background: #f8f9fa; padding: 15px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; max-height: 400px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Analysis Details</h1>
        <a href="/" class="btn">Back to Dashboard</a>
    </div>
    
    <div class="detail-card">
        <h2>{{ analysis.file_path }}</h2>
        <p><strong>Security Score:</strong> {{ analysis.security_score }}/100 
           <span class="risk-badge risk-{{ analysis.risk_level.lower() }}">{{ analysis.risk_level }}</span></p>
        <p><strong>File Size:</strong> {{ "{:,}".format(analysis.file_size) }} bytes</p>
        <p><strong>Analysis Date:</strong> {{ analysis.analysis_date }}</p>
        <p><strong>File Hash:</strong> {{ analysis.file_hash }}</p>
        
        <div style="margin-top: 20px;">
            <a href="/api/export/{{ analysis.id }}?format=json" class="btn">Export JSON</a>
            <a href="/api/export/{{ analysis.id }}?format=csv" class="btn">Export CSV</a>
        </div>
    </div>
    
    {% if analysis.analysis_data %}
    <div class="detail-card">
        <h3>Analysis Data</h3>
        <div class="json-viewer">{{ analysis.analysis_data | tojson(indent=2) }}</div>
    </div>
    {% endif %}
    
    {% if analysis.file_metadata %}
    <div class="detail-card">
        <h3>File Metadata</h3>
        <div class="json-viewer">{{ analysis.file_metadata | tojson(indent=2) }}</div>
    </div>
    {% endif %}
</body>
</html>
    """
    
    with open(os.path.join(templates_dir, 'dashboard.html'), 'w', encoding='utf-8') as f:
        f.write(dashboard_html)
    
    with open(os.path.join(templates_dir, 'analysis_detail.html'), 'w', encoding='utf-8') as f:
        f.write(detail_html)

if __name__ == '__main__':
    create_templates()
    port = config.get('web.port', 5000)
    app.run(debug=True, host='0.0.0.0', port=port)
