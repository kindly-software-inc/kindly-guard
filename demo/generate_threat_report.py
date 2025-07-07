#!/usr/bin/env python3
"""
Generate a comprehensive threat detection report from test results.
Analyzes KindlyGuard's performance against various threat categories.
"""

import json
import sys
import glob
import datetime
from typing import Dict, List
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

def load_test_results(pattern: str = "test_results_*.json") -> List[Dict]:
    """Load all test result files matching pattern"""
    results = []
    for filename in sorted(glob.glob(pattern)):
        with open(filename, 'r') as f:
            data = json.load(f)
            data['filename'] = filename
            results.append(data)
    return results

def analyze_threat_categories(results: List[Dict]) -> Dict:
    """Analyze detection rates by threat category"""
    category_stats = defaultdict(lambda: {'detected': 0, 'total': 0, 'quarantined': 0})
    
    for result_file in results:
        for test in result_file.get('detailed_results', []):
            # Extract category from test name
            category = 'unknown'
            test_name = test.get('test_name', '').lower()
            
            if 'unicode' in test_name or 'bidi' in test_name or 'homograph' in test_name:
                category = 'Unicode Attacks'
            elif 'sql' in test_name or 'union' in test_name or 'nosql' in test_name:
                category = 'SQL Injection'
            elif 'xss' in test_name or 'script' in test_name or 'dom' in test_name:
                category = 'XSS Attacks'
            elif 'command' in test_name or 'shell' in test_name or 'exec' in test_name:
                category = 'Command Injection'
            elif 'path' in test_name or 'traversal' in test_name or 'directory' in test_name:
                category = 'Path Traversal'
            elif 'prompt' in test_name or 'instruction' in test_name or 'jailbreak' in test_name:
                category = 'Prompt Injection'
            
            category_stats[category]['total'] += 1
            if test.get('threats_detected'):
                category_stats[category]['detected'] += 1
            if test.get('quarantined'):
                category_stats[category]['quarantined'] += 1
    
    # Calculate percentages
    for category, stats in category_stats.items():
        if stats['total'] > 0:
            stats['detection_rate'] = (stats['detected'] / stats['total']) * 100
            stats['quarantine_rate'] = (stats['quarantined'] / stats['total']) * 100
        else:
            stats['detection_rate'] = 0
            stats['quarantine_rate'] = 0
    
    return dict(category_stats)

def generate_html_report(results: List[Dict], output_file: str = "threat_report.html"):
    """Generate an HTML report with charts and statistics"""
    
    # Analyze categories
    category_stats = analyze_threat_categories(results)
    
    # Calculate overall statistics
    total_tests = sum(r['summary']['total_tests'] for r in results)
    total_detected = sum(r['summary']['total_detected'] for r in results)
    total_quarantined = sum(r['summary']['total_quarantined'] for r in results)
    
    overall_detection_rate = (total_detected / total_tests * 100) if total_tests > 0 else 0
    overall_quarantine_rate = (total_quarantined / total_detected * 100) if total_detected > 0 else 0
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>KindlyGuard Threat Detection Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; text-align: center; }}
        h2 {{ color: #666; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }}
        .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ text-align: center; padding: 20px; background: #f8f8f8; border-radius: 8px; }}
        .stat-value {{ font-size: 36px; font-weight: bold; color: #2196F3; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .category-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
        .category-card {{ background: #fafafa; border: 1px solid #e0e0e0; border-radius: 8px; padding: 15px; }}
        .category-title {{ font-weight: bold; color: #333; margin-bottom: 10px; }}
        .progress-bar {{ width: 100%; height: 20px; background: #e0e0e0; border-radius: 10px; overflow: hidden; margin: 5px 0; }}
        .progress-fill {{ height: 100%; background: #4CAF50; transition: width 0.3s; }}
        .detection-rate {{ color: #4CAF50; }}
        .quarantine-rate {{ color: #2196F3; }}
        .threat-list {{ max-height: 300px; overflow-y: auto; background: #f5f5f5; padding: 10px; border-radius: 5px; margin-top: 10px; }}
        .threat-item {{ margin: 5px 0; padding: 5px; background: white; border-radius: 3px; }}
        .detected {{ background: #e8f5e9; }}
        .not-detected {{ background: #ffebee; }}
        .timestamp {{ color: #999; font-size: 14px; text-align: center; margin-top: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; font-weight: bold; }}
        .excellent {{ color: #4CAF50; }}
        .good {{ color: #FF9800; }}
        .poor {{ color: #F44336; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ KindlyGuard Threat Detection Report</h1>
        
        <div class="summary">
            <div class="stat-box">
                <div class="stat-value">{total_tests}</div>
                <div class="stat-label">Total Tests</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{overall_detection_rate:.1f}%</div>
                <div class="stat-label">Detection Rate</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{overall_quarantine_rate:.1f}%</div>
                <div class="stat-label">Quarantine Rate</div>
            </div>
        </div>
        
        <h2>📊 Detection Performance by Category</h2>
        <table>
            <tr>
                <th>Threat Category</th>
                <th>Tests Run</th>
                <th>Detected</th>
                <th>Detection Rate</th>
                <th>Quarantine Rate</th>
                <th>Status</th>
            </tr>
"""
    
    for category, stats in sorted(category_stats.items()):
        detection_rate = stats['detection_rate']
        if detection_rate >= 95:
            status_class = 'excellent'
            status_text = '✅ Excellent'
        elif detection_rate >= 80:
            status_class = 'good'
            status_text = '⚠️ Good'
        else:
            status_class = 'poor'
            status_text = '❌ Needs Improvement'
        
        html_content += f"""
            <tr>
                <td><strong>{category}</strong></td>
                <td>{stats['total']}</td>
                <td>{stats['detected']}</td>
                <td class="{status_class}">{detection_rate:.1f}%</td>
                <td>{stats['quarantine_rate']:.1f}%</td>
                <td class="{status_class}">{status_text}</td>
            </tr>
"""
    
    html_content += """
        </table>
        
        <h2>🔍 Detailed Category Analysis</h2>
        <div class="category-grid">
"""
    
    # Add detailed cards for each category
    for category, stats in sorted(category_stats.items()):
        html_content += f"""
            <div class="category-card">
                <div class="category-title">{category}</div>
                <div>Total Tests: {stats['total']}</div>
                <div class="detection-rate">Detection Rate: {stats['detection_rate']:.1f}%</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {stats['detection_rate']}%"></div>
                </div>
                <div class="quarantine-rate">Quarantine Rate: {stats['quarantine_rate']:.1f}%</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {stats['quarantine_rate']}%; background: #2196F3;"></div>
                </div>
            </div>
"""
    
    # Add missed threats section
    html_content += """
        </div>
        
        <h2>⚠️ Undetected Threats</h2>
        <div class="threat-list">
"""
    
    missed_threats = []
    for result_file in results:
        for test in result_file.get('detailed_results', []):
            if not test.get('threats_detected'):
                missed_threats.append({
                    'name': test.get('test_name', 'Unknown'),
                    'payload': test.get('payload', '')[:50] + '...' if len(test.get('payload', '')) > 50 else test.get('payload', '')
                })
    
    if missed_threats:
        for threat in missed_threats[:20]:  # Show first 20
            html_content += f"""
            <div class="threat-item not-detected">
                <strong>{threat['name']}</strong>: <code>{threat['payload']}</code>
            </div>
"""
    else:
        html_content += "<div>No undetected threats found! 🎉</div>"
    
    html_content += f"""
        </div>
        
        <h2>📈 Recommendations</h2>
        <ul>
"""
    
    # Add recommendations based on results
    for category, stats in category_stats.items():
        if stats['detection_rate'] < 80:
            html_content += f"<li>⚠️ <strong>{category}</strong>: Detection rate is only {stats['detection_rate']:.1f}%. Consider enhancing detection rules.</li>"
        if stats['quarantine_rate'] < 50 and stats['detected'] > 0:
            html_content += f"<li>📦 <strong>{category}</strong>: Low quarantine rate ({stats['quarantine_rate']:.1f}%). Review quarantine policies.</li>"
    
    html_content += f"""
        </ul>
        
        <div class="timestamp">
            Report generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
</body>
</html>
"""
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"Report generated: {output_file}")

def generate_markdown_summary(results: List[Dict], output_file: str = "threat_summary.md"):
    """Generate a markdown summary report"""
    category_stats = analyze_threat_categories(results)
    
    total_tests = sum(r['summary']['total_tests'] for r in results)
    total_detected = sum(r['summary']['total_detected'] for r in results)
    total_quarantined = sum(r['summary']['total_quarantined'] for r in results)
    
    overall_detection_rate = (total_detected / total_tests * 100) if total_tests > 0 else 0
    
    content = f"""# KindlyGuard Threat Detection Summary

Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Overall Performance

- **Total Tests**: {total_tests}
- **Detection Rate**: {overall_detection_rate:.1f}%
- **Quarantine Rate**: {(total_quarantined / total_detected * 100) if total_detected > 0 else 0:.1f}%

## Category Breakdown

| Category | Tests | Detected | Detection Rate | Status |
|----------|-------|----------|----------------|--------|
"""
    
    for category, stats in sorted(category_stats.items()):
        detection_rate = stats['detection_rate']
        if detection_rate >= 95:
            status = '✅ Excellent'
        elif detection_rate >= 80:
            status = '⚠️ Good'
        else:
            status = '❌ Poor'
        
        content += f"| {category} | {stats['total']} | {stats['detected']} | {detection_rate:.1f}% | {status} |\n"
    
    content += """

## Key Findings

"""
    
    # Add findings
    weak_categories = [cat for cat, stats in category_stats.items() if stats['detection_rate'] < 80]
    if weak_categories:
        content += f"### Areas Needing Improvement\n\n"
        for cat in weak_categories:
            content += f"- **{cat}**: Detection rate below 80%\n"
    
    strong_categories = [cat for cat, stats in category_stats.items() if stats['detection_rate'] >= 95]
    if strong_categories:
        content += f"\n### Strong Protection Areas\n\n"
        for cat in strong_categories:
            content += f"- **{cat}**: Excellent detection rate\n"
    
    with open(output_file, 'w') as f:
        f.write(content)
    
    print(f"Summary generated: {output_file}")

def main():
    # Load all test results
    results = load_test_results()
    
    if not results:
        print("No test results found. Run test_advanced_threats.py first.")
        sys.exit(1)
    
    print(f"Found {len(results)} test result file(s)")
    
    # Generate reports
    generate_html_report(results)
    generate_markdown_summary(results)
    
    # Show quick summary
    total_tests = sum(r['summary']['total_tests'] for r in results)
    total_detected = sum(r['summary']['total_detected'] for r in results)
    
    print(f"\nQuick Summary:")
    print(f"- Total tests across all runs: {total_tests}")
    print(f"- Overall detection rate: {(total_detected / total_tests * 100) if total_tests > 0 else 0:.1f}%")
    print("\nReports generated:")
    print("- threat_report.html (detailed HTML report)")
    print("- threat_summary.md (markdown summary)")

if __name__ == "__main__":
    main()