import json
from typing import List, Dict, Any
from datetime import datetime
from colorama import Fore, Style
from .rules.base import Finding


class BaseReporter:
    """Base class for all reporters"""
    
    def generate(self, findings: List[Finding], stats: Dict[str, Any]) -> str:
        """Generate report from findings"""
        raise NotImplementedError


class ConsoleReporter(BaseReporter):
    """Generate colored console output report"""
    
    def generate(self, findings: List[Finding], stats: Dict[str, Any]) -> str:
        """Generate console report with colors"""
        output = []
        
        # Summary section
        output.append(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        output.append(f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
        output.append(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        
        output.append(f"Files Scanned:        {stats['files_scanned']}")
        output.append(f"Lines Scanned:        {stats['lines_scanned']}")
        output.append(f"Total Findings:       {stats['total_findings']}")
        output.append(f"Files with Issues:    {stats['unique_files_with_issues']}\n")
        
        # Severity breakdown
        output.append(f"{Fore.YELLOW}Severity Breakdown:{Style.RESET_ALL}")
        for severity, count in stats['findings_by_severity'].items():
            if count > 0:
                color = self._get_severity_color(severity)
                output.append(f"  {color}{severity:10s}: {count}{Style.RESET_ALL}")
        
        if not findings:
            output.append(f"\n{Fore.GREEN}✓ No security issues found!{Style.RESET_ALL}\n")
            return '\n'.join(output)
        
        # Group findings by severity
        findings_by_severity = {}
        for finding in findings:
            severity = finding.severity.value
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)
        
        # Display findings by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        for severity in severity_order:
            if severity not in findings_by_severity:
                continue
            
            findings_list = findings_by_severity[severity]
            color = self._get_severity_color(severity)
            
            output.append(f"\n{color}{'='*80}{Style.RESET_ALL}")
            output.append(f"{color}{severity} SEVERITY FINDINGS ({len(findings_list)}){Style.RESET_ALL}")
            output.append(f"{color}{'='*80}{Style.RESET_ALL}\n")
            
            for i, finding in enumerate(findings_list, 1):
                output.append(f"{color}[{severity}] {finding.rule_id}: {finding.title}{Style.RESET_ALL}")
                output.append(f"  File:        {finding.file_path}:{finding.line_number}")
                output.append(f"  OWASP:       {finding.owasp_category.value}")
                if finding.cwe_id:
                    output.append(f"  CWE:         {finding.cwe_id}")
                output.append(f"  Description: {finding.description}")
                output.append(f"  Code:        {Fore.WHITE}{finding.code_snippet}{Style.RESET_ALL}")
                output.append(f"  Fix:         {finding.recommendation}")
                output.append("")
        
        output.append(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        
        return '\n'.join(output)
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        colors = {
            'CRITICAL': Fore.RED + Style.BRIGHT,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE,
            'INFO': Fore.CYAN
        }
        return colors.get(severity, Fore.WHITE)


class JSONReporter(BaseReporter):
    """Generate JSON format report"""
    
    def generate(self, findings: List[Finding], stats: Dict[str, Any]) -> str:
        """Generate JSON report"""
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'scanner_version': '1.0.0',
                'owasp_version': '2024'
            },
            'statistics': stats,
            'findings': [finding.to_dict() for finding in findings]
        }
        
        return json.dumps(report, indent=2)


class HTMLReporter(BaseReporter):
    """Generate HTML format report"""
    
    def generate(self, findings: List[Finding], stats: Dict[str, Any]) -> str:
        """Generate HTML report"""
        
        # Group findings by severity
        findings_by_severity = {}
        for finding in findings:
            severity = finding.severity.value
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Swift Security Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
        }}
        
        .header h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f9f9f9;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .stat-card h3 {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        
        .stat-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        
        .severity-breakdown {{
            padding: 30px;
        }}
        
        .severity-section {{
            margin-bottom: 30px;
        }}
        
        .severity-header {{
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        
        .critical {{ background: #fee; color: #c00; border-left: 4px solid #c00; }}
        .high {{ background: #fdd; color: #d00; border-left: 4px solid #d00; }}
        .medium {{ background: #ffd; color: #d80; border-left: 4px solid #d80; }}
        .low {{ background: #def; color: #06c; border-left: 4px solid #06c; }}
        .info {{ background: #dff; color: #0aa; border-left: 4px solid #0aa; }}
        
        .finding {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        
        .finding-title {{
            font-size: 1.1em;
            font-weight: bold;
            margin-bottom: 10px;
            color: #333;
        }}
        
        .finding-meta {{
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            font-size: 0.9em;
            color: #666;
        }}
        
        .finding-meta span {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .code-snippet {{
            background: #f5f5f5;
            border-left: 3px solid #667eea;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .recommendation {{
            background: #e7f3ff;
            border-left: 3px solid #2196F3;
            padding: 15px;
            margin-top: 15px;
            border-radius: 4px;
        }}
        
        .recommendation strong {{
            color: #1976D2;
        }}
        
        .footer {{
            padding: 20px 30px;
            background: #f9f9f9;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Swift Security Scan Report</h1>
            <p>OWASP Mobile Top 10 (2024) Vulnerability Assessment</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Files Scanned</h3>
                <div class="value">{stats['files_scanned']}</div>
            </div>
            <div class="stat-card">
                <h3>Lines Scanned</h3>
                <div class="value">{stats['lines_scanned']:,}</div>
            </div>
            <div class="stat-card">
                <h3>Total Findings</h3>
                <div class="value">{stats['total_findings']}</div>
            </div>
            <div class="stat-card">
                <h3>Files with Issues</h3>
                <div class="value">{stats['unique_files_with_issues']}</div>
            </div>
        </div>
        
        <div class="severity-breakdown">
            <h2>Security Findings</h2>
"""
        
        if not findings:
            html += """
            <div style="padding: 40px; text-align: center; color: #4caf50;">
                <h3>✓ No security issues found!</h3>
                <p>Your code passed all security checks.</p>
            </div>
"""
        else:
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            
            for severity in severity_order:
                if severity not in findings_by_severity:
                    continue
                
                findings_list = findings_by_severity[severity]
                severity_class = severity.lower()
                
                html += f"""
            <div class="severity-section">
                <div class="severity-header {severity_class}">
                    {severity} ({len(findings_list)})
                </div>
"""
                
                for finding in findings_list:
                    html += f"""
                <div class="finding">
                    <div class="finding-title">{finding.rule_id}: {finding.title}</div>
                    <div class="finding-meta">
                        <span>📁 {finding.file_path}:{finding.line_number}</span>
                        <span>🏷️ {finding.owasp_category.value}</span>
                        {f'<span>⚠️ {finding.cwe_id}</span>' if finding.cwe_id else ''}
                    </div>
                    <p>{finding.description}</p>
                    <div class="code-snippet">{self._escape_html(finding.code_snippet)}</div>
                    <div class="recommendation">
                        <strong>💡 Recommendation:</strong> {finding.recommendation}
                    </div>
                </div>
"""
                
                html += """
            </div>
"""
        
        html += f"""
        </div>
        
        <div class="footer">
            <p>Swift Security Scanner v1.0.0 | OWASP Mobile Top 10 2024</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))