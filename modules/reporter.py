"""
Advanced Report Generation Module for WP-SEC-AUDIT
Professional security reports with intelligent risk scoring
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    """Professional report generator with intelligent risk assessment"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.report_dir = self._get_report_dir()
    
    def _get_report_dir(self):
        """Get report directory path"""
        report_dir = self.config.get('output', {}).get('report_dir', '')
        if not report_dir:
            report_dir = os.path.expanduser("~/Desktop/WP-SEC-AUDIT-Results")
        else:
            report_dir = os.path.expanduser(report_dir)
        
        Path(report_dir).mkdir(parents=True, exist_ok=True)
        return report_dir
    
    def generate_report(self, results, format='text'):
        """Generate report in specified format"""
        format = format.lower()
        
        if format == 'json':
            return self._generate_json_report(results)
        elif format == 'html':
            return self._generate_html_report(results)
        elif format == 'markdown' or format == 'md':
            return self._generate_markdown_report(results)
        else:
            return self._generate_text_report(results)
    
    def _generate_text_report(self, results):
        """Generate detailed text report"""
        scan_type = results.get('scan_type', 'standard')
        
        report = []
        report.append("=" * 70)
        report.append(f"WP-SEC-AUDIT SECURITY REPORT - {scan_type.upper()} SCAN")
        report.append("=" * 70)
        report.append(f"Target URL: {results.get('url', 'Unknown')}")
        report.append(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"WordPress Detected: {'YES' if results.get('wordpress') else 'NO'}")
        report.append(f"Scan Type: {scan_type}")
        report.append("")
        
        if results.get('wordpress'):
            if results.get('users_exposed'):
                report.append("⚠️ CRITICAL: USER ENUMERATION VULNERABILITY")
                report.append("-" * 50)
                users = results.get('users', [])
                report.append(f"Found {len(users)} exposed user accounts:")
                for user in users[:15]:
                    user_info = f"  • {user.get('name', 'Unknown')}"
                    if user.get('id'):
                        user_info += f" (ID: {user.get('id')}"
                        if user.get('username'):
                            user_info += f", Username: {user.get('username')}"
                        if user.get('method'):
                            user_info += f", Method: {user.get('method')}"
                        user_info += ")"
                    report.append(user_info)
                if len(users) > 15:
                    report.append(f"  ... and {len(users) - 15} more users")
                report.append("")
            else:
                report.append("✅ User enumeration appears to be blocked")
                report.append("")
            
            cves = results.get('cves', [])
            if cves:
                report.append(f"💀 {len(cves)} KNOWN CVEs DETECTED")
                report.append("-" * 50)
                for cve in cves[:10]:
                    report.append(f"  • {cve.get('cve_id', 'Unknown')}: {cve.get('description', '')}")
                    if cve.get('severity'):
                        report.append(f"    Severity: {cve.get('severity').upper()}")
                if len(cves) > 10:
                    report.append(f"  ... and {len(cves) - 10} more CVEs")
                report.append("")
            
            vulns = results.get('vulnerabilities', [])
            if vulns:
                report.append(f"⚠️ {len(vulns)} VULNERABILITIES FOUND")
                report.append("-" * 50)
                for vuln in vulns:
                    report.append(f"  • {vuln.get('description', 'Unknown')}")
                    if vuln.get('severity'):
                        report.append(f"    Severity: {vuln.get('severity').upper()}")
                    if vuln.get('solution'):
                        report.append(f"    Solution: {vuln.get('solution')}")
                report.append("")
            
            files = results.get('sensitive_files', [])
            if files:
                critical_files = [f for f in files if f.get('critical')]
                if critical_files:
                    report.append(f"🔓 {len(critical_files)} CRITICAL FILES EXPOSED")
                    report.append("-" * 50)
                    for file in critical_files:
                        report.append(f"  • {file.get('path', 'Unknown')}")
                        if file.get('status_code'):
                            report.append(f"    Status Code: {file.get('status_code')}")
                report.append("")
            
            dirs = results.get('directory_listings', [])
            if dirs:
                report.append(f"📁 {len(dirs)} DIRECTORY LISTINGS ENABLED")
                report.append("-" * 50)
                for directory in dirs:
                    report.append(f"  • {directory.get('directory', 'Unknown')}")
                report.append("")
            
            plugins = results.get('plugins', [])
            if plugins:
                report.append(f"🔌 {len(plugins)} PLUGINS DETECTED")
                report.append("-" * 50)
                for plugin in plugins[:10]:
                    plugin_info = f"  • {plugin.get('name', 'Unknown')}"
                    if plugin.get('version') and plugin['version'] != 'unknown':
                        plugin_info += f" (v{plugin.get('version')})"
                    report.append(plugin_info)
                if len(plugins) > 10:
                    report.append(f"  ... and {len(plugins) - 10} more plugins")
                report.append("")
            
            themes = results.get('themes', [])
            if themes:
                report.append(f"🎨 {len(themes)} THEMES DETECTED")
                report.append("-" * 50)
                for theme in themes:
                    theme_info = f"  • {theme.get('full_name', theme.get('name', 'Unknown'))}"
                    if theme.get('version') and theme['version'] != 'unknown':
                        theme_info += f" (v{theme.get('version')})"
                    report.append(theme_info)
                report.append("")
            
            config_issues = results.get('config_issues', [])
            if config_issues:
                report.append(f"⚙️ {len(config_issues)} CONFIGURATION ISSUES")
                report.append("-" * 50)
                for issue in config_issues:
                    report.append(f"  • {issue}")
                report.append("")
            
            issues = results.get('issues', [])
            if issues:
                report.append(f"🚨 {len(issues)} SECURITY ISSUES IDENTIFIED")
                report.append("-" * 50)
                for issue in issues:
                    report.append(f"  • {issue}")
                report.append("")
            
            report.append("📊 RISK ASSESSMENT")
            report.append("-" * 50)
            risk_score = self._calculate_risk_score(results)
            risk_level = self._get_risk_level(risk_score)
            
            report.append(f"Overall Risk Score: {risk_score}/100")
            report.append(f"Risk Level: {risk_level}")
            report.append("")
            
            report.append("💡 SECURITY RECOMMENDATIONS")
            report.append("-" * 50)
            recommendations = self._generate_recommendations(results)
            for i, rec in enumerate(recommendations, 1):
                report.append(f"{i}. {rec}")
            
        else:
            report.append("❌ NOT A WORDPRESS SITE")
            report.append("The target does not appear to be a WordPress installation.")
            
            if results.get('sensitive_files') or results.get('directory_listings'):
                report.append("\n⚠️ Non-WordPress Findings:")
                if results.get('sensitive_files'):
                    report.append(f"  • Found {len(results['sensitive_files'])} sensitive files")
                if results.get('directory_listings'):
                    report.append(f"  • Found {len(results['directory_listings'])} directory listings")
        
        report.append("")
        report.append("=" * 70)
        report.append("Report generated by WP-SEC-AUDIT v1.2.0")
        report.append("For authorized security testing only")
        
        return "\n".join(report)
    
    def _calculate_risk_score(self, results):
        """Intelligent risk scoring based on vulnerability severity"""
        score = 0
        
        if results.get('users_exposed'):
            users = results.get('users', [])
            user_count = len(users)
            
            base_score = 25
            
            if user_count >= 20:
                user_multiplier = 2.0
            elif user_count >= 10:
                user_multiplier = 1.5
            elif user_count >= 5:
                user_multiplier = 1.2
            else:
                user_multiplier = 1.0
            
            admin_users = []
            for user in users:
                username = str(user.get('username', '')).lower()
                name = str(user.get('name', '')).lower()
                if any(admin_keyword in username or admin_keyword in name 
                      for admin_keyword in ['admin', 'administrator', 'root', 'super']):
                    admin_users.append(user)
            
            admin_count = len(admin_users)
            admin_bonus = admin_count * 5
            
            email_exposed = any('@' in str(user.get('email', '')) for user in users)
            email_bonus = 3 if email_exposed else 0
            
            user_score = min(40, base_score + (user_count * user_multiplier) + admin_bonus + email_bonus)
            score += user_score
        
        cves = results.get('cves', [])
        if cves:
            cve_score = 0
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            for cve in cves:
                severity = cve.get('severity', 'medium').lower()
                
                if severity == 'critical':
                    weight = 15
                    severity_counts['critical'] += 1
                elif severity == 'high':
                    weight = 10
                    severity_counts['high'] += 1
                elif severity == 'medium':
                    weight = 5
                    severity_counts['medium'] += 1
                else:
                    weight = 2
                    severity_counts['low'] += 1
                
                cve_score += weight
                
                cve_id = cve.get('cve_id', '')
                if cve_id and 'CVE-' in cve_id:
                    try:
                        year = int(cve_id.split('-')[1])
                        current_year = datetime.now().year
                        if current_year - year <= 1:
                            cve_score += 5
                        elif current_year - year <= 2:
                            cve_score += 3
                    except:
                        pass
            
            if severity_counts['critical'] >= 2:
                cve_score += 10
            
            cve_score = min(35, cve_score)
            score += cve_score
        
        vulns = results.get('vulnerabilities', [])
        if vulns:
            vuln_score = 0
            
            vulnerability_context = {
                'xmlrpc_enabled': {'base': 12, 'severity': 'high'},
                'debug_log_exposed': {'base': 15, 'severity': 'high'},
                'wpconfig_exposed': {'base': 20, 'severity': 'critical'},
                'readme_exposed': {'base': 5, 'severity': 'low'},
                'directory_listing': {'base': 8, 'severity': 'medium'}
            }
            
            for vuln in vulns:
                vuln_type = vuln.get('type', '')
                severity = vuln.get('severity', 'medium').lower()
                
                if vuln_type in vulnerability_context:
                    context_info = vulnerability_context[vuln_type]
                    base_weight = context_info['base']
                    
                    if severity == 'critical':
                        multiplier = 1.5
                    elif severity == 'high':
                        multiplier = 1.3
                    elif severity == 'medium':
                        multiplier = 1.1
                    else:
                        multiplier = 1.0
                    
                    vuln_score += base_weight * multiplier
                    
                    if vuln_type == 'wpconfig_exposed':
                        vuln_score += 5
                    elif vuln_type == 'xmlrpc_enabled':
                        if results.get('users_exposed'):
                            vuln_score += 3
                else:
                    if severity == 'critical':
                        vuln_score += 15
                    elif severity == 'high':
                        vuln_score += 10
                    elif severity == 'medium':
                        vuln_score += 7
                    else:
                        vuln_score += 3
            
            vuln_score = min(25, vuln_score)
            score += vuln_score
        
        files = results.get('sensitive_files', [])
        if files:
            file_score = 0
            
            file_sensitivity = {
                'wp-config.php': {'weight': 25, 'risk': 'critical'},
                'wp-config.php.bak': {'weight': 20, 'risk': 'high'},
                'debug.log': {'weight': 18, 'risk': 'high'},
                'xmlrpc.php': {'weight': 10, 'risk': 'medium'},
                'readme.html': {'weight': 5, 'risk': 'low'}
            }
            
            for file in files:
                file_path = file.get('path', '')
                status_code = file.get('status_code', 0)
                
                file_weight = 5
                
                for file_type, sensitivity in file_sensitivity.items():
                    if file_type in file_path:
                        file_weight = sensitivity['weight']
                        break
                
                if status_code == 200:
                    file_weight *= 1.5
                elif status_code == 403:
                    file_weight *= 1.2
                elif status_code == 401:
                    file_weight *= 1.1
                
                file_score += file_weight
            
            file_score = min(20, file_score)
            score += file_score
        
        compound_bonus = 0
        
        wpconfig_exposed = any('wp-config' in f.get('path', '') for f in files)
        xmlrpc_enabled = any(v.get('type') == 'xmlrpc_enabled' for v in vulns)
        
        if wpconfig_exposed and xmlrpc_enabled:
            compound_bonus += 8
        
        if results.get('users_exposed'):
            outdated_components = self._check_outdated_components(results)
            if outdated_components:
                compound_bonus += 5
        
        critical_count = sum([
            1 for f in files if any(critical in f.get('path', '') for critical in ['wp-config', 'debug.log'])
        ] + [
            1 for v in vulns if v.get('severity') == 'critical'
        ])
        
        if critical_count >= 3:
            compound_bonus += 10
        elif critical_count >= 2:
            compound_bonus += 5
        
        compound_bonus = min(15, compound_bonus)
        score += compound_bonus
        
        score = min(100, score)
        
        if score > 0 and score < 10:
            score = 10
        
        score = round(score)
        
        if self.config.get('logging', {}).get('level') == 'DEBUG':
            print(f"\n[DEBUG] Final risk score: {score}")
        
        return score
    
    def _check_outdated_components(self, results):
        """Check for outdated plugins and themes"""
        outdated = []
        
        plugins = results.get('plugins', [])
        for plugin in plugins:
            version = plugin.get('version', '')
            if version != 'unknown' and self._is_outdated_version(version):
                outdated.append(f"{plugin.get('name')} v{version}")
        
        themes = results.get('themes', [])
        for theme in themes:
            version = theme.get('version', '')
            if version != 'unknown' and self._is_outdated_version(version):
                outdated.append(f"{theme.get('name')} v{version}")
        
        return outdated
    
    def _is_outdated_version(self, version):
        """Check if version is outdated"""
        try:
            version = ''.join(c for c in version if c.isdigit() or c == '.')
            parts = version.split('.')
            
            if len(parts) < 2:
                return True
            
            major = int(parts[0]) if parts[0].isdigit() else 0
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            
            if major == 0:
                return True
            elif major == 1 and minor < 5:
                return True
            elif major < 4:
                return True
            
            return False
        except:
            return False
    
    def _generate_json_report(self, results):
        """Generate JSON report"""
        report_data = {
            'metadata': {
                'tool': 'WP-SEC-AUDIT',
                'version': '1.2.0',
                'scan_time': datetime.now().isoformat(),
                'report_format': 'json'
            },
            'target': {
                'url': results.get('url'),
                'wordpress_detected': results.get('wordpress', False)
            },
            'findings': {
                'user_enumeration': {
                    'exposed': results.get('users_exposed', False),
                    'user_count': len(results.get('users', [])),
                    'users': results.get('users', [])
                },
                'vulnerabilities': {
                    'cves': results.get('cves', []),
                    'other_vulnerabilities': results.get('vulnerabilities', []),
                    'total_count': len(results.get('cves', [])) + len(results.get('vulnerabilities', []))
                },
                'files_and_directories': {
                    'sensitive_files': results.get('sensitive_files', []),
                    'directory_listings': results.get('directory_listings', []),
                    'critical_files': [f for f in results.get('sensitive_files', []) if f.get('critical')]
                },
                'components': {
                    'plugins': results.get('plugins', []),
                    'themes': results.get('themes', [])
                },
                'configuration': {
                    'issues': results.get('config_issues', [])
                },
                'summary': {
                    'issues': results.get('issues', []),
                    'risk_score': self._calculate_risk_score(results),
                    'risk_level': self._get_risk_level(self._calculate_risk_score(results))
                }
            },
            'recommendations': self._generate_recommendations(results),
            'scan_details': {
                'scan_type': results.get('scan_type'),
                'timestamp': results.get('timestamp'),
                'error': results.get('error')
            }
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_html_report(self, results):
        """Generate HTML report"""
        risk_score = self._calculate_risk_score(results)
        
        if risk_score >= 70:
            risk_color = "#e74c3c"
            risk_level = "CRITICAL"
            risk_icon = "🔴"
        elif risk_score >= 40:
            risk_color = "#e67e22"
            risk_level = "HIGH"
            risk_icon = "🟡"
        elif risk_score >= 20:
            risk_color = "#f1c40f"
            risk_level = "MEDIUM"
            risk_icon = "🟠"
        else:
            risk_color = "#27ae60"
            risk_level = "LOW"
            risk_icon = "🟢"
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WP-SEC-AUDIT Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .vulnerable {{ color: #e74c3c; font-weight: bold; }}
        .secure {{ color: #27ae60; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 WP-SEC-AUDIT Security Report</h1>
        <p>Target: {results.get('url', 'Unknown')}</p>
        <p>Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Risk Score: <span style="color: {risk_color}">{risk_score}/100 ({risk_level})</span></p>
    </div>
"""
        
        if results.get('wordpress'):
            html += """
    <div class="finding">
        <h2>✅ WordPress Detected</h2>
"""
            
            if results.get('users_exposed'):
                html += f"""
        <p class="vulnerable">⚠️ User Enumeration Vulnerability Found</p>
        <p>Found {len(results.get('users', []))} exposed user accounts.</p>
"""
            else:
                html += """
        <p class="secure">✅ User enumeration appears blocked</p>
"""
            
            plugins = results.get('plugins', [])
            if plugins:
                html += f"""
        <h3>Detected Plugins ({len(plugins)})</h3>
        <ul>
"""
                for plugin in plugins[:10]:
                    html += f"<li>{plugin.get('name', 'Unknown')}</li>\n"
                html += "</ul>\n"
            
            cves = results.get('cves', [])
            if cves:
                html += f"""
        <h3>CVEs Found ({len(cves)})</h3>
        <ul>
"""
                for cve in cves[:5]:
                    html += f"<li>{cve.get('cve_id', 'Unknown')}: {cve.get('description', '')}</li>\n"
                html += "</ul>\n"
            
            html += """
    </div>
"""
        else:
            html += """
    <div class="finding">
        <h2>❌ Not a WordPress Site</h2>
        <p>The target does not appear to be a WordPress installation.</p>
    </div>
"""
        
        recommendations = self._generate_recommendations(results)
        if recommendations:
            html += """
    <div class="finding">
        <h2>💡 Recommendations</h2>
        <ul>
"""
            for rec in recommendations[:5]:
                html += f"<li>{rec}</li>\n"
            html += """
        </ul>
    </div>
"""
        
        html += """
    <div style="margin-top: 40px; padding: 20px; background: #f8f9fa;">
        <p>Report generated by <strong>WP-SEC-AUDIT v1.2.0</strong></p>
        <p><em>For authorized security testing only</em></p>
    </div>
</body>
</html>
"""
        return html
    
    def _generate_markdown_report(self, results):
        """Generate Markdown report"""
        risk_score = self._calculate_risk_score(results)
        risk_level = self._get_risk_level(risk_score)
        
        md = f"""# WP-SEC-AUDIT Security Report

## 📊 Scan Summary
- **Target URL**: {results.get('url', 'Unknown')}
- **Scan Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **WordPress Detected**: {'✅ Yes' if results.get('wordpress') else '❌ No'}
- **Risk Score**: {risk_score}/100 ({risk_level})

## 🔍 Findings
"""
        
        if results.get('wordpress'):
            if results.get('users_exposed'):
                md += f"\n### 🚨 Critical: User Enumeration\nFound **{len(results.get('users', []))}** exposed user accounts!\n"
            
            cves = results.get('cves', [])
            if cves:
                md += f"\n### 💀 CVEs Detected ({len(cves)})\n"
                for cve in cves[:5]:
                    md += f"- **{cve.get('cve_id')}**: {cve.get('description')}\n"
            
            plugins = results.get('plugins', [])
            if plugins:
                md += f"\n### 🔌 Plugins Detected ({len(plugins)})\n"
                for plugin in plugins[:10]:
                    md += f"- {plugin['name']}\n"
            
            md += f"\n### 💡 Recommendations\n"
            recommendations = self._generate_recommendations(results)
            for rec in recommendations:
                md += f"- {rec}\n"
        else:
            md += "\n❌ Not a WordPress site or inaccessible.\n"
        
        md += f"\n---\n*Report generated by WP-SEC-AUDIT v1.2.0 on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        return md
    
    def _get_risk_level(self, score):
        """Get risk level based on score"""
        if score >= 70:
            return "CRITICAL 🔴"
        elif score >= 40:
            return "HIGH 🟡"
        elif score >= 20:
            return "MEDIUM 🟠"
        else:
            return "LOW 🟢"
    
    def _generate_recommendations(self, results):
        """Generate security recommendations"""
        recommendations = []
        
        if results.get('users_exposed'):
            recommendations.append("Disable user enumeration via REST API")
            recommendations.append("Implement login rate limiting")
        
        if results.get('cves'):
            recommendations.append("Update WordPress core to latest version")
            recommendations.append("Apply all security patches")
        
        if results.get('vulnerabilities'):
            if any('xmlrpc' in str(v).lower() for v in results.get('vulnerabilities', [])):
                recommendations.append("Disable XML-RPC if not needed")
        
        files = results.get('sensitive_files', [])
        if files:
            if any('wp-config' in f.get('path', '').lower() for f in files):
                recommendations.append("Protect wp-config.php file")
        
        recommendations.extend([
            "Implement Web Application Firewall (WAF)",
            "Use strong passwords and two-factor authentication",
            "Keep all plugins and themes updated",
            "Regularly backup your WordPress site"
        ])
        
        return list(dict.fromkeys(recommendations))[:8]
    
    def save_report(self, report_content, filename, format='text'):
        """Save report to file"""
        extensions = {
            'text': '.txt',
            'json': '.json',
            'html': '.html',
            'markdown': '.md',
            'md': '.md'
        }
        
        ext = extensions.get(format.lower(), '.txt')
        
        if not filename.endswith(ext):
            filename += ext
        
        filepath = os.path.join(self.report_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return filepath
        except Exception as e:
            print(f"[!] Error saving report: {e}")
            return None
