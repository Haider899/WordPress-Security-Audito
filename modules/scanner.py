import re
import json
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin
import concurrent.futures
from dataclasses import dataclass

import requests
from bs4 import BeautifulSoup


@dataclass
class Vulnerability:
    title: str
    type: str
    severity: str
    description: str
    solution: str
    cve: Optional[str] = None


class WordPressScanner:
    """WordPress security scanner with multiple modules"""
    
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config['scanning']['user_agent']
        })
        self.session.verify = config['scanning']['verify_ssl']
        self.timeout = config['scanning']['timeout']
    
    def enumerate_users(self, url: str) -> List[Dict]:
        """Enumerate WordPress users via various methods"""
        users = []
        
        # Method 1: REST API (/wp-json/wp/v2/users)
        endpoints = [
            "/wp-json/wp/v2/users",
            "/?rest_route=/wp/v2/users",
            "/wp-json/wp/v2/users/1",
            "/wp-json/wp/v2/users?per_page=100"
        ]
        
        for endpoint in endpoints:
            try:
                response = self.session.get(
                    urljoin(url, endpoint),
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list):
                        for user in data:
                            users.append({
                                'id': user.get('id'),
                                'name': user.get('name'),
                                'slug': user.get('slug'),
                                'url': user.get('link'),
                                'method': 'rest_api'
                            })
                    elif isinstance(data, dict):
                        users.append({
                            'id': data.get('id'),
                            'name': data.get('name'),
                            'slug': data.get('slug'),
                            'method': 'rest_api_single'
                        })
            except Exception as e:
                self.logger.debug(f"User enum failed for {endpoint}: {e}")
        
        # Method 2: Author pages (?author=1)
        for i in range(1, 11):
            try:
                author_url = f"{url}/?author={i}"
                response = self.session.get(
                    author_url,
                    allow_redirects=False,
                    timeout=self.timeout
                )
                
                if response.status_code in [301, 302]:
                    location = response.headers.get('location', '')
                    if 'author' in location.lower():
                        username = location.split('/author/')[-1].strip('/')
                        users.append({
                            'id': i,
                            'name': username,
                            'slug': username,
                            'method': 'author_pages'
                        })
            except:
                continue
        
        # Remove duplicates
        unique_users = []
        seen = set()
        for user in users:
            identifier = f"{user['id']}-{user['slug']}"
            if identifier not in seen:
                seen.add(identifier)
                unique_users.append(user)
        
        return unique_users
    
    def detect_plugins(self, url: str) -> List[Dict]:
        """Detect installed WordPress plugins"""
        plugins = []
        
        # Common plugins to check
        common_plugins = [
            "akismet", "contact-form-7", "yoast-seo", "elementor",
            "woocommerce", "jetpack", "wordfence", "all-in-one-seo-pack",
            "google-site-kit", "wpforms", "really-simple-ssl"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for plugin in common_plugins:
                future = executor.submit(self._check_plugin, url, plugin)
                futures[future] = plugin
            
            for future in concurrent.futures.as_completed(futures):
                plugin_name = futures[future]
                try:
                    plugin_info = future.result()
                    if plugin_info:
                        plugins.append(plugin_info)
                except Exception as e:
                    self.logger.debug(f"Plugin check failed for {plugin_name}: {e}")
        
        return plugins
    
    def _check_plugin(self, url: str, plugin_name: str) -> Optional[Dict]:
        """Check if a specific plugin exists"""
        plugin_url = urljoin(url, f"/wp-content/plugins/{plugin_name}/")
        
        try:
            response = self.session.get(
                plugin_url,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            if response.status_code in [200, 403, 301, 302]:
                # Check for readme.txt for version info
                readme_url = urljoin(url, f"/wp-content/plugins/{plugin_name}/readme.txt")
                version = "unknown"
                
                try:
                    readme_response = self.session.get(readme_url, timeout=self.timeout)
                    if readme_response.status_code == 200:
                        content = readme_response.text
                        version_match = re.search(r'Stable tag:\s*([\d.]+)', content, re.IGNORECASE)
                        if version_match:
                            version = version_match.group(1)
                except:
                    pass
                
                return {
                    'name': plugin_name,
                    'url': plugin_url,
                    'version': version,
                    'status': 'detected',
                    'outdated': self._is_outdated(version)
                }
        except:
            pass
        
        return None
    
    def detect_themes(self, url: str) -> List[Dict]:
        """Detect WordPress themes"""
        themes = []
        
        try:
            # Try to get active theme from homepage
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for theme links
            theme_links = soup.find_all('link', {'rel': 'stylesheet'})
            
            for link in theme_links:
                href = link.get('href', '')
                if '/wp-content/themes/' in href:
                    theme_name = href.split('/wp-content/themes/')[1].split('/')[0]
                    
                    # Get theme info
                    style_url = urljoin(url, f"/wp-content/themes/{theme_name}/style.css")
                    theme_info = self._get_theme_info(style_url)
                    
                    if theme_info:
                        themes.append(theme_info)
                        break  # Usually only one active theme
        except Exception as e:
            self.logger.debug(f"Theme detection failed: {e}")
        
        return themes
    
    def _get_theme_info(self, style_url: str) -> Optional[Dict]:
        """Get theme information from style.css"""
        try:
            response = self.session.get(style_url, timeout=self.timeout)
            if response.status_code == 200:
                content = response.text
                
                theme_name = self._extract_theme_info(content, 'Theme Name')
                theme_version = self._extract_theme_info(content, 'Version')
                theme_author = self._extract_theme_info(content, 'Author')
                
                if theme_name:
                    return {
                        'name': theme_name,
                        'version': theme_version or 'unknown',
                        'author': theme_author or 'unknown',
                        'url': style_url,
                        'outdated': self._is_outdated(theme_version)
                    }
        except:
            pass
        
        return None
    
    def check_wp_config(self, url: str) -> List[Dict]:
        """Check for exposed wp-config.php"""
        issues = []
        
        wpconfig_url = urljoin(url, "/wp-config.php")
        
        try:
            response = self.session.get(wpconfig_url, timeout=self.timeout)
            if response.status_code == 200 and "DB_NAME" in response.text:
                issues.append({
                    'issue': 'Exposed wp-config.php',
                    'severity': 'critical',
                    'url': wpconfig_url,
                    'description': 'WordPress configuration file is publicly accessible',
                    'solution': 'Move wp-config.php one level above web root or restrict access'
                })
        except:
            pass
        
        return issues
    
    def scan_vulnerabilities(self, url: str) -> List[Dict]:
        """Scan for known vulnerabilities"""
        vulnerabilities = []
        
        # Check WordPress version for known vulnerabilities
        version = self._get_wordpress_version(url)
        if version:
            vulns = self._check_version_vulnerabilities(version)
            vulnerabilities.extend(vulns)
        
        # Check plugins for vulnerabilities
        plugins = self.detect_plugins(url)
        for plugin in plugins:
            plugin_vulns = self._check_plugin_vulnerabilities(plugin['name'], plugin.get('version'))
            vulnerabilities.extend(plugin_vulns)
        
        return vulnerabilities
    
    def _get_wordpress_version(self, url: str) -> Optional[str]:
        """Extract WordPress version"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Check generator meta tag
            soup = BeautifulSoup(response.text, 'html.parser')
            generator = soup.find('meta', {'name': 'generator'})
            if generator and 'WordPress' in generator.get('content', ''):
                version = generator.get('content').split('WordPress ')[-1]
                return version
            
            # Check readme.html
            readme_url = urljoin(url, "/readme.html")
            readme_response = self.session.get(readme_url, timeout=self.timeout)
            if readme_response.status_code == 200:
                version_match = re.search(r'Version\s*([\d.]+)', readme_response.text)
                if version_match:
                    return version_match.group(1)
            
            # Check feed
            feed_url = urljoin(url, "/feed/")
            feed_response = self.session.get(feed_url, timeout=self.timeout)
            if feed_response.status_code == 200:
                version_match = re.search(r'wordpress.org/\?v=([\d.]+)', feed_response.text)
                if version_match:
                    return version_match.group(1)
        
        except:
            pass
        
        return None
    
    def _check_version_vulnerabilities(self, version: str) -> List[Dict]:
        """Check for vulnerabilities in WordPress version"""
        vulnerabilities = []
        
        # Known vulnerability patterns (simplified)
        vuln_db = {
            '5.0': {'critical': ['RCE vulnerabilities']},
            '4.9': {'high': ['XSS vulnerabilities']},
            '4.7': {'critical': ['REST API vulnerability']}
        }
        
        for vuln_version, vulns in vuln_db.items():
            if version.startswith(vuln_version):
                for severity, issues in vulns.items():
                    for issue in issues:
                        vulnerabilities.append({
                            'title': f'WordPress {version} {issue}',
                            'type': 'core',
                            'severity': severity,
                            'description': f'Known vulnerability in WordPress {version}',
                            'solution': 'Update to latest version'
                        })
        
        return vulnerabilities
    
    def _check_plugin_vulnerabilities(self, plugin_name: str, version: str = None) -> List[Dict]:
        """Check for plugin vulnerabilities (simplified)"""
        # This would normally query a vulnerability database
        known_vuln_plugins = {
            'contact-form-7': {'versions': ['<5.0'], 'issue': 'XSS vulnerability'},
            'elementor': {'versions': ['<3.0'], 'issue': 'RCE vulnerability'}
        }
        
        vulnerabilities = []
        
        if plugin_name in known_vuln_plugins:
            vuln_info = known_vuln_plugins[plugin_name]
            vulnerabilities.append({
                'title': f'{plugin_name} {vuln_info["issue"]}',
                'type': 'plugin',
                'severity': 'high',
                'description': f'Known vulnerability in {plugin_name}',
                'solution': f'Update {plugin_name} to latest version'
            })
        
        return vulnerabilities
    
    def check_configuration(self, url: str) -> List[Dict]:
        """Check WordPress configuration issues"""
        issues = []
        
        checks = [
            self._check_debug_mode,
            self._check_xmlrpc,
            self._check_directory_listing,
            self._check_error_display
        ]
        
        for check in checks:
            try:
                result = check(url)
                if result:
                    issues.extend(result)
            except Exception as e:
                self.logger.debug(f"Configuration check failed: {e}")
        
        return issues
    
    def _check_debug_mode(self, url: str) -> List[Dict]:
        """Check if debug mode is enabled"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            if 'WP_DEBUG' in response.text and 'true' in response.text.lower():
                return [{
                    'issue': 'Debug mode enabled',
                    'severity': 'medium',
                    'description': 'WordPress debug mode exposes sensitive information',
                    'solution': 'Disable WP_DEBUG in wp-config.php'
                }]
        except:
            pass
        return []
    
    def _check_xmlrpc(self, url: str) -> List[Dict]:
        """Check XML-RPC status"""
        xmlrpc_url = urljoin(url, "/xmlrpc.php")
        
        try:
            response = self.session.get(xmlrpc_url, timeout=self.timeout)
            if response.status_code == 200 and 'XML-RPC' in response.text:
                return [{
                    'issue': 'XML-RPC enabled',
                    'severity': 'medium',
                    'description': 'XML-RPC can be used for brute force attacks',
                    'solution': 'Disable XML-RPC if not needed'
                }]
        except:
            pass
        return []
    
    def _check_directory_listing(self, url: str) -> List[Dict]:
        """Check for directory listing"""
        dirs_to_check = [
            "/wp-content/uploads/",
            "/wp-content/plugins/",
            "/wp-content/themes/"
        ]
        
        issues = []
        for directory in dirs_to_check:
            dir_url = urljoin(url, directory)
            try:
                response = self.session.get(dir_url, timeout=self.timeout)
                if response.status_code == 200 and 'Index of' in response.text:
                    issues.append({
                        'issue': f'Directory listing enabled: {directory}',
                        'severity': 'low',
                        'description': f'Directory listing exposes file structure',
                        'solution': 'Add "Options -Indexes" to .htaccess'
                    })
            except:
                pass
        
        return issues
    
    def _check_error_display(self, url: str) -> List[Dict]:
        """Check for error display"""
        # Try to trigger an error
        error_url = urljoin(url, "/?p=999999999")
        
        try:
            response = self.session.get(error_url, timeout=self.timeout)
            if 'mysql' in response.text.lower() or 'error' in response.text.lower():
                return [{
                    'issue': 'Error display enabled',
                    'severity': 'low',
                    'description': 'Errors expose system information',
                    'solution': 'Disable error display in production'
                }]
        except:
            pass
        return []
    
    def _extract_theme_info(self, content: str, key: str) -> Optional[str]:
        """Extract theme information from style.css"""
        pattern = rf'{key}:\s*(.+)'
        match = re.search(pattern, content, re.IGNORECASE)
        return match.group(1).strip() if match else None
    
    def _is_outdated(self, version: str) -> bool:
        """Check if version is outdated (simplified)"""
        if version == 'unknown' or not version:
            return False
        
        # Simple check - if version has less than 3 parts (major.minor.patch)
        parts = version.split('.')
        return len(parts) < 3 or int(parts[0]) < 2
