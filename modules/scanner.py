"""
Advanced WordPress Security Scanner Module
Aggressive scanning with subdomain support, CVE detection, and advanced enumeration
"""

import requests
import json
import time
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import dns.resolver

class WordPressScanner:
    """Advanced scanner with aggressive scanning capabilities"""
    
    def __init__(self, config=None, logger=None):
        self.config = config or {}
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.get('scanning', {}).get('user_agent', 
                         'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WP-SEC-AUDIT/3.0')
        })
        self.session.verify = False  # Disable SSL verification for aggressive scanning
        self.timeout = self.config.get('scanning', {}).get('timeout', 30)
        self.threads = self.config.get('scanning', {}).get('threads', 10)
        
        # Enhanced wordlists
        self.user_endpoints = [
            '/wp-json/wp/v2/users',
            '/?rest_route=/wp/v2/users',
            '/wp-json/wp/v2/users/1',
            '/wp-json/wp/v2/users?per_page=100',
            '/wp-json/wp/v2/users?context=edit',
            '/author/admin',
            '/?author=1',
            '/feed/',
            '/?feed=rss2',
            '/wp-json/oembed/1.0/embed',
            '/index.php/wp-json/wp/v2/users'
        ]
        
        self.sensitive_files = [
            '/wp-config.php',
            '/wp-config.php.bak',
            '/wp-config.php.save',
            '/wp-config.php.old',
            '/wp-config.php.orig',
            '/wp-config.php.dist',
            '/wp-config.php.backup',
            '/wp-admin/admin-ajax.php',
            '/xmlrpc.php',
            '/readme.html',
            '/license.txt',
            '/wp-login.php',
            '/wp-content/debug.log',
            '/wp-content/uploads/',
            '/wp-includes/'
        ]
    
    def aggressive_scan(self, url):
        """Perform aggressive security scan"""
        print(f"[*] Starting AGGRESSIVE scan for: {url}")
        results = {
            'url': url,
            'wordpress': False,
            'users_exposed': False,
            'plugins': [],
            'themes': [],
            'vulnerabilities': [],
            'sensitive_files': [],
            'directory_listings': [],
            'cves': [],
            'issues': [],
            'config_issues': [],
            'subdomains': [],
            'timestamp': time.time(),
            'scan_type': 'aggressive'
        }
        
        try:
            # Phase 1: Basic WordPress detection
            if self._is_wordpress(url):
                results['wordpress'] = True
                
                # Phase 2: Parallel scanning
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {
                        executor.submit(self._aggressive_user_enumeration, url): 'users',
                        executor.submit(self._deep_plugin_scan, url): 'plugins',
                        executor.submit(self._deep_theme_scan, url): 'themes',
                        executor.submit(self._scan_sensitive_files, url): 'files',
                        executor.submit(self._check_directory_listing, url): 'directories',
                        executor.submit(self._check_vulnerabilities, url): 'vulns',
                        executor.submit(self._check_cves, url): 'cves',
                        executor.submit(self._scan_configuration, url): 'config'
                    }
                    
                    for future in as_completed(futures):
                        scan_type = futures[future]
                        try:
                            data = future.result()
                            if scan_type == 'users' and data:
                                results['users_exposed'] = True
                                results['users'] = data
                            elif scan_type == 'plugins':
                                results['plugins'] = data
                            elif scan_type == 'themes':
                                results['themes'] = data
                            elif scan_type == 'files':
                                results['sensitive_files'] = data
                            elif scan_type == 'directories':
                                results['directory_listings'] = data
                            elif scan_type == 'vulns':
                                results['vulnerabilities'] = data
                            elif scan_type == 'cves':
                                results['cves'] = data
                            elif scan_type == 'config':
                                results['config_issues'] = data
                        except Exception as e:
                            if self.logger:
                                self.logger.debug(f"Scan {scan_type} failed: {e}")
                
                # Collect issues
                self._collect_issues(results)
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            return results
    
    def _aggressive_user_enumeration(self, url):
        """Aggressive user enumeration with multiple techniques"""
        users = []
        
        # Technique 1: REST API enumeration
        for endpoint in self.user_endpoints:
            try:
                response = self.session.get(
                    urljoin(url, endpoint),
                    timeout=self.timeout,
                    allow_redirects=False
                )
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            for user in data:
                                user_info = {
                                    'id': user.get('id'),
                                    'name': user.get('name'),
                                    'username': user.get('slug'),
                                    'email': user.get('email', ''),
                                    'url': user.get('link', ''),
                                    'description': user.get('description', ''),
                                    'method': 'rest_api'
                                }
                                if user_info not in users:
                                    users.append(user_info)
                        elif isinstance(data, dict):
                            user_info = {
                                'id': data.get('id'),
                                'name': data.get('name'),
                                'username': data.get('slug'),
                                'method': 'rest_api_single'
                            }
                            if user_info not in users:
                                users.append(user_info)
                    except:
                        pass  # Not JSON
            except:
                continue
        
        # Technique 2: Author ID enumeration (1-50)
        for author_id in range(1, 51):
            try:
                author_url = f"{url}/?author={author_id}"
                response = self.session.get(
                    author_url,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                if response.status_code in [301, 302]:
                    location = response.headers.get('location', '')
                    if 'author' in location.lower():
                        username = location.split('/author/')[-1].strip('/')
                        user_info = {
                            'id': author_id,
                            'username': username,
                            'method': 'author_pages'
                        }
                        if user_info not in users:
                            users.append(user_info)
            except:
                continue
        
        # Technique 3: Check feeds
        feed_urls = [f"{url}/feed/", f"{url}/?feed=rss2", f"{url}/comments/feed/"]
        for feed_url in feed_urls:
            try:
                response = self.session.get(feed_url, timeout=self.timeout)
                if response.status_code == 200:
                    # Extract usernames from feed
                    content = response.text
                    # Look for author tags in RSS
                    authors = re.findall(r'<dc:creator>([^<]+)</dc:creator>', content, re.IGNORECASE)
                    authors += re.findall(r'<author>([^<]+)</author>', content, re.IGNORECASE)
                    for author in set(authors):
                        user_info = {
                            'username': author.strip(),
                            'method': 'feed'
                        }
                        if user_info not in users:
                            users.append(user_info)
            except:
                continue
        
        return users
    
    def _deep_plugin_scan(self, url):
        """Deep plugin scanning with version detection"""
        # Extended plugin list (150+ common plugins)
        common_plugins = [
            'akismet', 'contact-form-7', 'yoast-seo', 'elementor', 'woocommerce',
            'jetpack', 'wordfence', 'all-in-one-seo-pack', 'google-site-kit',
            'wpforms', 'really-simple-ssl', 'litespeed-cache', 'updraftplus',
            'advanced-custom-fields', 'gravityforms', 'ninja-forms', 'wp-rocket',
            'imagify', 'sucuri-scanner', 'wp-super-cache', 'w3-total-cache',
            'duplicator', 'redirection', 'broken-link-checker', 'wp-mail-smtp',
            'better-wp-security', 'backwpup', 'wp-optimize', 'seo-by-rank-math',
            'wp-file-manager', 'tablepress', 'cookie-notice', 'complianz'
        ]
        
        found_plugins = []
        
        # Check each plugin
        for plugin in common_plugins:
            plugin_url = urljoin(url, f'/wp-content/plugins/{plugin}/')
            try:
                response = self.session.head(plugin_url, timeout=10)
                if response.status_code in [200, 403, 301, 302]:
                    plugin_info = {
                        'name': plugin,
                        'url': plugin_url,
                        'status': 'detected',
                        'version': 'unknown',
                        'vulnerable': False
                    }
                    
                    # Try to get version from readme.txt
                    readme_url = urljoin(url, f'/wp-content/plugins/{plugin}/readme.txt')
                    try:
                        readme_response = self.session.get(readme_url, timeout=10)
                        if readme_response.status_code == 200:
                            content = readme_response.text
                            version_match = re.search(r'Stable tag:\s*([\d.]+)', content, re.IGNORECASE)
                            if version_match:
                                plugin_info['version'] = version_match.group(1).strip()
                    except:
                        pass
                    
                    found_plugins.append(plugin_info)
            except:
                continue
        
        return found_plugins
    
    def _deep_theme_scan(self, url):
        """Deep theme scanning"""
        themes = []
        
        # Common themes to check
        common_themes = [
            'twentytwentyfour', 'twentytwentythree', 'twentytwentytwo',
            'twentytwentyone', 'twentytwenty', 'twentynineteen',
            'twentyseventeen', 'twentysixteen', 'twentyfifteen',
            'astra', 'generatepress', 'oceanwp', 'neve', 'hello-elementor',
            'kadence', 'blocksy', 'storefront'
        ]
        
        for theme in common_themes:
            theme_url = urljoin(url, f'/wp-content/themes/{theme}/style.css')
            try:
                response = self.session.head(theme_url, timeout=10)
                if response.status_code == 200:
                    theme_info = {
                        'name': theme,
                        'url': theme_url,
                        'status': 'detected',
                        'version': 'unknown'
                    }
                    
                    # Get theme info
                    try:
                        style_response = self.session.get(theme_url, timeout=10)
                        if style_response.status_code == 200:
                            content = style_response.text
                            # Extract theme info
                            name_match = re.search(r'Theme Name:\s*(.+)', content, re.IGNORECASE)
                            version_match = re.search(r'Version:\s*(.+)', content, re.IGNORECASE)
                            if name_match:
                                theme_info['full_name'] = name_match.group(1).strip()
                            if version_match:
                                theme_info['version'] = version_match.group(1).strip()
                    except:
                        pass
                    
                    themes.append(theme_info)
            except:
                continue
        
        return themes
    
    def _scan_sensitive_files(self, url):
        """Scan for sensitive files"""
        found_files = []
        
        for file_path in self.sensitive_files:
            file_url = urljoin(url, file_path)
            try:
                response = self.session.head(file_url, timeout=10)
                if response.status_code == 200:
                    found_files.append({
                        'path': file_path,
                        'url': file_url,
                        'status_code': response.status_code,
                        'critical': self._is_critical_file(file_path)
                    })
            except:
                continue
        
        return found_files
    
    def _check_directory_listing(self, url):
        """Check for directory listing vulnerabilities"""
        directories = [
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-includes/',
            '/wp-admin/',
            '/'
        ]
        
        listings = []
        
        for directory in directories:
            dir_url = urljoin(url, directory)
            try:
                response = self.session.get(dir_url, timeout=10)
                if response.status_code == 200 and 'Index of' in response.text:
                    listings.append({
                        'directory': directory,
                        'url': dir_url,
                        'vulnerable': True
                    })
            except:
                continue
        
        return listings
    
    def _check_vulnerabilities(self, url):
        """Check for known vulnerabilities"""
        vulns = []
        
        # Check for common vulnerabilities
        # 1. User enumeration (already checked)
        # 2. XML-RPC
        xmlrpc_url = urljoin(url, '/xmlrpc.php')
        try:
            response = self.session.head(xmlrpc_url, timeout=10)
            if response.status_code == 200:
                vulns.append({
                    'type': 'xmlrpc_enabled',
                    'severity': 'medium',
                    'description': 'XML-RPC is enabled (can be used for brute force attacks)',
                    'solution': 'Disable XML-RPC if not needed'
                })
        except:
            pass
        
        # 3. Readme.html exposure
        readme_url = urljoin(url, '/readme.html')
        try:
            response = self.session.head(readme_url, timeout=10)
            if response.status_code == 200:
                vulns.append({
                    'type': 'readme_exposed',
                    'severity': 'low',
                    'description': 'readme.html file is publicly accessible',
                    'solution': 'Remove or restrict access to readme.html'
                })
        except:
            pass
        
        # 4. Debug mode
        debug_url = urljoin(url, '/wp-content/debug.log')
        try:
            response = self.session.head(debug_url, timeout=10)
            if response.status_code == 200:
                vulns.append({
                    'type': 'debug_log_exposed',
                    'severity': 'high',
                    'description': 'debug.log file is publicly accessible',
                    'solution': 'Delete debug.log and disable debug mode'
                })
        except:
            pass
        
        return vulns
    
    def _check_cves(self, url):
        """Check for known CVEs (simplified version)"""
        cves = []
        
        # Get WordPress version
        version = self._get_wordpress_version(url)
        if version:
            # Check for known version-specific CVEs
            known_cves = {
                '5.0': ['CVE-2019-9787', 'CVE-2019-17671'],
                '4.9': ['CVE-2018-12895', 'CVE-2018-20148'],
                '4.7': ['CVE-2017-6814', 'CVE-2017-6817'],
                '4.6': ['CVE-2017-9061', 'CVE-2017-9062'],
                '5.7': ['CVE-2021-29447', 'CVE-2021-29500'],
                '5.8': ['CVE-2021-39201', 'CVE-2021-39200']
            }
            
            major_version = version.split('.')[0] + '.' + version.split('.')[1]
            if major_version in known_cves:
                for cve in known_cves[major_version]:
                    cves.append({
                        'cve_id': cve,
                        'affected_version': version,
                        'severity': 'high',
                        'description': f'Known vulnerability in WordPress {version}',
                        'reference': f'https://nvd.nist.gov/vuln/detail/{cve}'
                    })
        
        return cves
    
    def _scan_configuration(self, url):
        """Scan for configuration issues"""
        issues = []
        
        # Check wp-config.php
        wpconfig_url = urljoin(url, '/wp-config.php')
        try:
            response = self.session.head(wpconfig_url, timeout=10)
            if response.status_code == 200:
                issues.append('wp-config.php is publicly accessible')
        except:
            pass
        
        # Check for exposed database credentials (simplified)
        try:
            response = self.session.get(url, timeout=10)
            content = response.text.lower()
            if 'db_name' in content or 'db_user' in content or 'db_password' in content:
                issues.append('Database credentials might be exposed')
        except:
            pass
        
        return issues
    
    def _get_wordpress_version(self, url):
        """Extract WordPress version"""
        try:
            response = self.session.get(url, timeout=10)
            content = response.text
            
            # Check meta generator tag
            version_match = re.search(r'content="WordPress ([\d.]+)"', content, re.IGNORECASE)
            if version_match:
                return version_match.group(1)
            
            # Check readme.html
            readme_url = urljoin(url, '/readme.html')
            readme_response = self.session.get(readme_url, timeout=10)
            if readme_response.status_code == 200:
                version_match = re.search(r'Version\s*([\d.]+)', readme_response.text)
                if version_match:
                    return version_match.group(1)
            
            # Check feed
            feed_url = urljoin(url, '/feed/')
            feed_response = self.session.get(feed_url, timeout=10)
            if feed_response.status_code == 200:
                version_match = re.search(r'wordpress.org/\?v=([\d.]+)', feed_response.text)
                if version_match:
                    return version_match.group(1)
            
        except:
            pass
        
        return None
    
    def _is_wordpress(self, url):
        """Check if site is WordPress"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Check for WordPress indicators
            indicators = [
                'wp-content', 'wp-includes', 'wordpress', '/wp-json/',
                'wp-embed.min.js', 'wp-admin', 'wp-login.php'
            ]
            
            content = response.text.lower()
            return any(indicator in content for indicator in indicators)
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"WordPress check failed: {e}")
            return False
    
    def _is_critical_file(self, file_path):
        """Check if file is critical"""
        critical_files = ['wp-config.php', 'debug.log', 'wp-config.php.bak']
        return any(critical in file_path for critical in critical_files)
    
    def _collect_issues(self, results):
        """Collect all issues from scan results"""
        issues = []
        
        if results.get('users_exposed'):
            issues.append(f"User enumeration vulnerability ({len(results.get('users', []))} users exposed)")
        
        if results.get('sensitive_files'):
            critical_files = [f for f in results['sensitive_files'] if f.get('critical')]
            if critical_files:
                issues.append(f"Critical files exposed ({len(critical_files)} files)")
        
        if results.get('directory_listings'):
            issues.append(f"Directory listing enabled ({len(results['directory_listings'])} directories)")
        
        if results.get('vulnerabilities'):
            issues.extend([v['description'] for v in results['vulnerabilities']])
        
        if results.get('cves'):
            issues.append(f"Known CVEs detected ({len(results['cves'])} CVEs)")
        
        results['issues'] = list(set(issues))  # Remove duplicates
    
    def scan_subdomains(self, domain, subdomain_file=None):
        """Scan subdomains from file or generate common ones"""
        subdomains = []
        
        if subdomain_file:
            # Read subdomains from file
            try:
                with open(subdomain_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            except:
                print(f"[!] Could not read subdomain file: {subdomain_file}")
                return []
        else:
            # Generate common subdomains
            common_subs = [
                'www', 'mail', 'ftp', 'admin', 'blog', 'test', 'dev',
                'staging', 'secure', 'api', 'app', 'web', 'portal',
                'cpanel', 'whm', 'webmail', 'server', 'ns1', 'ns2',
                'smtp', 'pop', 'imap', 'git', 'm', 'mobile', 'static'
            ]
            subdomains = [f"{sub}.{domain}" for sub in common_subs]
        
        # Scan each subdomain
        results = []
        print(f"[*] Scanning {len(subdomains)} subdomains...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_subdomain, sub): sub for sub in subdomains}
            
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    is_live, url = future.result()
                    if is_live:
                        print(f"[+] Subdomain alive: {url}")
                        results.append({
                            'subdomain': subdomain,
                            'url': url,
                            'alive': True
                        })
                except:
                    pass
        
        return results
    
    def _check_subdomain(self, subdomain):
        """Check if subdomain is alive"""
        for protocol in ['https://', 'http://']:
            url = f"{protocol}{subdomain}"
            try:
                response = self.session.head(url, timeout=5, allow_redirects=True)
                if response.status_code < 400:
                    return True, url
            except:
                continue
        
        return False, None
    
    def quick_scan(self, url):
        """Quick scan for backward compatibility"""
        return self.aggressive_scan(url)
