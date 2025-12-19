"""
WordPress Security Scanner Module
Core scanning functionality
"""

import requests
from urllib.parse import urljoin
import time

class WordPressScanner:
    """Main scanner class for WordPress security checks"""
    
    def __init__(self, config=None, logger=None):
        self.config = config or {}
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.get('scanning', {}).get('user_agent', 'Mozilla/5.0 WP-SEC-AUDIT/3.0')
        })
        self.session.verify = self.config.get('scanning', {}).get('verify_ssl', False)
        self.timeout = self.config.get('scanning', {}).get('timeout', 30)
    
    def check_site(self, url):
        """Basic WordPress site check"""
        results = {
            'url': url,
            'wordpress': False,
            'users_exposed': False,
            'plugins': [],
            'themes': [],
            'issues': [],
            'vulnerabilities': [],
            'config_issues': [],
            'timestamp': time.time()
        }
        
        try:
            # Check if it's a WordPress site
            if self._is_wordpress(url):
                results['wordpress'] = True
                
                # Check for user enumeration
                users = self._enumerate_users(url)
                if users:
                    results['users_exposed'] = True
                    results['users'] = users
                    results['issues'].append(f'Found {len(users)} exposed users')
                
                # Check for plugins
                plugins = self._check_common_plugins(url)
                if plugins:
                    results['plugins'] = plugins
                
                # Check for themes
                themes = self._check_themes(url)
                if themes:
                    results['themes'] = themes
                
                # Check wp-config
                if self._check_wpconfig(url):
                    results['config_issues'].append('wp-config.php might be accessible')
                    results['issues'].append('wp-config.php exposure')
                
                # Check XML-RPC
                if self._check_xmlrpc(url):
                    results['issues'].append('XML-RPC enabled')
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            return results
    
    def _is_wordpress(self, url):
        """Check if site is WordPress"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Check for WordPress indicators
            indicators = [
                'wp-content',
                'wp-includes', 
                'wordpress',
                '/wp-json/',
                'wp-embed.min.js'
            ]
            
            content = response.text.lower()
            return any(indicator in content for indicator in indicators)
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"WordPress check failed: {e}")
            return False
    
    def _enumerate_users(self, url):
        """Check for user enumeration vulnerability"""
        endpoints = [
            '/wp-json/wp/v2/users',
            '/?rest_route=/wp/v2/users',
            '/wp-json/wp/v2/users/1',
            '/wp-json/wp/v2/users?per_page=100'
        ]
        
        users = []
        
        for endpoint in endpoints:
            try:
                response = self.session.get(
                    urljoin(url, endpoint),
                    timeout=self.timeout
                )
                if response.status_code == 200:
                    # Try to parse JSON
                    import json
                    data = response.json()
                    if isinstance(data, list):
                        for user in data:
                            users.append({
                                'id': user.get('id'),
                                'name': user.get('name'),
                                'username': user.get('slug'),
                                'url': user.get('link')
                            })
                    elif isinstance(data, dict):
                        users.append({
                            'id': data.get('id'),
                            'name': data.get('name'),
                            'username': data.get('slug')
                        })
                    break  # Found users, no need to check other endpoints
            except:
                continue
        
        return users
    
    def _check_common_plugins(self, url):
        """Check for common plugins"""
        common_plugins = [
            'akismet',
            'contact-form-7', 
            'yoast-seo',
            'elementor',
            'woocommerce',
            'jetpack',
            'wordfence',
            'all-in-one-seo-pack'
        ]
        
        found_plugins = []
        
        for plugin in common_plugins:
            plugin_url = urljoin(url, f'/wp-content/plugins/{plugin}/')
            try:
                response = self.session.head(plugin_url, timeout=10)
                if response.status_code in [200, 403, 301, 302]:
                    found_plugins.append({
                        'name': plugin,
                        'url': plugin_url,
                        'status': 'detected'
                    })
            except:
                continue
        
        return found_plugins
    
    def _check_themes(self, url):
        """Check for themes"""
        themes = []
        
        # Check for common themes
        common_themes = ['twentytwentyfour', 'twentytwentythree', 'astra', 'generatepress']
        
        for theme in common_themes:
            theme_url = urljoin(url, f'/wp-content/themes/{theme}/style.css')
            try:
                response = self.session.head(theme_url, timeout=10)
                if response.status_code == 200:
                    themes.append({
                        'name': theme,
                        'url': theme_url,
                        'status': 'detected'
                    })
            except:
                continue
        
        return themes
    
    def _check_wpconfig(self, url):
        """Check if wp-config.php is accessible"""
        wpconfig_url = urljoin(url, '/wp-config.php')
        try:
            response = self.session.head(wpconfig_url, timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def _check_xmlrpc(self, url):
        """Check if XML-RPC is enabled"""
        xmlrpc_url = urljoin(url, '/xmlrpc.php')
        try:
            response = self.session.head(xmlrpc_url, timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def quick_scan(self, url):
        """Perform quick security scan"""
        print(f"[*] Starting quick scan for: {url}")
        
        results = self.check_site(url)
        
        # Print results
        if results.get('wordpress'):
            print("[+] WordPress site detected")
            
            if results.get('users_exposed'):
                users = results.get('users', [])
                print(f"[-] VULNERABILITY: Found {len(users)} exposed users!")
                for user in users[:5]:  # Show first 5 users
                    print(f"    • {user.get('name')} (ID: {user.get('id')})")
            else:
                print("[+] User enumeration appears blocked")
            
            plugins = results.get('plugins', [])
            if plugins:
                print(f"[+] Found {len(plugins)} plugins:")
                for plugin in plugins[:5]:  # Show first 5 plugins
                    print(f"    • {plugin['name']}")
            
            issues = results.get('issues', [])
            if issues:
                print(f"[!] Security issues found:")
                for issue in issues:
                    print(f"    • {issue}")
            else:
                print("[+] No critical security issues found")
        else:
            print("[-] Not a WordPress site or inaccessible")
        
        return results
