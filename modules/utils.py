"""
Utility Functions for WP-SEC-AUDIT
Complete version with all required functions including subdomain generation
"""

import yaml
import os
import sys
import importlib.util
from colorama import Fore, Style
from datetime import datetime
import re

def load_config(config_path=None):
    """Load configuration from YAML file"""
    default_config = {
        'scanning': {
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WP-SEC-AUDIT/3.0',
            'timeout': 30,
            'threads': 10,
            'retries': 3,
            'verify_ssl': False
        },
        'output': {
            'save_reports': True,
            'report_dir': '~/Desktop/WP-SEC-AUDIT-Results',
            'formats': ['html', 'json', 'text', 'md'],
            'auto_open': False
        },
        'logging': {
            'level': 'INFO',
            'file': 'wp_sec_audit.log',
            'console': True
        },
        'advanced': {
            'aggressive_mode': False,
            'max_subdomains': 100,
            'cve_check': True,
            'directory_enum': True
        }
    }
    
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f) or {}
                # Deep merge configuration
                return _merge_dicts(default_config, user_config)
        except Exception as e:
            print_error(f"Error loading config: {e}")
            return default_config
    
    return default_config

def _merge_dicts(dict1, dict2):
    """Recursively merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_dicts(result[key], value)
        else:
            result[key] = value
    return result

def validate_url(url):
    """Validate and format URL"""
    if not url or not isinstance(url, str):
        return None
    
    url = url.strip()
    
    # Remove any quotes
    url = url.strip('"\'')
    
    # Add https:// if no protocol specified
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Remove trailing slash
    url = url.rstrip('/')
    
    return url

def print_banner():
    """Print tool banner"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔════════════════════════════════════════════════════════════════╗
║                WP-SEC-AUDIT v1.2.0                             ║
║           Enterprise WordPress Security Scanner                ║
║         Aggressive Edition with Subdomain Scanning             ║
╚════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def print_result(message, level="info"):
    """Print colored result messages"""
    colors = {
        "success": Fore.GREEN + Style.BRIGHT,
        "error": Fore.RED + Style.BRIGHT,
        "warning": Fore.YELLOW + Style.BRIGHT,
        "info": Fore.CYAN,
        "debug": Fore.MAGENTA
    }
    
    prefix = {
        "success": "[+]",
        "error": "[-]",
        "warning": "[!]",
        "info": "[*]",
        "debug": "[DEBUG]"
    }
    
    color = colors.get(level, Fore.WHITE)
    prefix_text = prefix.get(level, "[*]")
    
    print(f"{color}{prefix_text} {message}{Style.RESET_ALL}")

def print_error(message):
    """Print error message"""
    print_result(message, "error")

def print_success(message):
    """Print success message"""
    print_result(message, "success")

def print_info(message):
    """Print info message"""
    print_result(message, "info")

def print_warning(message):
    """Print warning message"""
    print_result(message, "warning")

def create_directories():
    """Create necessary directories"""
    try:
        # Create report directory on Desktop
        desktop = os.path.expanduser("~/Desktop")
        report_dir = os.path.join(desktop, "WP-SEC-AUDIT-Results")
        
        os.makedirs(report_dir, exist_ok=True)
        
        # Create subdirectories
        subdirs = ['reports', 'scans', 'subdomains', 'wordlists']
        for subdir in subdirs:
            os.makedirs(os.path.join(report_dir, subdir), exist_ok=True)
        
        return report_dir
        
    except Exception as e:
        print_error(f"Failed to create directories: {e}")
        return None

def check_dependencies():
    """Check if required packages are installed"""
    required = [
        ('requests', 'requests'),
        ('colorama', 'colorama'),
        ('yaml', 'pyyaml'),
        ('bs4', 'beautifulsoup4'),
        ('urllib3', 'urllib3')
    ]
    
    missing = []
    
    for import_name, package_name in required:
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(package_name)
    
    if missing:
        print_error(f"Missing required packages: {', '.join(missing)}")
        print_info("Install with: pip install " + " ".join(missing))
        return False
    
    return True

def ensure_config_exists():
    """Ensure configuration file exists"""
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'settings.yaml')
    
    if not os.path.exists(config_path):
        print_warning("Configuration file not found. Creating default...")
        
        # Create config directory if it doesn't exist
        config_dir = os.path.dirname(config_path)
        os.makedirs(config_dir, exist_ok=True)
        
        # Create default config
        default_config = """# WP-SEC-AUDIT Configuration

scanning:
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WP-SEC-AUDIT/3.0"
  timeout: 30
  threads: 10
  retries: 3
  verify_ssl: false

output:
  save_reports: true
  report_dir: "~/Desktop/WP-SEC-AUDIT-Results"
  formats: ["html", "json", "text", "md"]
  auto_open: false

logging:
  level: "INFO"
  console: true

advanced:
  aggressive_mode: false
  max_subdomains: 100
  cve_check: true
  directory_enum: true
"""
        
        try:
            with open(config_path, 'w') as f:
                f.write(default_config)
            print_success(f"Created default configuration at: {config_path}")
        except Exception as e:
            print_error(f"Failed to create config file: {e}")
    
    return config_path

def get_timestamp():
    """Get current timestamp for filenames"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def get_readable_timestamp():
    """Get human-readable timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sanitize_filename(filename):
    """Sanitize string for use as filename"""
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Replace spaces and dots
    filename = filename.replace(' ', '_').replace('.', '_')
    
    # Remove multiple underscores
    filename = re.sub(r'_+', '_', filename)
    
    # Limit length
    if len(filename) > 100:
        filename = filename[:100]
    
    return filename

def generate_subdomain_list(domain, output_file=None):
    """Generate common subdomains list"""
    if not output_file:
        output_file = f"subdomains_{sanitize_filename(domain)}.txt"
    
    common_subdomains = [
        'www', 'mail', 'ftp', 'admin', 'blog', 'test', 'dev', 'staging',
        'secure', 'api', 'app', 'web', 'portal', 'cpanel', 'whm', 'webmail',
        'server', 'ns1', 'ns2', 'smtp', 'pop', 'imap', 'git', 'm', 'mobile',
        'static', 'cdn', 'media', 'images', 'img', 'video', 'videos',
        'download', 'uploads', 'files', 'docs', 'wiki', 'forum', 'forums',
        'shop', 'store', 'payment', 'billing', 'account', 'accounts',
        'login', 'signin', 'signup', 'register', 'dashboard', 'panel',
        'support', 'help', 'status', 'monitor', 'analytics', 'stats',
        'news', 'blog', 'blogs', 'newsletter', 'feed', 'rss', 'atom',
        'search', 'find', 'discover', 'explore', 'directory', 'list',
        'map', 'location', 'geo', 'weather', 'time', 'clock', 'calendar',
        'events', 'event', 'meet', 'meeting', 'conference', 'webinar',
        'chat', 'messenger', 'message', 'mail', 'email', 'sms', 'mms',
        'voice', 'call', 'phone', 'fax', 'contact', 'contacts', 'address',
        'office', 'branch', 'location', 'site', 'sites', 'node', 'nodes',
        'alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta',
        'prod', 'production', 'live', 'demo', 'sandbox', 'play', 'playground',
        'assets', 'static', 'media', 'uploads', 'images', 'img', 'pics',
        'photos', 'gallery', 'album', 'music', 'audio', 'podcast', 'radio',
        'tv', 'video', 'stream', 'live', 'broadcast', 'onair', 'studio',
        'code', 'source', 'git', 'svn', 'hg', 'repo', 'repository', 'version',
        'build', 'ci', 'cd', 'jenkins', 'travis', 'circle', 'gitlab',
        'github', 'bitbucket', 'docker', 'kubernetes', 'k8s', 'helm',
        'swarm', 'mesos', 'nomad', 'consul', 'vault', 'terraform', 'packer',
        'ansible', 'puppet', 'chef', 'salt', 'vagrant', 'virtualbox', 'vmware'
    ]
    
    # Remove duplicates and sort
    common_subdomains = sorted(set(common_subdomains))
    
    # Generate full subdomains
    subdomains = [f"{sub}.{domain}" for sub in common_subdomains]
    
    # Also add domain itself
    subdomains.insert(0, domain)
    
    try:
        with open(output_file, 'w') as f:
            f.write('\n'.join(subdomains))
        
        print_success(f"Generated {len(subdomains)} subdomains in {output_file}")
        return output_file
    except Exception as e:
        print_error(f"Failed to generate subdomain list: {e}")
        return None

def read_file_lines(file_path):
    """Read lines from a file, ignoring comments and empty lines"""
    try:
        with open(file_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        return lines
    except Exception as e:
        print_error(f"Error reading file {file_path}: {e}")
        return []

def write_file_lines(file_path, lines):
    """Write lines to a file"""
    try:
        with open(file_path, 'w') as f:
            f.write('\n'.join(lines))
        return True
    except Exception as e:
        print_error(f"Error writing to file {file_path}: {e}")
        return False

def extract_domain(url):
    """Extract domain from URL"""
    try:
        # Remove protocol
        if '://' in url:
            url = url.split('://')[1]
        
        # Remove path
        if '/' in url:
            url = url.split('/')[0]
        
        # Remove port
        if ':' in url:
            url = url.split(':')[0]
        
        return url
    except:
        return url

def is_valid_domain(domain):
    """Check if a string is a valid domain"""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """Display progress bar"""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    # Print New Line on Complete
    if iteration == total: 
        print()

def print_table(headers, rows, max_width=80):
    """Print data in table format"""
    if not rows:
        return
    
    # Calculate column widths
    col_widths = []
    for i in range(len(headers)):
        col_data = [str(row[i]) for row in rows]
        col_width = max(len(headers[i]), max([len(d) for d in col_data]))
        col_width = min(col_width, max_width // len(headers))
        col_widths.append(col_width)
    
    # Print headers
    header_line = ""
    for i, header in enumerate(headers):
        header_line += f"{header:<{col_widths[i]}} | "
    print(Fore.CYAN + header_line + Style.RESET_ALL)
    print("-" * (sum(col_widths) + len(headers) * 3))
    
    # Print rows
    for row in rows:
        row_line = ""
        for i, cell in enumerate(row):
            cell_str = str(cell)
            if len(cell_str) > col_widths[i]:
                cell_str = cell_str[:col_widths[i]-3] + "..."
            row_line += f"{cell_str:<{col_widths[i]}} | "
        print(row_line)
    
    print()

def check_internet_connection():
    """Check if internet connection is available"""
    import socket
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=5)
        return True
    except OSError:
        return False

def get_file_size(file_path):
    """Get file size in human readable format"""
    size = os.path.getsize(file_path)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"

def create_backup(file_path):
    """Create backup of a file"""
    if os.path.exists(file_path):
        backup_path = f"{file_path}.backup_{get_timestamp()}"
        try:
            import shutil
            shutil.copy2(file_path, backup_path)
            print_success(f"Created backup: {backup_path}")
            return backup_path
        except Exception as e:
            print_error(f"Failed to create backup: {e}")
    return None

def cleanup_old_files(directory, days=7):
    """Cleanup files older than specified days"""
    import time
    current_time = time.time()
    cutoff = current_time - (days * 24 * 60 * 60)
    
    try:
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path):
                file_time = os.path.getmtime(file_path)
                if file_time < cutoff:
                    os.remove(file_path)
                    print_info(f"Removed old file: {filename}")
    except Exception as e:
        print_error(f"Cleanup failed: {e}")
