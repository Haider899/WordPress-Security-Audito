import os
import sys
import yaml
import logging
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
import time


class ConfigManager:
    """Manage tool configuration"""
    
    def __init__(self, config_path: str = "config/settings.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        default_config = {
            'scanning': {
                'user_agent': 'WP-SEC-AUDIT/3.0',
                'timeout': 30,
                'threads': 10,
                'retries': 3,
                'verify_ssl': False
            },
            'output': {
                'save_reports': True,
                'report_dir': str(Path.home() / "Desktop" / "WP-SEC-AUDIT-Results"),
                'formats': ['json', 'html', 'md']
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    # Merge with defaults
                    return self._merge_dicts(default_config, loaded_config)
            except Exception as e:
                print(f"Error loading config: {e}, using defaults")
        
        return default_config
    
    def _merge_dicts(self, dict1: Dict, dict2: Dict) -> Dict:
        """Recursively merge two dictionaries"""
        result = dict1.copy()
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_dicts(result[key], value)
            else:
                result[key] = value
        return result
    
    def save_config(self):
        """Save configuration to file"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)


class Logger:
    """Custom logger with colors"""
    
    def __init__(self, level: str = "INFO"):
        self.logger = logging.getLogger("WP-SEC-AUDIT")
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Console handler with colors
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, level.upper()))
        
        # Color formatter
        class ColorFormatter(logging.Formatter):
            """Custom formatter with colors"""
            COLORS = {
                'DEBUG': '\033[36m',  # Cyan
                'INFO': '\033[32m',   # Green
                'WARNING': '\033[33m', # Yellow
                'ERROR': '\033[31m',   # Red
                'CRITICAL': '\033[41m' # Red background
            }
            RESET = '\033[0m'
            
            def format(self, record):
                color = self.COLORS.get(record.levelname, self.RESET)
                record.msg = f"{color}{record.msg}{self.RESET}"
                return super().format(record)
        
        formatter = ColorFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(console_handler)
    
    def debug(self, msg):
        self.logger.debug(msg)
    
    def info(self, msg):
        self.logger.info(msg)
    
    def warning(self, msg):
        self.logger.warning(msg)
    
    def error(self, msg):
        self.logger.error(msg)
    
    def critical(self, msg):
        self.logger.critical(msg)


class ProgressBar:
    """Progress bar for long operations"""
    
    def __init__(self, total: int = 100, desc: str = "Processing"):
        self.total = total
        self.desc = desc
        self.current = 0
        self.start_time = None
        self.bar_length = 40
    
    def __enter__(self):
        self.start_time = time.time()
        self.update(0, "Starting...")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.time() - self.start_time
        print(f"\n✅ Completed in {elapsed:.1f}s")
    
    def update(self, progress: int, status: str = ""):
        """Update progress bar"""
        self.current = progress
        percent = self.current / self.total
        filled_length = int(self.bar_length * percent)
        bar = '█' * filled_length + '░' * (self.bar_length - filled_length)
        
        elapsed = time.time() - self.start_time
        if percent > 0:
            eta = (elapsed / percent) - elapsed
            eta_str = f"ETA: {eta:.0f}s"
        else:
            eta_str = ""
        
        sys.stdout.write(f"\r{self.desc}: [{bar}] {percent*100:.1f}% {status} {eta_str}")
        sys.stdout.flush()


def check_dependencies():
    """Check if required dependencies are installed"""
    required = ['requests', 'colorama', 'beautifulsoup4', 'pyyaml']
    missing = []
    
    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"Missing dependencies: {', '.join(missing)}")
        print("Install with: pip install " + " ".join(missing))
        sys.exit(1)


def get_wordlists_dir() -> Path:
    """Get wordlists directory path"""
    wordlists_dir = Path(__file__).parent.parent / "wordlists"
    wordlists_dir.mkdir(exist_ok=True)
    return wordlists_dir


def ensure_directories():
    """Ensure all required directories exist"""
    directories = [
        Path.home() / "Desktop" / "WP-SEC-AUDIT-Results",
        Path("config"),
        Path("wordlists"),
        Path("logs")
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
