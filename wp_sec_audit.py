#!/usr/bin/env python3
"""
WP-SEC-AUDIT: WordPress Security Auditor
Main entry point
"""

import sys
import argparse
from colorama import init

# Import our modules
from modules.scanner import WordPressScanner
from modules.reporter import ReportGenerator
from modules.utils import (
    load_config, validate_url, print_banner,
    print_result, create_directories, check_dependencies,
    print_error, print_success, print_info, ensure_config_exists,
    get_timestamp, sanitize_filename
)

init(autoreset=True)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="WP-SEC-AUDIT: Professional WordPress Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Interactive mode
  %(prog)s -t https://example.com   # Quick scan
  %(prog)s -o html                  # Output HTML report
  %(prog)s -b targets.txt           # Batch scan
        """
    )
    
    parser.add_argument('-t', '--target', help='Target URL to scan')
    parser.add_argument('-o', '--output', choices=['text', 'json', 'html'],
                       default='text', help='Output format (default: text)')
    parser.add_argument('-b', '--batch', help='File with list of targets (one per line)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--version', action='version',
                       version='WP-SEC-AUDIT v1.0.0')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        return 1
    
    # Create directories
    report_dir = create_directories()
    if report_dir:
        print_info(f"Reports will be saved to: {report_dir}")
    
    # Ensure config exists
    config_path = ensure_config_exists()
    config = load_config(config_path)
    
    if args.target:
        # Single target scan
        target = validate_url(args.target)
        if not target:
            print_error("Invalid URL format")
            return 1
        
        perform_scan(target, config, args.output)
        
    elif args.batch:
        # Batch scan
        print_info(f"Batch scanning from: {args.batch}")
        try:
            with open(args.batch, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            for i, target in enumerate(targets, 1):
                if target and not target.startswith('#'):
                    target = validate_url(target)
                    if target:
                        print_info(f"[{i}/{len(targets)}] Scanning: {target}")
                        perform_scan(target, config, args.output)
        
        except FileNotFoundError:
            print_error(f"File not found: {args.batch}")
            return 1
            
    else:
        # Interactive mode
        print_info("Interactive mode selected")
        print_info("Please enter target URL or use command line options")
        print("\n" + parser.format_help())
    
    return 0

def perform_scan(target, config, output_format):
    """Perform scan on single target"""
    print_info(f"Starting scan for: {target}")
    
    # Initialize scanner and perform scan
    scanner = WordPressScanner(config)
    results = scanner.quick_scan(target)
    
    # Generate report
    reporter = ReportGenerator(config)
    report = reporter.generate_report(results, output_format)
    
    # Save report
    if config['output'].get('save_reports', True):
        timestamp = get_timestamp()
        target_name = target.replace('https://', '').replace('http://', '')
        target_name = sanitize_filename(target_name)
        filename = f"scan_{target_name}_{timestamp}"
        
        filepath = reporter.save_report(report, filename, output_format)
        print_success(f"Report saved to: {filepath}")
    
    # Print report to console if text format
    if output_format == 'text':
        print("\n" + report)
    
    return results

if __name__ == "__main__":
    sys.exit(main())
