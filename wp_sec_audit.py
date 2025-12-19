#!/usr/bin/env python3
"""
WP-SEC-AUDIT: Advanced WordPress Security Auditor
Enterprise-grade security scanner with aggressive scanning capabilities
"""

import sys
import argparse
import warnings
import urllib3
import time
from colorama import init

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

# Import our modules
from modules.scanner import WordPressScanner
from modules.reporter import ReportGenerator
from modules.utils import (
    load_config, validate_url, print_banner,
    print_result, create_directories, check_dependencies,
    print_error, print_success, print_info, ensure_config_exists,
    get_timestamp, sanitize_filename, generate_subdomain_list
)

init(autoreset=True)

def perform_scan(target, config, output_format='text'):
    """Perform scan on single target"""
    print_info(f"Starting scan for: {target}")
    
    # Initialize scanner and perform scan
    scanner = WordPressScanner(config, logger=None)
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

def aggressive_scan(target, config, output_format='text'):
    """Perform aggressive scan"""
    print_info(f"🚀 Starting AGGRESSIVE scan for: {target}")
    print_info(f"Threads: {config['scanning'].get('threads', 10)}, Timeout: {config['scanning'].get('timeout', 30)}s")
    
    scanner = WordPressScanner(config, logger=None)
    results = scanner.aggressive_scan(target)
    
    # Display results
    display_aggressive_results(results)
    
    # Generate report
    reporter = ReportGenerator(config)
    report = reporter.generate_report(results, output_format)
    
    # Save report
    if config['output'].get('save_reports', True):
        timestamp = get_timestamp()
        target_name = target.replace('https://', '').replace('http://', '')
        target_name = sanitize_filename(target_name)
        filename = f"aggressive_scan_{target_name}_{timestamp}"
        
        filepath = reporter.save_report(report, filename, output_format)
        print_success(f"Aggressive report saved to: {filepath}")
    
    return results

def scan_subdomains(domain, config, subdomain_file=None):
    """Scan subdomains"""
    print_info(f"🌐 Scanning subdomains for: {domain}")
    
    scanner = WordPressScanner(config, logger=None)
    subdomains = scanner.scan_subdomains(domain, subdomain_file)
    
    if subdomains:
        print_success(f"Found {len([s for s in subdomains if s.get('alive')])} live subdomains:")
        for sub in subdomains:
            if sub.get('alive'):
                print(f"  • {sub.get('url')}")
        
        # Save subdomain results
        timestamp = get_timestamp()
        domain_name = domain.replace('https://', '').replace('http://', '').split('/')[0]
        filename = f"subdomains_{domain_name}_{timestamp}.txt"
        
        report_dir = create_directories()
        if report_dir:
            filepath = f"{report_dir}/{filename}"
            with open(filepath, 'w') as f:
                f.write(f"Subdomain scan for: {domain}\n")
                f.write(f"Scan time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n\n")
                for sub in subdomains:
                    status = "ALIVE" if sub.get('alive') else "DEAD"
                    f.write(f"{sub.get('subdomain')} - {status}\n")
            
            print_success(f"Subdomain results saved to: {filepath}")
        
        # Ask to scan found subdomains
        if any(sub.get('alive') for sub in subdomains):
            print("\n" + "="*50)
            choice = input("[?] Scan all LIVE subdomains? (y/n): ").lower()
            if choice == 'y':
                for sub in subdomains:
                    if sub.get('alive'):
                        print(f"\n[*] Scanning subdomain: {sub['url']}")
                        perform_scan(sub['url'], config, 'text')
    
    return subdomains

def batch_scan(file_path, config, output_format='text', aggressive=False):
    """Scan multiple targets from file"""
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print_error(f"File not found: {file_path}")
        return []
    
    print_info(f"📋 Batch scanning {len(targets)} targets")
    
    all_results = []
    for i, target in enumerate(targets, 1):
        print(f"\n[{i}/{len(targets)}] Processing: {target}")
        
        try:
            target = validate_url(target)
            if target:
                if aggressive:
                    results = aggressive_scan(target, config, output_format)
                else:
                    results = perform_scan(target, config, output_format)
                all_results.append(results)
            else:
                print_error(f"Invalid URL: {target}")
        except Exception as e:
            print_error(f"Error scanning {target}: {e}")
            continue
    
    # Generate batch summary
    if all_results:
        generate_batch_summary(all_results, file_path, config)
    
    return all_results

def generate_batch_summary(results, file_path, config):
    """Generate batch scan summary"""
    total_targets = len(results)
    wordpress_sites = sum(1 for r in results if r.get('wordpress'))
    vulnerable_sites = sum(1 for r in results if r.get('users_exposed') or r.get('vulnerabilities'))
    total_users = sum(len(r.get('users', [])) for r in results if r.get('users'))
    total_cves = sum(len(r.get('cves', [])) for r in results)
    
    summary = f"""=== BATCH SCAN SUMMARY ===
Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
Target File: {file_path}

📊 Statistics:
• Total Targets: {total_targets}
• WordPress Sites: {wordpress_sites}
• Vulnerable Sites: {vulnerable_sites}
• Total Exposed Users: {total_users}
• Total CVEs Found: {total_cves}

🔍 Critical Findings:
"""
    
    # List critical findings
    for result in results:
        if result.get('users_exposed') or result.get('cves'):
            url = result.get('url', 'Unknown')
            users = len(result.get('users', []))
            cves = len(result.get('cves', []))
            
            if users > 0 or cves > 0:
                summary += f"\n• {url}:\n"
                if users > 0:
                    summary += f"  - {users} exposed users\n"
                if cves > 0:
                    summary += f"  - {cves} CVEs found\n"
    
    summary += "\n=== END OF REPORT ===\n"
    
    # Save summary
    report_dir = create_directories()
    if report_dir:
        timestamp = get_timestamp()
        filename = f"batch_summary_{timestamp}.txt"
        filepath = f"{report_dir}/{filename}"
        
        with open(filepath, 'w') as f:
            f.write(summary)
        
        print_success(f"Batch summary saved to: {filepath}")
    
    print("\n" + summary)

def display_aggressive_results(results):
    """Display aggressive scan results"""
    print("\n" + "="*70)
    print("🔥 AGGRESSIVE SCAN RESULTS")
    print("="*70)
    
    if results.get('wordpress'):
        print(f"✅ WordPress Site: {results.get('url')}")
        
        # Users
        if results.get('users_exposed'):
            users = results.get('users', [])
            print(f"\n🚨 CRITICAL: {len(users)} USERS EXPOSED")
            for user in users[:10]:  # Show first 10 users
                print(f"  • {user.get('name', 'Unknown')} (ID: {user.get('id')}, Method: {user.get('method')})")
            if len(users) > 10:
                print(f"  ... and {len(users) - 10} more users")
        else:
            print("\n✅ User enumeration appears blocked")
        
        # CVEs
        cves = results.get('cves', [])
        if cves:
            print(f"\n💀 {len(cves)} KNOWN CVEs FOUND")
            for cve in cves[:5]:  # Show first 5 CVEs
                print(f"  • {cve['cve_id']} - {cve['description']}")
            if len(cves) > 5:
                print(f"  ... and {len(cves) - 5} more CVEs")
        
        # Vulnerabilities
        vulns = results.get('vulnerabilities', [])
        if vulns:
            print(f"\n⚠️ {len(vulns)} VULNERABILITIES")
            for vuln in vulns:
                print(f"  • {vuln['description']} ({vuln['severity'].upper()})")
        
        # Sensitive files
        files = results.get('sensitive_files', [])
        if files:
            critical = [f for f in files if f.get('critical')]
            if critical:
                print(f"\n🔓 {len(critical)} CRITICAL FILES EXPOSED")
                for file in critical[:5]:
                    print(f"  • {file['path']}")
                if len(critical) > 5:
                    print(f"  ... and {len(critical) - 5} more files")
        
        # Directory listings
        dirs = results.get('directory_listings', [])
        if dirs:
            print(f"\n📁 {len(dirs)} DIRECTORY LISTINGS ENABLED")
            for dir_listing in dirs:
                print(f"  • {dir_listing['directory']}")
        
        # Plugins & Themes
        plugins = results.get('plugins', [])
        if plugins:
            print(f"\n🔌 {len(plugins)} PLUGINS DETECTED")
            for plugin in plugins[:5]:
                version = f" v{plugin['version']}" if plugin.get('version') and plugin['version'] != 'unknown' else ''
                print(f"  • {plugin['name']}{version}")
            if len(plugins) > 5:
                print(f"  ... and {len(plugins) - 5} more")
        
        themes = results.get('themes', [])
        if themes:
            print(f"\n🎨 {len(themes)} THEMES DETECTED")
            for theme in themes[:3]:
                version = f" v{theme['version']}" if theme.get('version') and theme['version'] != 'unknown' else ''
                print(f"  • {theme.get('full_name', theme['name'])}{version}")
        
        # Risk Summary
        print(f"\n📊 RISK SUMMARY:")
        print(f"  • Users Exposed: {len(results.get('users', []))}")
        print(f"  • CVEs Found: {len(cves)}")
        print(f"  • Vulnerabilities: {len(vulns)}")
        print(f"  • Critical Files: {len([f for f in files if f.get('critical')])}")
        print(f"  • Directory Listings: {len(dirs)}")
        print(f"  • Total Issues: {len(results.get('issues', []))}")
        
    else:
        print("❌ Not a WordPress site or inaccessible")
    
    print("\n" + "="*70)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="WP-SEC-AUDIT: Enterprise WordPress Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Quick scan
  wp_sec_audit.py -t https://example.com
  
  # Aggressive scan with 20 threads
  wp_sec_audit.py -t example.com -a --threads 20
  
  # Scan subdomains
  wp_sec_audit.py -s example.com
  
  # Scan subdomains from file
  wp_sec_audit.py -s example.com -sf subdomains.txt
  
  # Batch scan with aggressive mode
  wp_sec_audit.py -b targets.txt -a
  
  # Generate HTML report
  wp_sec_audit.py -t example.com -o html
  
  # Generate subdomain list
  wp_sec_audit.py --generate-subdomains example.com

SCAN TYPES:
  • Quick: Basic WordPress detection and user enumeration
  • Aggressive: Deep scanning with CVE detection, file enumeration
  • Subdomain: Discover and scan subdomains
  • Batch: Scan multiple targets from file
        """
    )
    
    # Scan modes
    scan_group = parser.add_argument_group('Scan Modes')
    scan_group.add_argument('-t', '--target', help='Single target URL to scan')
    scan_group.add_argument('-s', '--subdomains', help='Scan subdomains (provide domain)')
    scan_group.add_argument('-sf', '--subdomain-file', help='File containing subdomains to scan')
    scan_group.add_argument('-b', '--batch', help='File with list of targets (one per line)')
    scan_group.add_argument('-a', '--aggressive', action='store_true', 
                           help='Perform aggressive deep scan')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', choices=['text', 'json', 'html', 'md'],
                            default='text', help='Output format (default: text)')
    output_group.add_argument('--no-save', action='store_true',
                            help='Do not save reports to disk')
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('--threads', type=int, default=10,
                          help='Number of threads for scanning (default: 10)')
    perf_group.add_argument('--timeout', type=int, default=30,
                          help='Timeout in seconds (default: 30)')
    
    # Utility options
    util_group = parser.add_argument_group('Utility Options')
    util_group.add_argument('--generate-subdomains', metavar='DOMAIN',
                          help='Generate common subdomains list for a domain')
    util_group.add_argument('--interactive', action='store_true',
                          help='Launch interactive mode')
    
    # Info options
    info_group = parser.add_argument_group('Info Options')
    info_group.add_argument('-v', '--verbose', action='store_true',
                          help='Verbose output')
    info_group.add_argument('--version', action='version',
                          version='WP-SEC-AUDIT v1.2.0 (Aggressive Edition)')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        return 1
    
    # Create directories
    report_dir = create_directories()
    if report_dir and not args.no_save:
        print_info(f"Reports will be saved to: {report_dir}")
    
    # Ensure config exists
    config_path = ensure_config_exists()
    config = load_config(config_path)
    
    # Update config with command line arguments
    config['scanning']['threads'] = args.threads
    config['scanning']['timeout'] = args.timeout
    
    if args.no_save:
        config['output']['save_reports'] = False
    
    # Handle different scan modes
    if args.generate_subdomains:
        # Generate subdomain list
        generate_subdomain_list(args.generate_subdomains)
        return 0
    
    elif args.aggressive and args.target:
        # Aggressive scan
        target = validate_url(args.target)
        if not target:
            print_error("Invalid URL format")
            return 1
        
        results = aggressive_scan(target, config, args.output)
        
    elif args.subdomains:
        # Subdomain scanning
        domain = args.subdomains
        if not domain.startswith(('http://', 'https://')):
            domain = f"https://{domain}"
        
        scan_subdomains(domain, config, args.subdomain_file)
        
    elif args.batch:
        # Batch scan
        if args.aggressive:
            print_info("🚀 Starting AGGRESSIVE batch scan")
        else:
            print_info("📋 Starting batch scan")
        
        batch_scan(args.batch, config, args.output, args.aggressive)
        
    elif args.target:
        # Normal scan
        target = validate_url(args.target)
        if not target:
            print_error("Invalid URL format")
            return 1
        
        perform_scan(target, config, args.output)
        
    elif args.interactive:
        # Interactive mode
        interactive_mode(config)
        
    else:
        # No arguments, show help
        print_info("No scan target specified. Use --help for options.")
        print("\nQuick examples:")
        print("  python wp_sec_audit.py -t example.com           # Quick scan")
        print("  python wp_sec_audit.py -t example.com -a        # Aggressive scan")
        print("  python wp_sec_audit.py -s example.com           # Subdomain scan")
        print("  python wp_sec_audit.py -b targets.txt           # Batch scan")
        print("  python wp_sec_audit.py --interactive            # Interactive mode")
    
    return 0

def interactive_mode(config):
    """Interactive menu system"""
    while True:
        print("\n" + "="*60)
        print("🤖 WP-SEC-AUDIT INTERACTIVE MODE")
        print("="*60)
        print("\nSelect scan type:")
        print("  1. Quick Scan (Single target)")
        print("  2. Aggressive Scan (Deep analysis)")
        print("  3. Subdomain Discovery")
        print("  4. Batch Scan (Multiple targets)")
        print("  5. Generate Subdomain List")
        print("  6. Settings")
        print("  0. Exit")
        
        choice = input("\n[?] Select option (0-6): ").strip()
        
        if choice == '1':
            target = input("[?] Enter target URL: ").strip()
            if target:
                target = validate_url(target)
                if target:
                    perform_scan(target, config, 'text')
                else:
                    print_error("Invalid URL")
            else:
                print_error("No target specified")
        
        elif choice == '2':
            target = input("[?] Enter target URL: ").strip()
            if target:
                target = validate_url(target)
                if target:
                    threads = input("[?] Threads (default: 10): ").strip()
                    if threads.isdigit():
                        config['scanning']['threads'] = int(threads)
                    
                    aggressive_scan(target, config, 'text')
                else:
                    print_error("Invalid URL")
            else:
                print_error("No target specified")
        
        elif choice == '3':
            domain = input("[?] Enter domain (e.g., example.com): ").strip()
            if domain:
                use_file = input("[?] Use subdomain file? (y/n): ").lower()
                subdomain_file = None
                if use_file == 'y':
                    subdomain_file = input("[?] Path to subdomain file: ").strip()
                
                scan_subdomains(domain, config, subdomain_file)
            else:
                print_error("No domain specified")
        
        elif choice == '4':
            file_path = input("[?] Path to targets file: ").strip()
            if file_path:
                aggressive = input("[?] Aggressive mode? (y/n): ").lower() == 'y'
                batch_scan(file_path, config, 'text', aggressive)
            else:
                print_error("No file specified")
        
        elif choice == '5':
            domain = input("[?] Enter domain to generate subdomains for: ").strip()
            if domain:
                generate_subdomain_list(domain)
            else:
                print_error("No domain specified")
        
        elif choice == '6':
            print("\n📊 Current Settings:")
            print(f"  • Threads: {config['scanning']['threads']}")
            print(f"  • Timeout: {config['scanning']['timeout']}s")
            print(f"  • Save Reports: {config['output']['save_reports']}")
            
            change = input("\n[?] Change settings? (y/n): ").lower()
            if change == 'y':
                threads = input(f"Threads [{config['scanning']['threads']}]: ").strip()
                if threads.isdigit():
                    config['scanning']['threads'] = int(threads)
                
                timeout = input(f"Timeout [{config['scanning']['timeout']}]: ").strip()
                if timeout.isdigit():
                    config['scanning']['timeout'] = int(timeout)
                
                save = input(f"Save reports [{config['output']['save_reports']}]: ").strip().lower()
                if save in ['y', 'yes', 'true']:
                    config['output']['save_reports'] = True
                elif save in ['n', 'no', 'false']:
                    config['output']['save_reports'] = False
        
        elif choice == '0':
            print_success("Exiting interactive mode. Goodbye!")
            break
        
        else:
            print_error("Invalid option")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    sys.exit(main())
