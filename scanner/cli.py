import click
import sys
from pathlib import Path
from colorama import init, Fore, Style

from .scanner import SwiftSecurityScanner, load_all_rules
from .reporter import ConsoleReporter, JSONReporter, HTMLReporter

# Initialize colorama
init(autoreset=True)


@click.command()
@click.argument('target', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['console', 'json', 'html']), default='console', help='Output format')
@click.option('--severity', '-s', type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']), help='Minimum severity level to report')
@click.option('--recursive/--no-recursive', '-r', default=True, help='Scan directories recursively')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def main(target, output, format, severity, recursive, verbose):
    """
    Swift Security Scanner - Scan iOS Swift code for OWASP Mobile Top 10 vulnerabilities
    
    TARGET: Path to Swift file or directory to scan
    """
    
    # Print banner
    print_banner()
    
    # Load all rules
    if verbose:
        click.echo(f"{Fore.CYAN}[*] Loading security rules...{Style.RESET_ALL}")
    
    try:
        rules = load_all_rules()
        if verbose:
            click.echo(f"{Fore.GREEN}[+] Loaded {len(rules)} security rules{Style.RESET_ALL}")
    except Exception as e:
        click.echo(f"{Fore.RED}[!] Error loading rules: {e}{Style.RESET_ALL}", err=True)
        sys.exit(1)
    
    # Initialize scanner
    scanner = SwiftSecurityScanner(rules=rules)
    
    # Determine if target is file or directory
    target_path = Path(target)
    
    if verbose:
        click.echo(f"{Fore.CYAN}[*] Scanning target: {target}{Style.RESET_ALL}")
    
    try:
        if target_path.is_file():
            if target_path.suffix != '.swift':
                click.echo(f"{Fore.RED}[!] Error: Target file must be a .swift file{Style.RESET_ALL}", err=True)
                sys.exit(1)
            scanner.scan_file(str(target_path))
        elif target_path.is_dir():
            scanner.scan_directory(str(target_path), recursive=recursive)
        else:
            click.echo(f"{Fore.RED}[!] Error: Invalid target path{Style.RESET_ALL}", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"{Fore.RED}[!] Error during scanning: {e}{Style.RESET_ALL}", err=True)
        sys.exit(1)
    
    # Get findings
    findings = scanner.get_findings()
    
    # Filter by severity if specified
    if severity:
        severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_severity_index = severity_order.index(severity)
        findings = [f for f in findings if severity_order.index(f.severity.value) >= min_severity_index]
    
    # Get stats
    stats = scanner.get_stats()
    
    if verbose:
        click.echo(f"{Fore.GREEN}[+] Scan complete!{Style.RESET_ALL}")
        click.echo(f"{Fore.CYAN}[*] Files scanned: {stats['files_scanned']}{Style.RESET_ALL}")
        click.echo(f"{Fore.CYAN}[*] Lines scanned: {stats['lines_scanned']}{Style.RESET_ALL}")
        click.echo(f"{Fore.CYAN}[*] Total findings: {len(findings)}{Style.RESET_ALL}")
    
    # Generate report
    if format == 'console':
        reporter = ConsoleReporter()
        report = reporter.generate(findings, stats)
        click.echo(report)
        
        if output:
            with open(output, 'w') as f:
                f.write(report)
            if verbose:
                click.echo(f"{Fore.GREEN}[+] Report saved to: {output}{Style.RESET_ALL}")
    
    elif format == 'json':
        reporter = JSONReporter()
        report = reporter.generate(findings, stats)
        
        if output:
            with open(output, 'w') as f:
                f.write(report)
            if verbose:
                click.echo(f"{Fore.GREEN}[+] JSON report saved to: {output}{Style.RESET_ALL}")
        else:
            click.echo(report)
    
    elif format == 'html':
        reporter = HTMLReporter()
        report = reporter.generate(findings, stats)
        
        if output:
            with open(output, 'w') as f:
                f.write(report)
            if verbose:
                click.echo(f"{Fore.GREEN}[+] HTML report saved to: {output}{Style.RESET_ALL}")
        else:
            click.echo(report)
    
    # Exit with appropriate code
    if findings:
        critical_count = sum(1 for f in findings if f.severity.value == 'CRITICAL')
        high_count = sum(1 for f in findings if f.severity.value == 'HIGH')
        
        if critical_count > 0 or high_count > 0:
            sys.exit(1)  # Exit with error if critical or high severity findings
    
    sys.exit(0)


def print_banner():
    """Print ASCII banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        {Fore.RED}Swift Security Scanner v1.0{Fore.CYAN}                      ║
║        {Fore.YELLOW}OWASP Mobile Top 10 Vulnerability Detector{Fore.CYAN}       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    click.echo(banner)


if __name__ == '__main__':
    main()