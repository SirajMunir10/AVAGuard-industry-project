"""Command-line interface for AVAGuard."""
import os

import click
import logging
import sys
import json
from pathlib import Path
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate

# Initialize colorama for Windows
init()

from avaguard.config import Config
from avaguard_core.auth import AzureAuthenticator, AuthenticationError
from avaguard_core.graph_api_client import GraphAPIClient
from avaguard_core.reporter import EnhancedReporter as Reporter
from avaguard_core.checks.base_check import CISSeverity
from avaguard_core.checks import AVAILABLE_CHECKS, FREE_TIER_CHECKS, PREMIUM_CHECKS
from avaguard_core.risk_scorer import RiskScorer


logger = logging.getLogger(__name__)

from avaguard_core import __version__ as core_version

MIN_CORE_VERSION = "0.1.0"

def _check_core_version(_override=None):
    """Run at CLI startup. Exits if core version is incompatible."""
    from packaging.version import Version
    from colorama import Fore, Style
    import sys

    version_to_check = _override or core_version

    if Version(version_to_check) < Version(MIN_CORE_VERSION):
        print(f"\n{Fore.RED}[ERROR] avaguard-core version mismatch.{Style.RESET_ALL}")
        print(f"  Required : >= {MIN_CORE_VERSION}")
        print(f"  Installed: {version_to_check}")
        print(f"  Fix      : pip install --upgrade avaguard-core\n")
        sys.exit(1)

@click.group()
@click.version_option(version=core_version)
def cli():
    """AVAGuard - Azure CIS Benchmark Compliance Checker"""
    from avaguard_core.logging_config import configure_logging
    configure_logging(
        level="INFO",
        log_file="output/logs/avaguard_cli.log"
    )
    _check_core_version()

@cli.command('health')
@click.option(
    '--config-file',
    default='config.ini',
    show_default=True,
    help='Path to config.ini'
)
@click.option(
    '--json', 'output_json',
    is_flag=True,
    default=False,
    help='Output results as JSON (for CI pipeline integration)'
)
def health_check(config_file, output_json):
    """Run a health check on the AVAGuard installation."""
    from avaguard.health import HealthChecker, HealthStatus

    checker = HealthChecker(config_file)
    report = checker.run_all()

    if output_json:
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        click.echo("")
        click.echo("AVAGuard Health Check")
        click.echo("=" * 45)

        for check in report.checks:
            if check.status == HealthStatus.PASS:
                symbol = click.style("[✓]", fg='green')
            elif check.status == HealthStatus.FAIL:
                symbol = click.style("[✗]", fg='red')
            else:
                symbol = click.style("[~]", fg='yellow')

            click.echo(f"{symbol} {check.message}")
            if check.detail and check.status != HealthStatus.PASS:
                click.echo(f"      {click.style(check.detail, fg='cyan')}")

        click.echo("")
        click.echo("=" * 45)

        summary_color = 'red' if report.failed > 0 else (
            'yellow' if report.warnings > 0 else 'green'
        )
        click.echo(click.style(
            f"Summary: {report.total} checks — "
            f"{report.passed} passed, "
            f"{report.failed} failed, "
            f"{report.warnings} warnings",
            fg=summary_color
        ))
        click.echo("")

    sys.exit(report.exit_code)

@cli.command()
def list_checks():
    """List all available CIS compliance checks."""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Available CIS Compliance Checks{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    table_data = []
    for check_id, check_class in AVAILABLE_CHECKS.items():
        tier = "Premium" if check_id in PREMIUM_CHECKS else "Free"
        tier_color = Fore.YELLOW if tier == "Premium" else Fore.GREEN
        
        table_data.append([
            check_id,
            check_class.TITLE[:60] + "..." if len(check_class.TITLE) > 60 else check_class.TITLE,
            f"{tier_color}{tier}{Style.RESET_ALL}"
        ])
    
    print(tabulate(table_data, headers=["Check ID", "Title", "Tier"], tablefmt="grid"))
    print(f"\n{Fore.CYAN}Total: {len(AVAILABLE_CHECKS)} checks available{Style.RESET_ALL}\n")

@cli.command()
def setup():
    """Run initial setup to create configuration and directories."""
    try:
        from avaguard.setup_config import setup_avaguard
        setup_avaguard()
    except ImportError:
        print(f"{Fore.RED}Setup module not available.{Style.RESET_ALL}")
        print(f"Please ensure all required files are present.")
        sys.exit(1)

def determine_scan_mode(mock_flag, live_flag, interactive=True):
    """
    Determine the scan mode based on flags and user input.
    
    Args:
        mock_flag: --mock flag value
        live_flag: --live flag value  
        interactive: Whether to prompt user if no flag provided
    
    Returns:
        str: 'mock' or 'live'
    """
    # Check for conflicting flags
    if mock_flag and live_flag:
        print(f"{Fore.RED}Error: Cannot use both --mock and --live flags{Style.RESET_ALL}")
        sys.exit(1)
    
    # If flags provided, use them
    if mock_flag:
        return 'mock'
    if live_flag:
        return 'live'
    
    # If non-interactive mode, use config default
    if not interactive:
        return None  # Let config decide
    
    # Interactive mode: prompt user
    print(f"\n{Fore.CYAN}Choose scan mode:{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[1]{Style.RESET_ALL} Live Azure tenant")
    print(f"  {Fore.YELLOW}[2]{Style.RESET_ALL} Mock data")
    
    while True:
        try:
            choice = input(f"{Fore.CYAN}Enter choice (1/2): {Style.RESET_ALL}").strip()
            if choice == '1':
                return 'live'
            elif choice == '2':
                return 'mock'
            else:
                print(f"{Fore.RED}Invalid choice. Please enter 1 or 2.{Style.RESET_ALL}")
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Fore.YELLOW}Scan cancelled.{Style.RESET_ALL}")
            sys.exit(0)

def setup_graph_client(config, scan_mode):
    """
    Set up the appropriate Graph API client based on scan mode.
    
    Args:
        config: Configuration object
        scan_mode: 'mock' or 'live'
    
    Returns:
        Graph API client instance
    """
    from avaguard_core.client_factory import GraphClientFactory
    
    if scan_mode == 'mock':
        print(f"{Fore.YELLOW}[2/5] Loading mock data...{Style.RESET_ALL}")
        try:
            graph_client = GraphClientFactory.create_client(
                mode='mock', 
                config={'mock_data': config.mock_data_file}
            )
            print(f"{Fore.GREEN}✓ Mock data loaded successfully{Style.RESET_ALL}")
            print(f"      Mock File: {config.mock_data_file}\n")
            return graph_client
        except FileNotFoundError as e:
            print(f"{Fore.RED}✗ Mock data file not found: {e}{Style.RESET_ALL}")
            print(f"Please ensure the mock data file exists at: {config.mock_data_file}")
            sys.exit(1)
        except ValueError as e:
            print(f"{Fore.RED}✗ Invalid mock data: {e}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}✗ Error loading mock data: {e}{Style.RESET_ALL}")
            sys.exit(1)
    
    else:  # live mode
        print(f"{Fore.YELLOW}[2/5] Authenticating to Azure AD...{Style.RESET_ALL}")
        try:
            # First try configured values, fall back to environment variables
            tenant_id = config.tenant_id or os.environ.get('AZURE_TENANT_ID')
            client_id = config.client_id or os.environ.get('AZURE_CLIENT_ID')
            client_secret = config.client_secret or os.environ.get('AZURE_CLIENT_SECRET')
            
            if not tenant_id or not client_id:
                print(f"{Fore.RED}✗ Missing authentication details{Style.RESET_ALL}")
                print(f"Live mode requires tenant_id and client_id in config.ini or environment variables.")
                sys.exit(1)
                
            graph_client = GraphClientFactory.create_client(
                mode='live',
                config={
                    'tenant_id': tenant_id,
                    'client_id': client_id,
                    'client_secret': client_secret
                }
            )
            
            # Trigger initial auth/token fetch to verify credentials early
            graph_client._get_access_token()
            print(f"{Fore.GREEN}✓ Authentication successful{Style.RESET_ALL}")
            print(f"      Tenant: {tenant_id}\n")
            return graph_client
            
        except Exception as e:
            print(f"{Fore.RED}✗ Authentication failed: {e}{Style.RESET_ALL}")
            print(f"\nPlease check your credentials in the configuration file")
            print(f"or use mock mode with --mock flag for offline testing.")
            sys.exit(1)

def display_detailed_resources(result):
    """
    Display detailed resource breakdown for a check result.
    
    Args:
        result: CheckResult object
    """
    # Display non-compliant resources
    if result.non_compliant_resources:
        print(f"{Fore.RED}      NON-COMPLIANT RESOURCES ({len(result.non_compliant_resources)}):{Style.RESET_ALL}")
        for res in result.non_compliant_resources[:5]:  # Limit to 5 in CLI to avoid flooding
            # Try to find a readable name or ID
            name = (
                res.get('userPrincipalName') or 
                res.get('displayName') or 
                res.get('domain') or          # For domain checks
                res.get('policy') or          # For policy checks
                res.get('id') or 
                'Unknown Resource'
            )
            reason = res.get('reason') or 'Configuration mismatch'
            print(f"        - {name} ({reason})")
        if len(result.non_compliant_resources) > 5:
            print(f"        ... and {len(result.non_compliant_resources) - 5} more.")

    # Display compliant resources
    if result.compliant_resources:
        print(f"{Fore.GREEN}      COMPLIANT RESOURCES ({len(result.compliant_resources)}):{Style.RESET_ALL}")
        for res in result.compliant_resources[:5]:
            name = (
                res.get('userPrincipalName') or 
                res.get('displayName') or 
                res.get('domain') or          # For domain checks
                res.get('policy') or          # For policy checks
                res.get('id') or 
                'Unknown Resource'
            )
            print(f"        + {name}")
        if len(result.compliant_resources) > 5:
            print(f"        ... and {len(result.compliant_resources) - 5} more.")

@cli.command()
@click.option('--checks', '-c', default=None, help='Comma-separated list of check IDs to run (e.g., 1.1,1.3,1.5)')
@click.option('--tier', '-t', type=click.Choice(['free', 'premium', 'all']), default=None, 
              help='Run checks for specific tier (overrides config)')
@click.option('--output', '-o', type=click.Choice(['html', 'json', 'csv', 'pdf', 'both', 'all']), default=None,
              help='Report file format corresponding to core Reporter (overrides config)')
@click.option('--output-format', type=click.Choice(['table', 'json', 'csv']), default='table',
              help='Format for stdout output (useful for CI/CD)')
@click.option('--upload', is_flag=True, help='Upload results to AVAGuard Web Portal target')
@click.option('--config-file', default='config.ini', help='Path to configuration file')
@click.option('--mock', is_flag=True, help='Use mock data instead of real Azure API')
@click.option('--live', is_flag=True, help='Force real Azure connection (overrides config)')
@click.option('--non-interactive', is_flag=True, help='Run without user prompts (for CI/CD)')
@click.option('--setup', is_flag=True, help='Run initial setup and create configuration')
@click.option('--detailed', is_flag=True, help='Show detailed resource breakdown for each check')
def scan(checks, tier, output, output_format, upload, config_file, mock, live, non_interactive, setup, detailed):
    """Run compliance scan against Azure AD tenant."""
    
    # Run setup if requested
    if setup:
        from avaguard.setup_config import setup_avaguard
        setup_avaguard()
        return
    
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}AVAGuard - Azure CIS Benchmark Compliance Checker{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    try:
        # Load configuration
        print(f"{Fore.YELLOW}[1/5] Loading configuration...{Style.RESET_ALL}")
        
        from avaguard_core.config_validator import validate_config, ValidationSeverity
        report = validate_config(config_file)
        
        # Critical config structure failure (file missing, bad ini syntax)
        if not report.is_valid_for_mock:
            print(f"{Fore.RED}✗ Fatal Configuration Error.{Style.RESET_ALL}")
            for err in report.get_errors():
                print(f"  - {err.field}: {err.message} (Fix: {err.suggested_fix})")
            sys.exit(1)
            
        # Optional warnings/errors
        if report.has_warnings() or report.has_errors():
            print(f"\n{Fore.YELLOW}⚠ Configuration Warnings/Errors:{Style.RESET_ALL}")
            for res in report.results:
                color = Fore.RED if res.severity == ValidationSeverity.ERROR else Fore.YELLOW if res.severity == ValidationSeverity.WARNING else Fore.CYAN
                print(f"  {color}[{res.severity.value.upper()}] {res.field}: {res.message}{Style.RESET_ALL}")
                print(f"      Fix: {res.suggested_fix}")
            print()

        config = Config(config_file)
        print(f"{Fore.GREEN}✓ Configuration parsed{Style.RESET_ALL}")
        
        # Determine scan mode
        scan_mode = determine_scan_mode(mock, live, interactive=not non_interactive)
        
        # If no mode chosen in non-interactive, use config default
        if scan_mode is None:
            scan_mode = 'mock' if config.use_mock_data else 'live'
            
        # Protect live mode from broken Azure configurations by failing gracefully to Code 0
        if scan_mode == 'live' and not report.is_valid_for_live:
            print(f"{Fore.RED}✗ Cannot run in LIVE mode due to missing or invalid credentials.{Style.RESET_ALL}")
            print(f"\nPlease edit {Fore.CYAN}{config_file}{Style.RESET_ALL} to provide valid Azure credentials.")
            print(f"Or run safely using mock data: {Fore.CYAN}avaguard scan --mock{Style.RESET_ALL}")
            sys.exit(0)
        
        print(f"      Tenant ID: {config.tenant_id}")
        print(f"      Tier: {config.tier.upper()}")
        print(f"      Mode: {Fore.YELLOW}MOCK DATA{Style.RESET_ALL}" if scan_mode == 'mock' else f"      Mode: {Fore.GREEN}LIVE AZURE{Style.RESET_ALL}")
        if scan_mode == 'mock':
            print(f"      Mock File: {config.mock_data_file}")
        if detailed:
            print(f"      Output: {Fore.CYAN}DETAILED{Style.RESET_ALL}")
        print()
        
        # Determine which checks to run
        if checks:
            check_ids = [c.strip() for c in checks.split(',')]
        elif tier:
            if tier == 'free':
                check_ids = list(FREE_TIER_CHECKS)
            elif tier == 'premium':
                check_ids = list(PREMIUM_CHECKS)
            else:  # all
                check_ids = list(AVAILABLE_CHECKS.keys())
        elif config.default_checks:
            check_ids = config.default_checks
        else:
            # Default to tier-appropriate checks
            check_ids = list(FREE_TIER_CHECKS if config.tier == 'free' else AVAILABLE_CHECKS.keys())
        
        # Validate check IDs
        invalid_checks = [c for c in check_ids if c not in AVAILABLE_CHECKS]
        if invalid_checks:
            print(f"{Fore.RED}Error: Invalid check IDs: {', '.join(invalid_checks)}{Style.RESET_ALL}")
            print(f"Run 'avaguard list-checks' to see available checks")
            sys.exit(1)
        
        # Warn about premium checks on free tier
        if config.tier == 'free':
            premium_selected = [c for c in check_ids if c in PREMIUM_CHECKS]
            if premium_selected:
                print(f"{Fore.YELLOW}⚠ Warning: The following checks require Premium tier:{Style.RESET_ALL}")
                for check_id in premium_selected:
                    print(f"      - {check_id}: {AVAILABLE_CHECKS[check_id].TITLE}")
                print(f"{Fore.YELLOW}      These checks may fail or return incomplete results.{Style.RESET_ALL}\n")
        
        print(f"Selected {len(check_ids)} check(s) to run\n")
        
        # Set up Graph API client based on scan mode
        graph_client = setup_graph_client(config, scan_mode)
        
        # If using mock data, skip authentication step in output
        if scan_mode == 'mock':
            print(f"{Fore.YELLOW}[3/5] Skipping authentication (mock mode){Style.RESET_ALL}\n")
        
        # Run checks
        print(f"{Fore.YELLOW}[4/5] Running compliance checks...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}\n")
        
        results = []
        passed = 0
        failed = 0
        errors = 0
        
        for i, check_id in enumerate(check_ids, 1):
            check_class = AVAILABLE_CHECKS[check_id]
            check_instance = check_class(graph_client)
            
            print(f"[{i}/{len(check_ids)}] Running check {check_id}: {check_instance.TITLE[:50]}...")
            
            try:
                result = check_instance.execute()
                results.append(result)
                
                # Display result
                if result.status.value == 'PASS':
                    print(f"    {Fore.GREEN}✓ PASS{Style.RESET_ALL} - {result.details}")
                    passed += 1
                elif result.status.value == 'FAIL':
                    print(f"    {Fore.RED}✗ FAIL{Style.RESET_ALL} - {result.details}")
                    failed += 1
                elif result.status.value == 'ERROR':
                    print(f"    {Fore.YELLOW}⚠ ERROR{Style.RESET_ALL} - {result.error_message}")
                    errors += 1
                else:
                    print(f"    {Fore.CYAN}○ SKIPPED{Style.RESET_ALL}")
                
                # Display detailed resource breakdown if requested
                if detailed:
                    display_detailed_resources(result)
                
            except Exception as e:
                logger.error(f"Unexpected error in check {check_id}: {e}")
                print(f"    {Fore.RED}✗ ERROR{Style.RESET_ALL} - Unexpected error: {str(e)}")
                errors += 1
            
            print()  # Blank line between checks
        
        print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}\n")
        
        # Display summary
        total = len(results)
        score = RiskScorer.calculate_score(results)
        risk_level = RiskScorer.get_risk_level(score)
        
        print(f"{Fore.CYAN}Scan Summary:{Style.RESET_ALL}")
        print(f"  Total Checks: {total}")
        print(f"  {Fore.GREEN}Passed: {passed}{Style.RESET_ALL}")
        print(f"  {Fore.RED}Failed: {failed}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Errors: {errors}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Overall Score: {score:.1f}% ({risk_level} Risk){Style.RESET_ALL}\n")
        
        # Generate reports
        print(f"{Fore.YELLOW}[5/5] Generating reports...{Style.RESET_ALL}")
        reporter = Reporter(output_dir=config.reports_dir)
        
        output_format_file = output if output else config.output_format
        # Convert output format to list for reporter
        if output_format_file == 'both':
            format_list = ['html', 'json']
        elif output_format_file == 'all':
            format_list = ['html', 'json', 'csv', 'pdf']
        elif output_format_file:
            format_list = [output_format_file]
        else:
            format_list = ['html', 'json']
            
        generated_files = reporter.generate_reports(results, formats=format_list)
        
        print(f"{Fore.GREEN}✓ Reports generated:{Style.RESET_ALL}")
        for filepath in generated_files:
            print(f"      {filepath}")
            
        if upload:
            print(f"\n{Fore.YELLOW}Uploading results to AVAGuard Web Portal...{Style.RESET_ALL}")
            try:
                import requests
                import json
                
                json_report = next((f for f in generated_files if f.endswith('.json')), None)
                if not json_report:
                    print(f"{Fore.RED}✗ Upload requires JSON report generation (add --output json){Style.RESET_ALL}")
                else:
                    with open(json_report, 'r') as f:
                        payload = json.load(f)
                    
                    api_endpoint = f"{config.portal_url.rstrip('/')}/api/v1/scans/sync"
                    
                    sync_payload = {
                        "tenant_id": config.tenant_id or "cli-mock-tenant",
                        "scan_id": payload.get('metadata', {}).get('scan_id', 'cli-scan'),
                        "timestamp": payload.get('metadata', {}).get('timestamp', datetime.now().isoformat()),
                        "score": score,
                        "results": payload.get('results', [])
                    }
                    
                    response = requests.post(
                        api_endpoint, 
                        json=sync_payload,
                        headers={"Content-Type": "application/json", "X-AVAGuard-Source": "CLI"},
                        timeout=10
                    )
                    
                    if response.status_code in (200, 201):
                        print(f"{Fore.GREEN}✓ Successfully uploaded to portal{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}✗ Upload failed: HTTP {response.status_code} - {response.text[:100]}{Style.RESET_ALL}")
            except ImportError:
                print(f"{Fore.RED}✗ Upload failed: 'requests' module not found{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}✗ Upload failed: {str(e)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Scan completed successfully!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        # Exit with appropriate code
        sys.exit(0 if failed == 0 and errors == 0 else 1)
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)

@cli.command()
@click.option('--mock', is_flag=True, help='Test with mock data instead of real Azure API')
def test_connection(mock):
    """Test connection to Azure AD or mock data."""
    print(f"\n{Fore.CYAN}Testing connection...{Style.RESET_ALL}\n")
    
    try:
        config = Config()
        
        if mock:
            print(f"{Fore.YELLOW}Testing mock data connection...{Style.RESET_ALL}")
            print(f"Mock File: {config.mock_data_file}\n")
            
            try:
                graph_client = MockGraphAPIClient(config.mock_data_file)
                # Test mock data loading
                users = graph_client.get_users()
                groups = graph_client.get_groups()
                
                print(f"{Fore.GREEN}✓ Mock data loaded successfully!{Style.RESET_ALL}")
                print(f"  Users: {len(users)}")
                print(f"  Groups: {len(groups)}")
                print(f"  Service Principals: {len(graph_client.get_service_principals())}")
                print(f"\n{Fore.GREEN}Mock connection test passed!{Style.RESET_ALL}\n")
                
            except Exception as e:
                print(f"{Fore.RED}✗ Mock data error: {e}{Style.RESET_ALL}\n")
                sys.exit(1)
                
        else:
            # Check if Azure is configured
            if not config.is_azure_configured():
                print(f"{Fore.RED}✗ Azure credentials not configured{Style.RESET_ALL}")
                print(f"\nTo test live Azure connection, please:")
                print(f"  1. Edit config.ini")
                print(f"  2. Set your Azure credentials in the [azure] section")
                print(f"  3. Or test mock data with {Fore.CYAN}--mock{Style.RESET_ALL} flag")
                sys.exit(1)
            
            print(f"{Fore.YELLOW}Testing Azure AD connection...{Style.RESET_ALL}")
            print(f"Tenant ID: {config.tenant_id}")
            print(f"Client ID: {config.client_id}\n")
            
            authenticator = AzureAuthenticator(
                tenant_id=config.tenant_id,
                client_id=config.client_id,
                client_secret=config.client_secret
            )
            
            print("Attempting authentication...")
            token = authenticator.get_token()
            
            print(f"{Fore.GREEN}✓ Authentication successful!{Style.RESET_ALL}")
            print(f"Token obtained (length: {len(token)} chars)\n")
            
            # Test a simple Graph API call
            graph_client = GraphAPIClient(token)
            print("Testing Graph API call...")
            org = graph_client.get_organization()
            
            print(f"{Fore.GREEN}✓ Graph API connection successful!{Style.RESET_ALL}")
            print(f"Organization: {org.get('displayName', 'Unknown')}")
            print(f"Tenant ID: {org.get('id', 'Unknown')}\n")
            
            print(f"{Fore.GREEN}Connection test passed!{Style.RESET_ALL}\n")
        
    except AuthenticationError as e:
        print(f"{Fore.RED}✗ Authentication failed: {e}{Style.RESET_ALL}\n")
        sys.exit(1)
    except GraphAPIError as e:
        print(f"{Fore.RED}✗ Graph API error: {e}{Style.RESET_ALL}\n")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}\n")
        sys.exit(1)

@cli.command('compare')
@click.argument('scan_a_file', type=click.Path(exists=True))
@click.argument('scan_b_file', type=click.Path(exists=True))
def compare_command(scan_a_file, scan_b_file):
    """Compare two scan result JSON files and output the difference."""
    import json
    from avaguard_core.compare import compare_scans
    
    with open(scan_a_file, 'r', encoding='utf-8') as f:
        scan_a = json.load(f)
    with open(scan_b_file, 'r', encoding='utf-8') as f:
        scan_b = json.load(f)
        
    diff = compare_scans(scan_a, scan_b)
    
    click.echo("")
    click.echo(click.style(f"Score Delta: {diff.score_delta:>+0.2f}%", bold=True, fg="yellow" if diff.score_delta < 0 else "green"))
    click.echo(f"Newly Passing: {len(diff.newly_passing)} checks")
    for cp in diff.newly_passing:
        click.echo(click.style(f"  [+] {cp}", fg="green"))
        
    click.echo(f"Newly Failing: {len(diff.newly_failing)} checks")
    for cf in diff.newly_failing:
        click.echo(click.style(f"  [-] {cf}", fg="red"))
        
    click.echo(f"Unchanged: {len(diff.unchanged)} checks")
    click.echo("")

def main():
    """Main entry point."""
    cli()

if __name__ == '__main__':
    main()