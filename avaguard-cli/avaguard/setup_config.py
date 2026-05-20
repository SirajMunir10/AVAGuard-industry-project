"""Setup script to create initial configuration and directories."""

import os
import json
from pathlib import Path
from colorama import init, Fore, Style

# Initialize colorama
init()

def setup_avaguard():
    """Setup AVAGuard with initial configuration and directories."""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}AVAGuard Initial Setup{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    # Create directories
    directories = [
        'output/reports',
        'output/logs', 
        'data'
    ]
    
    print(f"{Fore.YELLOW}Creating directory structure...{Style.RESET_ALL}")
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ Created: {directory}/")
    
    # Check if config.ini exists
    if not os.path.exists('config.ini'):
        print(f"\n{Fore.YELLOW}Creating default configuration...{Style.RESET_ALL}")
        
        # Import Config to create default config
        from avaguard.config import Config
        config = Config()
        print(f"  ✓ Created: config.ini")
        
        print(f"\n{Fore.GREEN}Default configuration created!{Style.RESET_ALL}")
        print(f"  Edit {Fore.CYAN}config.ini{Style.RESET_ALL} to configure:")
        print(f"    - Azure credentials for live mode")
        print(f"    - Scan settings and output preferences")
    else:
        print(f"\n{Fore.GREEN}Configuration already exists: config.ini{Style.RESET_ALL}")
    
    # Check if mock data exists
    mock_data_file = 'data/azure_tenant.json'
    if not os.path.exists(mock_data_file):
        print(f"\n{Fore.YELLOW}Would you like to generate sample mock data?{Style.RESET_ALL}")
        print(f"  This will create a realistic Azure AD dataset for testing.")
        response = input(f"  {Fore.CYAN}Generate mock data? (y/n): {Style.RESET_ALL}").strip().lower()
        
        if response in ['y', 'yes']:
            try:
                from avaguard.mock_data_generator import AzureADMockGenerator
                generator = AzureADMockGenerator()
                dataset = generator.generate_dataset(100)  # Smaller dataset for testing
                generator.save_to_file(dataset, mock_data_file)
                print(f"  {Fore.GREEN}✓ Mock data generated: {mock_data_file}{Style.RESET_ALL}")
            except ImportError:
                print(f"  {Fore.YELLOW}⚠ Mock data generator not available{Style.RESET_ALL}")
            except Exception as e:
                print(f"  {Fore.RED}✗ Error generating mock data: {e}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}⚠ Mock data not generated{Style.RESET_ALL}")
            print(f"  You can generate it later with: {Fore.CYAN}python -m avaguard.mock_data_generator{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN}Mock data already exists: {mock_data_file}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Setup completed!{Style.RESET_ALL}")
    print(f"\nNext steps:")
    print(f"  1. Edit {Fore.CYAN}config.ini{Style.RESET_ALL} to configure Azure credentials")
    print(f"  2. Run {Fore.CYAN}avaguard scan{Style.RESET_ALL} to start compliance checking")
    print(f"  3. Use {Fore.CYAN}avaguard list-checks{Style.RESET_ALL} to see available checks")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

if __name__ == '__main__':
    setup_avaguard()