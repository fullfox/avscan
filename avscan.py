#!/usr/bin/env python3

import requests
import argparse
import json
import time
import hashlib
import os
from colorama import Fore, Style, init

init(autoreset=True)

parser = argparse.ArgumentParser(description="Scan a file with Kleenscan")
parser.add_argument("filename", nargs="?", help="Path to the file to scan")
parser.add_argument("-avs", "--antiviruses", default="microsoftdefender", 
                    help="Comma-separated list of antiviruses to use (default: microsoftdefender)")
parser.add_argument("-l", "--list", action="store_true", 
                    help="List available antivirus engines")
parser.add_argument("-o", "--output", 
                    help="Save scan results to a JSON file")
args = parser.parse_args()


# Read API_KEY from ~/.kleenscan
def get_api_key():
    key_path = os.path.expanduser("~/.kleenscan")
    
    # Try to read existing key
    if os.path.exists(key_path):
        try:
            with open(key_path, "r") as f:
                return f.read().strip()
        except Exception as e:
            print(f"{Fore.RED}❌ Error reading API key from {key_path}: {e}{Style.RESET_ALL}")
            exit(1)
    
    # Prompt for new key if file doesn't exist
    print(f"{Fore.YELLOW}⚠️  API key file not found at {key_path}{Style.RESET_ALL}")
    api_key = input(f"{Fore.CYAN}Please enter your Kleenscan API key: {Style.RESET_ALL}").strip()
    
    if not api_key:
        print(f"{Fore.RED}❌ No API key provided{Style.RESET_ALL}")
        exit(1)
    
    # Save the API key
    try:
        with open(key_path, "w") as f:
            f.write(api_key)
        print(f"{Fore.GREEN}✓ API key saved to {key_path}{Style.RESET_ALL}")
        return api_key
    except Exception as e:
        print(f"{Fore.RED}❌ Error saving API key: {e}{Style.RESET_ALL}")
        exit(1)

# Check if listing AV engines
if args.list:
    API_KEY = get_api_key()
    
    print("Fetching available antivirus engines...")
    try:
        r = requests.get('https://kleenscan.com/api/v1/get/avlist', headers={'X-Auth-Token': API_KEY})
        response_data = json.loads(r.text)
        
        if response_data.get('success') and response_data.get('data', {}).get('file'):
            print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
            print(f"{Fore.CYAN}                    AVAILABLE ANTIVIRUS ENGINES                {Style.RESET_ALL}")
            print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════{Style.RESET_ALL}\n")
            
            file_avs = response_data['data']['file']
            for av_key, av_display_name in file_avs.items():
                print(f"✓ {Fore.YELLOW}Engine:{Style.RESET_ALL} {Fore.WHITE}{av_display_name}{Style.RESET_ALL} {Fore.BLUE}key:{Style.RESET_ALL} {Fore.CYAN}{av_key}{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}Total available engines: {len(file_avs)}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Usage example:{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}./avscan myfile.exe -avs \"microsoftdefender,sophos,trendmicro\"{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Error fetching AV list: {response_data.get('message', 'Unknown error')}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Error fetching AV list: {e}{Style.RESET_ALL}")
    
    exit(0)

# Ensure filename is provided for scanning
if not args.filename:
    parser.print_help()
    exit(1)

API_KEY = get_api_key()

# Check if file exists
if not os.path.exists(args.filename):
    print(f"{Fore.RED}❌ Error: File '{args.filename}' not found{Style.RESET_ALL}")
    exit(1)

# Calculate MD5 hash of the file
with open(args.filename, 'rb') as f:
    file_content = f.read()
    md5_hash = hashlib.md5(file_content).hexdigest()
    print(f"{Fore.CYAN}MD5 Hash:{Style.RESET_ALL} {Fore.WHITE}{md5_hash}{Style.RESET_ALL}")

# Upload file for scanning
print("Uploading file for scanning...")
r = requests.post('https://kleenscan.com/api/v1/file/scan',
                  files={'path': open(args.filename, 'rb')},
                  data={'avList': args.antiviruses},
                  headers={'X-Auth-Token': API_KEY}
                )

# Parse the response to get scan token
response_data = json.loads(r.text)

if response_data.get('success'):
    scan_token = response_data['data']['scan_token']
    print(f"Scan initiated. Token: {scan_token}")
    
    # Get scan results
    print("Retrieving scan results...")    
    while True:
        r = requests.get(f'https://kleenscan.com/api/v1/file/result/{scan_token}', headers={'X-Auth-Token': API_KEY})
        result_data = json.loads(r.text)
        
        if result_data.get('success') and result_data.get('data'):
            # Check if all scans are complete (status is "ok")
            all_complete = all(item.get('status') == 'ok' for item in result_data['data'])
            if all_complete:
                print(f"{Fore.GREEN}✓ Scan complete!{Style.RESET_ALL}")
                print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
                print(f"{Fore.CYAN}                        SCAN RESULTS                           {Style.RESET_ALL}")
                print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════{Style.RESET_ALL}\n")
                
                for item in result_data['data']:
                    avname = item.get('avname', 'Unknown')
                    status = item.get('status', 'Unknown')
                    flagname = item.get('flagname', 'Undetected')
                    lastupdate = item.get('lastupdate', 'Unknown')
                    
                    # Color coding based on detection
                    if flagname and flagname not in ['Undetected', '']:
                        status_color = Fore.RED
                        flag_color = Fore.RED
                        status_icon = "⚠️"
                    else:
                        status_color = Fore.GREEN
                        flag_color = Fore.GREEN
                        status_icon = "✓"
                        if not flagname or flagname == '':
                            flagname = "Undetected"
                    
                    print(f"{status_icon} {Fore.YELLOW}AV Engine:{Style.RESET_ALL} {Fore.WHITE}{avname.upper()}{Style.RESET_ALL}")
                    print(f"  {Fore.BLUE}Status:{Style.RESET_ALL} {Fore.WHITE}{status}{Style.RESET_ALL}")
                    print(f"  {Fore.BLUE}Detection:{Style.RESET_ALL} {flag_color}{flagname}{Style.RESET_ALL}")
                    print(f"  {Fore.BLUE}Last Update:{Style.RESET_ALL} {Fore.WHITE}{lastupdate}{Style.RESET_ALL}")
                    print()
                
                # Save results to file if output specified
                if args.output:
                    try:
                        with open(args.output, 'w') as f:
                            json.dump(result_data, f, indent=2)
                        print(f"{Fore.GREEN}✓ Results saved to {args.output}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}❌ Error saving results to {args.output}: {e}{Style.RESET_ALL}")
                
                break
            else:
                print(f"{Fore.YELLOW}⏳ Scan in progress... waiting 5 seconds{Style.RESET_ALL}")
                time.sleep(5)
        else:
            print(f"{Fore.RED}❌ Error retrieving results:{Style.RESET_ALL}")
            print(json.dumps(result_data, indent=2))
            break
else:
    print(f"{Fore.RED}❌ Scan failed: {response_data.get('message', 'Unknown error')}{Style.RESET_ALL}")
    print(r.text)