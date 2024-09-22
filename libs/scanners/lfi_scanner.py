"""
Module for performing LFI scanning.
"""

import os
import time
import re
import urllib3
import requests
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init
from libs.utils import clear_screen
from libs.requests_helper import get_random_user_agent
from libs.argument_parser import get_common_arguments

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def run_lfi_scanner():
    """
    Runs the LFI scanner by performing requests with provided payloads
    to detect Local File Inclusion vulnerabilities.
    """
    parser = get_common_arguments("LFI Scanner")
    parser.add_argument('--success-patterns', default='root:x:0:', help='Comma-separated patterns indicating a successful LFI (default: "root:x:0:").')
    args = parser.parse_args()

    # Process URLs
    if args.url:
        urls = [args.url]
    elif args.url_file:
        with open(args.url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        print(Fore.RED + "[!] No URL provided.")
        return

    # Process Payloads
    if args.payload:
        payloads = [args.payload]
    elif args.payload_file:
        with open(args.payload_file, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
    else:
        print(Fore.RED + "[!] No payload provided.")
        return

    success_criteria = [pattern.strip() for pattern in args.success_patterns.split(',')]

    # Prepare headers and cookies
    headers = {'User-Agent': get_random_user_agent()}
    if args.headers:
        for header in args.headers:
            key_value = header.split(':', 1)
            if len(key_value) == 2:
                headers[key_value[0].strip()] = key_value[1].strip()
    cookies = {}
    if args.cookies:
        for cookie in args.cookies:
            key_value = cookie.split('=', 1)
            if len(key_value) == 2:
                cookies[key_value[0].strip()] = key_value[1].strip()

    # Start scanning
    print(f"{Fore.CYAN}[i] Starting LFI scan...")
    total_found = 0
    total_scanned = 0
    start_time = time.time()
    vulnerable_urls = []

    def perform_request(url, payload):
        encoded_payload = quote(payload.strip())
        target_url = f"{url}{encoded_payload}"
        try:
            if args.method == 'GET':
                response = requests.get(target_url, headers=headers, cookies=cookies, verify=False, timeout=10)
            else:
                response = requests.post(url, data={payload.strip(): ''}, headers=headers, cookies=cookies, verify=False, timeout=10)
            is_vulnerable = any(re.search(pattern, response.text) for pattern in success_criteria)
            if is_vulnerable:
                print(Fore.GREEN + f"[+] Vulnerable: {target_url}")
                return target_url
            else:
                print(Fore.RED + f"[-] Not Vulnerable: {target_url}")
        except requests.RequestException as e:
            print(Fore.RED + f"[!] Error accessing {target_url}: {str(e)}")
        return None

    if args.threads <= 1:
        for url in urls:
            for payload in payloads:
                total_scanned += 1
                result = perform_request(url.strip(), payload)
                if result:
                    total_found += 1
                    vulnerable_urls.append(result)
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = []
            for url in urls:
                for payload in payloads:
                    total_scanned += 1
                    futures.append(executor.submit(perform_request, url.strip(), payload))
            for future in as_completed(futures):
                result = future.result()
                if result:
                    total_found += 1
                    vulnerable_urls.append(result)

    # Print summary
    print(Fore.YELLOW + "\n[i] Scanning finished.")
    print(Fore.YELLOW + f"[i] Total found: {total_found}")
    print(Fore.YELLOW + f"[i] Total scanned: {total_scanned}")
    print(Fore.YELLOW + f"[i] Time taken: {int(time.time() - start_time)} seconds")

    # Save results
    if vulnerable_urls:
        output_file = 'vulnerable_urls.txt'
        with open(output_file, 'w') as f:
            for url in vulnerable_urls:
                f.write(url + '\n')
        print(Fore.GREEN + f"Vulnerable URLs have been saved to {output_file}")
