"""
Module for performing Open Redirect scanning.
"""

import os
import time
import urllib3
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init
from libs.utils import clear_screen
from libs.requests_helper import get_random_user_agent
from libs.argument_parser import get_common_arguments

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def run_or_scanner():
    """
    Runs the Open Redirect scanner.
    """
    parser = get_common_arguments("Open Redirect Scanner")
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
    print(f"{Fore.CYAN}[i] Starting Open Redirect scan...")
    vulnerable_urls = []
    total_scanned = 0
    start_time = time.time()

    def perform_request(url, payload):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for param in query_params:
            original_value = query_params[param][0]
            query_params[param] = payload
            new_query = urlencode(query_params, doseq=True)
            vulnerable_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
            try:
                if args.method == 'GET':
                    response = requests.get(vulnerable_url, headers=headers, cookies=cookies, verify=False, timeout=10, allow_redirects=False)
                else:
                    response = requests.post(url, data={param: payload}, headers=headers, cookies=cookies, verify=False, timeout=10, allow_redirects=False)
                if response.status_code in [301, 302] and 'Location' in response.headers and payload in response.headers['Location']:
                    print(Fore.GREEN + f"[+] Vulnerable: {vulnerable_url}")
                    return vulnerable_url
                else:
                    print(Fore.RED + f"[-] Not Vulnerable: {vulnerable_url}")
                query_params[param] = original_value  # Reset to original value
            except requests.RequestException as e:
                print(Fore.RED + f"[!] Error accessing {vulnerable_url}: {str(e)}")
        return None

    if args.threads <= 1:
        for url in urls:
            for payload in payloads:
                total_scanned += 1
                result = perform_request(url.strip(), payload)
                if result:
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
                    vulnerable_urls.append(result)

    # Print summary
    print(Fore.YELLOW + "\n[i] Scanning finished.")
    print(Fore.YELLOW + f"[i] Total found: {len(vulnerable_urls)}")
    print(Fore.YELLOW + f"[i] Total scanned: {total_scanned}")
    print(Fore.YELLOW + f"[i] Time taken: {int(time.time() - start_time)} seconds")

    # Save results
    if vulnerable_urls:
        output_file = 'vulnerable_urls.txt'
        with open(output_file, 'w') as f:
            for url in vulnerable_urls:
                f.write(url + '\n')
        print(Fore.GREEN + f"Vulnerable URLs have been saved to {output_file}")
