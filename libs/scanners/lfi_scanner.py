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
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from colorama import Fore, init
from libs.utils import clear_screen
from libs.requests_helper import get_random_user_agent

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def get_file_path(prompt_text):
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def prompt_for_urls():
    while True:
        try:
            url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter to input a single URL): ")
            if url_input:
                if not os.path.isfile(url_input):
                    raise FileNotFoundError(f"File not found: {url_input}")
                with open(url_input) as file:
                    urls = [line.strip() for line in file if line.strip()]
                return urls
            else:
                single_url = input(Fore.CYAN + "[?] Enter a single URL to scan: ").strip()
                if single_url:
                    return [single_url]
                else:
                    print(Fore.RED + "[!] You must provide either a file with URLs or a single URL.")
                    input(Fore.YELLOW + "\n[i] Press Enter to try again...")
                    clear_screen()
                    print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")
        except Exception as e:
            print(Fore.RED + f"[!] Error reading input file: {url_input}. Exception: {str(e)}")
            input(Fore.YELLOW + "[i] Press Enter to try again...")
            clear_screen()
            print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")

def prompt_for_payloads():
    while True:
        try:
            payload_input = get_file_path("[?] Enter the path to the payloads file: ")
            if not os.path.isfile(payload_input):
                raise FileNotFoundError(f"File not found: {payload_input}")
            with open(payload_input) as file:
                payloads = [line.strip() for line in file if line.strip()]
            return payloads
        except Exception as e:
            print(Fore.RED + f"[!] Error reading payload file: {payload_input}. Exception: {str(e)}")
            input(Fore.YELLOW + "[i] Press Enter to try again...")
            clear_screen()
            print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")

def print_scan_summary(total_found, total_scanned, start_time):
    print(Fore.YELLOW + "\n[i] Scanning finished.")
    print(Fore.YELLOW + f"[i] Total found: {total_found}")
    print(Fore.YELLOW + f"[i] Total scanned: {total_scanned}")
    print(Fore.YELLOW + f"[i] Time taken: {int(time.time() - start_time)} seconds")

def save_results(vulnerable_urls):
    save_choice = input(Fore.CYAN + "\n[?] Do you want to save the vulnerable URLs to a file? (y/n, press Enter for n): ").strip().lower()
    if save_choice == 'y':
        output_file = input(Fore.CYAN + "Enter the name of the output file (press Enter for 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
        with open(output_file, 'w') as f:
            for url in vulnerable_urls:
                f.write(url + '\n')
        print(Fore.GREEN + f"Vulnerable URLs have been saved to {output_file}")
    else:
        print(Fore.YELLOW + "Vulnerable URLs will not be saved.")

def run_lfi_scanner():
    """
    Runs the LFI scanner by performing requests with provided payloads
    to detect Local File Inclusion vulnerabilities.
    """
    clear_screen()
    print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")

    urls = prompt_for_urls()
    payloads = prompt_for_payloads()
    success_criteria_input = input("[?] Enter the success criteria patterns (comma-separated, e.g: 'root:,admin:', press Enter for 'root:x:0:'): ").strip()
    success_criteria = [pattern.strip() for pattern in success_criteria_input.split(',')] if success_criteria_input else ['root:x:0:']

    max_threads_input = input("[?] Enter the number of concurrent threads (0-10, press Enter for 5): ").strip()
    max_threads = int(max_threads_input) if max_threads_input.isdigit() and 0 <= int(max_threads_input) <= 10 else 5

    print(Fore.YELLOW + "\n[i] Loading, Please Wait...")
    time.sleep(1)
    clear_screen()
    print(Fore.CYAN + "[i] Starting scan...\n")

    total_found = 0
    total_scanned = 0
    start_time = time.time()
    vulnerable_urls = []

    for url in urls:
        print(Fore.YELLOW + f"\n[i] Scanning URL: {url}\n")
        found, urls_with_payloads = test_lfi(url, payloads, success_criteria, max_threads)
        total_found += found
        total_scanned += len(payloads)
        vulnerable_urls.extend(urls_with_payloads)

    print_scan_summary(total_found, total_scanned, start_time)
    save_results(vulnerable_urls)

def test_lfi(url, payloads, success_criteria, max_threads=5):
    def perform_request(payload):
        encoded_payload = quote(payload.strip())
        target_url = f"{url}{encoded_payload}"
        headers = {'User-Agent': get_random_user_agent()}
        try:
            response = requests.get(target_url, headers=headers)
            is_vulnerable = any(re.search(pattern, response.text) for pattern in success_criteria)
            if is_vulnerable:
                result = Fore.GREEN + f"[+] Vulnerable: {target_url}"
            else:
                result = Fore.RED + f"[-] Not Vulnerable: {target_url}"
            return result, is_vulnerable
        except requests.RequestException as e:
            print(Fore.RED + f"[!] Error accessing {target_url}: {str(e)}")
            return None, False

    found_vulnerabilities = 0
    vulnerable_urls = []

    if max_threads <= 1:
        for payload in payloads:
            result, is_vulnerable = perform_request(payload)
            if result:
                print(result)
                if is_vulnerable:
                    found_vulnerabilities += 1
                    vulnerable_urls.append(url + quote(payload.strip()))
    else:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(perform_request, payload): payload for payload in payloads}
            for future in as_completed(futures):
                try:
                    result, is_vulnerable = future.result()
                    if result:
                        print(result)
                        if is_vulnerable:
                            found_vulnerabilities += 1
                            vulnerable_urls.append(url + quote(futures[future].strip()))
                except Exception as e:
                    print(Fore.RED + f"[!] Exception occurred: {str(e)}")
    return found_vulnerabilities, vulnerable_urls
