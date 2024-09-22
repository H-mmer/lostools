"""
Module for performing XSS scanning.
"""

import os
import time
import re
import urllib3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlparse, parse_qs, urlencode, urlunparse
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
                    print(Fore.GREEN + "Welcome to the XSS Testing Tool!\n")
        except Exception as e:
            print(Fore.RED + f"[!] Error reading input file: {url_input}. Exception: {str(e)}")
            input(Fore.YELLOW + "[i] Press Enter to try again...")
            clear_screen()
            print(Fore.GREEN + "Welcome to the XSS Testing Tool!\n")


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
            print(Fore.GREEN + "Welcome to the XSS Testing Tool!\n")


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


def run_xss_scanner():
    """
    Runs the XSS scanner.
    """
    clear_screen()
    print(Fore.GREEN + "Welcome to the XSS Testing Tool!\n")

    urls = prompt_for_urls()
    payloads = prompt_for_payloads()

    threads_input = input("[?] Enter the number of concurrent threads (0-10, press Enter for 5): ").strip()
    threads = int(threads_input) if threads_input.isdigit() and 0 <= int(threads_input) <= 10 else 5

    print(f"\n{Fore.YELLOW}[i] Loading, Please Wait...")
    time.sleep(1)
    clear_screen()
    print(f"{Fore.CYAN}[i] Starting scan...")

    vulnerable_urls = []
    total_scanned = 0
    start_time = time.time()

    def perform_request(url, payload):
        headers = {'User-Agent': get_random_user_agent()}
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            for param in query_params:
                original_value = query_params[param][0]
                query_params[param] = payload
                new_query = urlencode(query_params, doseq=True)
                vulnerable_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
                response = requests.get(vulnerable_url, headers=headers, timeout=5, verify=False)
                if payload in response.text:
                    print(f"{Fore.GREEN}Vulnerable: {Fore.WHITE}{vulnerable_url}")
                    return vulnerable_url
                else:
                    print(f"{Fore.RED}Not Vulnerable: {Fore.WHITE}{vulnerable_url}")
                query_params[param] = original_value  # Reset to original value
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Error: {e}")
        return None

    if threads <= 1:
        for url in urls:
            for payload in payloads:
                total_scanned += 1
                result = perform_request(url.strip(), payload.strip())
                if result:
                    vulnerable_urls.append(result)
    else:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for url in urls:
                for payload in payloads:
                    total_scanned += 1
                    futures.append(executor.submit(perform_request, url.strip(), payload.strip()))
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerable_urls.append(result)

    print_scan_summary(len(vulnerable_urls), total_scanned, start_time)
    save_results(vulnerable_urls)
