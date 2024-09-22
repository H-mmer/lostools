"""
Module for performing SQL Injection scanning.
"""

import os
import time
import sys
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
                    print(Fore.GREEN + "Welcome to the SQL Injection Testing Tool!\n")
        except Exception as e:
            print(Fore.RED + f"[!] Error reading input file: {url_input}. Exception: {str(e)}")
            input(Fore.YELLOW + "[i] Press Enter to try again...")
            clear_screen()
            print(Fore.GREEN + "Welcome to the SQL Injection Testing Tool!\n")

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
            print(Fore.GREEN + "Welcome to the SQL Injection Testing Tool!\n")

def print_scan_summary(total_found, total_scanned, start_time):
    print(f"{Fore.YELLOW}\n[i] Scanning finished.")
    print(f"{Fore.YELLOW}[i] Total found: {total_found}")
    print(f"{Fore.YELLOW}[i] Total scanned: {total_scanned}")
    print(f"{Fore.YELLOW}[i] Time taken: {int(time.time() - start_time)} seconds")

def save_prompt(vulnerable_urls=[]):
    save_choice = input(f"{Fore.CYAN}\n[?] Do you want to save the vulnerable URLs to a file? (y/n, press Enter for n): ").strip().lower()
    if save_choice == 'y':
        output_file = input(f"{Fore.CYAN}[?] Enter the name of the output file (press Enter for 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
        with open(output_file, 'w') as f:
            for url in vulnerable_urls:
                f.write(url + '\n')
        print(f"{Fore.GREEN}Vulnerable URLs have been saved to {output_file}")
    else:
        print(f"{Fore.YELLOW}Vulnerable URLs will not be saved.")

def run_sql_scanner():
    """
    Runs the SQL Injection scanner.
    """
    clear_screen()
    print(f"{Fore.GREEN}Welcome to the SQL Injection Testing Tool!\n")

    urls = prompt_for_urls()
    payloads = prompt_for_payloads()

    cookie = input("[?] Enter the cookie to include in the GET request (press Enter if none): ").strip() or None

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
        url_with_payload = f"{url}{payload}"
        headers = {'User-Agent': get_random_user_agent()}
        try:
            response = requests.get(url_with_payload, headers=headers, cookies={'cookie': cookie} if cookie else None, timeout=5)
            response_time = response.elapsed.total_seconds()
            # Logic to determine if the response indicates a vulnerability
            if response.status_code == 200 and "error" in response.text.lower():
                print(f"{Fore.GREEN}Vulnerable: {Fore.WHITE}{url_with_payload}")
                return url_with_payload
            else:
                print(f"{Fore.RED}Not Vulnerable: {Fore.WHITE}{url_with_payload}")
                return None
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
    save_prompt(vulnerable_urls)
