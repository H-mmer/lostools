# scanners/lfi_scanner.py

"""
Module for Local File Inclusion (LFI) scanning functionality.
Optimized for handling large files efficiently.
"""

import os
import sys
import time
import random
import asyncio
import aiohttp
import urllib3
from urllib.parse import quote
from colorama import Fore, Style, init
from rich import print as rich_print
from rich.panel import Panel
from utils import get_random_user_agent, clear_screen, get_file_path, read_file_lines
from color import Color

def run_lfi_scanner(urls=None, payloads=None, threads=50, output_file=None):
    """
    Runs the LFI scanner.
    Accepts optional arguments for URLs, payloads, number of threads, and output file.
    Optimized for large files by reading inputs lazily.
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    init(autoreset=True)

    async def perform_request(session, url, payload):
        encoded_payload = quote(payload.strip())
        target_url = f"{url}{encoded_payload}"
        start_time = time.time()
            
        headers = {
            'User-Agent': get_random_user_agent()
        }

        try:
            async with session.get(target_url, headers=headers) as response:
                content = await response.text()
                response_time = time.time() - start_time
                is_vulnerable = any(criteria in content for criteria in success_criteria)
                return is_vulnerable, target_url, response_time
        except Exception as e:
            print(Fore.RED + f"[!] Error accessing {target_url}: {str(e)}")
            return False, target_url, time.time() - start_time

    def save_prompt(vulnerable_urls=[]):
        if output_file:
            with open(output_file, 'w') as f:
                for url in vulnerable_urls:
                    f.write(url + '\n')
            print(f"{Fore.GREEN}Vulnerable URLs have been saved to {output_file}")
        else:
            save_choice = input(f"{Fore.CYAN}\n[?] Do you want to save the vulnerable URLs to a file? (y/n, press Enter for n): ").strip().lower()
            if save_choice == 'y':
                output_file_name = input(f"{Fore.CYAN}[?] Enter the name of the output file (press Enter for 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
                with open(output_file_name, 'w') as f:
                    for url in vulnerable_urls:
                        f.write(url + '\n')
                print(f"{Fore.GREEN}Vulnerable URLs have been saved to {output_file_name}")
            else:
                print(f"{Fore.YELLOW}Vulnerable URLs will not be saved.")

    def prompt_for_urls():
        while True:
            try:
                url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter to input a single URL): ")
                if url_input:
                    if not os.path.isfile(url_input):
                        raise FileNotFoundError(f"File not found: {url_input}")
                    urls = read_file_lines(url_input)
                    return urls
                else:
                    single_url = input(Fore.CYAN + "[?] Enter a single URL to scan: ").strip()
                    if single_url:
                        return [single_url]
                    else:
                        print(Fore.RED + "[!] You must provide either a file with URLs or a single URL.")
                        input(Fore.YELLOW + "\n[i] Press Enter to try again...")
                        clear_screen()
                        print(Fore.GREEN + "Welcome to the LFI Scanner!\n")
            except Exception as e:
                print(Fore.RED + f"[!] Error reading input file: {url_input}. Exception: {str(e)}")
                input(Fore.YELLOW + "[i] Press Enter to try again...")
                clear_screen()
                print(Fore.GREEN + "Welcome to the LFI Scanner!\n")

    def prompt_for_payloads():
        while True:
            try:
                payload_input = get_file_path("[?] Enter the path to the payloads file: ")
                if not os.path.isfile(payload_input):
                    raise FileNotFoundError(f"File not found: {payload_input}")
                payloads = read_file_lines(payload_input)
                return payloads
            except Exception as e:
                print(Fore.RED + f"[!] Error reading payload file: {payload_input}. Exception: {str(e)}")
                input(Fore.YELLOW + "[i] Press Enter to try again...")
                clear_screen()
                print(Fore.GREEN + "Welcome to the LFI Scanner!\n")

    def print_scan_summary(total_found, total_scanned, start_time):
        print(Fore.YELLOW + "\n[i] Scanning finished.")
        print(Fore.YELLOW + f"[i] Total found: {total_found}")
        print(Fore.YELLOW + f"[i] Total scanned: {total_scanned}")
        print(Fore.YELLOW + f"[i] Time taken: {int(time.time() - start_time)} seconds")

    async def main_async():
        nonlocal vulnerable_urls, total_scanned
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(ssl=False, limit=threads)
        sem = asyncio.Semaphore(threads)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = []
            batch_size = threads * 10  # Adjust batch size as needed

            for url in urls:
                for payload in payloads:
                    total_scanned += 1
                    task = asyncio.ensure_future(limited_perform_request(sem, session, url, payload))
                    tasks.append(task)

                    if len(tasks) >= batch_size:
                        for future in asyncio.as_completed(tasks):
                            is_vulnerable, target_url, response_time = await future
                            payload_part = target_url.replace(url, '')
                            print(Fore.YELLOW + f"\n[i] Scanning with payload: {payload_part}")
                            if is_vulnerable:
                                print(Fore.GREEN + f"[+] Vulnerable: {Fore.WHITE} {target_url} {Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                                vulnerable_urls.append(target_url)
                            else:
                                print(Fore.RED + f"[-] Not Vulnerable: {Fore.WHITE} {target_url} {Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                        tasks = []

            if tasks:
                for future in asyncio.as_completed(tasks):
                    is_vulnerable, target_url, response_time = await future
                    payload_part = target_url.replace(url, '')
                    print(Fore.YELLOW + f"\n[i] Scanning with payload: {payload_part}")
                    if is_vulnerable:
                        print(Fore.GREEN + f"[+] Vulnerable: {Fore.WHITE} {target_url} {Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                        vulnerable_urls.append(target_url)
                    else:
                        print(Fore.RED + f"[-] Not Vulnerable: {Fore.WHITE} {target_url} {Fore.CYAN} - Response Time: {response_time:.2f} seconds")

    async def limited_perform_request(sem, session, url, payload):
        async with sem:
            return await perform_request(session, url, payload)

    if urls is None or payloads is None:
        clear_screen()
        time.sleep(1)
        clear_screen()
        panel = Panel(r"""
    __    __________   _____                                 
   / /   / ____/  _/  / ___/_________ _____  ____  ___  _____
  / /   / /_   / /    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /___/ __/ _/ /    ___/ / /__/ /_/ / / / / / / /  __/ /    
/_____/_/   /___/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                                            
                """,
            style="bold green",
            border_style="blue",
            expand=False
        )
        rich_print(panel, "\n")
        print(Fore.GREEN + "Welcome to the LFI Scanner!\n")

        urls = prompt_for_urls()
        payloads = prompt_for_payloads()

        success_criteria_input = input("[?] Enter the success criteria patterns (comma-separated, e.g: 'root:,admin:', press Enter for 'root:x:0:'): ").strip()
        success_criteria = [pattern.strip() for pattern in success_criteria_input.split(',')] if success_criteria_input else ['root:x:0:']

        max_threads_input = input("[?] Enter the number of concurrent threads (0-1000, press Enter for 50): ").strip()
        threads = int(max_threads_input) if max_threads_input.isdigit() and 0 <= int(max_threads_input) <= 1000 else 50

        print(Fore.YELLOW + "\n[i] Loading, Please Wait...")
        time.sleep(1)
        clear_screen()
        print(Fore.CYAN + "[i] Starting scan...\n")
    else:
        if isinstance(urls, str):
            if os.path.isfile(urls):
                urls = read_file_lines(urls)
            else:
                urls = [urls]
        if isinstance(payloads, str):
            if os.path.isfile(payloads):
                payloads = read_file_lines(payloads)
            else:
                payloads = [payloads]
        if not urls:
            print(f"{Fore.RED}[!] No URLs provided.")
            sys.exit(1)
        if not payloads:
            print(f"{Fore.RED}[!] No payloads provided.")
            sys.exit(1)
        success_criteria = ['root:x:0:']  # Default success criteria

    vulnerable_urls = []
    total_scanned = 0

    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main_async())

        print_scan_summary(len(vulnerable_urls), total_scanned, time.time())
        save_prompt(vulnerable_urls)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nProgram terminated by the user!")
        print_scan_summary(len(vulnerable_urls), total_scanned, time.time())
        save_prompt(vulnerable_urls)
        sys.exit(0)
