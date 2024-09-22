# scanners/sql_scanner.py

"""
Module for SQL injection scanning functionality.
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

def run_sql_scanner(urls=None, payloads=None, cookie=None, threads=50, output_file=None):
    """
    Runs the SQL injection scanner.
    Accepts optional arguments for URLs, payloads, cookie, number of threads, and output file.
    Optimized for large files by reading inputs lazily.
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    init(autoreset=True)

    async def perform_request(session, url, payload, cookie):
        url_with_payload = f"{url}{payload.strip()}"
        start_time = time.time()
            
        headers = {
            'User-Agent': get_random_user_agent()
        }

        try:
            async with session.get(url_with_payload, headers=headers, cookies={'cookie': cookie} if cookie else None) as response:
                await response.text()
                response_time = time.time() - start_time
                if response_time >= 10:
                    success = True
                else:
                    success = False
                error_message = None
        except Exception as e:
            success = False
            error_message = str(e)
            response_time = time.time() - start_time

        return success, url_with_payload, response_time, error_message

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
                    single_url = input(f"{Fore.CYAN}[?] Enter a single URL to scan: ").strip()
                    if single_url:
                        return [single_url]
                    else:
                        print(f"{Fore.RED}[!] You must provide either a file with URLs or a single URL.")
                        input(f"{Fore.YELLOW}\n[i] Press Enter to try again...")
                        clear_screen()
                        print(f"{Fore.GREEN}Welcome to the SQL Injection Scanner!\n")
            except Exception as e:
                print(f"{Fore.RED}[!] Error reading input file: {url_input}. Exception: {str(e)}")
                input(f"{Fore.YELLOW}[i] Press Enter to try again...")
                clear_screen()
                print(f"{Fore.GREEN}Welcome to the SQL Injection Scanner!\n")

    def prompt_for_payloads():
        while True:
            try:
                payload_input = get_file_path("[?] Enter the path to the payloads file: ")
                if not os.path.isfile(payload_input):
                    raise FileNotFoundError(f"File not found: {payload_input}")
                payloads = read_file_lines(payload_input)
                return payloads
            except Exception as e:
                print(f"{Fore.RED}[!] Error reading payload file: {payload_input}. Exception: {str(e)}")
                input(f"{Fore.YELLOW}[i] Press Enter to try again...")
                clear_screen()
                print(f"{Fore.GREEN}Welcome to the SQL Injection Scanner!\n")

    def print_scan_summary(total_found, total_scanned, start_time):
        print(f"{Fore.YELLOW}\n[i] Scanning finished.")
        print(f"{Fore.YELLOW}[i] Total found: {total_found}")
        print(f"{Fore.YELLOW}[i] Total scanned: {total_scanned}")
        print(f"{Fore.YELLOW}[i] Time taken: {int(time.time() - start_time)} seconds")

    async def main_async():
        nonlocal vulnerable_urls, total_scanned
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(ssl=False, limit_per_host=threads)
        sem = asyncio.Semaphore(threads)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = []
            batch_size = threads * 10  # Adjust batch size as needed

            for url in urls:
                for payload in payloads:
                    total_scanned += 1
                    task = asyncio.ensure_future(limited_perform_request(sem, session, url, payload, cookie))
                    tasks.append(task)

                    if len(tasks) >= batch_size:
                        for future in asyncio.as_completed(tasks):
                            success, url_with_payload, response_time, error_message = await future
                            stripped_payload = url_with_payload.replace(url, '')
                            if success:
                                encoded_stripped_payload = quote(stripped_payload, safe='')
                                encoded_url = f"{url}{encoded_stripped_payload}"
                                print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                                print(f"{Fore.GREEN}Vulnerable: {Fore.WHITE}{encoded_url}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                                vulnerable_urls.append(url_with_payload)
                            else:
                                print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                                print(f"{Fore.RED}Not Vulnerable: {Fore.WHITE}{url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                        tasks = []

            if tasks:
                for future in asyncio.as_completed(tasks):
                    success, url_with_payload, response_time, error_message = await future
                    stripped_payload = url_with_payload.replace(url, '')
                    if success:
                        encoded_stripped_payload = quote(stripped_payload, safe='')
                        encoded_url = f"{url}{encoded_stripped_payload}"
                        print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                        print(f"{Fore.GREEN}Vulnerable: {Fore.WHITE}{encoded_url}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                        vulnerable_urls.append(url_with_payload)
                    else:
                        print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                        print(f"{Fore.RED}Not Vulnerable: {Fore.WHITE}{url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")

    async def limited_perform_request(sem, session, url, payload, cookie):
        async with sem:
            return await perform_request(session, url, payload, cookie)

    if urls is None or payloads is None:
        clear_screen()
        time.sleep(1)
        clear_screen()

        panel = Panel(r"""                                                       
           ___                                         
   _________ _/ (_)  ______________ _____  ____  ___  _____
  / ___/ __ `/ / /  / ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 (__  ) /_/ / / /  (__  ) /__/ /_/ / / / / / / /  __/ /    
/____/\__, /_/_/  /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
        /_/                                                
                    """,
            style="bold green",
            border_style="blue",
            expand=False
            )
        rich_print(panel, "\n")

        print(Fore.GREEN + "Welcome to the SQL Injection Scanner!\n")

        urls = prompt_for_urls()
        payloads = prompt_for_payloads()
        
        cookie = input("[?] Enter the cookie to include in the GET request (press Enter if none): ").strip() or None

        threads_input = input("[?] Enter the number of concurrent threads (0-1000, press Enter for 50): ").strip()
        threads = int(threads_input) if threads_input.isdigit() and 0 <= int(threads_input) <= 1000 else 50
        print(f"\n{Fore.YELLOW}[i] Loading, Please Wait...")
        time.sleep(1)
        clear_screen()
        print(f"{Fore.CYAN}[i] Starting scan...")
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

    vulnerable_urls = []
    total_scanned = 0
    start_time = time.time()

    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main_async())

        print_scan_summary(len(vulnerable_urls), total_scanned, start_time)
        save_prompt(vulnerable_urls)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Program terminated by the user!\n")
        print_scan_summary(len(vulnerable_urls), total_scanned, start_time)
        save_prompt(vulnerable_urls)
        sys.exit(0)
