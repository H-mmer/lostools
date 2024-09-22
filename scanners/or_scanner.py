# scanners/or_scanner.py

"""
Module for Open Redirect scanning functionality.
Optimized for handling large files efficiently.
"""

import os
import sys
import time
import asyncio
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from colorama import Fore, Style, init
from rich import print as rich_print
from rich.panel import Panel
from utils import clear_screen, check_and_install_packages, get_file_path, read_file_lines
from color import Color

def run_or_scanner(urls=None, payloads=None, threads=5, output_file=None):
    """
    Runs the Open Redirect scanner.
    Accepts optional arguments for URLs, payloads, number of threads, and output file.
    Optimized for handling large files efficiently.
    """
    init(autoreset=True)

    async def scan_url(sem, driver, target_url):
        async with sem:
            try:
                driver.get(target_url)
                await asyncio.sleep(2)
                current_url = driver.current_url

                if current_url == "https://www.google.com/":
                    print(Fore.GREEN + f"[+] Vulnerable: {target_url} redirects to {current_url}")
                    return True, target_url
                else:
                    print(Fore.RED + f"[-] Not Vulnerable: {target_url} (redirects to {current_url})")
                    return False, None

            except TimeoutException:
                print(Fore.RED + f"[-] Timeout occurred while testing {target_url}")
                return False, None

            except Exception as e:
                print(Fore.RED + f"[-] Error for URL {target_url}: {str(e)}")
                return False, None

    def test_open_redirect(urls, payloads, max_threads=5):
        found_vulnerabilities = 0
        vulnerable_urls = []

        async def main_async():
            nonlocal found_vulnerabilities, vulnerable_urls
            sem = asyncio.Semaphore(max_threads)
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--window-size=1920,1080")
            service = Service(ChromeDriverManager().install())

            tasks = []
            drivers = [webdriver.Chrome(service=service, options=chrome_options) for _ in range(max_threads)]
            driver_pool = asyncio.Queue()
            for driver in drivers:
                await driver_pool.put(driver)

            batch_size = max_threads * 10  # Adjust batch size as needed

            for url in urls:
                for payload in payloads:
                    target_url = f"{url}{payload.strip()}"
                    driver = await driver_pool.get()
                    task = asyncio.ensure_future(scan_url(sem, driver, target_url))
                    task.add_done_callback(lambda fut, drv=driver: driver_pool.put_nowait(drv))
                    tasks.append(task)

                    if len(tasks) >= batch_size:
                        results = await asyncio.gather(*tasks)
                        for is_vulnerable, target_url in results:
                            if is_vulnerable:
                                found_vulnerabilities += 1
                                vulnerable_urls.append(target_url)
                        tasks = []

            if tasks:
                results = await asyncio.gather(*tasks)
                for is_vulnerable, target_url in results:
                    if is_vulnerable:
                        found_vulnerabilities += 1
                        vulnerable_urls.append(target_url)

            while not driver_pool.empty():
                driver = await driver_pool.get()
                driver.quit()

        asyncio.run(main_async())
        return found_vulnerabilities, vulnerable_urls

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
                    single_url = input(Fore.BLUE + "[?] Enter a single URL to scan: ").strip()
                    if single_url:
                        return [single_url]
                    else:
                        print(Fore.RED + "[!] You must provide either a file with URLs or a single URL.")
                        input(Fore.YELLOW + "\n[i] Press Enter to try again...")
                        clear_screen()
                        print(Fore.GREEN + "Welcome to the Open Redirect Scanner!\n")
            except Exception as e:
                print(Fore.RED + f"[!] Error reading input file: {url_input}. Exception: {str(e)}")
                input(Fore.YELLOW + "[i] Press Enter to try again...")
                clear_screen()
                print(Fore.GREEN + "Welcome to the Open Redirect Scanner!\n")

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
                print(Fore.GREEN + "Welcome to the Open Redirect Scanner!\n")

    def print_scan_summary(total_found, total_scanned, start_time):
        print(Fore.YELLOW + "\n[i] Scanning finished.")
        print(Fore.YELLOW + f"[i] Total found: {total_found}")
        print(Fore.YELLOW + f"[i] Total scanned: {total_scanned}")
        print(Fore.YELLOW + f"[i] Time taken: {int(time.time() - start_time)} seconds")

    def save_results(vulnerable_urls):
        if output_file:
            with open(output_file, 'w') as f:
                for url in vulnerable_urls:
                    f.write(url + '\n')
            print(Fore.GREEN + f"Vulnerable URLs have been saved to {output_file}")
        else:
            save_choice = input(Fore.CYAN + "\n[?] Do you want to save the vulnerable URLs to a file? (y/n, press Enter for n): ").strip().lower()
            if save_choice == 'y':
                output_file_name = input(Fore.CYAN + "Enter the name of the output file (press Enter for 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
                with open(output_file_name, 'w') as f:
                    for url in vulnerable_urls:
                        f.write(url + '\n')
                print(Fore.GREEN + f"Vulnerable URLs have been saved to {output_file_name}")
            else:
                print(Fore.YELLOW + "Vulnerable URLs will not be saved.")

    if urls is None or payloads is None:
        clear_screen()

        required_packages = {
            'requests': '2.28.1',
            'prompt_toolkit': '3.0.36',
            'colorama': '0.4.6'
        }
        check_and_install_packages(required_packages)

        time.sleep(1)
        clear_screen()

        panel = Panel(r"""
            ____  ___    ____________   _  ___  __________
           / __ \/ _ \  / __/ ___/ _ | / |/ / |/ / __/ _  |
          / /_/ / , _/ _\ \/ /__/ __ |/    /    / _// , _/
          \____/_/|_| /___/\___/_/ |_/_/|_/_/|_/___/_/|_| 
                                                                
                                                                        
                                """,
            style="bold green",
            border_style="blue",
            expand=False
        )
        rich_print(panel, "\n")
        print(Fore.GREEN + "Welcome to the Open Redirect Scanner!\n")

        urls = prompt_for_urls()
        payloads = prompt_for_payloads()
        
        max_threads_input = input("[?] Enter the number of concurrent threads (0-100, press Enter for 5): ").strip()
        max_threads = int(max_threads_input) if max_threads_input.isdigit() and 0 <= int(max_threads_input) <= 100 else 5

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
        max_threads = threads

    total_found = 0
    total_scanned = 0
    start_time = time.time()
    vulnerable_urls = []

    if payloads:
        found, urls_with_payloads = test_open_redirect(urls, payloads, max_threads)
        total_found += found
        total_scanned += len(list(urls)) * len(list(payloads))
        vulnerable_urls.extend(urls_with_payloads)
    
    print_scan_summary(total_found, total_scanned, start_time)
    save_results(vulnerable_urls)
