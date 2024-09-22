# scanners/xss_scanner.py

"""
Module for Cross-Site Scripting (XSS) scanning functionality.
Optimized for handling large files efficiently.
"""

import os
import sys
import time
import random
import asyncio
import aiohttp
import logging
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from colorama import Fore, Style, init
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from utils import get_random_user_agent, clear_screen, get_file_path, read_file_lines
from color import Color

def run_xss_scanner(urls=None, payloads=None, threads=5, output_file=None):
    """
    Runs the XSS scanner.
    Accepts optional arguments for URLs, payloads, number of threads, and output file.
    Optimized for handling large files efficiently.
    """
    init(autoreset=True)
    logging.getLogger('WDM').setLevel(logging.ERROR)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    class MassScanner:
        def __init__(self, urls, payloads, output, concurrency, timeout):
            self.urls = urls
            self.payloads = payloads
            self.output = output
            self.concurrency = concurrency
            self.timeout = timeout
            self.injectables = []
            self.totalFound = 0
            self.totalScanned = 0
            self.t0 = time.time()

        def generate_payload_urls(self, url, payload):
            try:
                scheme, netloc, path, query_string, fragment = urlsplit(url)
                if not scheme:
                    scheme = 'http'
                query_params = parse_qs(query_string, keep_blank_values=True)
                for key in query_params.keys():
                    modified_params = query_params.copy()
                    modified_params[key] = [payload]
                    modified_query_string = urlencode(modified_params, doseq=True)
                    modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
                    yield modified_url
            except Exception as e:
                logging.error(f"Error generating payload URL for {url} with payload {payload}: {str(e)}")

        async def scan_url(self, sem, driver_queue, url):
            async with sem:
                driver = await driver_queue.get()
                self.totalScanned += 1
                try:
                    driver.get(url)
                    await asyncio.sleep(1)
                    try:
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                        print(Color.GREEN + f"[+] Vulnerable URL : {url}")
                        self.injectables.append(url)
                    except:
                        print(Color.RED + f"[-] Not Vulnerable: {url}")
                except Exception as e:
                    logging.error(f"Error scanning {url}: {str(e)}")
                finally:
                    await driver_queue.put(driver)

        async def scan(self):
            sem = asyncio.Semaphore(self.concurrency)
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--log-level=3")

            service = ChromeService(executable_path=ChromeDriverManager().install())

            drivers = [webdriver.Chrome(service=service, options=chrome_options) for _ in range(self.concurrency)]
            driver_queue = asyncio.Queue()
            for driver in drivers:
                await driver_queue.put(driver)

            tasks = []
            batch_size = self.concurrency * 10  # Adjust batch size as needed

            for payload in self.payloads:
                print(f"{Fore.YELLOW}[i] Scanning with payload: {payload}\n")
                for url in self.urls:
                    for payload_url in self.generate_payload_urls(url.strip(), payload):
                        task = asyncio.ensure_future(self.scan_url(sem, driver_queue, payload_url))
                        tasks.append(task)

                        if len(tasks) >= batch_size:
                            await asyncio.gather(*tasks)
                            tasks = []

                if tasks:
                    await asyncio.gather(*tasks)
                    tasks = []

            while not driver_queue.empty():
                driver = await driver_queue.get()
                driver.quit()

        def save_injectables_to_file(self):
            if self.injectables:
                with open(self.output, "w") as output_file:
                    for url in self.injectables:
                        output_file.write(url + "\n")
                print(f"{Fore.GREEN}[+] Vulnerable URLs saved to {self.output}")
            else:
                print(f"{Fore.YELLOW}No vulnerabilities found. No URLs to save.")

        def run(self):
            asyncio.run(self.scan())
            try:
                print(f"{Fore.YELLOW}\n[i] Scanning finished.")
                print(f"{Fore.YELLOW}[i] Total scanned: {self.totalScanned}")
                print(f"{Fore.YELLOW}[i] Time taken: {int(time.time() - self.t0)} seconds\n")
                print(f"{Fore.GREEN}[i] Vulnerabilities found: {len(self.injectables)}")

                if self.output:
                    self.save_injectables_to_file()
                else:
                    save_option = input(f"{Fore.CYAN}[?] Do you want to save the vulnerable URLs to a file? (y/n, press Enter for n): ").strip().lower()
                    if save_option == 'y':
                        output_file_name = input(f"{Fore.CYAN}[?] Enter the name of the output file (press Enter for 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
                        self.output = output_file_name
                        self.save_injectables_to_file()
                    else:
                        print(f"{Fore.YELLOW}Vulnerable URLs will not be saved.")
            except KeyboardInterrupt:
                sys.exit(0)

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
                        print(Fore.GREEN + "Welcome to the XSS Scanner!\n")
            except Exception as e:
                print(Fore.RED + f"[!] Error reading input file: {url_input}. Exception: {str(e)}")
                input(Fore.YELLOW + "[i] Press Enter to try again...")
                clear_screen()
                print(Fore.GREEN + "Welcome to the XSS Scanner!\n")

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
                print(Fore.GREEN + "Welcome to the XSS Scanner!\n")

    if urls is None or payloads is None:
        clear_screen()
        time.sleep(1)
        clear_screen()
        panel = Panel(r"""
       _  __________  ____________   _  ___  __________
      | |/_/ __/ __/ / __/ ___/ _ | / |/ / |/ / __/ _  |
      >  <_\ \_\ \  _\ \/ /__/ __ |/    /    / _// , _/
    /_/|_/___/___/ /___/\___/_/ |_/_/|_/_/|_/___/_/|_| 

                                            """,
            style="bold green",
            border_style="blue",
            expand=False
        )
        rich_print(panel, "\n")

        print(Fore.GREEN + "Welcome to the XSS Scanner!\n")
        urls = prompt_for_urls()
        payloads = prompt_for_payloads()

        concurrency_input = input("\n[?] Enter the number of concurrent threads (0-100, press Enter for 5): ").strip()
        concurrency = int(concurrency_input) if concurrency_input.isdigit() and 0 <= int(concurrency_input) <= 100 else 5

        timeout_input = input("[?] Enter the request timeout in seconds (press Enter for 3): ").strip()
        timeout = float(timeout_input) if timeout_input else 3.0

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
        concurrency = threads
        timeout = 3.0  # Default timeout if not specified

    scanner = MassScanner(
        urls=urls,
        payloads=payloads,
        output=output_file,
        concurrency=concurrency,
        timeout=timeout
    )

    scanner.run()
