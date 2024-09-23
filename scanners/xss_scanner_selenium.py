# scanners/xss_scanner.py

"""
Module for Cross-Site Scripting (XSS) scanning functionality.
Optimized for handling large files efficiently.
"""

import os
import sys
import time
import asyncio
import aiohttp
import logging
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from colorama import Fore, Style, init
from utils import get_random_user_agent, clear_screen, get_file_path, read_file_lines
from color import Color
from rich import print as rich_print
from rich.panel import Panel
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.chrome.service import Service  # Import Service

def run_xss_scanner_selenium(urls=None, payloads=None, threads=5, output_file=None):
    """
    Runs the XSS scanner.
    Accepts optional arguments for URLs, payloads, number of threads, and output file.
    Optimized for handling large files efficiently.
    """
    init(autoreset=True)
    logging.getLogger('aiohttp').setLevel(logging.CRITICAL)
    logging.getLogger('WDM').setLevel(logging.ERROR)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    class MassScanner:
        def __init__(self, urls, payloads, output, concurrency, timeout):
            self.urls = urls
            self.payloads = payloads
            self.output = output
            self.concurrency = concurrency
            self.timeout = timeout
            self.potential_vulnerable_urls = []
            self.confirmed_vulnerable_urls = []
            self.totalScanned = 0
            self.t0 = time.time()

        def generate_payload_urls(self):
            for url in self.urls:
                scheme, netloc, path, query_string, fragment = urlsplit(url)
                if not scheme:
                    scheme = 'http'
                query_params = parse_qs(query_string, keep_blank_values=True)
                if not query_params:
                    continue  # Skip URLs without query parameters
                for key in query_params.keys():
                    for payload in self.payloads:
                        modified_params = query_params.copy()
                        modified_params[key] = [payload]
                        modified_query_string = urlencode(modified_params, doseq=True)
                        modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
                        yield modified_url, payload, key

        async def scan_url(self, session, url, payload, param):
            try:
                headers = {
                    'User-Agent': get_random_user_agent(),
                    'Accept': '*/*',
                    'Connection': 'close'
                }
                async with session.get(url, headers=headers, timeout=self.timeout, ssl=False) as response:
                    self.totalScanned += 1
                    text = await response.text()
                    if payload in text:
                        print(Color.YELLOW + f"[!] Potential XSS found (reflected): {url}")
                        self.potential_vulnerable_urls.append((url, payload))
                    else:
                        print(Color.RED + f"[-] Not Vulnerable: {url}")
            except Exception as e:
                logging.error(f"Error scanning {url}: {str(e)}")

        async def initial_scan(self):
            sem = asyncio.Semaphore(self.concurrency)
            connector = aiohttp.TCPConnector(limit=0)  # No limit on total connections
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                async def bound_scan(url, payload, param):
                    async with sem:
                        await self.scan_url(session, url, payload, param)

                tasks = []
                for url, payload, param in self.generate_payload_urls():
                    task = asyncio.create_task(bound_scan(url, payload, param))
                    tasks.append(task)
                    # Process tasks in batches to limit memory usage
                    if len(tasks) >= 10000:
                        await asyncio.gather(*tasks)
                        tasks = []

                if tasks:
                    await asyncio.gather(*tasks)

        async def confirm_vulnerability(self, sem, driver, url, payload):
            async with sem:
                try:
                    driver.get(url)
                    WebDriverWait(driver, 0.03).until(EC.alert_is_present())
                    try:
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                        print(Color.GREEN + f"[+] XSS Vulnerability Confirmed: {url}")
                        self.confirmed_vulnerable_urls.append(url)
                    except:
                        print(Color.YELLOW + f"[!] Potential XSS not confirmed: {url}")
                except Exception as e:
                    logging.error(f"Error confirming XSS on {url}: {str(e)}")

        async def confirm_vulnerabilities(self):
            # Limit the number of concurrent Selenium instances
            sem = asyncio.Semaphore(min(self.concurrency, 5))  # Limit to 5 Selenium instances
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--log-level=3")
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-infobars')
            chrome_options.add_argument('--remote-debugging-port=9222')
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
            driver_path = ChromeDriverManager().install()

            # Create a fixed number of WebDriver instances
            drivers = [webdriver.Chrome(service=Service(driver_path), options=chrome_options) for _ in range(sem._value)]
            tasks = []
            for idx, (url, payload) in enumerate(self.potential_vulnerable_urls):
                driver = drivers[idx % len(drivers)]
                task = asyncio.create_task(self.confirm_vulnerability(sem, driver, url, payload))
                tasks.append(task)
            await asyncio.gather(*tasks)
            # Quit all drivers
            for driver in drivers:
                driver.quit()

        def save_vulnerable_urls(self):
            if self.confirmed_vulnerable_urls:
                with open(self.output, "w") as output_file:
                    for url in self.confirmed_vulnerable_urls:
                        output_file.write(url + "\n")
                print(f"{Fore.GREEN}[+] Vulnerable URLs saved to {self.output}")
            else:
                print(f"{Fore.YELLOW}No confirmed vulnerabilities found. No URLs to save.")

        def run(self):
            asyncio.run(self.initial_scan())
            print(f"{Fore.YELLOW}\n[i] Initial scanning finished.")
            print(f"{Fore.YELLOW}[i] Total URLs scanned: {self.totalScanned}")
            print(f"{Fore.YELLOW}[i] Potential vulnerabilities found: {len(self.potential_vulnerable_urls)}")

            if self.potential_vulnerable_urls:
                print(f"{Fore.CYAN}[i] Confirming potential vulnerabilities...")
                asyncio.run(self.confirm_vulnerabilities())
                print(f"{Fore.YELLOW}\n[i] Confirmation finished.")
                print(f"{Fore.GREEN}[i] Confirmed vulnerabilities: {len(self.confirmed_vulnerable_urls)}")
            else:
                print(f"{Fore.YELLOW}[i] No potential vulnerabilities to confirm.")

            if self.output:
                self.save_vulnerable_urls()
            else:
                #save_option = input(f"{Fore.CYAN}[?] Do you want to save the confirmed vulnerable URLs to a file? (y/n, press Enter for n): ").strip().lower()
                #if save_option == 'y':
                #    output_file_name = input(f"{Fore.CYAN}[?] Enter the name of the output file (press Enter for 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
                #    self.output = output_file_name
                #    self.save_vulnerable_urls()
                #else:
                print(f"{Fore.YELLOW}Confirmed vulnerable URLs will not be saved.")

            print(f"{Fore.YELLOW}[i] Total time taken: {int(time.time() - self.t0)} seconds")

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
                        print(Fore.GREEN + "Welcome to the XSS Scanner!\n")
            except Exception as e:
                print(Fore.RED + f"[!] Error reading input file: {url_input}. Exception: {str(e)}")
                input(Fore.YELLOW + "[i] Press Enter to try again...")
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
                print(Fore.GREEN + "Welcome to the XSS Scanner!\n")

    # Display the panel at the start of the module execution
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

    if urls is None or payloads is None:
        print(Fore.GREEN + "Welcome to the XSS Scanner!\n")
        urls = prompt_for_urls()
        payloads = prompt_for_payloads()

        concurrency_input = input("\n[?] Enter the number of concurrent threads (1-1000, press Enter for 50): ").strip()
        concurrency = int(concurrency_input) if concurrency_input.isdigit() and 1 <= int(concurrency_input) <= 1000 else 50

        timeout_input = input("[?] Enter the request timeout in seconds (press Enter for 3): ").strip()
        timeout = float(timeout_input) if timeout_input else 3.0

        print(f"\n{Fore.YELLOW}[i] Loading, Please Wait...")
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
