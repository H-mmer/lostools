# main.py

"""
Main entry point for the scanning tool.
"""

import sys
import time
import argparse
import os  # Import os module
from colorama import Fore, Style, init
from rich import print as rich_print
from rich.panel import Panel
from utils import clear_screen
from color import Color
from scanners.sql_scanner import run_sql_scanner
from scanners.xss_scanner import run_xss_scanner
from scanners.or_scanner import run_or_scanner
from scanners.lfi_scanner import run_lfi_scanner
from updater import run_update

def display_menu():
    """
    Displays the main menu.
    """
    title = r"""
.____                   __ ____  ___.__
|    |    ____  _______/  |\   \/  /|  |   __________
|    |   /  _ \/  ___/\   __\     / |  |  /  ___/  _ \
|    |__(  <_> )___ \  |  | /     \ |  |__\___ (  <_> )
|_______ \____/____  > |__|/___/\  \|____/____  >____/
        \/         \/            \_/          \/
    """
    print(Color.ORANGE + Style.BRIGHT + title.center(63))
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)
    border_color = Color.CYAN + Style.BRIGHT
    option_color = Fore.WHITE + Style.BRIGHT

    print(border_color + "┌" + "─" * 61 + "┐")

    options = [
        "1] LFi Scanner",
        "2] OR Scanner",
        "3] SQLi Scanner",
        "4] XSS Scanner",
        "5] tool Update",
        "6] Exit"
    ]

    for option in options:
        print(border_color + "│" + option_color + option.ljust(59) + border_color + "│")

    print(border_color + "└" + "─" * 61 + "┘")
    authors = "Created by: Coffinxp, HexSh1dow, Naho and AnonKryptiQuz "
    instructions = "Select an option by entering the corresponding number:"

    print(Fore.WHITE + Style.BRIGHT + "─" * 63)
    print(Fore.WHITE + Style.BRIGHT + authors.center(63))
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)
    print(Fore.WHITE + Style.BRIGHT + instructions.center(63))
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)

def print_exit_menu():
    """
    Displays the exit message and exits the program.
    """
    #clear_screen()

    panel = Panel(r"""
 ______               ______
|   __ \.--.--.-----.|   __ \.--.--.-----.
|   __ <|  |  |  -__||   __ <|  |  |  -__|
|______/|___  |_____||______/|___  |_____|
        |_____|              |_____|

  Credit -  Coffinxp - HexSh1dow - AnonKryptiQuz - Naho
            """,
        style="bold green",
        border_style="blue",
        expand=False
    )

    rich_print(panel)
    print(Color.RED + "\n\nSession Off..\n")
    exit()

def prompt_for_inputs(scanner_name):
    """
    Prompts the user for necessary inputs in interactive mode.
    """
    urls = []
    payloads = []
    url_input = input("Enter the URLs to scan (comma-separated) or path to URL file: ").strip()
    if os.path.isfile(url_input):
        with open(url_input, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        urls = [url.strip() for url in url_input.split(',') if url.strip()]

    payload_input = input("Enter the payloads to use (comma-separated) or path to payload file: ").strip()
    if os.path.isfile(payload_input):
        with open(payload_input, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
    else:
        payloads = [payload.strip() for payload in payload_input.split(',') if payload.strip()]

    threads_input = input("Enter the number of threads to use (default 5): ").strip()
    threads = int(threads_input) if threads_input else 5

    output_file = input("Enter the output file (leave blank for none): ").strip() or None

    cookie = None
    if scanner_name == 'sqli':
        cookie = input("Enter the cookie to include in requests (leave blank for none): ").strip() or None

    return {
        'urls': urls,
        'payloads': payloads,
        'threads': threads,
        'output_file': output_file,
        'cookie': cookie
    }

def handle_selection(selection, args=None):
    """
    Handles the user's menu selection.
    """
    if selection == '1' or (args and args.scanner == 'lfi'):
        clear_screen()
        if not args:
            inputs = prompt_for_inputs('lfi')
        else:
            inputs = {
                'urls': args.urls,
                'payloads': args.payloads,
                'threads': args.threads or 5,
                'output_file': args.output_file,
                'cookie': None
            }
        run_lfi_scanner(
            urls=inputs['urls'],
            payloads=inputs['payloads'],
            threads=inputs['threads'],
            output_file=inputs['output_file']
        )

    elif selection == '2' or (args and args.scanner == 'or'):
        clear_screen()
        if not args:
            inputs = prompt_for_inputs('or')
        else:
            inputs = {
                'urls': args.urls,
                'payloads': args.payloads,
                'threads': args.threads or 5,
                'output_file': args.output_file,
                'cookie': None
            }
        run_or_scanner(
            urls=inputs['urls'],
            payloads=inputs['payloads'],
            threads=inputs['threads'],
            output_file=inputs['output_file']
        )

    elif selection == '3' or (args and args.scanner == 'sqli'):
        clear_screen()
        if not args:
            inputs = prompt_for_inputs('sqli')
        else:
            inputs = {
                'urls': args.urls,
                'payloads': args.payloads,
                'threads': args.threads or 5,
                'output_file': args.output_file,
                'cookie': args.cookie
            }
        run_sql_scanner(
            urls=inputs['urls'],
            payloads=inputs['payloads'],
            cookie=inputs['cookie'],
            threads=inputs['threads'],
            output_file=inputs['output_file']
        )

    elif selection == '4' or (args and args.scanner == 'xss'):
        clear_screen()
        if not args:
            inputs = prompt_for_inputs('xss')
        else:
            inputs = {
                'urls': args.urls,
                'payloads': args.payloads,
                'threads': args.threads or 5,
                'output_file': args.output_file,
                'cookie': None
            }
        run_xss_scanner(
            urls=inputs['urls'],
            payloads=inputs['payloads'],
            threads=inputs['threads'],
            output_file=inputs['output_file']
        )

    elif selection == '5' or (args and args.scanner == 'update'):
        clear_screen()
        run_update()

    elif selection == '6':
        clear_screen()
        print_exit_menu()

    else:
        print_exit_menu()

def main():
    """
    Main function that runs the program.
    """
    #import urllib3
    #urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #clear_screen()
    #time.sleep(1)
    #clear_screen()

    parser = argparse.ArgumentParser(description='Scanning Tool')
    parser.add_argument('-s', '--scanner', choices=['lfi', 'or', 'sqli', 'xss', 'update'], help='Select scanner to run')
    parser.add_argument('-u', '--urls', nargs='+', help='URLs to scan (space-separated)')
    parser.add_argument('-uf', '--url-file', help='File containing URLs to scan')
    parser.add_argument('-p', '--payloads', nargs='+', help='Payloads to use (space-separated)')
    parser.add_argument('-pf', '--payload-file', help='File containing payloads to use')
    parser.add_argument('-c', '--cookie', help='Cookie to include in requests (for SQLi scanner)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    parser.add_argument('-o', '--output-file', help='Output file to save vulnerable URLs')
    args = parser.parse_args()

    if len(sys.argv) == 1:
        # No arguments provided, run in interactive mode
        while True:
            display_menu()
            choice = input(f"\n{Fore.CYAN}[?] Select an option (1-6): {Style.RESET_ALL}").strip()
            handle_selection(choice)
    else:
        # Arguments provided, run in non-interactive mode
        if args.url_file:
            if os.path.isfile(args.url_file):
                with open(args.url_file) as f:
                    args.urls = [line.strip() for line in f if line.strip()]
            else:
                print(f"{Fore.RED}[!] URL file not found: {args.url_file}")
                sys.exit(1)
        if args.payload_file:
            if os.path.isfile(args.payload_file):
                with open(args.payload_file) as f:
                    args.payloads = [line.strip() for line in f if line.strip()]
            else:
                print(f"{Fore.RED}[!] Payload file not found: {args.payload_file}")
                sys.exit(1)
        handle_selection(None, args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_exit_menu()
