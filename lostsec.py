#!/usr/bin/env python
"""
Main entry point for the lostxlso scanning tool.
This module handles command-line arguments and invokes the relevant scanner functions.
When run without arguments, it displays the interactive menu.
"""

import sys
import argparse
from libs.utils import clear_screen, display_menu, print_exit_menu
from libs.scanners.lfi_scanner import run_lfi_scanner
from libs.scanners.sql_scanner import run_sql_scanner
from libs.scanners.xss_scanner import run_xss_scanner
from libs.scanners.or_scanner import run_or_scanner
from libs.update import run_update

def handle_selection(selection):
    """
    Handles user selection and invokes the appropriate scanner or function.

    Args:
        selection (str): The user's menu choice.
    """
    if selection == '1':
        clear_screen()
        run_lfi_scanner()
    elif selection == '2':
        clear_screen()
        run_or_scanner()
    elif selection == '3':
        clear_screen()
        run_sql_scanner()
    elif selection == '4':
        clear_screen()
        run_xss_scanner()
    elif selection == '5':
        clear_screen()
        run_update()
    elif selection == '6':
        clear_screen()
        print_exit_menu()
    else:
        print("Invalid selection. Please try again.")

def main():
    """
    Main function that parses command-line arguments and runs the specified scanner.
    When no arguments are provided, displays the interactive menu.
    """
    parser = argparse.ArgumentParser(description="Lostxlso Scanning Tool", add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit.')
    parser.add_argument('-s', '--scanner', choices=['lfi', 'sql', 'xss', 'or', 'update'], help='Choose the scanner to run.')
    args, unknown = parser.parse_known_args()

    if args.help:
        # Show help message and exit
        print("""Usage: python main.py [options]

Lostxlso Scanning Tool

Options:
  -h, --help            Show this help message and exit.
  -s {lfi,sql,xss,or,update}, --scanner {lfi,sql,xss,or,update}
                        Choose the scanner to run.

If no options are provided, the interactive menu will be displayed.
""")
        sys.exit(0)

    if args.scanner:
        # Pass any unknown arguments to the scanner
        sys.argv = [sys.argv[0]] + unknown
        if args.scanner == 'lfi':
            run_lfi_scanner()
        elif args.scanner == 'sql':
            run_sql_scanner()
        elif args.scanner == 'xss':
            run_xss_scanner()
        elif args.scanner == 'or':
            run_or_scanner()
        elif args.scanner == 'update':
            run_update()
        else:
            parser.print_help()
            sys.exit(1)
    else:
        # No scanner specified, show interactive menu
        clear_screen()
        try:
            while True:
                display_menu()
                choice = input("Select an option (1-6): ").strip()
                handle_selection(choice)
        except KeyboardInterrupt:
            print_exit_menu()

if __name__ == "__main__":
    main()
