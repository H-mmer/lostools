#!/usr/bin/env python
"""
Main entry point for the lostxlso scanning tool.
This module handles the user interface and controls the flow
of the program by invoking the relevant scanner functions.
"""

import sys
from libs.utils import clear_screen, display_menu, print_exit_menu
from libs.scanners.lfi_scanner import run_lfi_scanner
from libs.scanners.sql_scanner import run_sql_scanner
from libs.scanners.xss_scanner import run_xss_scanner
from libs.scanners.or_scanner import run_or_scanner
from libs.update import run_update
import argparse

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
    Main function that displays the menu and captures user input.
    Loops until the user selects an exit option.
    """
    # If command-line arguments are provided, skip the menu
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Lostxlso Scanning Tool")
        parser.add_argument('-s', '--scanner', choices=['lfi', 'sql', 'xss', 'or'], required=True, help='Choose the scanner to run.')
        args, unknown = parser.parse_known_args()
        if args.scanner == 'lfi':
            run_lfi_scanner()
        elif args.scanner == 'sql':
            run_sql_scanner()
        elif args.scanner == 'xss':
            run_xss_scanner()
        elif args.scanner == 'or':
            run_or_scanner()
    else:
        clear_screen()
        while True:
            display_menu()
            choice = input("Select an option (1-6): ").strip()
            handle_selection(choice)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_exit_menu()
