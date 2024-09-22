"""
Module for parsing command-line arguments.
"""

import argparse

def get_common_arguments(description):
    parser = argparse.ArgumentParser(description=description)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Single URL to scan.')
    group.add_argument('-U', '--url-file', help='File containing URLs to scan (one per line).')
    
    payload_group = parser.add_mutually_exclusive_group(required=True)
    payload_group.add_argument('-p', '--payload', help='Single payload to use.')
    payload_group.add_argument('-P', '--payload-file', help='File containing payloads to use (one per line).')
    
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads (default: 5).')
    parser.add_argument('-c', '--cookies', action='append', help='Cookies to include in the request. Can be used multiple times.')
    parser.add_argument('-H', '--headers', action='append', help='Headers to include in the request. Can be used multiple times.')
    parser.add_argument('-X', '--method', choices=['GET', 'POST'], default='GET', help='HTTP method to use (default: GET).')
    
    return parser
