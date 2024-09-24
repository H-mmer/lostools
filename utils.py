# utils.py

"""
Utility functions and constants used across modules.
"""

import os
import sys
import subprocess
import random
import requests
import psutil
from colorama import init

# Initialize colorama
init(autoreset=True)

USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
]

def check_and_install_packages(packages):
    """
    Checks if the specified packages are installed, and installs them if not.
    """
    for package, version in packages.items():
        try:
            __import__(package)
        except ImportError:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', f"{package}=={version}"])

def clear_screen():
    """
    Clears the console screen.
    """
    os.system('cls' if os.name == 'nt' else 'clear')

def get_random_user_agent():
    """
    Returns a random user agent string from a predefined list.
    """
    return random.choice(USER_AGENTS)

def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    """
    Returns a requests.Session object with retry capabilities.
    """
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def get_file_path(prompt_text):
    """
    Prompts the user for a file path, with auto-completion.
    """
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import PathCompleter
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def read_file_lines(file_path):
    """
    Lazily reads lines from a file.
    """
    with open(file_path, 'r') as file:
        for line in file:
            yield line.strip()

def get_optimal_threads(max_threads=50):
  """
  Dynamically determines the optimal number of threads based on system resources.
  """
  cpu_count = psutil.cpu_count(logical=True)
  available_memory = psutil.virtual_memory().available / (1024 ** 2)  # in MB

  # Simple heuristic:
  # - Use half the CPU cores if memory is limited
  # - Otherwise, use up to max_threads, but not exceeding CPU cores
  if available_memory < 512:  # Adjust threshold as needed
    optimal_threads = max(1, cpu_count // 2)
  else:
    optimal_threads = min(max_threads, cpu_count)

  return optimal_threads
