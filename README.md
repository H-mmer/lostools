![Screenshot (396)](https://github.com/user-attachments/assets/c5da3434-b021-4767-b470-6f3bf48fbb8a)
# Lostxlso: Multi-Vulnerability Scanner

**Lostxlso** is a powerful and versatile multi-vulnerability scanner designed to detect various web application vulnerabilities, including Local File Inclusion (LFI), Open Redirects (OR), SQL Injection (SQLi), and Cross-Site Scripting (XSS). This tool was created by **AnonKryptiQuz**, **Coffinxp**, **Hexsh1dow**, and **Naho**.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Requirements](#requirements)
- [Usage](#usage)
  - [Interactive Mode](#interactive-mode)
  - [Command-Line Mode](#command-line-mode)
- [Scanners](#scanners)
  - [SQL Injection Scanner](#sql-injection-scanner)
  - [XSS Scanner](#xss-scanner)
  - [Open Redirect Scanner](#open-redirect-scanner)
  - [LFI Scanner](#lfi-scanner)
- [Updater](#updater)
- [Contributing](#contributing)
- [License](#license)

## Features

- Modular design with separate scanners for different vulnerabilities.
- Optimized for speed using asynchronous programming and concurrency.
- Supports both interactive and command-line modes.
- Accepts both single URLs and lists of URLs from files.
- Customizable payloads via files or command-line arguments.
- Outputs results to files for easy analysis.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/advanced-vulnerability-scanner.git
   cd advanced-vulnerability-scanner
   ```


2. **Install Dependencies**

Ensure you have Python 3.7 or higher installed. Install required packages using `pip`:

   ```bash
   pip install -r requirements.txt
   ```
_Note_: If requirements.txt is not provided, you can install packages manually:

   ```bash
   pip install aiohttp asyncio requests prompt_toolkit colorama rich selenium webdriver-manager PyYAML gitpython
   ```
3. **Set Up WebDriver (For XSS and Open Redirect Scanners)**

The XSS and Open Redirect scanners use Selenium WebDriver. ChromeDriver will be installed automatically via webdriver-manager.

## Requirements

 - Python3.7+
 - Internet connection for installing dependencies and running scans.

## Usage

You can run the tool in two ways:

### Interactive Mode

Simply run `lostsec.py` without any arguments:
   ```bash
   python3 lostsec.py
   ```
This will launch an interactive menu where you can select the scanner and provide inputs as prompted.

### Command-Line Mode
Use command-line arguments to run the scanners directly:
   ```bash
   python3 main.py [options]
   ```
Use the `-h` or `--help` flag to see available options:

   ```bash
   python3 main.py -h
   ```

### Available Command-Line Arguments:

 - `-s`, `--scanner`: Select scanner to run (`lfi`, `or`, `sqli`, `xss`, `update`).
 - `-u`, `--urls`: URLs to scan (space-separated).
 - `-uf`, `--url-file`: File containing URLs to scan.
 - `-p`, `--payloads`: Payloads to use (space-separated).
 - `-pf`, `--payload-file`: File containing payloads to use.
 - `-c`, `--cookie`: Cookie to include in requests (for SQLi scanner).
 - `-t`, `--threads`: Number of concurrent threads (default: 5).
 - `-o`, `--output-file`: Output file to save vulnerable URLs.

### Examples:

**SQL Injection Scanner:**

   ```bash
   python3 main.py -s sqli -uf urls.txt -pf sqli_payloads.txt -t 50 -o sqli_results.txt
   ```
**XSS Scanner:**

   ```bash
   python3 main.py -s xss -u "http://example.com/search?q=" -p "<script>alert(1)</script>" -t 10 -o xss_results.txt
   ```
**Open Redirect Scanner:**

   ```bash
   python3 main.py -s or -uf urls.txt -pf or_payloads.txt -t 20 -o or_results.txt
   ```
**LFI Scanner:**

   ```bash
   python3 main.py -s lfi -uf urls.txt -pf lfi_payloads.txt -t 50 -o lfi_results.txt
   ```

## Scanners

### SQL Injection Scanner

**Description:**

Detects SQL Injection vulnerabilities by appending payloads to URLs and measuring response times. If a significant delay is observed, the URL is considered vulnerable.

**Usage:**

Interactive:

   ```bash
   python3 main.py
   # Select option 3 for SQLi Scanner
   ```

Command-Line:

   ```bash
   python3 main.py -s sqli -uf urls.txt -pf sqli_payloads.txt -t 50 -o sqli_results.txt
   ```

**Options:**

 - `-c`, `--cookie`: Include a cookie in the requests.

### XSS Scanner

**Description:**

Detects Cross-Site Scripting vulnerabilities by injecting payloads into URL parameters and checking for JavaScript execution using Selenium WebDriver.

**Usage:**

Interactive:

   ```bash
   python3 main.py
   # Select option 4 for XSS Scanner
   ```

Command-Line:

   ```bash
   python3 main.py -s xss -uf urls.txt -pf xss_payloads.txt -t 10 -o xss_results.txt
   ```

### Open Redirect Scanner

**Description:**

Identifies Open Redirect vulnerabilities by appending payloads that attempt to redirect the user to an external site.

**Usage:**

Interactive:

   ```bash
   python3 main.py
   # Select option 2 for OR Scanner
   ```
Command-Line:

   ```bash
   python3 main.py -s or -uf urls.txt -pf or_payloads.txt -t 20 -o or_results.txt
   ```

### LFI Scanner

**Description:**

Checks for Local File Inclusion vulnerabilities by injecting file paths into URL parameters and looking for specific content patterns in the response.

**Usage:**

Interactive:

   ```bash
   python3 main.py
   # Select option 1 for LFi Scanner
   ```
Command-Line:

   ```bash
   python3 main.py -s lfi -uf urls.txt -pf lfi_payloads.txt -t 50 -o lfi_results.txt
   ```

**Options:**

 - During interactive mode, you can specify success criteria patterns for more accurate detection.


### Updater

The updater module checks for updates from the remote repository and updates the tool if a newer version is available.

**Usage:**

Interactive:

   ```bash
   python3 main.py
   # Select option 5 for tool Update
   ```
Command-Line:

   ```bash
   python3 main.py -s update
   ```
_Note_: Ensure that `config.yml` is properly configured with the repository information.


### Contributing
Contributions are welcome! Please follow these steps:

 1. Fork the repository.

 2. Create a new branch:

   ```bash
   git checkout -b feature/your-feature-name
   ```

 3. Make your changes and commit them:

   ```bash
   git commit -am 'Add new feature'
   ```
 4. Push to the branch:

   ```bash
   git push origin feature/your-feature-name
   ```
 5. Open a Pull Request.

### License
This project is licensed under the MIT License. See the LICENSE file for details.



## Additional Documentation

### Project Structure
   ```css
   lostools/
   ├── __init__.py
   ├── lostsec.py
   ├── color.py
   ├── utils.py
   ├── scanners/
   │   ├── __init__.py
   │   ├── sql_scanner.py
   │   ├── xss_scanner.py
   │   ├── or_scanner.py
   │   └── lfi_scanner.py
   ├── updater.py
   └── config.yml
   ```

### Modules Description
 - **main.py**: Entry point of the application. Handles interactive menu and command-line arguments.
 - **color.py**: Defines color codes for terminal output.
 - **utils.py**: Contains utility functions and constants used across modules.
 - **scanners/**: Package containing scanner modules.
   - **sql_scanner.py**: Module for SQL Injection scanning functionality.
   - **xss_scanner.py**: Module for Cross-Site Scripting scanning functionality.
   - **or_scanner.py**: Module for Open Redirect scanning functionality.
   - **lfi_scanner.py**: Module for Local File Inclusion scanning functionality.
 - **updater.py**: Module for updating the tool from a remote repository.
 - **config.yml**: Configuration file containing repository information for updates.

### Dependencies
 - **Python Packages:**
   - aiohttp
   - asyncio
   - requests
   - prompt_toolkit
   - colorama
   - rich
   - selenium
   - webdriver-manager
   - PyYAML
   - gitpython
 - **External Tools:**
   - ChromeDriver (managed automatically via `webdriver-manager`).

### Adding Custom Payloads
You can create your own payload files for different scanners:

 1. Create a new text file (e.g., custom_payloads.txt).

 2. Add your payloads, one per line.

 3. Use the `-pf` or `--payload-file` option to specify your custom payload file:
   ```bash
   python3 main.py -s xss -uf urls.txt -pf custom_payloads.txt -t 10 -o xss_results.txt
   ```

### Notes
 - Be cautious when running scans against websites. Always ensure you have permission to test the target systems.
 - High concurrency levels (large number of threads) can put significant load on your system and network. Adjust the `-t` or `--threads` parameter according to your system's capabilities.
 - The XSS and Open Redirect scanners use Selenium WebDriver, which can consume more resources. Optimize the `threads` parameter if you encounter performance issues.
