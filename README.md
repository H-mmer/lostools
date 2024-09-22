![Screenshot (396)](https://github.com/user-attachments/assets/c5da3434-b021-4767-b470-6f3bf48fbb8a)
# Lostxlso: Multi-Vulnerability Scanner

**Lostxlso** is a powerful and versatile multi-vulnerability scanner designed to detect various web application vulnerabilities, including Local File Inclusion (LFI), Open Redirects (OR), SQL Injection (SQLi), and Cross-Site Scripting (XSS). This tool was created by **AnonKryptiQuz**, **Coffinxp**, **Hexsh1dow**, and **Naho**.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive Menu](#interactive-menu)
  - [Command-Line Arguments](#command-line-arguments)
    - [Common Arguments](#common-arguments)
    - [Examples](#examples)
- [Customization](#customization)
- [Chrome Installation Instructions](#chrome-installation-instructions)
- [Disclaimer](#disclaimer)

## Features

- **LFI Scanner**: Detect Local File Inclusion vulnerabilities.
- **OR Scanner**: Identify Open Redirect vulnerabilities.
- **SQL Scanner**: Detect SQL Injection vulnerabilities.
- **XSS Scanner**: Identify Cross-Site Scripting vulnerabilities.
- **Multi-threaded scanning**: Improved performance through multi-threading.
- **Customizable payloads**: Adjust payloads to suit specific targets.
- **Success criteria**: Modify success detection criteria for specific use cases.
- **Command-line interface**: Flexible usage through command-line arguments.
- **Save vulnerable URLs**: Automatically saves the results of vulnerable URLs to a file.

## Requirements

- **Python 3.x**
- **Libraries**:
  - `requests`
  - `urllib3`
  - `argparse`
  - `concurrent.futures`
  - `colorama`
  - `prompt_toolkit`
  - `PyYAML`
  - `gitpython`
  - `rich`
  - `Flask`
  - `selenium`
  - `webdriver_manager`
  - `aiohttp`
  - `beautifulsoup4`

You can install all required packages using:

```bash
pip install -r requirements.txt
```

## Installation

### Clone the repository

```bash
git clone https://github.com/coffinsp/lostools
cd lostools
```
## Set Up the Tool
Ensure that you have Python 3 installed. Install the required packages:

```bash
pip install -r requirements.txt
```

## Usage

### Interactive Menu

To run the tool with the interactive menu, simply execute:
```bash
python3 lostsec.py
```

You'll be presented with a menu to select the desired scanner:
```bash

.____                   __ ____  ___.__
|    |    ____  _______/  |\   \/  /|  |   __________
|    |   /  _ \/  ___/\   __\     / |  |  /  ___/  _ \
|    |__(  <_> )___ \  |  | /     \ |  |__\___ (  <_> )
|_______ \____/____  > |__|/___/\  \|____/____  >____/
\/         \/            \_/          \/

───────────────────────────────────────────────────────────────
┌─────────────────────────────────────────────────────────────┐
│1] LFi Scanner                                             │
│2] OR Scanner                                              │
│3] SQLi Scanner                                            │
│4] XSS Scanner                                             │
│5] tool Update                                             │
│6] Exit                                                    │
└─────────────────────────────────────────────────────────────┘
───────────────────────────────────────────────────────────────
Created by: Coffinxp, HexSh1dow, Naho and AnonKryptiQuz
───────────────────────────────────────────────────────────────
Select an option by entering the corresponding number:
───────────────────────────────────────────────────────────────
Select an option (1-6):
```
Follow the on-screen prompts to input URLs, payloads, and other options.

### Command-Line Arguments

Lostxlso can also be used entirely via command-line arguments for automation and scripting purposes.
#### General Syntax
```bash
python lostsec.py -s [scanner] [options]
```
#### Available scanners
 - `xss`
 - `lfi`
 - `sql`
 - `or`

#### Common Arguments
 - `-s`, `--scanner`: (Required) Specify the scanner to use (lfi, sql, xss, or, update).
 - `-u`, `--url`: Single URL to scan.
 - `-U`, `--url-file`: File containing URLs to scan (one per line).
 - `-p`, `--payload`: Single payload to use.
 - `-P`, `--payload-file`: File containing payloads to use (one per line).
 - `-t`, `--threads`: Number of concurrent threads (default: 5).
 - `-c`, `--cookies`: Cookies to include in the request. Can be used multiple times or comma-separated.
 - `-H`, `--headers`: Headers to include in the request. Can be used multiple times or comma-separated.
 - `-X`, `--method`: HTTP method to use (GET, POST; default: GET).

#### LFI Scanner Specific Option
 - `--success-pattern`: Comma-separated patterns indicating a successful LFI (default: `root:x:0:`).

### Examples

#### Run LFI Scanner with a Single URL and Payload
```bash
python lostsec.py -s lfi -u http://example.com/page.php?file= -p ../../etc/passwd
```
#### Run SQL Injection Scanner with URL File and Payload File, Using 10 Threads
```bash
python lostsec.py -s sql -U urls.txt -P payloads.txt -t 10
```
#### Run XSS Scanner with Custom Headers and Cookies
```bash
python lostsec.py -s xss -u http://example.com/search?q= -p "<script>alert(1)</script>" -H "Referer: http://google.com" -c "sessionid=abc123"
```
#### Run Open Redirect Scanner Using POST Method
```bash
python lostsec.py -s or -u http://example.com/redirect?url= -p "http://malicious.com" -X POST
```
#### Update the Tool to the Latest Version

```bash
python lostsec.py -s update
```
After updating, you can run the tool again to use the updated version.

### Display Help Information

To display help information and see all available options, run:

```bash
python lostsec.py -h
```
Or for a specific scanner:
```bash
python lostsec.py -s lfi -h
```

## Input Information

 - **Input URL/File**: Provide a single URL using `-u` or a file containing URLs using `-U`.
 - **Payload**: Provide a single payload using `-p` or a file containing payloads using `-P`.
 - **Success Criteria**: For LFI Scanner, you can define patterns that indicate a successful exploitation attempt using `--success-patterns`.
 - **Concurrent Threads**: Set the number of threads using `-t` to optimize performance.
 - **Cookies and Headers**: Use `-c` and `-H` to include cookies and headers in the requests.

## Customization

Lostxlso allows for various levels of customization to fit your specific testing needs:

 - **Custom Payloads**: Create or modify payload files to suit specific vulnerability types or applications. Payloads should be tailored to the vulnerability being tested.
 - **Success Criteria**: Adjust the success criteria patterns in the tool to identify successful exploitation attempts more accurately.
 - **Concurrent Threads**: Control the number of concurrent threads used during the scan to optimize performance based on system resources.

## Chrome Installation Instructions

Some of the scanners may require Chrome to be installed for Selenium dependencies.
 1. Launch Terminal
 2. Downlaod the Google Chrome `.deb` file:
    ```bash
    wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
    ```
 3. Install the downloaded Google Chrome `.deb` file:
    ```bash
    sudo dpkg -i google-chrome-stable_current_amd64.deb
    ```
 4. If you encounter errors during the installation, run:
    ```bash
    sudo apt -f install
    sudo dpkg -i google-chrome-stable_current_amd64.deb
    ```
 5. Google Chrome should now be installed.

## Disclaimer

Lostxlso is intended for educational and ethical hacking purposes only. It should only be used to test systems you own or have explicit permission to test. Unauthorized use of third-party websites or systems without consent is illegal and unethical.
