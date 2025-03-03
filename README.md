# Overview
# Disclaimer
This tool is intended for educational and security research purposes only. Unauthorized use on systems you do not own or have permission to test is illegal.

This is an advanced web vulnerability scanner that tests for multiple security flaws, including SQL Injection, Blind SQL Injection, Command Injection, Cross-Site Scripting (XSS), and Server-Side Request Forgery (SSRF). The scanner incorporates advanced WAF evasion techniques, payload randomization, and response caching to optimize performance and detection accuracy.

Features

SQL Injection Detection: Identifies SQL injection vulnerabilities using various payloads and evasion techniques.

Blind SQL Injection (Boolean & Time-Based): Tests for blind SQL injection using boolean comparison and time delays.

Command Injection: Detects command execution vulnerabilities by testing common command injection payloads.

Cross-Site Scripting (XSS): Scans for XSS vulnerabilities using a set of well-known payloads.

SSRF Exploitation: Attempts to exploit SSRF vulnerabilities by probing internal resources and external endpoints.

WAF/IDS Evasion: Uses multiple payload obfuscation techniques to bypass security mechanisms.

Response Caching: Prevents redundant requests by caching responses.

Randomized User-Agent Rotation: Mimics real users by cycling through various User-Agent strings.

Logging & Error Handling: Logs scan results, errors, and responses for analysis.

# Installation

Requirements

Python 3.x

Required Libraries: Install dependencies using:

pip install requests argparse pyfiglet

# Usage

Run the script with the target URL:

python scanner.py --url http://example.com/page.php?id=1

# Optional Arguments:

--proxy http://127.0.0.1:8080 → Use a proxy.

--verbose → Enable detailed logging.

--timeout 10 → Set request timeout.

# Example Output

[INFO] Testing for SQL Injection...
[ALERT] SQL Injection Detected! Payload: ' OR 1=1--
[INFO] Extracting database information...
[INFO] Database Name: my_database

Feel free to fork and add to it.
