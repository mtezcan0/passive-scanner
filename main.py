import requests
import re
import ssl
import socket
import threading
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import whois
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urljoin

with open('/home/lenovo/python-project/Passive Scanner/wordlist.txt', 'r') as f:
    wordlist = [re.sub(r'\s+', '', line) for line in f if line.strip()]



# ----------------------------------Scanner Functions---------------------------------- #

def header_analysis(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        report = {}
        report["Server"] = headers.get("Server", "NO")
        report["X-Powered-By"] = headers.get("X-Powered-By", "NO")
        report["Content-Security-Policy"] = headers.get("Content-Security-Policy", "NO")
        report["Strict-Transport-Security"] = headers.get("Strict-Transport-Security", "NO")
        report["X-Frame-Options"] = headers.get("X-Frame-Options", "NO")
        report["X-XSS-Protection"] = headers.get("X-XSS-Protection", "NO")
        report["Referrer-Policy"] = headers.get("Referrer-Policy", "NO")
        report["Permissions-Policy"] = headers.get("Permissions-Policy", "NO")
        print("------Header Analysis result------")
        if meta_generator and meta_generator.has_attr('content'):
                print(f"CMS/Generator: {meta_generator['content']}")
        if 'wp-settings-1' in response.cookies:
                print(f"Technology: WordPress (It was understood from the cookie trace)")
        for key, value in report.items():
            print(f"{key}: {value}")
        print("\nSafety Warnings!!!\n")
        if report["X-Powered-By"] != "NO":
            print("- X-Powered-By title is on, revealing the technology")
        if report["Server"] != "NO":
            print("- Server title is on, shows server type")
        if report["Content-Security-Policy"] == "NO":
            print("- CSP policy is missing")
        if report["Strict-Transport-Security"] == "NO":
            print("- HSTS policy is missing")
    except requests.exceptions.RequestException as e:
        print("Connection error", e)
   

def ssl_certificate_check(domain, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((domain, port)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            issuer = cert.issuer
            not_after = cert.not_valid_after_utc
            not_before = cert.not_valid_before_utc
            now = datetime.now(timezone.utc)
            print(f"[+] Domain: {domain}")
            print(f"[+] Certificate starts: {not_before}")
            print(f"[+] Certificate ends: {not_after}")
            print(f"[+] Certificate remaining days: {(not_after - now).days}")
            print(f"[+] Issuer: {issuer.rfc4514_string()}")
            if now > not_after:
                print("[!] Warning: Certificate expired")
            else:
                print("[+] Certificate is valid")

def test_subdomain(domain, sub):
    subdomain = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(subdomain)
        print(f"[+] Found: {subdomain} -> {ip}")
    except:
        pass

def subdomain_test(domain, wordlist):
    threads = []
    print("----------Subdomain test result-----------------")
    for sub in wordlist:
        t = threading.Thread(target=test_subdomain, args=(domain, sub))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()



def test_path(url, path):
    full_url = f"{url.rstrip('/')}/{path}"
    try:
        response = requests.get(full_url, timeout=5)
        if response.status_code == 200:
            print(f"[+] Found: {full_url}")
        elif response.status_code in [301,302]:
            print(f"[>] Redirect: {full_url}")
        elif response.status_code in [403,401]:
            print(f"[!] Forbidden/Unauthorized: {full_url}")
    except requests.RequestException:
        pass


def directory_scan(url, wordlist):
    print("-------Directory Scan Result------")
    threads = []
    for path in wordlist:
        t = threading.Thread(target=test_path, args=(url,path))
        t.start()
        threads.append(t)
    for t in threads:
        t.join

def robots_txt_check(url):
    print("------Robots.txt Check-----")
    if not url.startswith("http"):
        url = "http://" + url
    if url.endswith("/"):
        robots_url = url + "robots.txt"
    else:
        robots_url = url + "/robots.txt"
    try:
        response = requests.get(robots_txt_check, timeout=5)
        if response.status_code == 200:
            print(f"[+] Found: {robots_url}\n")
            print(response.text)
            
            lines = response.text.splitlines()
            for line in lines:
                if "Disallow" in line or "Allow" in line:
                    print(f"[i] Rule: {line.strip()}")
        else:
            print(f"[-] No robots.txt found.")
    except requests.RequestException as e:
        print(f"[-] Error fetching robots.txt:",e)

                
def whois_lookup(domain):
    print("------Whois Lookup------")
    try:
        w = whois.whois(domain)
        print(f"Domain: {domain}")
        print(f"Registrar: {w.registrar}")
        print(f"Creation Date: {w.creation_date}")
        print(f"Expiration Date: {w.expiration_date}")
        print(f"Name Servers: {w.name_servers}")
    except Exception as e:
        print(f"Error {e}")

def options_check(url):
    print("----------Http Options Check----------")
    try:
        response = requests.options(url)
        allow = response.headers.get("Allow")
        if allow:
            print(f"Allowed Methods: {allow}")
        else:
            print("No ALlow header found.")
    except Exception as e:
        print(f"Error checking Options: {e}")

def dns_lookup(domain):
    print("------DNS Records------")
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            print(f"\n[+] {record_type} Records: ")
            for rdata in answers:
                if record_type =='MX':
                    print(f"  -Priority: {rdata.prefences}, Server: {rdata.extended_rdatatype.to_text()}")
                else:
                    print(f" -{rdata.to_text()}")
        except dns.resolver.NoAnswer:
            print(f"\n[!] {record_type} no found")
        except dns.resolver.NXDOMAIN:
            print(f"\n[!] Error: {domain} no found")
            return
        except Exception as e:
            print(f"Error: {e}")

def check_port(domain, port):
    try:
        with socket.create_connection((domain, port), timeout=0.5):
           print(f"[+] Port {port} OPEN")
           return port, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False
    
def port_scan(domain):
    print(f"---------Port Scan {domain} ---------")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    open_ports = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(lambda port: check_port(domain, port), common_ports)

        for port, is_open in results:
            if is_open:
                open_ports.append(port)

    if not open_ports:
        print(f"[-] None of the common ports scanned are open")
    if open_ports:
        print(f"[+] Open ports: {open_ports}")



def find_sensitive_files(url):
    
    print(f"------ Precise File Scanning: {url} ------")
    sensitive_paths = [
        '.git/config',      
        '.env',            
        'app.log',         
        'error.log',   
        'backup.zip',     
        'database.sql',   
        'config.php.bak'    
    ]
    
    found_any = False
    for path in sensitive_paths:
        full_url = urljoin(url, path)
        try:
            response = requests.get(full_url, timeout=3, allow_redirects=False)
            if response.status_code == 200:
                print(f"[!!!] CRITICAL: Sensitive file found: {full_url} (Status: 200)")
                found_any = True
        except requests.RequestException:
            pass
            
    if not found_any:
        print("[-] None of the known sensitive files were found.")


# ----------------------------------Start the Program---------------------------------- #

def main_menu():
    url = input("Please enter URL (with http/https): ").strip()
    domain = urlparse(url).hostname

    while True:
        print("\n===== Passive Scanner Menu =====")
        print("1. Header Analysis")
        print("2. SSL Certificate Check")
        print("3. Subdomain Scan")
        print("4. Directory Scan")
        print("5. robots.txt Check")
        print("6. WHOIS Lookup")
        print("7. HTTP Options Check")
        print("8. DNS lookup")
        print("9. Port Scan")
        print("10. Sensitive Files Scan")
        print("11. Run All")
        print("0. Exit")

        choice = input("Select an option: ").strip()

        if choice == "1":
            header_analysis(url)
        elif choice == "2":
            ssl_certificate_check(domain)
        elif choice == "3":
            subdomain_test(domain, wordlist)
        elif choice == "4":
            directory_scan(url, wordlist)
        elif choice == "5":
            robots_txt_check(url)
        elif choice == "6":
            whois_lookup(domain)
        elif choice == "7":
            options_check(url)
        elif choice == "8":
            dns_lookup(domain)
        elif choice == "9":
            port_scan(domain)
        elif choice == "10":
            find_sensitive_files(url)
        elif choice == "11":
            header_analysis(url)
            ssl_certificate_check(domain)
            subdomain_test(domain, wordlist)
            directory_scan(url, wordlist)
            robots_txt_check(url)
            whois_lookup(domain)
            options_check(url)
            dns_lookup(domain)
            port_scan(domain)
            find_sensitive_files(url)
            
        elif choice == "0":
            print("Exiting program.")
            break
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main_menu()