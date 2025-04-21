import socket
import requests
import whois
import subprocess

def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] IP Address    : {ip}")
    except Exception as e:
        print(f"[!] Gagal resolve IP: {e}")

def mx_record(domain):
    try:
        result = subprocess.check_output(["dig", "+short", "mx", domain]).decode().strip()
        print("[+] MX Records    :")
        if result:
            for line in result.splitlines():
                print(f"    - {line}")
        else:
            print("    (tidak ditemukan)")
    except Exception as e:
        print(f"[!] Gagal cek MX: {e}")

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print(f"[+] Registrar     : {w.registrar}")
        print(f"[+] Country       : {w.country}")
    except Exception as e:
        print(f"[!] Gagal WHOIS: {e}")

def get_http_headers(domain):
    try:
        url = f"http://{domain}"
        headers = requests.get(url, timeout=5).headers
        print("[+] Web Headers   :")
        print(f"    - Server: {headers.get('Server')}")
        print(f"    - X-Powered-By: {headers.get('X-Powered-By')}")
    except Exception as e:
        print(f"[!] Gagal ambil header HTTP: {e}")

def subdomain_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=10)
        subdomains = set()
        for entry in response.json():
            name = entry['name_value']
            if domain in name:
                subdomains.update(name.split('\n'))
        print("[+] Subdomains    :")
        for sub in sorted(subdomains):
            print(f"    - {sub}")
    except Exception as e:
        print(f"[!] Gagal ambil subdomain dari crt.sh: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 osint_resolver.py <domain>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[•] Target Domain : {target}")
    print("=" * 50)

    resolve_ip(target)
    mx_record(target)
    whois_lookup(target)
    get_http_headers(target)
    subdomain_crtsh(target)
