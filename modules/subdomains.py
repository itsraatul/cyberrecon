import requests

def run(target):
    wordlist = ["www", "mail", "ftp", "test", "dev", "api"]
    print(f"[*] Subdomain Enumeration for {target}")
    for sub in wordlist:
        url = f"http://{sub}.{target}"
        try:
            res = requests.get(url, timeout=2)
            if res.status_code < 400:
                print(f"[+] Found: {url} (Status {res.status_code})")
        except requests.exceptions.RequestException:
            pass
