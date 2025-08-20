import requests

def subdomain_enum(target, wordlist=None):
    if wordlist is None:
        # a small built-in wordlist (can expand later)
        wordlist = ["www", "mail", "ftp", "test", "dev", "api"]

    found = []
    print(f"\n[*] Starting subdomain enumeration for {target}...")

    for sub in wordlist:
        url = f"http://{sub}.{target}"
        try:
            res = requests.get(url, timeout=2)
            if res.status_code < 400:
                print(f"[+] Found: {url} (Status {res.status_code})")
                found.append(url)
        except requests.exceptions.RequestException:
            pass

    return found