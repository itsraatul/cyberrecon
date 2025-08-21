import nmap
import requests
import os
from dotenv import load_dotenv
from core.utils import save_json_report
from rich.console import Console
from rich.table import Table

console = Console()
load_dotenv()
API_KEY = os.getenv("VULNERS_API_KEY")
API_URL = "https://vulners.com/api/v3/search/lucene/"

def query_vulners(software: str, version: str):
    if not API_KEY:
        console.print("[red][!][/red] No VULNERS_API_KEY found. Please set in .env")
        return []
    query = f"{software} {version}"
    try:
        r = requests.post(API_URL, headers={"X-Api-Key": API_KEY}, json={"query": query, "size": 5})
        if r.status_code != 200:
            return []
        data = r.json()
        results = data.get("data", {}).get("search", [])
        cves = []
        for res in results:
            cves.append({
                "id": res.get("id"),
                "title": res.get("title"),
                "score": res.get("cvss", {}).get("score", "N/A"),
                "href": res.get("_source", {}).get("href", "")
            })
        return cves
    except Exception as e:
        console.print(f"[!] Vulners query failed: {e}")
        return []

def run(target: str):
    console.print(f"[*] CVE Mapping for [bold]{target}[/bold] using Nmap + Vulners API")
    nm = nmap.PortScanner()
    nm.scan(target, "1-1000", arguments="-sV")  # -sV for service/version detection

    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]["name"]
                version = nm[host][proto][port].get("version", "")
                product = nm[host][proto][port].get("product", "")
                banner = f"{product} {version}".strip()
                if not banner:
                    continue
                console.print(f"[+] {host}:{port} → {banner}")
                vulns = query_vulners(product or service, version)
                if vulns:
                    for v in vulns:
                        console.print(f"   - {v['id']} ({v['score']}): {v['title']} → {v['href']}")
                results.append({
                    "host": host,
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "vulns": vulns
                })

    path = save_json_report(target, "cve_scan", {"target": target, "results": results})
    console.print(f"[green][+][/green] CVE scan report saved: {path}")
