#!/usr/bin/env python3
import argparse
from modules.subdomains import subdomain_enum
from modules.portscan import port_scan

def banner():
    print(r"""
C y b e r | R e c o n
   CyberRecon - Automated Recon Tool
    """)

def main():
    banner()
    parser = argparse.ArgumentParser(description="CyberRecon - Automated Reconnaissance Tool")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--portscan", action="store_true", help="Run port scan (default 1-1000)")
    parser.add_argument("--ports", default="1-1000", help="Port range (default: 1-1000)")
    args = parser.parse_args()

    print(f"[+] Target received: {args.target}")

    if args.subdomains:
        subdomain_enum(args.target)

    if args.portscan:
        port_scan(args.target, args.ports)

if __name__ == "__main__":
    main()