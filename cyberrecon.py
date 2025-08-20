#!/usr/bin/env python3
import argparse
from modules.subdomains import subdomain_enum

def banner():
    print(r"""
C y b e r | R e c o n
   CyberRecon - Automated Recon Tool
    """)
def main():
    banner()
    parser = argparse.ArgumentParser(description="CyberRecon - Automated Reconnaissance Tool")
    parser.add_argument("target", help="Target domain to scan (example: example.com)")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    args = parser.parse_args()

    print(f"[+] Target received: {args.target}")

    if args.subdomains:
        subdomain_enum(args.target)

if __name__ == "__main__":
    main()