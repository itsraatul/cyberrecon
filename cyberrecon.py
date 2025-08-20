#!/usr/bin/env python3
import argparse
from core.engine import ReconEngine

def banner():
    print(r"""
   ____           __                 
  / ___|   _ _ __| |__   ___ _ __    
 | |  | | | | '__| '_ \ / _ \ '__|   
 | |__| |_| | |  | | | |  __/ |      
  \____\__,_|_|  |_| |_|\___|_|      

   CyberRecon - Modular Recon Framework
    """)

def main():
    banner()
    parser = argparse.ArgumentParser(description="CyberRecon - Automated Recon Framework")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--modules", nargs="+", help="Modules to run (example: subdomains portscan)")
    args = parser.parse_args()

    engine = ReconEngine(args.target)

    if args.modules:
        for mod in args.modules:
            engine.load_module(mod)
    else:
        print("[*] No modules specified. Example: --modules subdomains portscan")
        return

    engine.run()

if __name__ == "__main__":
    main()
