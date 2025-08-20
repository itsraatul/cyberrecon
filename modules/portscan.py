import nmap

def run(target):
    print(f"[*] Port Scan on {target} (1-1000)")
    nm = nmap.PortScanner()
    nm.scan(target, "1-1000")

    for host in nm.all_hosts():
        print(f"\n[+] Host: {host} ({nm[host].hostname()})")
        print(f"    State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"    Protocol: {proto}")
            for port in sorted(nm[host][proto].keys()):
                state = nm[host][proto][port]['state']
                name = nm[host][proto][port].get('name', 'unknown')
                print(f"    Port {port}: {state} ({name})")
