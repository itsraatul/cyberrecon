import nmap

def port_scan(target, ports="1-1000"):
    print(f"\n[*] Starting port scan on {target} (ports {ports})...")
    nm = nmap.PortScanner()
    try:
        nm.scan(target, ports)
    except Exception as e:
        print(f"[!] Nmap error: {e}")
        return

    for host in nm.all_hosts():
        print(f"\n[+] Host: {host} ({nm[host].hostname()})")
        print(f"    State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"    Protocol: {proto}")
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                state = nm[host][proto][port]['state']
                name = nm[host][proto][port].get('name', 'unknown')
                print(f"    Port {port}: {state} ({name})")
