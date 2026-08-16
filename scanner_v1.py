import nmap

target = "127.0.0.1"

scanner = nmap.PortScanner()

print("=" * 40)
print("      MINI NETWORK SCANNER")
print("=" * 40)

print(f"\nScanning: {target}")
print("Please wait...\n")

scanner.scan(target, arguments="-sV")

if target in scanner.all_hosts():
    print(f"Host: {target}")
    print(f"State: {scanner[target].state()}")

    for protocol in scanner[target].all_protocols():
        print(f"\nProtocol: {protocol}")

        ports = scanner[target][protocol].keys()

        for port in sorted(ports):
            state = scanner[target][protocol][port]["state"]
            service = scanner[target][protocol][port].get("name", "unknown")

            print(f"Port {port}: {state} | Service: {service}")
else:
    print("Host not found.")

print("\nScan completed.")
