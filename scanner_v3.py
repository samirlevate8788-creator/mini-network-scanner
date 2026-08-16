import nmap
from datetime import datetime

target = "127.0.0.1"
report_file = "scan_report.txt"

scanner = nmap.PortScanner()
start_time = datetime.now()

print("=" * 50)
print("           MINI NETWORK SCANNER")
print("=" * 50)

print(f"Target : {target}")
print("Scanning...")
print()

scanner.scan(target, arguments="-sV")

report = []
report.append("=" * 50)
report.append("           MINI NETWORK SCAN REPORT")
report.append("=" * 50)
report.append(f"Target    : {target}")
report.append(f"Scan Time : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

if target not in scanner.all_hosts():
    print("Host not found.")
    report.append("Status    : NOT FOUND")
else:
    state = scanner[target].state()
    print(f"Status : {state.upper()}")
    report.append(f"Status    : {state.upper()}")

    open_ports = []

    for protocol in scanner[target].all_protocols():
        for port in sorted(scanner[target][protocol].keys()):
            info = scanner[target][protocol][port]

            if info["state"] == "open":
                service = info.get("name", "unknown")
                version = info.get("version", "")
                open_ports.append((port, service, version))

    print("\n" + "-" * 50)

    if open_ports:
        print("OPEN PORTS")
        report.append("")
        report.append("OPEN PORTS")
        report.append("-" * 50)

        for port, service, version in open_ports:
            print(f"Port {port:<6} | {service:<12} | {version}")
            report.append(f"Port {port:<6} | {service:<12} | {version}")

        print("-" * 50)
        print(f"Total Open Ports: {len(open_ports)}")

        report.append("-" * 50)
        report.append(f"Total Open Ports: {len(open_ports)}")
    else:
        print("No open TCP ports found.")
        report.append("")
        report.append("No open TCP ports found.")

report.append("")
report.append("=" * 50)
report.append("Scan completed.")
report.append("=" * 50)

with open(report_file, "w") as file:
    file.write("\n".join(report))

print("\nScan completed.")
print(f"Report saved to: {report_file}")
print("=" * 50)
