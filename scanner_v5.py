import nmap
import sys
import time
from datetime import datetime


def show_banner():
    print("=" * 55)
    print("             MINI NETWORK SECURITY SCANNER")
    print("=" * 55)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py <target>")
        print("Example: python3 scanner.py 127.0.0.1")
        sys.exit(1)

    target = sys.argv[1]
    report_file = "scan_report.txt"

    show_banner()

    print(f"Target       : {target}")
    print("Port Range   : 1-1000")
    print("Scan Type    : TCP + Service Detection")
    print()

    scanner = nmap.PortScanner()

    start_time = time.time()
    scan_datetime = datetime.now()

    try:
        scanner.scan(
            target,
            ports="1-1000",
            arguments="-sV"
        )
    except Exception as error:
        print(f"Scan Error   : {error}")
        sys.exit(1)

    duration = time.time() - start_time

    if target not in scanner.all_hosts():
        print("Status       : NOT FOUND")
        print("Scan completed.")
        sys.exit(0)

    status = scanner[target].state()

    open_ports = []

    for protocol in scanner[target].all_protocols():
        for port in sorted(scanner[target][protocol].keys()):
            info = scanner[target][protocol][port]

            if info["state"] == "open":
                service = info.get("name", "unknown")
                version = info.get("version", "").strip()

                open_ports.append(
                    (port, service, version)
                )

    print(f"Status       : {status.upper()}")
    print(f"Open Ports   : {len(open_ports)}")
    print(f"Scan Time    : {duration:.2f} seconds")

    print("\n" + "-" * 55)

    if open_ports:
        print("OPEN PORTS")
        print("-" * 55)

        for port, service, version in open_ports:
            if version:
                print(
                    f"{port:<8} {service:<15} {version}"
                )
            else:
                print(
                    f"{port:<8} {service:<15} -"
                )
    else:
        print("No open TCP ports found.")

    print("-" * 55)

    report = []

    report.append("=" * 55)
    report.append("             MINI NETWORK SECURITY REPORT")
    report.append("=" * 55)
    report.append(f"Target       : {target}")
    report.append(
        f"Scan Date    : {scan_datetime.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    report.append("Port Range   : 1-1000")
    report.append(f"Status       : {status.upper()}")
    report.append(f"Open Ports   : {len(open_ports)}")
    report.append(f"Scan Time    : {duration:.2f} seconds")
    report.append("")

    if open_ports:
        report.append("OPEN PORTS")
        report.append("-" * 55)

        for port, service, version in open_ports:
            report.append(
                f"{port:<8} {service:<15} {version}"
            )
    else:
        report.append("No open TCP ports found.")

    report.append("")
    report.append("=" * 55)
    report.append("Scan completed.")
    report.append("=" * 55)

    with open(report_file, "w") as file:
        file.write("\n".join(report))

    print(f"Report       : {report_file}")
    print("=" * 55)


if __name__ == "__main__":
    main()
