import nmap
import time
from datetime import datetime


def show_banner():
    print("=" * 55)
    print("             MINI NETWORK SECURITY SCANNER")
    print("=" * 55)


def scan_target(target):
    report_file = "scan_report.txt"

    scanner = nmap.PortScanner()
    start_time = time.time()
    scan_datetime = datetime.now()

    print("\n" + "=" * 55)
    print(f"Target       : {target}")
    print("Port Range   : 1-1000")
    print("Scan Type    : TCP + Service Detection")
    print("=" * 55)
    print("\nScanning...\n")

    try:
        scanner.scan(
            target,
            ports="1-1000",
            arguments="-sV"
        )
    except Exception as error:
        print(f"Scan Error: {error}")
        return

    duration = time.time() - start_time

    if target not in scanner.all_hosts():
        print("Status       : NOT FOUND")
        return

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

    report = [
        "=" * 55,
        "             MINI NETWORK SECURITY REPORT",
        "=" * 55,
        f"Target       : {target}",
        f"Scan Date    : {scan_datetime.strftime('%Y-%m-%d %H:%M:%S')}",
        "Port Range   : 1-1000",
        f"Status       : {status.upper()}",
        f"Open Ports   : {len(open_ports)}",
        f"Scan Time    : {duration:.2f} seconds",
        ""
    ]

    if open_ports:
        report.append("OPEN PORTS")
        report.append("-" * 55)

        for port, service, version in open_ports:
            report.append(
                f"{port:<8} {service:<15} {version}"
            )
    else:
        report.append("No open TCP ports found.")

    report.extend([
        "",
        "=" * 55,
        "Scan completed.",
        "=" * 55
    ])

    with open(report_file, "w") as file:
        file.write("\n".join(report))

    print(f"Report       : {report_file}")


def main():
    while True:
        show_banner()

        print("\n1. Scan localhost")
        print("2. Enter authorized target")
        print("3. Exit")

        choice = input("\nChoose option: ").strip()

        if choice == "1":
            scan_target("127.0.0.1")

        elif choice == "2":
            target = input(
                "Enter authorized target IP/hostname: "
            ).strip()

            if not target:
                print("Target cannot be empty.")
                continue

            scan_target(target)

        elif choice == "3":
            print("\nExiting scanner. Goodbye!")
            break

        else:
            print("\nInvalid option. Choose 1, 2, or 3.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
