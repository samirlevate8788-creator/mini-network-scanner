import nmap
import time
from datetime import datetime
from pathlib import Path


REPORT_DIR = Path("reports")
VERSION = "1.0"


def show_banner():
    print("=" * 60)
    print("             MINI NETWORK SECURITY SCANNER")
    print("                       v1.0")
    print("=" * 60)


def get_risk_level(open_ports):
    count = len(open_ports)

    if count == 0:
        return "LOW"
    elif count <= 3:
        return "MEDIUM"
    else:
        return "HIGH"


def show_help():
    print("\n" + "=" * 60)
    print("                         HELP")
    print("=" * 60)

    print("""
1. Scan localhost
   Scans your own Kali system (127.0.0.1).

2. Scan authorized target
   Enter an IP address or hostname that you own
   or have permission to test.

3. View saved reports
   Displays previously generated scan reports.

4. Help
   Shows this help information.

5. About
   Displays project information.

6. Exit
   Closes the scanner.
""")

    print("=" * 60)


def show_about():
    print("\n" + "=" * 60)
    print("                        ABOUT")
    print("=" * 60)

    print("""
Project : Mini Network Security Scanner
Version : 1.0
Language: Python
Engine  : Nmap

Purpose:
Basic network security assessment and
educational port/service discovery.

Features:
- TCP port scanning
- Service detection
- Risk-level summary
- Scan duration
- Timestamped reports
- Report viewer
- Interactive CLI
""")

    print("=" * 60)


def scan_target(target):
    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    scanner = nmap.PortScanner()

    start_time = time.time()
    scan_datetime = datetime.now()

    timestamp = scan_datetime.strftime(
        "%Y%m%d_%H%M%S"
    )

    report_file = (
        REPORT_DIR / f"scan_{timestamp}.txt"
    )

    print("\n" + "=" * 60)
    print(f"Target       : {target}")
    print("Port Range   : 1-1000")
    print("Scan Type    : TCP + Service Detection")
    print("=" * 60)

    print("\nScanning...\n")

    try:
        scanner.scan(
            target,
            ports="1-1000",
            arguments="-sV"
        )

    except Exception as error:
        print(f"Scan Error   : {error}")
        return

    duration = time.time() - start_time

    if target not in scanner.all_hosts():
        print("Status       : NOT FOUND")
        return

    status = scanner[target].state()

    open_ports = []

    for protocol in scanner[target].all_protocols():

        for port in sorted(
            scanner[target][protocol].keys()
        ):

            info = scanner[target][protocol][port]

            if info["state"] == "open":

                service = info.get(
                    "name",
                    "unknown"
                )

                version = info.get(
                    "version",
                    ""
                ).strip()

                open_ports.append(
                    (port, service, version)
                )

    risk_level = get_risk_level(
        open_ports
    )

    if risk_level == "LOW":

        recommendation = (
            "No open TCP ports were detected "
            "in the scanned range."
        )

    elif risk_level == "MEDIUM":

        recommendation = (
            "Review detected open services "
            "and close unnecessary ones."
        )

    else:

        recommendation = (
            "Review exposed services and "
            "restrict unnecessary network access."
        )

    print(f"Status       : {status.upper()}")
    print(f"Open Ports   : {len(open_ports)}")
    print(f"Risk Level   : {risk_level}")
    print(
        f"Scan Time    : {duration:.2f} seconds"
    )

    print("\n" + "-" * 60)

    if open_ports:

        print("OPEN PORTS")
        print("-" * 60)

        print(
            f"{'PORT':<8}"
            f"{'SERVICE':<15}"
            "VERSION"
        )

        print("-" * 60)

        for port, service, version in open_ports:

            print(
                f"{port:<8}"
                f"{service:<15}"
                f"{version or '-'}"
            )

    else:

        print(
            "No open TCP ports found."
        )

    print("-" * 60)

    print("\nSECURITY SUMMARY")
    print("-" * 60)

    print(
        f"Risk Level   : {risk_level}"
    )

    print(
        f"Recommendation: {recommendation}"
    )

    print("-" * 60)

    report = [

        "=" * 60,

        "             MINI NETWORK SECURITY REPORT",

        "=" * 60,

        f"Target       : {target}",

        f"Scan Date    : "
        f"{scan_datetime.strftime('%Y-%m-%d %H:%M:%S')}",

        "Port Range   : 1-1000",

        "Scan Type    : TCP + Service Detection",

        f"Status       : {status.upper()}",

        f"Open Ports   : {len(open_ports)}",

        f"Risk Level   : {risk_level}",

        f"Scan Time    : {duration:.2f} seconds",

        "",

        "OPEN PORTS",

        "-" * 60,

    ]

    if open_ports:

        report.append(
            f"{'PORT':<8}"
            f"{'SERVICE':<15}"
            "VERSION"
        )

        report.append("-" * 60)

        for port, service, version in open_ports:

            report.append(
                f"{port:<8}"
                f"{service:<15}"
                f"{version or '-'}"
            )

    else:

        report.append(
            "No open TCP ports found."
        )

    report.extend([

        "",

        "SECURITY SUMMARY",

        "-" * 60,

        f"Risk Level   : {risk_level}",

        f"Recommendation: {recommendation}",

        "",

        "=" * 60,

        "Scan completed.",

        "=" * 60,

    ])

    with open(
        report_file,
        "w"
    ) as file:

        file.write(
            "\n".join(report)
        )

    print(
        f"\nReport saved : {report_file}"
    )


def list_reports():

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    reports = sorted(
        REPORT_DIR.glob("scan_*.txt"),
        reverse=True
    )

    print("\n" + "=" * 60)
    print("                  SAVED REPORTS")
    print("=" * 60)

    if not reports:

        print("No saved reports found.")
        return

    for index, report in enumerate(
        reports,
        start=1
    ):

        print(
            f"{index}. {report.name}"
        )

    print("=" * 60)

    choice = input(
        "Enter report number to view, "
        "or press Enter to go back: "
    ).strip()

    if not choice:
        return

    if not choice.isdigit():

        print(
            "Invalid report number."
        )

        return

    number = int(choice)

    if number < 1 or number > len(reports):

        print(
            "Report not found."
        )

        return

    selected_report = reports[
        number - 1
    ]

    print("\n" + "=" * 60)

    print(
        f"REPORT: {selected_report.name}"
    )

    print("=" * 60)

    with open(
        selected_report,
        "r"
    ) as file:

        print(
            file.read()
        )

    print("=" * 60)


def main():

    while True:

        show_banner()

        print("\n1. Scan localhost")
        print("2. Scan authorized target")
        print("3. View saved reports")
        print("4. Help")
        print("5. About")
        print("6. Exit")

        choice = input(
            "\nChoose option: "
        ).strip()

        if choice == "1":

            scan_target(
                "127.0.0.1"
            )

        elif choice == "2":

            target = input(
                "Enter authorized target "
                "IP/hostname: "
            ).strip()

            if not target:

                print(
                    "Target cannot be empty."
                )

                continue

            scan_target(
                target
            )

        elif choice == "3":

            list_reports()

        elif choice == "4":

            show_help()

        elif choice == "5":

            show_about()

        elif choice == "6":

            print(
                "\nExiting scanner. Goodbye!"
            )

            break

        else:

            print(
                "\nInvalid option. "
                "Choose 1-6."
            )

        input(
            "\nPress Enter to continue..."
        )


if __name__ == "__main__":

    main()
