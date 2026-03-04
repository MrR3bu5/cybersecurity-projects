import argparse
import socket
import sys
from typing import List, Optional


WEB_APP_PORTS: List[int] = [
    80,    # HTTP
    8080,  # Alternate HTTP
    8000,  # App/web frameworks
    443,   # HTTPS
    8443,  # Alternate HTTPS / admin
]

NETWORK_SERVICE_PORTS: List[int] = [
    20, 21,          # FTP
    22, 2222,        # SSH and alt SSH
    23,              # Telnet
    25,              # SMTP
    53,              # DNS
    110, 143,        # POP3, IMAP
    161, 162,        # SNMP
    389, 636,        # LDAP, LDAPS
    445,             # SMB
    587, 993, 995,   # Submission, IMAPS, POP3S
    3306,            # MySQL
    3389,            # RDP
]

DEFAULT_PORTS: List[int] = sorted(set(WEB_APP_PORTS + NETWORK_SERVICE_PORTS))


def scan_ports(target: str, ports: List[int], timeout: float = 1.0) -> None:
    """Scan TCP ports on a target host and print open ones."""
    print(f"\nStarting scan on host: {target}")
    print(f"Ports: {ports}")

    try:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)

            result = s.connect_ex((target, port))

            if result == 0:
                print(f"Port {port:5} is open")

            s.close()

    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit(1)

    except socket.gaierror:
        print("ERROR: Hostname could not be resolved.")
        sys.exit(1)

    except socket.error:
        print("ERROR: Could not connect to server.")
        sys.exit(1)


def select_scan_type_interactive() -> List[int]:
    print("\nSelect scan type:")
    print("1. Web app services")
    print("2. Network services")
    print("3. Default common ports")
    print("4. Custom ports (comma-separated)")

    choice = input("Enter choice (1-4): ").strip()

    if choice == "1":
        print(f"Selected: Web app services -> {WEB_APP_PORTS}")
        return WEB_APP_PORTS

    if choice == "2":
        print(f"Selected: Network services -> {NETWORK_SERVICE_PORTS}")
        return NETWORK_SERVICE_PORTS

    if choice == "3":
        print(f"Selected: Default ports -> {DEFAULT_PORTS}")
        return DEFAULT_PORTS

    if choice == "4":
        raw = input("Enter ports (e.g. 80,443,8080): ").strip()
        ports: List[int] = []
        for part in raw.split(","):
            part = part.strip()
            if part.isdigit():
                ports.append(int(part))
        if not ports:
            print("No valid ports entered, falling back to DEFAULT_PORTS.")
            return DEFAULT_PORTS
        print(f"Selected: Custom ports -> {ports}")
        return ports

    print("Invalid choice, falling back to DEFAULT_PORTS.")
    return DEFAULT_PORTS


def parse_ports_arg(ports_str: str) -> List[int]:
    ports: List[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            continue
        ports.append(int(part))
    return ports


def resolve_profile(profile: str, ports_arg: Optional[str]) -> List[int]:
    profile = profile.lower()

    if profile == "web":
        return WEB_APP_PORTS
    if profile == "network":
        return NETWORK_SERVICE_PORTS
    if profile == "default":
        return DEFAULT_PORTS
    if profile == "custom":
        if not ports_arg:
            print("ERROR: --ports is required when --profile custom is used.")
            sys.exit(1)
        ports = parse_ports_arg(ports_arg)
        if not ports:
            print("ERROR: No valid ports parsed from --ports.")
            sys.exit(1)
        return ports

    print("ERROR: Unknown profile. Use web, network, default, or custom.")
    sys.exit(1)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple TCP port scanner.")
    parser.add_argument(
        "-t",
        "--target",
        help="Target IP or hostname.",
    )
    parser.add_argument(
        "-p",
        "--profile",
        choices=["web", "network", "default", "custom"],
        help="Port profile: web, network, default, custom.",
    )
    parser.add_argument(
        "--ports",
        help="Comma separated list of ports (used with --profile custom).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0).",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if not args.target:
        target = input("Enter target IP or hostname: ").strip()
        ports = select_scan_type_interactive()
        timeout = 1.0
    else:
        target = args.target.strip()
        profile = args.profile or "default"
        ports = resolve_profile(profile, args.ports)
        timeout = args.timeout
        print(f"\nProfile: {profile}")
        print(f"Ports: {ports}")

    scan_ports(target, ports, timeout=timeout)


if __name__ == "__main__":
    main()
