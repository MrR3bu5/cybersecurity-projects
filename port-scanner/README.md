# Python Port Scanner

A Python tool for quickly scanning common service ports on a target host, with predefined scan profiles, custom port selection, and both interactive and CLI modes.

## Features

- TCP connect scans using Python `socket`
- Predefined scan profiles for web and network services
- Default profile combining common infrastructure ports
- Custom port list input (interactive or CLI)
- Interactive prompts when no CLI arguments are provided
- Command-line interface with `argparse`
- Graceful error handling for DNS and connectivity issues

## Requirements

Standard library only:

- socket
- sys
- argparse
- typing (for type hints, Python 3.8+ has these built in)

No external packages are required.

## Usage

### Interactive Mode

Run without arguments to use interactive prompts.

    python port_scanner.py

You will be prompted for:

- Target IP or hostname
- Scan type:
  - Web app services
  - Network services
  - Default common ports
  - Custom ports (comma separated)

Example interactive flow:

    Enter target IP or hostname: 192.168.1.10

    Select scan type:
    1. Web app services
    2. Network services
    3. Default common ports
    4. Custom ports (comma-separated)
    Enter choice (1-4): 1
    Selected: Web app services -> [80, 8080, 8000, 443, 8443]

    Starting scan on host: 192.168.1.10
    Ports: [80, 8080, 8000, 443, 8443]
    Port    80 is open
    Port   443 is open

### CLI Mode

You can also provide all parameters via the command line.

    python port_scanner.py --target 192.168.1.10 --profile web

Supported options:

- `--target` or `-t`  
  Target IP or hostname.

- `--profile` or `-p`  
  Port profile to use:

  - `web`  
    Web app services (80, 8080, 8000, 443, 8443).

  - `network`  
    Network and infrastructure services (FTP, SSH, SMTP, DNS, SMB, RDP, and related ports).

  - `default`  
    Union of the web and network profiles.

  - `custom`  
    Use ports provided with `--ports`.

- `--ports`  
  Comma separated list of ports, required when `--profile custom` is used.  
  Example: `--ports 21,22,80,443,3389`

- `--timeout`  
  Connection timeout in seconds for each port (default: `1.0`).

#### CLI Examples

Web app services on a host:

    python port_scanner.py --target example.com --profile web

Network services on a host:

    python port_scanner.py --target 10.0.0.5 --profile network

Default combined profile:

    python port_scanner.py --target 192.168.1.10 --profile default

Custom ports:

    python port_scanner.py --target 192.168.1.20 --profile custom --ports 21,22,80,443,3389

Custom timeout:

    python port_scanner.py --target 192.168.1.20 --profile web --timeout 0.5

## Output

The tool prints:

- Target host
- Selected port list (profile or custom)
- Open ports in the format `Port <number> is open`

Example:

    Starting scan on host: 192.168.1.10
    Ports: [80, 8080, 8000, 443, 8443]

    Port    80 is open
    Port   443 is open

## Security Notes

- This scanner performs simple TCP connect scans.
- Use it only against systems and networks you are explicitly authorized to test.
- Port lists and timeouts are intentionally conservative to keep behavior predictable.

## Skills Demonstrated

- Socket programming with Python
- TCP port scanning logic and service awareness
- Command-line argument parsing with `argparse`
- Input validation and error handling
- Designing user friendly security tooling (profiles, interactive mode, and CLI)
- Structuring small security utilities for portfolio and GitHub projects
