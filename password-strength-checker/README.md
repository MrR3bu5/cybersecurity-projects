# Password Strength Checker

A Python tool that evaluates password security using NIST 2024 guidelines, entropy analysis, and breach detection.

## Features

- NIST SP 800-63B Rev. 4 (2024) compliant password strength scoring
- Entropy calculation with interpretive labels
- Crack time estimation based on current hardware capabilities
- HaveIBeenPwned API integration for breach detection
- Privacy-preserving k-anonymity implementation
- Common password screening
- Pattern detection (repeats, sequences)
- CLI and file audit modes
- JSON export for automation

## Requirements

pip install requests

Standard library modules used: re, math, json, hashlib, argparse

## Usage

### Interactive Mode

python password_checker.py

Enter passwords when prompted. Type \q to quit.

### Single Password Check

python password_checker.py --password "YourP@ssw0rd"

### Audit Mode

python password_checker.py --file passwords.txt

### JSON Export

python password_checker.py --password "test123" --json

## Output

The tool returns:
- Overall strength (Very Weak / Weak / Good / Strong / Very Strong)
- Entropy score in bits with interpretive label
- Estimated crack time at 100 billion guesses per second
- Breach status from HaveIBeenPwned database
- Actionable recommendations for improvement

## Security Notes

Your password is never sent over the network. The tool uses SHA-1 hashing and k-anonymity to check breaches securely. Only the first 5 characters of the hash are transmitted.

## NIST 2024 Alignment

This tool follows NIST SP 800-63B Rev. 4 guidelines:
- Minimum 8 character length enforced
- 15+ character length recommended
- Length prioritized over complexity
- Mandatory breach checking
- No forced complexity requirements
- No arbitrary expiration policies

## Skills Demonstrated

- API integration with external security services
- Cryptographic hashing (SHA-1)
- Password entropy calculation
- Privacy-preserving data lookup patterns (k-anonymity)
- Compliance with current NIST security standards
- Command-line argument parsing
- File I/O and batch processing
- JSON serialization for automation workflows
