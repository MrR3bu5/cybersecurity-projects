import re
import math
import json
import hashlib
import argparse
import requests


allowed = re.compile(r'^[\x20-\x7E]+$')

STRENGTH_LABELS = {
    4: "Very Strong",
    3: "Strong",
    2: "Good",
    1: "Weak",
    0: "Very Weak"
}

# Check password against: https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt
try:
    with open("passwords.txt") as f:
        common_passwords = f.read().splitlines()
except FileNotFoundError:
    common_passwords = []


def analyzepassword(p):
    plen         = len(p)
    has_upper    = bool(re.search(r'[A-Z]', p))
    has_lower    = bool(re.search(r'[a-z]', p))
    has_digit    = bool(re.search(r'[0-9]', p))
    has_special  = bool(re.search(r'[^A-Za-z0-9]', p))
    has_repeats  = bool(re.search(r'(.)\1{3,}', p))
    has_sequence = bool(re.search(r'(0123|1234|2345|3456|4567|5678|6789|abcd|qwerty|password)', p.lower()))

    # NIST 2024: length is primary driver
    if plen >= 20:
        length_score = 4
    elif plen >= 16:
        length_score = 3
    elif plen >= 12:
        length_score = 2
    elif plen >= 8:
        length_score = 1
    else:
        length_score = 0

    # complexity is a bonus modifier, not a requirement
    comp_bonus = sum([has_upper, has_lower, has_digit, has_special])
    if has_repeats:  comp_bonus -= 2
    if has_sequence: comp_bonus -= 1

    if comp_bonus >= 3:
        modifier = 1
    elif comp_bonus <= 0:
        modifier = -1
    else:
        modifier = 0

    final_score = max(0, min(4, length_score + modifier))
    final = STRENGTH_LABELS[final_score]

    # entropy
    charset = sum([26 * has_lower, 26 * has_upper, 10 * has_digit, 32 * has_special])
    entropy = math.log2(charset ** plen) if charset else 0

    if entropy >= 80:
        elabel = "Very Strong"
    elif entropy >= 60:
        elabel = "Strong"
    elif entropy >= 40:
        elabel = "Moderate"
    else:
        elabel = "Weak"

    # recommendations
    tips = []
    if plen < 8:  tips.append("Password must be at least 8 characters (NIST minimum)")
    if plen < 15: tips.append("NIST recommends 15+ characters for best security")
    if has_repeats:  tips.append("Avoid repeating characters")
    if has_sequence: tips.append("Avoid sequential patterns like 1234 or qwerty")
    if p.lower() in common_passwords: tips.append("This is a commonly used password, change it")

    return final, entropy, elabel, tips

# Crack time based on entropy
def estimatecracktime(entropy):
    guesses_needed = 2 ** entropy
    guesses_per_sec = 100_000_000_000
    seconds = guesses_needed / guesses_per_sec
    
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} days"
    elif seconds < 31536000 * 100:
        return f"{seconds/31536000:.2f} years"
    else:
        return "centuries (effectively uncrackable)"

# Check for password against "HaveIBeenPawned API"
def hibpcheck(p):
    sha1 = hashlib.sha1(p.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
        return 0
    except requests.RequestException:
        return None


def checkpass(p, export_json=False):
    final, entropy, elabel, tips = analyzepassword(p)

    print("Checking password strength...")
    print(f"Overall strength:      {final}")
    print(f"Entropy score:         {entropy:.1f} bits ({elabel})")
    cracktime = estimatecracktime(entropy)
    print(f"Estimated crack time:  {cracktime}")

    print("Checking breach database...")
    breach_count = hibpcheck(p)
    if breach_count is None:
        print("HIBP check failed, no connection.")
        tips.append("Could not check breach database, verify manually")
    elif breach_count > 0:
        print(f"WARNING: Password found in {breach_count:,} breaches.")
        tips.append(f"This password appeared in {breach_count:,} known breaches, change it immediately")
    else:
        print("Password not found in known breaches.")

    if tips:
        print("Recommendations:")
        for tip in tips:
            print(f"  - {tip}")
    else:
        print("No recommendations, password looks good.")

    if export_json:
        result = {
            "overall_strength": final,
            "entropy_bits":     round(entropy, 1),
            "entropy_label":    elabel,
            "crack_time":       cracktime,
            "breach_count":     breach_count,
            "recommendations":  tips
        }
        print(json.dumps(result, indent=2))


def auditfile(filepath, export_json=False):
    try:
        with open(filepath) as f:
            passwords = f.read().splitlines()
        print(f"Auditing {len(passwords)} passwords...\n")
        for p in passwords:
            print(f"Password: {p}")
            checkpass(p, export_json=export_json)
            print("-" * 40)
    except FileNotFoundError:
        print(f"File not found: {filepath}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("--password", help="Check a single password")
    parser.add_argument("--file",     help="Audit a file of passwords")
    parser.add_argument("--json",     action="store_true", help="Export results as JSON")
    args = parser.parse_args()

    if args.file:
        auditfile(args.file, export_json=args.json)
    elif args.password:
        if not allowed.match(args.password):
            print("Password contains invalid characters.")
        else:
            checkpass(args.password, export_json=args.json)
    else:
        while True:
            password = input("Enter Password to Check Strength (or \\q to quit): ")

            if password == "\\q":
                print("Exiting...")
                break
            elif not password:
                print("No password entered. Try again.")
            elif not allowed.match(password):
                print("Password contains invalid characters. Try again.")
            else:
                checkpass(password, export_json=args.json)
