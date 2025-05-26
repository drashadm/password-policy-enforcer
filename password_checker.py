import re
import csv
import yaml
import os
import sys


def load_policy(policy_file):
    with open(policy_file, 'r') as f:
        return yaml.safe_load(f)


def validate_password(password, policy):
    reasons = []
    
    if len(password) < policy.get("min_length", 8):
        reasons.append("Too short")

    if policy.get("require_uppercase", True) and not re.search(r'[A-Z]', password):
        reasons.append("Missing uppercase letter")

    if policy.get("require_lowercase", True) and not re.search(r'[a-z]', password):
        reasons.append("Missing lowercase letter")

    if policy.get("require_number", True) and not re.search(r'\d', password):
        reasons.append("Missing number")

    if policy.get("require_symbol", True) and not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        reasons.append("Missing symbol")

    return (len(reasons) == 0), ", ".join(reasons)


def analyze_passwords(password_file, policy_file, output_file):
    print(f"[~] Loading policy from {policy_file}")
    policy = load_policy(policy_file)

    with open(password_file, 'r', encoding='utf-8') as f:
        passwords = [line.strip() for line in f if line.strip()]

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["Password", "Valid", "Reason"])
        writer.writeheader()

        for pwd in passwords:
            valid, reason = validate_password(pwd, policy)
            writer.writerow({
                "Password": pwd,
                "Valid": "✅" if valid else "❌",
                "Reason": "Compliant" if valid else reason
            })

    print(f"[+] Password audit complete. Results saved to {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python password_checker.py <password_file.txt> <policy.yaml> <output.csv>")
        sys.exit(1)

    analyze_passwords(sys.argv[1], sys.argv[2], sys.argv[3])
