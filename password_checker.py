import re
import csv
import yaml
import os
import sys
from collections import Counter

DEFAULT_POLICY = {
    "min_length": 12,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_number": True,
    "require_symbol": True
}

def load_policy(policy_file):
    if not os.path.exists(policy_file):
        print(f"[!] Policy file not found: {policy_file}. Using default policy.")
        return DEFAULT_POLICY
    with open(policy_file, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def validate_password(password, policy):
    reasons = []
    score = 0

    if len(password) >= policy.get("min_length", 12):
        score += 1
    else:
        reasons.append("Too short")

    if policy.get("require_uppercase", True):
        if re.search(r'[A-Z]', password): score += 1
        else: reasons.append("Missing uppercase letter")

    if policy.get("require_lowercase", True):
        if re.search(r'[a-z]', password): score += 1
        else: reasons.append("Missing lowercase letter")

    if policy.get("require_number", True):
        if re.search(r'\d', password): score += 1
        else: reasons.append("Missing number")

    if policy.get("require_symbol", True):
        if re.search(r'[!@#$%^&*(),.?\":{}|<>]', password): score += 1
        else: reasons.append("Missing symbol")

    strength = "Weak" if score <= 2 else "Medium" if score == 3 else "Strong"
    return (len(reasons) == 0), ", ".join(reasons) if reasons else "Compliant", strength

def analyze_passwords(password_file, policy_file, output_file):
    print(f"[~] Using policy: {policy_file}")
    policy = load_policy(policy_file)

    with open(password_file, 'r', encoding='utf-8') as f:
        passwords = [line.strip() for line in f if line.strip()]

    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    results = []
    summary = Counter()

    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["#", "Password", "Valid", "Strength", "Reason"])
        writer.writeheader()

        for i, pwd in enumerate(passwords, 1):
            valid, reason, strength = validate_password(pwd, policy)
            results.append((pwd, valid, strength))
            summary[strength] += 1
            writer.writerow({
                "#": i,
                "Password": pwd,
                "Valid": "✅" if valid else "❌",
                "Strength": strength,
                "Reason": reason
            })

    print(f"\n[+] Password audit complete. Summary:")
    for k in ["Strong", "Medium", "Weak"]:
        print(f"  - {k}: {summary.get(k, 0)}")

    print(f"\n[✔] Results saved to: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage:\n  python password_checker.py <passwords.txt> <policy.yaml> <output.csv>")
        sys.exit(1)

    analyze_passwords(sys.argv[1], sys.argv[2], sys.argv[3])
