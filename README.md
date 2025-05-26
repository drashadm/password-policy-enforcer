# password-policy-enforcer
Python script to audit and enforce password policies using YAML configuration.

# Password Policy Enforcer

## What It Does
This script checks a list of passwords against a configurable YAML policy and outputs a report on compliance.

## Policy Options
- Minimum length
- Requires uppercase, lowercase, number, and symbol

## Usage

```bash
python password_checker.py passwords_sample.txt policy_config.yaml outputs/results.csv
