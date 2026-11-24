#!/usr/bin/env python3
"""Stand-in for `gitleaks stdin` used by the unit tests.

Implements just enough of the CLI (stdin, --report-path, --config) and applies
the extra rules from gitleaks.toml plus two default-style rules, with gitleaks'
secret-group semantics (secretGroup, else first non-empty group, else match).
"""
import json
import re
import sys
import tomllib

args = sys.argv[1:]
assert args[0] == "stdin", args
report = args[args.index("--report-path") + 1]
config = args[args.index("--config") + 1] if "--config" in args else None
data = sys.stdin.buffer.read().decode("utf-8", errors="surrogateescape")

if "FORCE_GITLEAKS_ERROR" in data:
    print("simulated failure", file=sys.stderr)
    sys.exit(3)

rules = [
    {"id": "aws-access-token", "regex": r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"},
    {"id": "github-pat", "regex": r"ghp_[0-9a-zA-Z]{36}"},
]
if config:
    with open(config, "rb") as f:
        rules += tomllib.load(f).get("rules", [])

findings = []
for rule in rules:
    rx = rule["regex"]
    flags = 0
    if rx.startswith("(?i)"):
        rx, flags = rx[4:], re.I
    for m in re.finditer(rx, data, flags):
        groups = m.groups()
        if rule.get("secretGroup"):
            secret = m.group(rule["secretGroup"])
        else:
            secret = next((g for g in groups if g), m.group(0))
        allow = [re.compile(a2) for al in rule.get("allowlists", []) for a2 in al.get("regexes", [])]
        if any(a.search(secret) for a in allow):  # like gitleaks' per-rule allowlists (regexTarget = secret)
            continue
        findings.append({"RuleID": rule["id"], "Secret": secret, "Match": m.group(0)})

with open(report, "w", encoding="utf-8") as f:
    json.dump(findings, f)
