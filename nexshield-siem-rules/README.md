# NexShield SIEM Rules

Professional detection rules for NexShield SOC platform — covering OWASP Top 10 with anti-bypass techniques.

## Structure

```
rules/
└── splunk/
    ├── nexshield_base_macro.spl     ← Base macro (add this to Splunk first!)
    ├── rule_01_sql_injection.*
    ├── rule_02_xss.*
    ├── rule_03_path_traversal.*
    ├── rule_04_brute_force.*
    ├── rule_05_ddos.*
    ├── rule_06_sensitive_files.*
    ├── rule_07_command_injection.*
    ├── rule_08_scanner_detection.*
    ├── rule_09_directory_enumeration.*
    ├── rule_10_log4shell.*
    ├── rule_11_ssrf.*
    ├── rule_12_xxe.*
    ├── rule_13_broken_access_control.*
    ├── rule_14_mail_attack.*
    └── rule_15_api_abuse.*
scripts/
└── push_rules_to_splunk.py         ← Pushes all rules via Splunk REST API
```

Each rule has two files:
- `.spl` — the full SPL detection query
- `.json` — metadata (name, severity, MITRE ID, cron schedule)

## Rules Summary

| ID | Rule | OWASP | MITRE | Severity |
|----|------|-------|-------|----------|
| 001 | SQL Injection | A03:2021 | T1190 | CRITICAL |
| 002 | Cross-Site Scripting (XSS) | A03:2021 | T1189 | HIGH |
| 003 | Path Traversal | A01:2021 | T1083 | HIGH |
| 004 | Brute Force Login | A07:2021 | T1110 | CRITICAL |
| 005 | DDoS Detection | A06:2021 | T1498 | CRITICAL |
| 006 | Sensitive File Access | A05:2021 | T1083 | HIGH |
| 007 | Command Injection | A03:2021 | T1059 | CRITICAL |
| 008 | Security Scanner Detection | A05:2021 | T1595 | HIGH |
| 009 | Directory Enumeration | A05:2021 | T1595.003 | MEDIUM |
| 010 | Log4Shell CVE-2021-44228 | A06:2021 | T1190 | CRITICAL |
| 011 | SSRF | A10:2021 | T1190 | CRITICAL |
| 012 | XXE Injection | A03:2021 | T1190 | HIGH |
| 013 | Broken Access Control | A01:2021 | T1078 | HIGH |
| 014 | Mail Server Attack | A07:2021 | T1110.001 | HIGH |
| 015 | API Abuse & Flooding | A04:2021 | T1499 | HIGH |

## Anti-Bypass Techniques Used

- **Risk scoring** — multiple indicators required, single bypass not enough
- **Double URL decoding** — catches `%252e%252e` and similar
- **Behavioral detection** — volume + pattern, not just signatures
- **False positive reduction** — internal IP exclusion, health endpoint exclusion
- **Time windowing** — catches slow/distributed attacks
- **Unicode and encoding tricks** — hex IP, octal IP, IFS evasion

## Usage

### 1. Add the base macro to Splunk
Settings → Advanced Search → Search Macros → New
- Name: `nexshield_base`
- Definition: paste content of `nexshield_base_macro.spl`

### 2. Push all rules automatically
```bash
pip install requests
python3 scripts/push_rules_to_splunk.py
```

### 3. Update a rule
Edit the `.spl` file on GitHub → run the push script → Splunk updates automatically
