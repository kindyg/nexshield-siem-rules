#!/usr/bin/env python3
"""
NexShield SIEM Rule Pusher
Fetches rules from GitHub and pushes them to Splunk via REST API.
Run this script whenever you update rules on GitHub.

Usage:
    pip install requests
    python3 push_rules_to_splunk.py
"""

import requests
import json
import os
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CONFIG ──────────────────────────────────────────────────────────────────
SPLUNK_HOST     = "splunk.nexshield.store"
SPLUNK_PORT     = 8089                          # Splunk REST API port (not 8000)
SPLUNK_USER     = "imhanrimteam"
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "lifeis100%Beautiful")

GITHUB_REPO     = "kindyg/nexshield-siem-rules"
GITHUB_BRANCH   = "main"
RULES_PATH      = "nexshield-siem-rules/rules/splunk"
GITHUB_TOKEN    = os.environ.get("GITHUB_TOKEN", "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")  # Optional: for private repos

SPLUNK_APP      = "search"         # App to create saved searches in
TELEGRAM_WEBHOOK = os.environ.get("TELEGRAM_WEBHOOK", "")  # Optional alert webhook
# ─────────────────────────────────────────────────────────────────────────────

GITHUB_RAW = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{RULES_PATH}"
SPLUNK_BASE = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"


def github_headers():
    h = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"token {GITHUB_TOKEN}"
    return h


def get_rule_files():
    """Get list of rule JSON files from GitHub."""
    print(f"[*] Fetching rule list from GitHub: {GITHUB_REPO}")
    resp = requests.get(GITHUB_API, headers=github_headers(), timeout=15)
    resp.raise_for_status()
    files = resp.json()
    json_files = [f for f in files if f["name"].endswith(".json") and f["name"].startswith("rule_")]
    print(f"[+] Found {len(json_files)} rule definitions")
    return json_files


def fetch_raw(path):
    """Fetch raw file content from GitHub."""
    url = f"{GITHUB_RAW}/{RULES_PATH}/{path}"
    headers = github_headers()
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.text


def load_rule(json_filename):
    """Load rule metadata and SPL from GitHub."""
    meta = json.loads(fetch_raw(json_filename))
    spl_content = fetch_raw(meta["spl_file"])
    return meta, spl_content.strip()


def push_to_splunk(meta, spl):
    """Create or update a saved search in Splunk."""
    rule_name = f"{meta['id']} - {meta['name']}"
    url = f"{SPLUNK_BASE}/servicesNS/nobody/{SPLUNK_APP}/saved/searches"
    auth = (SPLUNK_USER, SPLUNK_PASSWORD)

    payload = {
        "search": spl,
        "description": meta.get("description", ""),
        "cron_schedule": meta.get("cron", "* * * * *"),
        "is_scheduled": "1",
        "schedule_window": "auto",
        "alert_type": "number of events",
        "alert_comparator": meta.get("alert_comparator", "greater than"),
        "alert_threshold": str(meta.get("alert_threshold", 0)),
        "alert.severity": severity_to_int(meta.get("severity", "MEDIUM")),
        "alert.suppress": "1",
        "alert.suppress.fields": "final_ip",
        "alert.suppress.period": "60s",
        "dispatch.earliest_time": "-5m",
        "dispatch.latest_time": "now",
        "actions": "script",
        "alert.execute.cmd": "telegram_alert.sh",
        "alert.track": "1",
        "counttype": "number of events",
        "relation": "greater than",
        "quantity": str(meta.get("alert_threshold", 0)),
    }

    # Try CREATE first
    create_payload = {"name": rule_name, **payload}
    resp = requests.post(url, data=create_payload, auth=auth, verify=False, timeout=15)

    if resp.status_code in (200, 201):
        print(f"  [✓] CREATED: {rule_name}")
        return True

    elif resp.status_code == 409:
        # Already exists — update it instead
        from urllib.parse import quote
        update_url = f"{url}/{quote(rule_name, safe='')}"
        resp = requests.post(update_url, data=payload, auth=auth, verify=False, timeout=15)
        if resp.status_code in (200, 201):
            print(f"  [✓] UPDATED: {rule_name}")
            return True
        else:
            print(f"  [✗] UPDATE FAILED ({resp.status_code}): {rule_name}")
            print(f"      Response: {resp.text[:200]}")
            return False

    else:
        print(f"  [✗] FAILED ({resp.status_code}): {rule_name}")
        print(f"      Response: {resp.text[:200]}")
        return False


def push_macro_to_splunk(macro_spl):
    """Create or update the nexshield_base macro in Splunk."""
    url = f"{SPLUNK_BASE}/servicesNS/nobody/{SPLUNK_APP}/configs/conf-macros"
    auth = (SPLUNK_USER, SPLUNK_PASSWORD)

    payload = {
        "definition": macro_spl.strip(),
        "iseval": "0",
    }

    # Try update first since macro likely already exists
    update_url = f"{url}/nexshield_base"
    resp = requests.post(update_url, data=payload, auth=auth, verify=False, timeout=15)

    if resp.status_code in (200, 201):
        print(f"  [✓] MACRO UPDATED: nexshield_base")
        return True

    # If update failed, try create
    create_payload = {"name": "nexshield_base", **payload}
    resp = requests.post(url, data=create_payload, auth=auth, verify=False, timeout=15)

    if resp.status_code in (200, 201):
        print(f"  [✓] MACRO CREATED: nexshield_base")
        return True
    else:
        print(f"  [✗] MACRO FAILED ({resp.status_code}): {resp.text[:200]}")
        return False


def severity_to_int(severity):
    """Convert severity string to Splunk integer (1-6)."""
    mapping = {
        "INFORMATIONAL": "1",
        "LOW":           "2",
        "MEDIUM":        "3",
        "HIGH":          "4",
        "CRITICAL":      "5",
    }
    return mapping.get(severity.upper(), "3")


def test_splunk_connection():
    """Test Splunk API connectivity."""
    try:
        resp = requests.get(
            f"{SPLUNK_BASE}/services/server/info",
            auth=(SPLUNK_USER, SPLUNK_PASSWORD),
            verify=False,
            timeout=10
        )
        if resp.status_code == 200:
            print(f"[+] Splunk connection OK: {SPLUNK_HOST}:{SPLUNK_PORT}")
            return True
        else:
            print(f"[!] Splunk connection failed: HTTP {resp.status_code}")
            return False
    except Exception as e:
        print(f"[!] Cannot connect to Splunk: {e}")
        return False


def main():
    print("=" * 60)
    print("  NexShield SIEM Rule Pusher")
    print("=" * 60)

    # Test connection
    if not test_splunk_connection():
        print("[!] Aborting — cannot reach Splunk API")
        sys.exit(1)

    # Push base macro first
    print("\n[*] Pushing base macro...")
    try:
        macro_spl = fetch_raw("nexshield_base_macro.spl")
        push_macro_to_splunk(macro_spl)
    except Exception as e:
        print(f"  [!] Macro push failed: {e}")

    # Fetch and push all rules
    print("\n[*] Pushing detection rules...")
    rule_files = get_rule_files()

    success_count = 0
    fail_count    = 0

    for rf in sorted(rule_files, key=lambda x: x["name"]):
        try:
            meta, spl = load_rule(rf["name"])
            ok = push_to_splunk(meta, spl)
            if ok:
                success_count += 1
            else:
                fail_count += 1
        except Exception as e:
            print(f"  [✗] ERROR loading {rf['name']}: {e}")
            fail_count += 1

    print("\n" + "=" * 60)
    print(f"  Done! {success_count} rules pushed, {fail_count} failed")
    print("=" * 60)

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
