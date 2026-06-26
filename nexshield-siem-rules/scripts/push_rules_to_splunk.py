#!/usr/bin/env python3
import requests
import json
import sys
import urllib3
from requests.utils import quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CONFIG ──────────────────────────────────────────────────────────────────
SPLUNK_HOST     = "splunk.nexshield.store"
SPLUNK_PORT     = 8089
SPLUNK_USER     = "imhanrimteam"
SPLUNK_PASSWORD = "lifeis100%Beautiful"

GITHUB_REPO     = "kindyg/nexshield-siem-rules"
GITHUB_BRANCH   = "main"
RULES_PATH      = "nexshield-siem-rules/rules/splunk"
GITHUB_TOKEN    = "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"

SPLUNK_APP      = "search"
# ─────────────────────────────────────────────────────────────────────────────

GITHUB_RAW  = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}"
GITHUB_API  = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{RULES_PATH}"
SPLUNK_BASE = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"


def github_headers():
    return {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {GITHUB_TOKEN}"
    }


def fetch_raw(filename):
    url = f"{GITHUB_RAW}/{RULES_PATH}/{filename}"
    resp = requests.get(url, headers=github_headers(), timeout=15)
    resp.raise_for_status()
    return resp.text


def get_rule_files():
    print(f"[*] Fetching rule list from GitHub: {GITHUB_REPO}")
    resp = requests.get(GITHUB_API, headers=github_headers(), timeout=15)
    resp.raise_for_status()
    files = resp.json()
    json_files = [f for f in files if f["name"].endswith(".json") and f["name"].startswith("rule_")]
    print(f"[+] Found {len(json_files)} rule definitions")
    return json_files


def load_rule(json_filename):
    meta = json.loads(fetch_raw(json_filename))
    spl  = fetch_raw(meta["spl_file"]).strip()
    return meta, spl


def severity_to_int(severity):
    return {"INFORMATIONAL":"1","LOW":"2","MEDIUM":"3","HIGH":"4","CRITICAL":"5"}.get(severity.upper(), "3")


def push_to_splunk(meta, spl):
    rule_name = f"{meta['id']} - {meta['name']}"
    base_url  = f"{SPLUNK_BASE}/servicesNS/nobody/{SPLUNK_APP}/saved/searches"
    auth      = (SPLUNK_USER, SPLUNK_PASSWORD)

    payload = {
        "search":                   spl,
        "description":              meta.get("description", ""),
        "cron_schedule":            meta.get("cron", "*/5 * * * *"),
        "is_scheduled":             "1",
        "schedule_window":          "auto",
        "alert_type":               "number of events",
        "alert_comparator":         "greater than",
        "alert_threshold":          str(meta.get("alert_threshold", 0)),
        "alert.severity":           severity_to_int(meta.get("severity", "MEDIUM")),
        "alert.suppress":           "1",
        "alert.suppress.period":    "60s",
        "alert.suppress.fields":    "final_ip",
        "alert.track":              "1",
        "dispatch.earliest_time":   "-10m",
        "dispatch.latest_time":     "now",
    }

    # Try CREATE first
    create_payload = {"name": rule_name, **payload}
    resp = requests.post(base_url, data=create_payload, auth=auth, verify=False, timeout=15)

    if resp.status_code in (200, 201):
        print(f"  [✓] CREATED: {rule_name}")
        return True

    if resp.status_code == 409:
        # Already exists — UPDATE via POST to named endpoint
        update_url = f"{base_url}/{quote(rule_name, safe='')}"
        resp = requests.post(update_url, data=payload, auth=auth, verify=False, timeout=15)
        if resp.status_code in (200, 201):
            print(f"  [✓] UPDATED: {rule_name}")
            return True

    print(f"  [✗] FAILED ({resp.status_code}): {rule_name}")
    print(f"      {resp.text[:200]}")
    return False


def push_macro_to_splunk(macro_spl):
    base_url = f"{SPLUNK_BASE}/servicesNS/nobody/{SPLUNK_APP}/configs/conf-macros"
    auth     = (SPLUNK_USER, SPLUNK_PASSWORD)

    payload = {"definition": macro_spl.strip(), "iseval": "0"}

    # Try CREATE first
    resp = requests.post(base_url, data={"name": "nexshield_base", **payload}, auth=auth, verify=False, timeout=15)
    if resp.status_code in (200, 201):
        print(f"  [✓] MACRO CREATED: nexshield_base")
        return True

    if resp.status_code == 409:
        # Already exists — UPDATE
        update_url = f"{base_url}/nexshield_base"
        resp = requests.post(update_url, data=payload, auth=auth, verify=False, timeout=15)
        if resp.status_code in (200, 201):
            print(f"  [✓] MACRO UPDATED: nexshield_base")
            return True

    print(f"  [✗] MACRO FAILED ({resp.status_code}): {resp.text[:200]}")
    return False


def test_splunk_connection():
    try:
        resp = requests.get(
            f"{SPLUNK_BASE}/services/server/info",
            auth=(SPLUNK_USER, SPLUNK_PASSWORD),
            verify=False, timeout=10
        )
        if resp.status_code == 200:
            print(f"[+] Splunk connection OK: {SPLUNK_HOST}:{SPLUNK_PORT}")
            return True
        print(f"[!] Splunk connection failed: HTTP {resp.status_code}")
        return False
    except Exception as e:
        print(f"[!] Cannot connect to Splunk: {e}")
        return False


def main():
    print("=" * 60)
    print("  NexShield SIEM Rule Pusher")
    print("=" * 60)

    if not test_splunk_connection():
        sys.exit(1)

    print("\n[*] Pushing base macro...")
    try:
        push_macro_to_splunk(fetch_raw("nexshield_base_macro.spl"))
    except Exception as e:
        print(f"  [!] Macro error: {e}")

    print("\n[*] Pushing detection rules...")
    rule_files    = get_rule_files()
    success_count = 0
    fail_count    = 0

    for rf in sorted(rule_files, key=lambda x: x["name"]):
        try:
            meta, spl = load_rule(rf["name"])
            if push_to_splunk(meta, spl):
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
