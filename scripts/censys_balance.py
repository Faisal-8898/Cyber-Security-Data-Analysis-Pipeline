"""scripts/censys_balance.py — Show Censys credit balance using the Platform API v3.

Usage:  .venv/bin/python3 scripts/censys_balance.py
        make censys-balance

Uses the official Account Management endpoint (costs 0 credits):
  GET https://api.platform.censys.io/v3/accounts/users/credits
Docs: https://docs.censys.com/reference/v3-accountmanagement-user-credits
"""
import os
import sys
from datetime import date

import requests
from dotenv import load_dotenv

load_dotenv()

_CREDITS_URL       = "https://api.platform.censys.io/v3/accounts/users/credits"
_CREDITS_USAGE_URL = "https://api.platform.censys.io/v3/accounts/users/credits/usage"

api_secret = os.environ.get("CENSYS_API_SECRET", "").strip()
if not api_secret:
    print("ERROR: CENSYS_API_SECRET is not set in .env or environment.", file=sys.stderr)
    print("  Set it to your Censys Personal Access Token from https://app.censys.io/account")
    sys.exit(1)

if not api_secret.startswith("censys_"):
    print(f"WARNING: CENSYS_API_SECRET doesn't look like a PAT (expected 'censys_...'): {api_secret[:12]}...")

headers = {
    "Accept":        "application/json",
    "Authorization": f"Bearer {api_secret}",
}

# ── Credit balance (free endpoint — costs 0 credits) ──────────────────────────
print("Fetching Censys credit balance (Platform API v3, Account Management)...")
resp = requests.get(_CREDITS_URL, headers=headers, timeout=15)

print(f"{'─'*58}")
print(f"  API endpoint : GET /v3/accounts/users/credits")
print(f"  Token prefix : {api_secret[:14]}...")
print(f"  HTTP status  : {resp.status_code}")

if resp.status_code == 401:
    print("  Auth result  : ❌  UNAUTHORIZED — check CENSYS_API_SECRET in .env", file=sys.stderr)
    sys.exit(1)

if resp.status_code == 403:
    print("  Auth result  : ❌  FORBIDDEN — token may lack API access permission", file=sys.stderr)
    sys.exit(1)

if resp.status_code == 404:
    print("  Auth result  : ❌  USER NOT FOUND — token may be invalid or revoked", file=sys.stderr)
    sys.exit(1)

if not resp.ok:
    print(f"  Auth result  : ❌  {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
    sys.exit(1)

data = resp.json()
# Response shape: { "result": { "allowance": int, "used": int, "remaining": int,
#                               "refresh_date": "YYYY-MM-DD", ... } }
result     = data.get("result") or data  # some versions return the object directly
allowance  = result.get("allowance",   result.get("total_credits",   "?"))
used       = result.get("used",        result.get("credits_used",    "?"))
remaining  = result.get("remaining",   result.get("credits_remaining","?"))
refresh    = result.get("refresh_date", result.get("refresh_at",     "?"))

print(f"  Auth result  : ✅  VALID — Bearer token accepted")
print(f"{'─'*58}")
print(f"  Plan allowance : {allowance} credits / month")
print(f"  Credits used   : {used}")
print(f"  Credits left   : {remaining}")
print(f"  Refresh date   : {refresh}")

# ── Monthly usage breakdown ────────────────────────────────────────────────────
today      = date.today()
month_start = today.replace(day=1).isoformat()
usage_resp = requests.get(
    _CREDITS_USAGE_URL,
    headers=headers,
    params={"start_date": month_start, "granularity": "monthly"},
    timeout=15,
)
if usage_resp.ok:
    usage_data = usage_resp.json()
    entries = (usage_data.get("result") or usage_data).get("usage", [])
    if entries:
        print(f"{'─'*58}")
        print(f"  Monthly usage breakdown (from {month_start}):")
        for entry in entries:
            print(f"    {entry.get('date', entry.get('period','?'))} : {entry.get('credits_used', entry.get('used','?'))} credits used")

print(f"{'─'*58}")
max_enrich = int(os.environ.get("CENSYS_MAX_ENRICH", "40"))
print(f"  Current CENSYS_MAX_ENRICH : {max_enrich} IPs/run")
print(f"  Budget reminder (Free = 100 cr/month):")
print(f"    {max_enrich} IPs × 1 cr/IP × 4 weeks = {max_enrich * 4} cr/month")
print(f"    To use ALL credits: make poll-censys-max  (sets CENSYS_MAX_ENRICH=100)")
print(f"{'─'*58}")
