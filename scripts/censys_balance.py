"""scripts/censys_balance.py — Validate Censys credentials and show credit info.

Usage:  .venv/bin/python3 scripts/censys_balance.py
        make censys-balance

Note: The Censys Platform API v3 does not expose a credits-remaining endpoint.
Credit balance (Free: 100/month) must be checked at:
  https://app.censys.io/account

This script validates the Bearer token by looking up a well-known public IP
(1.1.1.1 — Cloudflare DNS) and prints what the token can access.
"""
import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

_V3_HOST_URL = "https://api.platform.censys.io/v3/global/asset/host/{ip}"
_TEST_IP     = "1.1.1.1"   # Cloudflare — always indexed, costs 1 credit

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

print(f"Testing Censys Platform API v3 with a host lookup of {_TEST_IP} (costs 1 credit)...")
resp = requests.get(
    _V3_HOST_URL.format(ip=_TEST_IP),
    headers=headers,
    timeout=15,
)

print(f"{'─'*58}")
print(f"  API endpoint : GET /v3/global/asset/host/{_TEST_IP}")
print(f"  Token prefix : {api_secret[:14]}...")
print(f"  HTTP status  : {resp.status_code}")

if resp.status_code == 401:
    print("  Auth result  : ❌  UNAUTHORIZED — check CENSYS_API_SECRET in .env", file=sys.stderr)
    sys.exit(1)

if resp.status_code == 403:
    print("  Auth result  : ❌  FORBIDDEN — token may lack host-lookup permission", file=sys.stderr)
    sys.exit(1)

if not resp.ok and resp.status_code != 404:
    print(f"  Auth result  : ❌  {resp.status_code}: {resp.text[:120]}", file=sys.stderr)
    sys.exit(1)

print("  Auth result  : ✅  VALID — Bearer token accepted by Platform API v3")

if resp.ok:
    data     = resp.json()
    resource = (data.get("result") or {}).get("resource") or {}
    asn_info = resource.get("autonomous_system") or {}
    loc      = resource.get("location") or {}
    services = resource.get("services") or []
    print(f"  Test IP      : {resource.get('ip', _TEST_IP)}")
    print(f"  Country      : {loc.get('country_code','?')}")
    print(f"  ASN          : AS{asn_info.get('asn','?')} — {asn_info.get('name','?')}")
    print(f"  Open ports   : {[s.get('port') for s in services]}")
else:
    print(f"  Note         : {_TEST_IP} returned 404 (not indexed) — auth still valid")

print(f"{'─'*58}")
print("  Credit balance is NOT available via the API (Platform API v3).")
print("  Check your remaining credits at: https://app.censys.io/account")
print(f"  Free plan budget: 100 credits/month | CENSYS_MAX_ENRICH=80 (default)")
print(f"{'─'*58}")
print(f"  Budget reminder (Free plan = 100 credits/month):")
print(f"    64 queries × 1 credit = 64 credits/month  ✅")
print(f"{'─'*48}")
