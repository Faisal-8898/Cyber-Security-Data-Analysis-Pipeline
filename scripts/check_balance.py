"""scripts/check_balance.py — Print remaining Shodan API credits.

Usage:  .venv/bin/python3 scripts/check_balance.py
        make check-balance

Reads SHODAN_API_KEY from .env (or environment).
Reports plan, query credits remaining, and scan credits remaining.
"""
import os
import sys

from dotenv import load_dotenv

load_dotenv()

key = os.environ.get("SHODAN_API_KEY", "").strip()
if not key:
    print("ERROR: SHODAN_API_KEY is not set in .env or environment.", file=sys.stderr)
    sys.exit(1)

try:
    import shodan
except ImportError:
    print("ERROR: 'shodan' package not installed.  Run: pip install shodan", file=sys.stderr)
    sys.exit(1)

api = shodan.Shodan(key)
try:
    info = api.info()
except shodan.APIError as e:
    print(f"Shodan API error: {e}", file=sys.stderr)
    sys.exit(1)

plan           = info.get("plan", "unknown")
query_credits  = info.get("query_credits", "N/A")
scan_credits   = info.get("scan_credits",  "N/A")
usage_limits   = info.get("usage_limits",  {})

# Budget reference: 40 queries × 1 credit/query (100 results, 1 page) = 40 credits/week per account
weekly_needed = 40 * 1   # default: 100 results = 1 page = 1 credit per query
months_left   = int(query_credits) // weekly_needed if str(query_credits).isdigit() else "?"

print(f"{'─'*45}")
print(f"  Plan              : {plan}")
print(f"  Query credits left: {query_credits}  (need {weekly_needed}/week → ~{months_left} week(s) of polls)")
print(f"  Scan credits left : {scan_credits}")
if usage_limits:
    print(f"  Usage limits      : {usage_limits}")
print(f"{'─'*45}")
print("  Budget reminder (4 edu accounts, SHODAN_MAX_PER_QUERY=100):")
print(f"    40 queries × 1 credit × 4 weeks = 160 credits/month total")
print(f"    = 40 credits/account/month  (limit: 100/account)  ✅")
print(f"    Raise to 200 results (2 cr/query) for capped queries after first pull.")
print(f"{'─'*45}")
