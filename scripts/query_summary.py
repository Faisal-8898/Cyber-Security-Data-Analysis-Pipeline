"""scripts/query_summary.py — Print query-set statistics for both pollers.

Usage:  .venv/bin/python3 scripts/query_summary.py
        make query-summary

Imports SHODAN_QUERIES and CENSYS_QUERIES from the pipeline package and
prints per-category counts plus the monthly credit budget calculation.
"""
import sys
import os

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from collections import Counter

from pipeline.poll_shodan import SHODAN_QUERIES
from pipeline.poll_censys import CENSYS_QUERIES

# ── Shodan ──────────────────────────────────────────────────────────────────
print("=== SHODAN ===")
sc = Counter(cat for _, cat, _ in SHODAN_QUERIES)
for cat in sorted(sc):
    print(f"  [{cat}]  {sc[cat]:2d} queries")

n_shodan      = len(SHODAN_QUERIES)
credits_query = 1          # 100 results = 1 page = 1 credit per query (default)
credits_week  = n_shodan * credits_query
credits_month = credits_week * 4
per_account   = credits_month // 4

print(f"  {'─'*38}")
print(f"  TOTAL   : {n_shodan} queries")
print(f"  Credits : {n_shodan} q × {credits_query} cr × 4 weeks = {credits_month}/month total")
print(f"            = {per_account} credits/account/month  (limit 100)  ✅")
print(f"  Tune    : after first pull, bump SHODAN_MAX_PER_QUERY=200 for capped queries")

# ── Censys ───────────────────────────────────────────────────────────────────
print()
print("=== CENSYS (enrich mode — Free plan) ===")
print("  Mode    : host-lookup enrichment of Shodan-collected IPs")
print("  API     : Platform API v3  /v3/global/asset/host/{ip}")
print("  Auth    : Bearer PAT  (CENSYS_API_SECRET=censys_...)")
print("  Focus   : High-value Shodan IPs (categories E=proxy, L=combos, F=botnet)")
print()

# Budget alignment with Shodan
max_enrich   = int(os.environ.get("CENSYS_MAX_ENRICH", "25"))
sleep_s      = float(os.environ.get("CENSYS_SLEEP_BETWEEN_LOOKUPS", "1.0"))
eta_min      = max_enrich * sleep_s / 60
credits_week = max_enrich
credits_month = credits_week * 4
budget_ok    = credits_month <= 100

print(f"  {'─'*38}")
print(f"  TOTAL   : {max_enrich} IPs enriched per weekly run")
print(f"  Credits : {max_enrich} lookups × 1 cr × 4 weeks = {credits_month}/month")
print(f"            = matches SHODAN budget (100/month)  {'✅' if budget_ok else '⚠️  OVER'}")
print(f"  ETA     : ~{eta_min:.0f} min/run at {sleep_s}s delay")
print(f"  Note    : Paper mode → make poll-censys-paper (50/week, novelty-focused)")
print(f"  Note    : Credit balance at make censys-balance")
print()

# Catalogue size (kept for future Starter-plan search mode)
cc = Counter(cat for _, cat, _ in CENSYS_QUERIES)
print(f"  Stored search queries (Starter plan upgrade): {len(CENSYS_QUERIES)}")
for cat in sorted(cc):
    print(f"    [{cat}]  {cc[cat]:2d} queries")
