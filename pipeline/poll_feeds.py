"""pipeline/poll_feeds.py — Pull malware intelligence feeds and cross-match IOCs.

Sources (all FREE, no API key required for Tier-1):
  ThreatFox  — C2 server IPs/domains tagged by malware family (Mirai, Gafgyt, etc.)
  URLhaus    — Malicious download/dropper URLs

Paper context
-------------
  RQ2: cross-match honeypot IOC IPs against ThreatFox C2 records
       → "X of 1,918 honeypot IPs appear in known C2 infrastructure"
  RQ2: cross-match honeypot download_url against URLhaus
       → "Y download URLs confirmed as malware distribution infrastructure"
  Section 5.8 / Section 8: multi-vantage linkage evidence

Environment variables
---------------------
  THREATFOX_DAYS   days of ThreatFox history to pull  (default: 7)
  URLHAUS_DAYS     days of URLhaus history to pull     (default: 7)
  FEEDS_DRY_RUN    "1" → print counts, skip DB writes
"""
from __future__ import annotations

import os
import time
from datetime import date, datetime, timezone

import requests
from dotenv import load_dotenv

load_dotenv()

from .core import get_pipeline_version, logger, task

_THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
_URLHAUS_API   = "https://urlhaus-api.abuse.ch/v1/"
_TIMEOUT       = 30

# IoT-relevant malware families to fetch from ThreatFox
_IOT_FAMILIES = [
    "mirai", "gafgyt", "mozi", "bashlite", "satori", "okiru",
    "reaper", "hajime", "iotreaper", "muhstik", "tsunami",
    "xorddos", "dofloo", "lizkebab", "torlus", "luabot",
]

_DRY_RUN = os.environ.get("FEEDS_DRY_RUN", "0") == "1"


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------

def _pull_threatfox(days: int) -> list[dict]:
    """Return list of IOC dicts from ThreatFox for IoT malware families."""
    all_iocs: list[dict] = []

    # 1. Recent IOCs (last N days) — catches anything new
    payload = {"query": "get_recent", "limit": 1000}
    try:
        r = requests.post(_THREATFOX_API, json=payload, timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "ok":
            all_iocs.extend(data.get("data") or [])
            logger.info(f"ThreatFox recent: {len(data.get('data') or [])} IOCs")
    except Exception as exc:
        logger.warning(f"ThreatFox recent pull failed: {exc}")

    time.sleep(1)

    # 2. Per-family queries for IoT malware
    for family in _IOT_FAMILIES:
        payload = {"query": "get_iocs", "malware": family, "limit": 500}
        try:
            r = requests.post(_THREATFOX_API, json=payload, timeout=_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            if data.get("query_status") == "ok":
                iocs = data.get("data") or []
                if iocs:
                    logger.info(f"  ThreatFox {family}: {len(iocs)} IOCs")
                all_iocs.extend(iocs)
        except Exception as exc:
            logger.warning(f"ThreatFox {family} failed: {exc}")
        time.sleep(0.5)

    # Deduplicate by ioc value
    seen: set[str] = set()
    unique: list[dict] = []
    for ioc in all_iocs:
        val = ioc.get("ioc") or ""
        if val and val not in seen:
            seen.add(val)
            unique.append(ioc)

    logger.info(f"ThreatFox total unique IOCs: {len(unique)}")
    return unique


def _threatfox_to_feed_record(ioc: dict, snapshot_date: date) -> dict:
    """Normalise a ThreatFox IOC into a feed_iocs row."""
    ioc_type = (ioc.get("ioc_type") or "").lower()     # ip:port | domain | url | md5 | sha256
    raw_ioc  = ioc.get("ioc") or ""

    # Split "1.2.3.4:1080" → ip + port
    ip, port = None, None
    if ioc_type == "ip:port" and ":" in raw_ioc:
        parts = raw_ioc.rsplit(":", 1)
        ip = parts[0].strip("[]")   # handle IPv6 [::1]:port
        try:
            port = int(parts[1])
        except ValueError:
            pass
    elif ioc_type == "domain":
        ip = None   # domain, not IP

    malware    = (ioc.get("malware") or "").lower()
    confidence = ioc.get("confidence_level") or 0
    tags       = ioc.get("tags") or []
    first_seen = ioc.get("first_seen")
    last_seen  = ioc.get("last_seen")

    return {
        "source":        "threatfox",
        "ioc_type":      ioc_type,
        "ioc_value":     raw_ioc,
        "ip":            ip,
        "port":          port,
        "malware_family": malware,
        "confidence":    confidence,
        "tags":          tags,
        "first_seen":    first_seen,
        "last_seen":     last_seen,
        "snapshot_date": str(snapshot_date),
        "raw_data":      ioc,
    }


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

def _pull_urlhaus() -> list[dict]:
    """Return list of recent malicious URL records from URLhaus."""
    try:
        r = requests.post(
            f"{_URLHAUS_API}urls/recent/",
            data={"limit": 1000},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        urls = data.get("urls") or []
        logger.info(f"URLhaus recent: {len(urls)} URLs")
        return urls
    except Exception as exc:
        logger.warning(f"URLhaus pull failed: {exc}")
        return []


def _urlhaus_to_feed_record(entry: dict, snapshot_date: date) -> dict:
    return {
        "source":        "urlhaus",
        "ioc_type":      "url",
        "ioc_value":     entry.get("url") or "",
        "ip":            entry.get("ip_address") or None,
        "port":          None,
        "malware_family": (entry.get("tags") or ["unknown"])[0] if entry.get("tags") else "unknown",
        "confidence":    100 if entry.get("url_status") == "online" else 80,
        "tags":          entry.get("tags") or [],
        "first_seen":    entry.get("date_added"),
        "last_seen":     None,
        "snapshot_date": str(snapshot_date),
        "raw_data":      entry,
    }


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _upsert_feed_iocs(records: list[dict]) -> int:
    """Insert feed IOC records; skip duplicates. Returns inserted count."""
    if not records:
        return 0
    from . import db as _db
    inserted = 0
    with _db.get_connection() as conn:
        with conn.cursor() as cur:
            for rec in records:
                try:
                    cur.execute("""
                        INSERT INTO feed_iocs
                          (source, ioc_type, ioc_value, ip, port,
                           malware_family, confidence, tags, first_seen,
                           last_seen, snapshot_date, raw_data)
                        VALUES
                          (%(source)s, %(ioc_type)s, %(ioc_value)s, %(ip)s, %(port)s,
                           %(malware_family)s, %(confidence)s, %(tags)s, %(first_seen)s,
                           %(last_seen)s, %(snapshot_date)s, %(raw_data)s)
                        ON CONFLICT (source, ioc_value) DO UPDATE SET
                          last_seen       = EXCLUDED.last_seen,
                          confidence      = GREATEST(feed_iocs.confidence, EXCLUDED.confidence),
                          malware_family  = COALESCE(NULLIF(EXCLUDED.malware_family,''), feed_iocs.malware_family),
                          snapshot_date   = EXCLUDED.snapshot_date
                    """, {
                        **rec,
                        "tags":     rec.get("tags") or [],
                        "raw_data": _db._sanitize_record(rec.get("raw_data") or {}),
                    })
                    inserted += cur.rowcount
                except Exception as exc:
                    logger.warning(f"feed_iocs insert skip: {exc}")
                    conn.rollback()
                    continue
        conn.commit()
    return inserted


def _cross_match_honeypot_iocs() -> dict:
    """
    Cross-match honeypot IOC IPs against feed_iocs.
    Returns counts for the paper's RQ2 linkage claim.
    """
    from . import db as _db
    with _db.get_connection() as conn:
        with conn.cursor() as cur:
            # IPs seen in honeypot IOCs that also appear in ThreatFox
            cur.execute("""
                SELECT
                  COUNT(DISTINCT hi.ioc_value) AS matched_ips,
                  COUNT(DISTINCT fi.malware_family) AS malware_families,
                  array_agg(DISTINCT fi.malware_family) FILTER (WHERE fi.malware_family IS NOT NULL) AS families
                FROM ioc_records hi
                JOIN feed_iocs fi
                  ON hi.ioc_value = fi.ip
                WHERE hi.ioc_type = 'ip'
                  AND fi.source = 'threatfox'
            """)
            tf_row = cur.fetchone()

            # Download URLs from honeypot matched in URLhaus
            cur.execute("""
                SELECT COUNT(DISTINCT hi.ioc_value) AS matched_urls
                FROM ioc_records hi
                JOIN feed_iocs fi
                  ON hi.ioc_value = fi.ioc_value
                WHERE hi.ioc_type = 'url'
                  AND fi.source = 'urlhaus'
            """)
            uh_row = cur.fetchone()

            # Total honeypot IOC IPs for denominator
            cur.execute("SELECT COUNT(*) FROM ioc_records WHERE ioc_type = 'ip'")
            total_ips = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM ioc_records WHERE ioc_type = 'url'")
            total_urls = cur.fetchone()[0]

    tf_matched  = tf_row[0] if tf_row else 0
    uh_matched  = uh_row[0] if uh_row else 0
    families    = tf_row[2] if tf_row else []

    return {
        "honeypot_ips_total":       total_ips,
        "threatfox_ip_matches":     tf_matched,
        "threatfox_match_pct":      round(tf_matched / max(total_ips, 1) * 100, 1),
        "malware_families_matched": tf_row[1] if tf_row else 0,
        "families":                 families,
        "honeypot_urls_total":      total_urls,
        "urlhaus_url_matches":      uh_matched,
        "urlhaus_match_pct":        round(uh_matched / max(total_urls, 1) * 100, 1),
    }


# ---------------------------------------------------------------------------
# Main task
# ---------------------------------------------------------------------------

@task("poll_feeds")
def poll_feeds() -> None:
    now         = datetime.now(timezone.utc)
    today       = now.date()
    run_id      = str(__import__("uuid").uuid4())
    tf_days     = int(os.environ.get("THREATFOX_DAYS", "7"))

    logger.info(f"poll_feeds start — threatfox_days={tf_days} dry_run={_DRY_RUN}")

    # 1. ThreatFox
    tf_iocs  = _pull_threatfox(tf_days)
    tf_recs  = [_threatfox_to_feed_record(i, today) for i in tf_iocs]

    # 2. URLhaus
    uh_urls  = _pull_urlhaus()
    uh_recs  = [_urlhaus_to_feed_record(u, today) for u in uh_urls]

    all_recs = tf_recs + uh_recs
    logger.info(f"  ThreatFox: {len(tf_recs)} IOCs | URLhaus: {len(uh_recs)} URLs | total: {len(all_recs)}")

    if _DRY_RUN:
        logger.info("DRY RUN — skipping DB write")
        return

    stored = _upsert_feed_iocs(all_recs)
    logger.info(f"  stored/updated: {stored} feed_iocs rows")

    # 3. Cross-match against honeypot IOCs — print the RQ2 linkage numbers
    try:
        stats = _cross_match_honeypot_iocs()
        logger.info("─── RQ2 Cross-Match Results ───────────────────────────")
        logger.info(f"  Honeypot IPs total:          {stats['honeypot_ips_total']}")
        logger.info(f"  Matched in ThreatFox C2:     {stats['threatfox_ip_matches']} ({stats['threatfox_match_pct']}%)")
        logger.info(f"  Malware families identified: {stats['malware_families_matched']} → {stats['families']}")
        logger.info(f"  Honeypot URLs total:         {stats['honeypot_urls_total']}")
        logger.info(f"  Matched in URLhaus:          {stats['urlhaus_url_matches']} ({stats['urlhaus_match_pct']}%)")
        logger.info("────────────────────────────────────────────────────────")
    except Exception as exc:
        logger.warning(f"Cross-match query failed (feed_iocs table may not exist yet): {exc}")
