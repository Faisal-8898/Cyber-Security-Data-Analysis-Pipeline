"""pipeline/poll_feeds.py — Pull malware intelligence feeds and cross-match IOCs.

Sources (all FREE):
  ThreatFox       — C2 server IPs/domains tagged by malware family (Mirai, Gafgyt, etc.)
  URLhaus         — Malicious download/dropper URLs
  MalwareBazaar   — Malware sample hashes tagged by IoT family (auth key required)
  OTX AlienVault  — Community IoT botnet pulse indicators (auth key required)

Paper context
-------------
  RQ2: cross-match honeypot IOC IPs against ThreatFox C2 records and OTX indicators
       → "X of 1,918 honeypot IPs appear in known C2 infrastructure"
  RQ2: cross-match honeypot SHA256 hashes against MalwareBazaar
       → "Y hashes confirmed as known IoT malware"
  RQ2: cross-match honeypot download_url against URLhaus
       → "Z download URLs confirmed as malware distribution infrastructure"
  Section 5.8 / Section 8: multi-vantage linkage evidence

Environment variables
---------------------
  THREATFOX_DAYS        days of ThreatFox history to pull  (default: 7)
  URLHAUS_DAYS          days of URLhaus history to pull     (default: 7)
  MALWAREBAZAAR_API_KEY required for MalwareBazaar
  OTX_API_KEY           required for OTX AlienVault
  FEEDS_DRY_RUN         "1" → print counts, skip DB writes
"""
from __future__ import annotations

import json as _json
import os
import time
from datetime import date, datetime, timezone

import requests
from psycopg2.extras import Json
from dotenv import load_dotenv

load_dotenv()

from .core import get_pipeline_version, logger, task

_THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
_URLHAUS_API   = "https://urlhaus-api.abuse.ch/v1/"
_MB_API        = "https://mb-api.abuse.ch/api/v1/"
_OTX_API       = "https://otx.alienvault.com/api/v1"
_TIMEOUT       = 30

# IoT-relevant malware families to fetch from ThreatFox / MalwareBazaar / OTX
_IOT_FAMILIES = [
    "mirai", "gafgyt", "mozi", "bashlite", "satori", "okiru",
    "reaper", "hajime", "iotreaper", "muhstik", "tsunami",
    "xorddos", "dofloo", "lizkebab", "torlus", "luabot",
]

# OTX search keywords — broader than family names to catch IoT botnet campaigns
_OTX_QUERIES = [
    "mirai botnet", "gafgyt iot", "mozi botnet", "iot botnet",
    "bashlite", "satori botnet", "xorddos", "muhstik",
]

_DRY_RUN      = os.environ.get("FEEDS_DRY_RUN", "0") == "1"
_MB_KEY       = os.environ.get("MALWAREBAZAAR_API_KEY", "")
_OTX_KEY      = os.environ.get("OTX_API_KEY", "")
# ThreatFox + URLhaus share the same abuse.ch auth portal as MalwareBazaar
_ABUSECH_KEY  = os.environ.get("ABUSECH_API_KEY") or _MB_KEY


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------

def _pull_threatfox(days: int) -> list[dict]:
    """Return list of IOC dicts from ThreatFox for IoT malware families."""
    all_iocs: list[dict] = []
    # Auth-Key header is required as of 2025
    _tf_headers = {"Auth-Key": _ABUSECH_KEY} if _ABUSECH_KEY else {}
    if not _ABUSECH_KEY:
        logger.warning("ThreatFox: no Auth-Key — set ABUSECH_API_KEY or MALWAREBAZAAR_API_KEY")

    # 1. Recent IOCs (last N days, max 7) — catches everything new
    # Correct query name is 'get_iocs' with 'days' param (NOT 'get_recent')
    payload = {"query": "get_iocs", "days": min(days, 7)}
    try:
        r = requests.post(_THREATFOX_API, json=payload, headers=_tf_headers, timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "ok":
            all_iocs.extend(data.get("data") or [])
            logger.info(f"ThreatFox recent ({days}d): {len(data.get('data') or [])} IOCs")
        else:
            logger.warning(f"ThreatFox get_iocs status: {data.get('query_status')}")
    except Exception as exc:
        logger.warning(f"ThreatFox recent pull failed: {exc}")

    time.sleep(1)

    # 2. Per-family queries for IoT malware
    # Correct query name is 'malwareinfo' (NOT 'get_iocs' with 'malware' param)
    for family in _IOT_FAMILIES:
        payload = {"query": "malwareinfo", "malware": family, "limit": 1000}
        try:
            r = requests.post(_THREATFOX_API, json=payload, headers=_tf_headers, timeout=_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            if data.get("query_status") == "ok":
                iocs = data.get("data") or []
                if iocs:
                    logger.info(f"  ThreatFox malwareinfo={family}: {len(iocs)} IOCs")
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

# IoT-relevant URLhaus tags to query for maximum coverage
_URLHAUS_IOT_TAGS = [
    "elf", "mirai", "gafgyt", "mozi", "bashlite", "muhstik",
    "xorddos", "mips", "arm", "sh4", "satori",
]


def _pull_urlhaus() -> list[dict]:
    """
    Return list of recent malicious URL + ELF payload records from URLhaus.

    Strategy (GET-based API, Auth-Key header required):
      1. Recent URLs (last 3 days, max 1000)      → dropper/loader URLs
      2. Recent ELF payloads (last 3 days, max 1000) → IoT binary hashes
      3. Per-IoT-tag URL queries (up to 1000 each) → deep IoT coverage
    """
    _uh_headers = {"Auth-Key": _ABUSECH_KEY} if _ABUSECH_KEY else {}
    all_records: list[dict] = []

    # 1. Recent URLs — GET with limit in URL path (NOT POST with form data)
    try:
        r = requests.get(
            f"{_URLHAUS_API}urls/recent/limit/1000/",
            headers=_uh_headers,
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        urls = data.get("urls") or []
        logger.info(f"URLhaus recent URLs: {len(urls)}")
        all_records.extend(urls)
    except Exception as exc:
        logger.warning(f"URLhaus recent URLs failed: {exc}")

    time.sleep(0.5)

    # 2. Recent ELF payloads — catches IoT malware binary hashes
    try:
        r = requests.get(
            f"{_URLHAUS_API}payloads/recent/limit/1000/",
            headers=_uh_headers,
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        payloads = data.get("payloads") or []
        # Mark as payload records so the normaliser handles them correctly
        for p in payloads:
            p["_record_type"] = "payload"
        elf_payloads = [p for p in payloads if (p.get("file_type") or "").lower() == "elf"]
        logger.info(f"URLhaus recent ELF payloads: {len(elf_payloads)} of {len(payloads)} total")
        all_records.extend(elf_payloads)
    except Exception as exc:
        logger.warning(f"URLhaus recent payloads failed: {exc}")

    time.sleep(0.5)

    # 3. Per-IoT-tag queries for deeper coverage
    seen_url_ids: set[str] = {r.get("id") or r.get("url", "") for r in all_records}
    for tag in _URLHAUS_IOT_TAGS:
        try:
            r = requests.post(
                f"{_URLHAUS_API}tag/",
                data={"tag": tag},
                headers=_uh_headers,
                timeout=_TIMEOUT,
            )
            r.raise_for_status()
            data = r.json()
            if data.get("query_status") == "ok":
                tag_urls = data.get("urls") or []
                new = [u for u in tag_urls if (u.get("url_id") or u.get("url", "")) not in seen_url_ids]
                for u in new:
                    seen_url_ids.add(u.get("url_id") or u.get("url", ""))
                if new:
                    logger.info(f"  URLhaus tag={tag}: {len(new)} new URLs")
                all_records.extend(new)
        except Exception as exc:
            logger.warning(f"URLhaus tag={tag} failed: {exc}")
        time.sleep(0.3)

    return all_records


def _urlhaus_to_feed_record(entry: dict, snapshot_date: date) -> dict | None:
    """Normalise a URLhaus URL or payload record into a feed_iocs row."""
    # ELF payload records (from /payloads/recent/) — store as sha256
    if entry.get("_record_type") == "payload":
        sha256 = entry.get("sha256_hash") or ""
        if not sha256:
            return None
        sig = (entry.get("signature") or "").lower() or "unknown"
        return {
            "source":        "urlhaus",
            "ioc_type":      "sha256",
            "ioc_value":     sha256,
            "ip":            None,
            "port":          None,
            "malware_family": sig,
            "confidence":    85,
            "tags":          ["elf"],
            "first_seen":    entry.get("firstseen"),
            "last_seen":     entry.get("firstseen"),
            "snapshot_date": str(snapshot_date),
            "raw_data":      {
                "sha256_hash": sha256,
                "md5_hash":    entry.get("md5_hash"),
                "file_type":   entry.get("file_type"),
                "file_size":   entry.get("file_size"),
                "signature":   entry.get("signature"),
            },
        }

    # URL record
    url = entry.get("url") or ""
    if not url:
        return None
    tags = entry.get("tags") or []
    family = tags[0].lower() if tags else "unknown"
    return {
        "source":        "urlhaus",
        "ioc_type":      "url",
        "ioc_value":     url,
        "ip":            entry.get("host") if entry.get("host") and not entry.get("host", "").replace(".", "").isdigit() is False else None,
        "port":          None,
        "malware_family": family,
        "confidence":    100 if entry.get("url_status") == "online" else 80,
        "tags":          tags,
        "first_seen":    entry.get("date_added") or entry.get("dateadded"),
        "last_seen":     None,
        "snapshot_date": str(snapshot_date),
        "raw_data":      {k: v for k, v in entry.items() if k != "_record_type"},
    }


# ---------------------------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------------------------

def _pull_malwarebazaar() -> list[dict]:
    """
    Pull IoT-relevant ELF malware samples from MalwareBazaar.

    Strategy (maximises data within fair-use limits):
      1. Recent ELF detections (last 168 h = 1 week) — catches new IoT dropper samples
      2. Per-family tag queries for each IoT malware family (up to 1000 samples each)
      3. Lookup any SHA256 hashes already in our ioc_records (confirms our captured samples)
    """
    if not _MB_KEY:
        logger.warning("MalwareBazaar: MALWAREBAZAAR_API_KEY not set — skipping")
        return []

    headers = {"Auth-Key": _MB_KEY}
    all_samples: list[dict] = []
    seen_hashes: set[str] = set()

    def _post(payload: dict) -> list[dict]:
        try:
            # MalwareBazaar requires form-encoded POST data (not JSON body)
            r = requests.post(_MB_API, data=payload, headers=headers, timeout=_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            status = data.get("query_status", "")
            if status in ("ok", "hash_found"):
                result = data.get("data") or []
                # get_info returns a single dict, not a list
                if isinstance(result, dict):
                    result = [result]
                return result
            if status not in ("no_results", "hash_not_found"):
                logger.warning(f"MalwareBazaar unexpected status: {status} — payload={payload}")
        except Exception as exc:
            logger.warning(f"MalwareBazaar request failed: {exc}")
        return []

    # 1. Recent ELF detections (last 7 days — IoT malware is ELF/ARM/MIPS)
    samples = _post({"query": "get_file_type", "file_type": "elf", "limit": 1000})
    logger.info(f"MalwareBazaar ELF (recent): {len(samples)} samples")
    for s in samples:
        h = s.get("sha256_hash") or ""
        if h and h not in seen_hashes:
            seen_hashes.add(h)
            all_samples.append(s)
    time.sleep(1)

    # 2. Per-family tag queries
    for family in _IOT_FAMILIES:
        samples = _post({"query": "get_taginfo", "tag": family, "limit": 1000})
        if samples:
            logger.info(f"  MalwareBazaar tag={family}: {len(samples)} samples")
        for s in samples:
            h = s.get("sha256_hash") or ""
            if h and h not in seen_hashes:
                seen_hashes.add(h)
                all_samples.append(s)
        time.sleep(0.5)

    # 3. Look up SHA256 hashes from our own honeypot IOC records
    try:
        from . import db as _db
        with _db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT ioc_value FROM ioc_records WHERE ioc_type = 'sha256'"
                )
                our_hashes = [row[0] for row in cur.fetchall()]
        for h in our_hashes:
            if h in seen_hashes:
                continue
            result = _post({"query": "get_info", "hash": h})
            if result:
                logger.info(f"  MalwareBazaar OUR hash {h[:16]}…: FOUND — {result[0].get('signature')}")
                seen_hashes.add(h)
                all_samples.extend(result)
            time.sleep(0.3)
    except Exception as exc:
        logger.warning(f"MalwareBazaar hash lookup skipped: {exc}")

    logger.info(f"MalwareBazaar total unique samples: {len(all_samples)}")
    return all_samples


def _malwarebazaar_to_feed_record(sample: dict, snapshot_date: date) -> dict:
    """Normalise a MalwareBazaar sample into a feed_iocs row."""
    sha256   = sample.get("sha256_hash") or ""
    family   = (sample.get("signature") or "unknown").lower()
    tags     = sample.get("tags") or []
    # MalwareBazaar timestamps: "2024-04-25 12:00:01 UTC"
    first_seen = sample.get("first_seen")
    last_seen  = sample.get("last_seen")

    return {
        "source":        "malwarebazaar",
        "ioc_type":      "sha256",
        "ioc_value":     sha256,
        "ip":            None,
        "port":          None,
        "malware_family": family,
        "confidence":    90,
        "tags":          tags,
        "first_seen":    first_seen,
        "last_seen":     last_seen,
        "snapshot_date": str(snapshot_date),
        "raw_data":      {
            "sha256_hash":  sha256,
            "md5_hash":     sample.get("md5_hash"),
            "file_name":    sample.get("file_name"),
            "file_size":    sample.get("file_size"),
            "file_type":    sample.get("file_type"),
            "file_arch":    sample.get("file_arch"),
            "signature":    sample.get("signature"),
            "reporter":     sample.get("reporter"),
            "origin_country": sample.get("origin_country"),
            "tags":         tags,
        },
    }


# ---------------------------------------------------------------------------
# OTX AlienVault
# ---------------------------------------------------------------------------

def _pull_otx() -> list[dict]:
    """
    Pull IoT botnet indicators from OTX AlienVault.

    Strategy:
      1. Search for IoT/botnet pulses by keyword (multiple queries)
      2. For each pulse, fetch up to 500 indicators
      3. Normalise IPv4, domain, URL, and hash indicators into feed_iocs rows
    """
    if not _OTX_KEY:
        logger.warning("OTX: OTX_API_KEY not set — skipping")
        return []

    headers = {"X-OTX-API-KEY": _OTX_KEY}
    all_indicators: list[dict] = []
    seen_pulse_ids: set[str] = set()

    for query in _OTX_QUERIES:
        try:
            r = requests.get(
                f"{_OTX_API}/search/pulses",
                params={"q": query, "limit": 10, "page": 1},
                headers=headers,
                timeout=_TIMEOUT,
            )
            r.raise_for_status()
            pulses = r.json().get("results") or []
            logger.info(f"  OTX search '{query}': {len(pulses)} pulses found")
        except Exception as exc:
            logger.warning(f"OTX search '{query}' failed: {exc}")
            continue
        time.sleep(0.5)

        for pulse in pulses:
            pulse_id   = pulse.get("id") or ""
            pulse_name = pulse.get("name") or ""
            pulse_tags = pulse.get("tags") or []
            family     = _guess_family_from_tags(pulse_tags + [pulse_name])

            if not pulse_id or pulse_id in seen_pulse_ids:
                continue
            seen_pulse_ids.add(pulse_id)

            # Fetch indicators for this pulse (up to 500)
            try:
                ri = requests.get(
                    f"{_OTX_API}/pulses/{pulse_id}/indicators",
                    params={"limit": 500},
                    headers=headers,
                    timeout=_TIMEOUT,
                )
                ri.raise_for_status()
                indicators = ri.json().get("results") or []
                logger.info(f"    Pulse '{pulse_name[:50]}': {len(indicators)} indicators")
            except Exception as exc:
                logger.warning(f"OTX indicators for {pulse_id} failed: {exc}")
                continue
            time.sleep(0.3)

            for ind in indicators:
                ind["_pulse_id"]   = pulse_id
                ind["_pulse_name"] = pulse_name
                ind["_pulse_tags"] = pulse_tags
                ind["_family"]     = family
                all_indicators.append(ind)

    # Also pull recent subscribed/followed pulses (catches manually followed IoT feeds)
    try:
        r = requests.get(
            f"{_OTX_API}/pulses/subscribed",
            params={"modified_since": "2026-01-01T00:00:00", "limit": 20},
            headers=headers,
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        sub_pulses = r.json().get("results") or []
        logger.info(f"OTX subscribed pulses: {len(sub_pulses)}")
        for pulse in sub_pulses:
            pulse_id   = pulse.get("id") or ""
            pulse_name = pulse.get("name") or ""
            pulse_tags = pulse.get("tags") or []
            family     = _guess_family_from_tags(pulse_tags + [pulse_name])
            if not pulse_id or pulse_id in seen_pulse_ids:
                continue
            seen_pulse_ids.add(pulse_id)
            try:
                ri = requests.get(
                    f"{_OTX_API}/pulses/{pulse_id}/indicators",
                    params={"limit": 500},
                    headers=headers,
                    timeout=_TIMEOUT,
                )
                ri.raise_for_status()
                indicators = ri.json().get("results") or []
                for ind in indicators:
                    ind["_pulse_id"]   = pulse_id
                    ind["_pulse_name"] = pulse_name
                    ind["_pulse_tags"] = pulse_tags
                    ind["_family"]     = family
                    all_indicators.append(ind)
            except Exception as exc:
                logger.warning(f"OTX subscribed pulse {pulse_id} indicators failed: {exc}")
            time.sleep(0.3)
    except Exception as exc:
        logger.warning(f"OTX subscribed pulses failed: {exc}")

    logger.info(f"OTX total indicators: {len(all_indicators)}")
    return all_indicators


def _guess_family_from_tags(tags: list[str]) -> str:
    """Infer IoT malware family from a list of tag/name strings."""
    combined = " ".join(tags).lower()
    for family in _IOT_FAMILIES:
        if family in combined:
            return family
    return "unknown"


# OTX indicator type → our ioc_type
_OTX_TYPE_MAP = {
    "IPv4":              "ip",
    "IPv6":              "ip",
    "domain":            "domain",
    "hostname":          "domain",
    "URL":               "url",
    "FileHash-SHA256":   "sha256",
    "FileHash-MD5":      "md5",
    "FileHash-SHA1":     "sha1",
}


def _otx_to_feed_record(ind: dict, snapshot_date: date) -> dict | None:
    """Normalise an OTX indicator into a feed_iocs row. Returns None for unsupported types."""
    otx_type = ind.get("type") or ""
    ioc_type = _OTX_TYPE_MAP.get(otx_type)
    if not ioc_type:
        return None

    ioc_value = (ind.get("indicator") or "").strip()
    if not ioc_value:
        return None

    # Extract IP for INET column (only when ioc_type == 'ip')
    ip   = ioc_value if ioc_type == "ip" else None
    port = None

    family     = ind.get("_family") or "unknown"
    pulse_id   = ind.get("_pulse_id") or ""
    pulse_name = ind.get("_pulse_name") or ""
    pulse_tags = ind.get("_pulse_tags") or []

    return {
        "source":        "otx",
        "ioc_type":      ioc_type,
        "ioc_value":     ioc_value,
        "ip":            ip,
        "port":          port,
        "malware_family": family,
        "confidence":    75,
        "tags":          pulse_tags,
        "first_seen":    ind.get("created"),
        "last_seen":     ind.get("created"),
        "snapshot_date": str(snapshot_date),
        "raw_data":      {
            "pulse_id":   pulse_id,
            "pulse_name": pulse_name,
            "otx_type":   otx_type,
            "description": ind.get("description") or "",
        },
    }

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
                    # Flatten tags to list[str] — OTX tags can be dicts
                    tags = [
                        str(t) if not isinstance(t, str) else t
                        for t in (rec.get("tags") or [])
                    ]
                    # raw_data must be serialised to JSONB via Json() wrapper
                    raw_data = Json(_json.loads(_json.dumps(
                        rec.get("raw_data") or {}, default=str
                    )))
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
                        "tags":     tags,
                        "raw_data": raw_data,
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
    Cross-match honeypot IOC IPs/hashes against all feed sources.
    Returns counts for the paper's RQ2 linkage claim.
    """
    from . import db as _db
    with _db.get_connection() as conn:
        with conn.cursor() as cur:
            # ThreatFox: IPs seen in honeypot IOCs that also appear as C2
            cur.execute("""
                SELECT
                  COUNT(DISTINCT hi.ioc_value) AS matched_ips,
                  COUNT(DISTINCT fi.malware_family) AS families,
                  array_agg(DISTINCT fi.malware_family)
                    FILTER (WHERE fi.malware_family IS NOT NULL) AS fam_list
                FROM ioc_records hi
                JOIN feed_iocs fi ON hi.ioc_value = fi.ip::text
                WHERE hi.ioc_type = 'ip' AND fi.source = 'threatfox'
            """)
            tf = cur.fetchone()

            # OTX: honeypot IPs matched in OTX pulse indicators
            cur.execute("""
                SELECT COUNT(DISTINCT hi.ioc_value)
                FROM ioc_records hi
                JOIN feed_iocs fi ON hi.ioc_value = fi.ip::text
                WHERE hi.ioc_type = 'ip' AND fi.source = 'otx'
            """)
            otx_ips = cur.fetchone()[0]

            # URLhaus: download URLs matched
            cur.execute("""
                SELECT COUNT(DISTINCT hi.ioc_value)
                FROM ioc_records hi
                JOIN feed_iocs fi ON hi.ioc_value = fi.ioc_value
                WHERE hi.ioc_type = 'url' AND fi.source = 'urlhaus'
            """)
            uh_urls = cur.fetchone()[0]

            # MalwareBazaar: SHA256 hashes confirmed
            cur.execute("""
                SELECT COUNT(DISTINCT hi.ioc_value)
                FROM ioc_records hi
                JOIN feed_iocs fi ON hi.ioc_value = fi.ioc_value
                WHERE hi.ioc_type = 'sha256' AND fi.source = 'malwarebazaar'
            """)
            mb_hashes = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM ioc_records WHERE ioc_type = 'ip'")
            total_ips = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM ioc_records WHERE ioc_type = 'url'")
            total_urls = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM ioc_records WHERE ioc_type = 'sha256'")
            total_hashes = cur.fetchone()[0]

    tf_matched = tf[0] if tf else 0
    return {
        "honeypot_ips_total":         total_ips,
        "threatfox_ip_matches":        tf_matched,
        "threatfox_match_pct":         round(tf_matched / max(total_ips, 1) * 100, 1),
        "malware_families_matched":    tf[1] if tf else 0,
        "families":                    tf[2] if tf else [],
        "otx_ip_matches":              otx_ips,
        "otx_match_pct":               round(otx_ips / max(total_ips, 1) * 100, 1),
        "honeypot_urls_total":          total_urls,
        "urlhaus_url_matches":          uh_urls,
        "urlhaus_match_pct":            round(uh_urls / max(total_urls, 1) * 100, 1),
        "honeypot_hashes_total":        total_hashes,
        "malwarebazaar_hash_matches":   mb_hashes,
        "malwarebazaar_match_pct":      round(mb_hashes / max(total_hashes, 1) * 100, 1),
    }


# ---------------------------------------------------------------------------
# Main task
# ---------------------------------------------------------------------------

@task("poll_feeds")
def poll_feeds() -> None:
    now         = datetime.now(timezone.utc)
    today       = now.date()
    tf_days     = int(os.environ.get("THREATFOX_DAYS", "7"))

    logger.info(f"poll_feeds start — threatfox_days={tf_days} dry_run={_DRY_RUN}")
    logger.info(f"  Sources enabled: ThreatFox=✓ URLhaus=✓ "
                f"MalwareBazaar={'✓' if _MB_KEY else '✗ (no key)'} "
                f"OTX={'✓' if _OTX_KEY else '✗ (no key)'}")

    # 1. ThreatFox — C2 IPs/domains by IoT malware family
    tf_iocs = _pull_threatfox(tf_days)
    tf_recs = [_threatfox_to_feed_record(i, today) for i in tf_iocs]

    # 2. URLhaus — malicious download/dropper URLs + ELF payloads
    uh_urls = _pull_urlhaus()
    uh_recs = [r for u in uh_urls if (r := _urlhaus_to_feed_record(u, today)) is not None]

    # 3. MalwareBazaar — IoT ELF sample hashes + family labels
    mb_samples = _pull_malwarebazaar()
    mb_recs    = [_malwarebazaar_to_feed_record(s, today) for s in mb_samples]

    # 4. OTX AlienVault — IoT botnet pulse indicators (IPs, domains, URLs, hashes)
    otx_inds = _pull_otx()
    otx_recs = [r for ind in otx_inds if (r := _otx_to_feed_record(ind, today)) is not None]

    all_recs = tf_recs + uh_recs + mb_recs + otx_recs
    logger.info(
        f"  ThreatFox: {len(tf_recs):,} | URLhaus: {len(uh_recs):,} | "
        f"MalwareBazaar: {len(mb_recs):,} | OTX: {len(otx_recs):,} | "
        f"Total: {len(all_recs):,}"
    )

    if _DRY_RUN:
        logger.info("DRY RUN — skipping DB write")
        return

    stored = _upsert_feed_iocs(all_recs)
    logger.info(f"  stored/updated: {stored:,} feed_iocs rows")

    # 5. Cross-match against honeypot IOCs — print the RQ2 linkage numbers
    try:
        stats = _cross_match_honeypot_iocs()
        logger.info("─── RQ2 Cross-Match Results ───────────────────────────────────")
        logger.info(f"  Honeypot IPs  total:               {stats['honeypot_ips_total']:>6}")
        logger.info(f"  → Matched in ThreatFox C2:         {stats['threatfox_ip_matches']:>6} ({stats['threatfox_match_pct']}%)")
        logger.info(f"  → Matched in OTX pulse IOCs:       {stats['otx_ip_matches']:>6} ({stats['otx_match_pct']}%)")
        logger.info(f"  Malware families identified (TF):  {stats['malware_families_matched']:>6} → {stats['families']}")
        logger.info(f"  Honeypot URLs total:                {stats['honeypot_urls_total']:>6}")
        logger.info(f"  → Matched in URLhaus:              {stats['urlhaus_url_matches']:>6} ({stats['urlhaus_match_pct']}%)")
        logger.info(f"  Honeypot SHA256 hashes total:       {stats['honeypot_hashes_total']:>6}")
        logger.info(f"  → Confirmed in MalwareBazaar:      {stats['malwarebazaar_hash_matches']:>6} ({stats['malwarebazaar_match_pct']}%)")
        logger.info("────────────────────────────────────────────────────────────────")
    except Exception as exc:
        logger.warning(f"Cross-match query failed: {exc}")
