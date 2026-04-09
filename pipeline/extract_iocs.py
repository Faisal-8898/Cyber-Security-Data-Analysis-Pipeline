"""pipeline/extract_iocs.py — Extract IOCs and credentials from NormalizedEvents."""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .core import get_pipeline_version, logger, task
from .schema import NormalizedEvent

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)

_IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)

_SHA256_RE = re.compile(
    r"\b[0-9a-fA-F]{64}\b",
)

_MD5_RE = re.compile(
    r"\b[0-9a-fA-F]{32}\b",
)

_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|cn|io|to|cc|tk|xyz|top|info|biz|pw|su)\b",
    re.IGNORECASE,
)

# Private / loopback prefixes — skip these as IOCs
_PRIVATE_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "0.",
    "::1",
)


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


# ---------------------------------------------------------------------------
# Per-event extractors
# ---------------------------------------------------------------------------

def _ioc(ioc_type: str, ioc_value: str, source_ev: NormalizedEvent) -> dict[str, Any]:
    return {
        "ioc_type":          ioc_type,
        "ioc_value":         ioc_value.strip(),
        "first_seen":        source_ev["event_time"] or source_ev["ingested_at"],
        "last_seen":         source_ev["event_time"] or source_ev["ingested_at"],
        "source_honeypots":  [source_ev["source"]] if source_ev.get("source") else [],
        "occurrence_count":  1,
        "pipeline_run_id":   source_ev.get("pipeline_run_id"),
    }


def _cred(username: str | None, password: str | None, source_ev: NormalizedEvent) -> dict[str, Any] | None:
    if not username and not password:
        return None
    return {
        "username":         username or "",
        "password":         password or "",
        "first_seen":       source_ev["event_time"] or source_ev["ingested_at"],
        "last_seen":        source_ev["event_time"] or source_ev["ingested_at"],
        "source_honeypots": [source_ev["source"]] if source_ev.get("source") else [],
        "attempt_count":    1,
        "pipeline_run_id":  source_ev.get("pipeline_run_id"),
    }


def extract_from_event(ev: NormalizedEvent) -> tuple[list[dict], list[dict]]:
    """
    Return (iocs, creds) extracted from a single NormalizedEvent.

    iocs  — list of IOC dicts ready for db.upsert_iocs()
    creds — list of credential dicts ready for db.upsert_credentials()
    """
    iocs:  list[dict[str, Any]] = []
    creds: list[dict[str, Any]] = []

    # --- Source IP itself is always an IOC --------------------------------
    src_ip = ev.get("source_ip")
    if src_ip and not _is_private_ip(str(src_ip)):
        iocs.append(_ioc("ip", src_ip, ev))

    # --- Credentials from login events ------------------------------------
    username = ev.get("username")
    password = ev.get("password")
    if ev.get("event_type") in ("login.attempt", "login.success", "login.failed"):
        c = _cred(username, password, ev)
        if c:
            creds.append(c)

    # --- Command string — URLs, IPs, hashes, domains ---------------------
    cmd = ev.get("command_str") or ""
    if cmd:
        for url in _URL_RE.findall(cmd):
            iocs.append(_ioc("url", url, ev))

        for ip in _IP_RE.findall(cmd):
            if not _is_private_ip(ip):
                iocs.append(_ioc("ip", ip, ev))

        for sha in _SHA256_RE.findall(cmd):
            iocs.append(_ioc("sha256", sha.lower(), ev))

        for md5 in _MD5_RE.findall(cmd):
            iocs.append(_ioc("md5", md5.lower(), ev))

        for domain in _DOMAIN_RE.findall(cmd):
            iocs.append(_ioc("domain", domain.lower(), ev))

    # --- File download events — URL + hash --------------------------------
    raw = ev.get("raw_data") or {}
    if ev.get("event_type") == "session.file_download" or "shasum" in raw:
        url = raw.get("url") or ev.get("url")
        sha = raw.get("shasum") or raw.get("sha256")
        if url:
            iocs.append(_ioc("url", url, ev))
        if sha and len(sha) == 64:
            iocs.append(_ioc("sha256", sha.lower(), ev))
        elif sha and len(sha) == 32:
            iocs.append(_ioc("md5", sha.lower(), ev))

    # --- HTTP path can contain IOCs ----------------------------------------
    http_path = ev.get("http_path") or ""
    if http_path:
        for url in _URL_RE.findall(http_path):
            iocs.append(_ioc("url", url, ev))

    # Deduplicate by (type, value)
    seen: set[tuple[str, str]] = set()
    unique_iocs: list[dict[str, Any]] = []
    for i in iocs:
        key = (i["ioc_type"], i["ioc_value"])
        if key not in seen:
            seen.add(key)
            unique_iocs.append(i)

    return unique_iocs, creds


# ---------------------------------------------------------------------------
# Task
# ---------------------------------------------------------------------------

@task("extract_iocs")
def extract_iocs(events: list[NormalizedEvent]) -> tuple[int, int]:
    """
    Extract IOCs and credentials from a list of NormalizedEvents and upsert to DB.

    Returns (ioc_count, cred_count) — total rows upserted.
    """
    from . import db as _db

    all_iocs:  list[dict[str, Any]] = []
    all_creds: list[dict[str, Any]] = []

    for ev in events:
        iocs, creds = extract_from_event(ev)
        all_iocs.extend(iocs)
        all_creds.extend(creds)

    ioc_count  = _db.upsert_iocs(all_iocs)
    cred_count = _db.upsert_credentials(all_creds)

    logger.info(
        f"extract_iocs: {len(events)} events → {ioc_count} IOCs, {cred_count} credentials"
    )
    return ioc_count, cred_count
