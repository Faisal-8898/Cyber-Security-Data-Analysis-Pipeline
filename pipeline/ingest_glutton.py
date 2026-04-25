"""pipeline/ingest_glutton.py — Parse Glutton catch-all TCP log lines into NormalizedEvents.

Glutton emits newline-delimited JSON. Two kinds of lines are interleaved:

1. Connection events (what we store):
   {"time":"...Z","level":"INFO","msg":"Packet got handled by TCP handler",
    "sensorID":"...","dest_port":"8728","src_ip":"1.2.3.4","src_port":"60526",
    "handler":"tcp","payload_hash":"abc123..."}

2. Payload dumps (hex dump — skip for storage, payload_hash already on conn line):
   {"time":"...Z","level":"INFO","msg":"TCP payload:\\n00000000  ...","sensorID":"..."}

3. Startup / config / error messages (skip).

Only connection-event lines (those whose "msg" field starts with "Packet got handled")
are stored in honeypot_events. The payload hash is kept as file_hash for IOC linkage.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .bookmark import read_new_lines
from .core import get_pipeline_version, logger, task
from .schema import NormalizedEvent, make_event

_DEFAULT_LOG = Path(os.getenv("GLUTTON_LOG_PATH", "/data/raw-logs/glutton/glutton.log"))

# Known port → protocol mapping for IoT-relevant ports
_PORT_PROTOCOL: dict[str, str] = {
    "22":    "ssh",
    "23":    "telnet",
    "2323":  "telnet",
    "80":    "http",
    "443":   "https",
    "8080":  "http",
    "8443":  "https",
    "21":    "ftp",
    "25":    "smtp",
    "587":   "smtp",
    "3306":  "mysql",
    "5432":  "postgresql",
    "1433":  "mssql",
    "6379":  "redis",
    "9200":  "elasticsearch",
    "27017": "mongodb",
    "1883":  "mqtt",
    "5555":  "adb",           # Android Debug Bridge — IoT
    "7547":  "tr069",         # CWMP router management — Mirai
    "8728":  "mikrotik_api",  # MikroTik RouterOS API
    "8291":  "winbox",        # MikroTik Winbox
    "48101": "mirai_c2",      # Mirai C2 variant
    "5038":  "asterisk",
    "1080":  "socks",
    "3128":  "http_proxy",
}


def _parse_iso_time(s: str) -> str:
    """Convert Glutton's RFC3339Nano timestamp (e.g. '2026-04-23T20:16:52.506110092Z') to ISO8601."""
    try:
        # Truncate nanoseconds to microseconds (Python datetime supports up to 6 decimal places)
        if "." in s:
            base, frac = s.rstrip("Z").split(".", 1)
            frac = frac[:6]
            dt = datetime.strptime(f"{base}.{frac}", "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.strptime(s.rstrip("Z"), "%Y-%m-%dT%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def parse_glutton_line(
    raw: str,
    run_id: str,
    git_hash: str,
    log_file: str,
    line_no: int,
) -> NormalizedEvent | None:
    """Parse one Glutton JSON log line. Returns None for non-connection lines."""
    try:
        e = json.loads(raw)
    except json.JSONDecodeError:
        return None

    msg = e.get("msg", "")

    # Only store connection events
    if "Packet got handled" not in msg:
        return None

    # Synthesize timestamp field for make_event
    e["timestamp"] = _parse_iso_time(e.get("time", ""))

    dest_port_str = str(e.get("dest_port", ""))
    protocol = _PORT_PROTOCOL.get(dest_port_str, "tcp")

    ev = make_event("glutton", run_id, git_hash, log_file, line_no, e)

    ev["source_ip"]   = e.get("src_ip")
    ev["source_port"] = _safe_int(e.get("src_port"))
    ev["dest_port"]   = _safe_int(dest_port_str)
    ev["protocol"]    = protocol
    ev["event_type"]  = "connection"
    ev["session_id"]  = e.get("sensorID")   # sensorID is per-sensor, not per-session

    # payload_hash → store as file_hash for IOC extraction linkage
    ph = e.get("payload_hash")
    if ph and len(ph) == 64:
        ev["file_hash"] = ph

    return ev


def _safe_int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@task("ingest_glutton")
def ingest_glutton(log_path: Path = None, run_id: str = None) -> list[NormalizedEvent]:
    """Read new Glutton log lines, parse connection events, store to DB, return events."""
    log_path = log_path or _DEFAULT_LOG
    git_hash = get_pipeline_version()

    from . import db as _db

    if run_id is None:
        run_id = _db.record_run_start(
            "ingest_glutton",
            {"log_path": str(log_path)},
        )

    lines = read_new_lines(log_path, "glutton")
    if not lines:
        logger.info("ingest_glutton: no new lines")
        _db.record_run_end(run_id, "success", records_in=0, records_out=0)
        return []

    events = []
    for line_no, raw in lines:
        ev = parse_glutton_line(raw, run_id, git_hash, str(log_path), line_no)
        if ev:
            events.append(ev)

    stored = _db.store_events(events)
    _db.record_run_end(
        run_id,
        "success",
        records_in=len(lines),
        records_out=stored,
        source_files=[str(log_path)],
    )
    logger.info(
        f"ingest_glutton: {len(lines)} lines → {len(events)} connection events → {stored} stored"
    )
    return events
