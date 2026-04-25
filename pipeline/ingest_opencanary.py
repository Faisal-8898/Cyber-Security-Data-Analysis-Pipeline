"""pipeline/ingest_opencanary.py — Parse OpenCanary JSON log lines into NormalizedEvents."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .bookmark import read_new_lines
from .core import get_pipeline_version, logger, task
from .schema import NormalizedEvent, make_event

_DEFAULT_LOG = Path(os.getenv("OPENCANARY_LOG_PATH", "/data/raw-logs/opencanary/opencanary.log"))

# OpenCanary logtype → protocol name
_LOGTYPE_PROTOCOL: dict[int, str] = {
    2000: "ftp",
    3000: "http",
    4000: "ssh",
    5000: "telnet",
    6000: "smtp",
    8000: "mysql",
    9000: "mssql",
    10001: "snmp",
    11000: "rdp",
    12000: "vnc",
    13000: "git",
    14000: "redis",
    15000: "tftp",
    16000: "ntp",
    17000: "portscan",
}


def _parse_local_time(s: str) -> str:
    """Convert OpenCanary local_time string to ISO8601 UTC. Assumes log is UTC."""
    try:
        dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def parse_opencanary_line(
    raw: str,
    run_id: str,
    git_hash: str,
    log_file: str,
    line_no: int,
) -> NormalizedEvent | None:
    """Parse one OpenCanary JSON log line into a NormalizedEvent."""
    try:
        e = json.loads(raw)
    except json.JSONDecodeError:
        return None

    logtype  = e.get("logtype", 0)

    # logtype 1001 = internal OpenCanary startup/service messages — no attacker data
    if logtype == 1001:
        return None

    protocol = _LOGTYPE_PROTOCOL.get(logtype, f"unknown_{logtype}")

    # Synthesize a timestamp field so make_event picks it up
    e["timestamp"] = _parse_local_time(e.get("local_time", ""))

    ev = make_event("opencanary", run_id, git_hash, log_file, line_no, e)

    # Sanitize: empty string is not a valid INET value
    src_host = e.get("src_host") or None
    src_port = e.get("src_port")
    dst_port = e.get("dst_port")

    ev["source_ip"]   = src_host if src_host else None
    ev["source_port"] = src_port if isinstance(src_port, int) and src_port > 0 else None
    ev["dest_port"]   = dst_port if isinstance(dst_port, int) and dst_port > 0 else None
    ev["protocol"]    = protocol

    logdata = e.get("logdata", {}) or {}

    # Classify event_type
    if logtype in (2000, 4000, 5000, 8000, 9000):      # auth-capable protocols
        ev["event_type"] = "login.attempt"
        ev["username"]   = logdata.get("USERNAME") or logdata.get("username")
        ev["password"]   = logdata.get("PASSWORD") or logdata.get("password")

    elif logtype == 3000:                                # HTTP
        ev["event_type"] = "http.request"
        ev["http_path"]  = e.get("logdata", {}).get("PATH") or e.get("logdata", {}).get("path")
        headers          = logdata.get("HEADERS") or logdata.get("headers") or {}
        ev["user_agent"] = headers.get("User-Agent") or headers.get("user-agent")

    elif logtype == 17000:
        ev["event_type"] = "port_scan"

    else:
        ev["event_type"] = "connection"

    return ev


@task("ingest_opencanary")
def ingest_opencanary(log_path: Path = None, run_id: str = None) -> list[NormalizedEvent]:
    """Read new OpenCanary log lines, parse, store to DB, return parsed events."""
    log_path = log_path or _DEFAULT_LOG
    git_hash = get_pipeline_version()

    from . import db as _db

    if run_id is None:
        run_id = _db.record_run_start(
            "ingest_opencanary",
            {"log_path": str(log_path)},
        )

    lines = read_new_lines(log_path, "opencanary")
    if not lines:
        logger.info("ingest_opencanary: no new lines")
        _db.record_run_end(run_id, "success", records_in=0, records_out=0)
        return []

    events = []
    for line_no, raw in lines:
        ev = parse_opencanary_line(raw, run_id, git_hash, str(log_path), line_no)
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
    logger.info(f"ingest_opencanary: {len(lines)} lines → {len(events)} parsed → {stored} stored")
    return events
