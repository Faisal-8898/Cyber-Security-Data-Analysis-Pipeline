"""pipeline/ingest_cowrie.py — Parse Cowrie JSON log lines into NormalizedEvents."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .bookmark import read_new_lines
from .core import get_pipeline_version, logger, task
from .schema import NormalizedEvent, make_event

_DEFAULT_LOG = Path(os.getenv("COWRIE_LOG_PATH", "/data/raw-logs/cowrie/cowrie.json"))


def parse_cowrie_line(
    raw: str,
    run_id: str,
    git_hash: str,
    log_file: str,
    line_no: int,
) -> NormalizedEvent | None:
    """Parse one Cowrie JSON log line into a NormalizedEvent. Returns None on bad lines."""
    try:
        e = json.loads(raw)
    except json.JSONDecodeError:
        return None

    event_id = e.get("eventid", "")
    if not event_id.startswith("cowrie."):
        return None

    ev = make_event("cowrie", run_id, git_hash, log_file, line_no, e)

    ev["source_ip"]   = e.get("src_ip")
    ev["source_port"] = e.get("src_port")
    ev["dest_port"]   = e.get("dst_port", 22)
    ev["session_id"]  = e.get("session")
    ev["event_type"]  = event_id.removeprefix("cowrie.")

    # Determine protocol from eventid or dst_port
    if "telnet" in event_id or e.get("dst_port") == 23:
        ev["protocol"] = "telnet"
    else:
        ev["protocol"] = "ssh"

    # Event-specific fields
    if "login" in event_id:
        ev["username"] = e.get("username")
        ev["password"] = e.get("password")

    elif event_id == "cowrie.command.input":
        ev["command_str"] = e.get("input")

    elif event_id == "cowrie.session.file_download":
        ev["download_url"] = e.get("url")
        ev["file_hash"]    = e.get("shasum")

    # SSH client fingerprint
    ev["hassh"] = e.get("hassh") or e.get("hasshAlgorithms")

    return ev


def _bookmark_key_for(log_path: Path) -> str:
    """Return the bookmark key for a given log file path.

    The live file uses the stable key "cowrie" so its offset survives renames.
    Rotated files (cowrie.json.YYYY-MM-DD) get a key derived from their stem
    so each rotation is tracked independently.
    """
    if log_path.name == "cowrie.json":
        return "cowrie"
    # e.g. cowrie.json.2026-04-27 → "cowrie_2026-04-27"
    suffix = log_path.name.replace("cowrie.json.", "")
    return f"cowrie_{suffix}"


def _ingest_one_file(
    log_path: Path,
    run_id: str,
    git_hash: str,
    db_module,
) -> list[NormalizedEvent]:
    """Ingest a single Cowrie log file, returning parsed events."""
    bm_key = _bookmark_key_for(log_path)
    lines = read_new_lines(log_path, bm_key)
    if not lines:
        return []

    events = []
    for line_no, raw in lines:
        ev = parse_cowrie_line(raw, run_id, git_hash, str(log_path), line_no)
        if ev:
            events.append(ev)

    stored = db_module.store_events(events)
    logger.info(
        f"ingest_cowrie [{log_path.name}]: {len(lines)} lines → "
        f"{len(events)} parsed → {stored} stored"
    )
    return events


@task("ingest_cowrie")
def ingest_cowrie(log_path: Path = None, run_id: str = None) -> list[NormalizedEvent]:
    """Read new Cowrie log lines from all log files (live + rotated), parse and store.

    Rotated files follow the pattern cowrie.json.YYYY-MM-DD and are processed
    in chronological order before the live cowrie.json so the DB reflects
    events in timestamp order.  Each file has its own bookmark so re-runs are
    idempotent and rotated files are only read once.
    """
    log_path = log_path or _DEFAULT_LOG
    git_hash = get_pipeline_version()

    from . import db as _db

    if run_id is None:
        run_id = _db.record_run_start("ingest_cowrie", {"log_path": str(log_path)})

    # Build ordered list: rotated files first (chronological), then the live file.
    log_dir = log_path.parent
    rotated = sorted(
        (f for f in log_dir.glob("cowrie.json.*") if not f.name.endswith(".gz")),
        key=lambda p: p.name,
    )
    all_files = rotated + [log_path]

    all_events: list[NormalizedEvent] = []
    source_files: list[str] = []

    for lp in all_files:
        if not lp.exists():
            continue
        events = _ingest_one_file(lp, run_id, git_hash, _db)
        all_events.extend(events)
        if events:
            source_files.append(str(lp))

    if not all_events:
        logger.info("ingest_cowrie: no new lines in any file")

    _db.record_run_end(
        run_id,
        "success",
        records_in=sum(1 for _ in all_events),
        records_out=len(all_events),
        source_files=source_files,
    )
    return all_events
