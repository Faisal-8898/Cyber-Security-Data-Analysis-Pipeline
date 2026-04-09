"""pipeline/ingest_cowrie.py — Parse Cowrie JSON log lines into NormalizedEvents."""
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


@task("ingest_cowrie")
def ingest_cowrie(log_path: Path = None, run_id: str = None) -> list[NormalizedEvent]:
    """Read new Cowrie log lines, parse them, store to DB, return parsed events."""
    log_path = log_path or _DEFAULT_LOG
    git_hash = get_pipeline_version()

    # Import here to allow unit tests to run without DB
    from . import db as _db

    if run_id is None:
        run_id = _db.record_run_start(
            "ingest_cowrie",
            {"log_path": str(log_path)},
        )

    lines = read_new_lines(log_path, "cowrie")
    if not lines:
        logger.info("ingest_cowrie: no new lines")
        _db.record_run_end(run_id, "success", records_in=0, records_out=0)
        return []

    events = []
    for line_no, raw in lines:
        ev = parse_cowrie_line(raw, run_id, git_hash, str(log_path), line_no)
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
    logger.info(f"ingest_cowrie: {len(lines)} lines → {len(events)} parsed → {stored} stored")
    return events
