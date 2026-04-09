"""pipeline/schema.py — NormalizedEvent: the common format all sources map to."""
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, TypedDict


class NormalizedEvent(TypedDict):
    # -- Identity -------------------------------------------------------
    record_id:        str         # UUID4, generated at ingestion
    source:           str         # cowrie | opencanary | glutton | shodan | censys

    # -- Time -----------------------------------------------------------
    event_time:       str         # ISO8601 — when event happened on sensor
    collected_at:     str         # ISO8601 — file mtime (preserved by rsync -a)
    ingested_at:      str         # ISO8601 — when this run processed it

    # -- Provenance -----------------------------------------------------
    pipeline_run_id:  str         # UUID — FK to pipeline_runs
    pipeline_version: str         # git short hash
    raw_file_path:    str         # /data/raw-logs/cowrie/cowrie.json
    raw_line_number:  int         # exact line in that file

    # -- Content (all nullable) ----------------------------------------
    source_ip:        Optional[str]
    source_port:      Optional[int]
    dest_port:        Optional[int]
    protocol:         Optional[str]
    event_type:       Optional[str]
    session_id:       Optional[str]
    username:         Optional[str]
    password:         Optional[str]
    command_str:      Optional[str]
    download_url:     Optional[str]
    file_hash:        Optional[str]
    hassh:            Optional[str]
    user_agent:       Optional[str]
    http_path:        Optional[str]
    asn:              Optional[str]
    country_code:     Optional[str]
    org:              Optional[str]

    # -- Raw (verbatim, never modified) --------------------------------
    raw_data:         dict[str, Any]


def make_event(
    source: str,
    run_id: str,
    git_hash: str,
    raw_file: str,
    line_no: int,
    raw: dict,
) -> NormalizedEvent:
    """Build a NormalizedEvent with all provenance fields populated."""
    now = datetime.now(timezone.utc).isoformat()
    return NormalizedEvent(
        record_id=str(uuid.uuid4()),
        source=source,
        event_time=raw.get("timestamp", now),
        collected_at=raw.get("collected_at", now),
        ingested_at=now,
        pipeline_run_id=run_id,
        pipeline_version=git_hash,
        raw_file_path=raw_file,
        raw_line_number=line_no,
        source_ip=None,
        source_port=None,
        dest_port=None,
        protocol=None,
        event_type=None,
        session_id=None,
        username=None,
        password=None,
        command_str=None,
        download_url=None,
        file_hash=None,
        hassh=None,
        user_agent=None,
        http_path=None,
        asn=None,
        country_code=None,
        org=None,
        raw_data=raw,
    )
