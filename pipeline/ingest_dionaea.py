"""pipeline/ingest_dionaea.py — Ingest Dionaea honeypot captures from SQLite DB.

Dionaea stores all connection/download metadata in logsql.sqlite.
We read the `connections` and `downloads` tables and normalise them
into NormalizedEvents so extract_iocs can pull URLs, hashes, and IPs.

SQLite DB location (after rsync from VPS):
    ~/data/raw-logs/dionaea/dionaea.sqlite

Tables used:
    connections  — every incoming connection (src_ip, dst_port, proto, timestamp)
    downloads    — files downloaded/dropped by attackers (URL, MD5, SHA256)
"""
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .bookmark import get_bookmark, set_bookmark
from .core import get_pipeline_version, logger, task
from .schema import NormalizedEvent, make_event

_DEFAULT_SQLITE = Path(
    os.getenv(
        "DIONAEA_SQLITE_PATH",
        str(Path.home() / "data/raw-logs/dionaea/dionaea.sqlite"),
    )
)

# Map Dionaea service names → protocol string
_SERVICE_TO_PROTO: dict[str, str] = {
    "httpd":   "http",
    "smbd":    "smb",
    "mysqld":  "mysql",
    "mssqld":  "mssql",
    "ftpd":    "ftp",
    "telnetd": "telnet",
    "epmapper":"dcerpc",
}

# Bookmark key for tracking last processed connection row ID
_BOOKMARK_KEY = "dionaea_connection_id"


def _ts_to_iso(ts: float | int | None) -> str | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return None


def _map_service(service: str | None, dst_port: int | None) -> tuple[str, str]:
    """Return (protocol, event_type) from service name and destination port."""
    proto = _SERVICE_TO_PROTO.get(service or "", "tcp")
    event_type = f"{proto}.connection"
    return proto, event_type


def _build_connection_event(
    row: sqlite3.Row,
    downloads_by_connection: dict[int, list[dict]],
    run_id: str,
    git_hash: str,
    db_path: str,
) -> NormalizedEvent:
    """Convert one Dionaea `connections` row into a NormalizedEvent."""
    conn_id: int        = row["connection"]
    src_ip: str | None  = row["remote_host"]
    src_port: int | None = row["remote_port"]
    dst_port: int | None = row["local_port"]
    service: str | None = row["connection_type"]
    ts: float | None    = row["connection_timestamp"]

    proto, event_type = _map_service(service, dst_port)
    event_time = _ts_to_iso(ts)

    raw_data: dict = {
        "connection_id":   conn_id,
        "service":         service,
        "local_host":      row["local_host"],
        "local_port":      dst_port,
        "remote_host":     src_ip,
        "remote_port":     src_port,
        "connection_type": service,
        "connection_transport": row["connection_transport"],
        "connection_timestamp": ts,
    }

    # Attach any downloads associated with this connection
    connection_downloads = downloads_by_connection.get(conn_id, [])
    if connection_downloads:
        raw_data["downloads"] = connection_downloads
        # Promote first download URL/hash to top-level event fields
        first_dl = connection_downloads[0]
        download_url  = first_dl.get("url")
        file_hash     = first_dl.get("md5")
        if len(connection_downloads) > 1:
            # Additional URLs — encode in raw_data only; extract_iocs will pick them up
            pass
    else:
        download_url = None
        file_hash    = None

    ev = make_event("dionaea", run_id, git_hash, db_path, conn_id, raw_data)
    ev["event_time"]   = event_time
    ev["source_ip"]    = src_ip
    ev["source_port"]  = src_port
    ev["dest_port"]    = dst_port
    ev["protocol"]     = proto
    ev["event_type"]   = event_type
    ev["download_url"] = download_url
    ev["file_hash"]    = file_hash
    return ev


@task("ingest_dionaea")
def ingest_dionaea(
    db_path: Path = None,
    run_id: str = None,
) -> list[NormalizedEvent]:
    """Read new Dionaea SQLite connections, normalise, store to DB, return events."""
    db_path = db_path or _DEFAULT_SQLITE

    if not db_path.exists():
        logger.info(f"ingest_dionaea: SQLite not found at {db_path} — skipping")
        return []

    from . import db as _db

    git_hash = get_pipeline_version()

    if run_id is None:
        run_id = _db.record_run_start(
            "ingest_dionaea",
            {"db_path": str(db_path)},
        )

    # Last processed connection row ID (bookmark so we never re-ingest)
    # We store the connection id in the 'offset' field of the bookmark dict.
    bm = get_bookmark(_BOOKMARK_KEY)
    last_id: int = int(bm.get("offset", 0))

    try:
        con = sqlite3.connect(str(db_path))
        con.row_factory = sqlite3.Row

        # Fetch all downloads keyed by connection id
        downloads_by_conn: dict[int, list[dict]] = {}
        for dl_row in con.execute(
            "SELECT connection, download_url, download_md5_hash FROM downloads"
        ):
            cid = dl_row["connection"]
            downloads_by_conn.setdefault(cid, []).append(
                {
                    "url": dl_row["download_url"],
                    "md5": dl_row["download_md5_hash"],
                }
            )

        # Fetch only new connections since our bookmark
        cursor = con.execute(
            """
            SELECT connection, connection_type, connection_transport,
                   connection_timestamp,
                   local_host, local_port,
                   remote_host, remote_port
            FROM connections
            WHERE connection > ?
            ORDER BY connection ASC
            """,
            (last_id,),
        )
        rows = cursor.fetchall()
        con.close()
    except sqlite3.Error as exc:
        logger.error(f"ingest_dionaea: SQLite error — {exc}")
        _db.record_run_end(run_id, "failed", records_in=0, records_out=0)
        return []

    if not rows:
        logger.info("ingest_dionaea: no new connections")
        _db.record_run_end(run_id, "success", records_in=0, records_out=0)
        return []

    events: list[NormalizedEvent] = []
    for row in rows:
        ev = _build_connection_event(
            row, downloads_by_conn, run_id, git_hash, str(db_path)
        )
        events.append(ev)

    stored = _db.store_events(events)

    # Advance bookmark to the highest connection id we just processed
    max_id = max(int(r["connection"]) for r in rows)
    set_bookmark(_BOOKMARK_KEY, inode=0, offset=max_id)

    _db.record_run_end(
        run_id,
        "success",
        records_in=len(rows),
        records_out=stored,
        source_files=[str(db_path)],
    )
    logger.info(
        f"ingest_dionaea: {len(rows)} connections → {stored} stored"
        f" (downloads attached: {sum(len(v) for v in downloads_by_conn.values())})"
    )
    return events
