"""pipeline/db.py — PostgreSQL connection and UPSERT helpers."""
import os
import uuid
from typing import Optional

import psycopg2
import psycopg2.extras
from psycopg2.extras import execute_values
from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Unicode sanitization  (Shodan banners may contain lone surrogate characters
# from mis-decoded binary data — e.g. \udcff.  PostgreSQL/psycopg2 rejects
# them with UnicodeEncodeError: surrogates not allowed.)
# ---------------------------------------------------------------------------

def _sanitize_str(value: object) -> object:
    """Strip NUL bytes and replace lone surrogates so the string is safe for PostgreSQL.

    Two separate problems from Shodan banners:
      1. NUL bytes (0x00)  - valid UTF-8 but PostgreSQL rejects them in string literals.
      2. Lone surrogates   - psycopg2 rejects them with UnicodeEncodeError.
    """
    if not isinstance(value, str):
        return value
    # 1. Strip NUL bytes first
    value = value.replace('\x00', '')
    # 2. Replace any remaining lone surrogates
    return value.encode("utf-8", errors="replace").decode("utf-8")


def _sanitize_record(r: dict) -> dict:
    """Return a copy of the record dict with all string values sanitized."""
    out: dict = {}
    for k, v in r.items():
        if isinstance(v, str):
            out[k] = _sanitize_str(v)
        elif isinstance(v, list):
            out[k] = [_sanitize_str(i) if isinstance(i, str) else i for i in v]
        elif isinstance(v, dict):
            out[k] = _sanitize_record(v)
        else:
            out[k] = v
    return out


def get_connection():
    """Return a new psycopg2 connection. Caller is responsible for closing."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise EnvironmentError("DATABASE_URL is not set. Copy .env.example → .env and run `make db-up`.")
    return psycopg2.connect(url)


def check_connection() -> bool:
    """Return True if the DB is reachable, False otherwise."""
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------
# Pipeline run provenance
# ---------------------------------------------------------------

def record_run_start(task_name: str, parameters: Optional[dict] = None) -> str:
    run_id = str(uuid.uuid4())
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO pipeline_runs
                    (run_id, task_name, started_at, status, parameters)
                VALUES (%s, %s, NOW(), 'running', %s)
                """,
                (run_id, task_name, psycopg2.extras.Json(parameters or {})),
            )
    return run_id


def record_run_end(
    run_id: str,
    status: str,
    records_in: int = 0,
    records_out: int = 0,
    source_files: Optional[list[str]] = None,
) -> None:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE pipeline_runs
                SET status       = %s,
                    completed_at = NOW(),
                    records_in   = %s,
                    records_out  = %s,
                    source_files = %s
                WHERE run_id = %s
                """,
                (status, records_in, records_out, source_files or [], run_id),
            )


# ---------------------------------------------------------------
# Honeypot events
# ---------------------------------------------------------------

def store_events(events: list[dict]) -> int:
    """Bulk-insert normalized events into honeypot_events. Returns row count."""
    if not events:
        return 0

    rows = [
        (
            e.get("event_time"),
            e.get("ingested_at"),
            e.get("record_id"),
            e.get("source_ip"),
            e.get("source_port"),
            e.get("dest_port"),
            e.get("source"),            # → honeypot column
            e.get("protocol"),
            e.get("event_type"),
            e.get("session_id"),
            e.get("username"),
            e.get("password"),
            e.get("command_str"),
            e.get("download_url"),
            e.get("file_hash"),
            e.get("hassh"),
            e.get("user_agent"),
            e.get("http_path"),
            e.get("pipeline_run_id"),
            psycopg2.extras.Json(e.get("raw_data", {})),
        )
        for e in events
    ]
    with get_connection() as conn:
        with conn.cursor() as cur:
            execute_values(
                cur,
                """
                INSERT INTO honeypot_events (
                    event_time, ingested_at, record_id,
                    source_ip, source_port, dest_port,
                    honeypot, protocol, event_type, session_id,
                    username, password, command_str,
                    download_url, file_hash, hassh,
                    user_agent, http_path,
                    pipeline_run_id, raw_data
                ) VALUES %s
                """,
                rows,
            )
            return cur.rowcount


# ---------------------------------------------------------------
# IOC records
# ---------------------------------------------------------------

def upsert_iocs(iocs: list[dict]) -> int:
    """Insert or update IOC records. Returns number of rows affected."""
    if not iocs:
        return 0

    rows = [
        (
            i["ioc_type"],
            i["ioc_value"],
            i["first_seen"],
            i["last_seen"],
            i.get("source_honeypots", []),
        )
        for i in iocs
    ]
    with get_connection() as conn:
        with conn.cursor() as cur:
            execute_values(
                cur,
                """
                INSERT INTO ioc_records
                    (ioc_type, ioc_value, first_seen, last_seen, source_honeypots)
                VALUES %s
                ON CONFLICT (ioc_type, ioc_value) DO UPDATE
                    SET last_seen        = GREATEST(ioc_records.last_seen, EXCLUDED.last_seen),
                        occurrence_count = ioc_records.occurrence_count + 1,
                        source_honeypots = ARRAY(
                            SELECT DISTINCT unnest(
                                ioc_records.source_honeypots || EXCLUDED.source_honeypots
                            )
                        )
                """,
                rows,
            )
            return cur.rowcount


# ---------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------

def upsert_credentials(creds: list[dict]) -> int:
    """Insert or update credential pairs. Returns rows affected."""
    if not creds:
        return 0

    rows = [
        (c["username"], c["password"], c["first_seen"], c["last_seen"])
        for c in creds
    ]
    with get_connection() as conn:
        with conn.cursor() as cur:
            execute_values(
                cur,
                """
                INSERT INTO credentials
                    (username, password, first_seen, last_seen)
                VALUES %s
                ON CONFLICT (username, password) DO UPDATE
                    SET last_seen     = GREATEST(credentials.last_seen, EXCLUDED.last_seen),
                        attempt_count = credentials.attempt_count + 1
                """,
                rows,
            )
            return cur.rowcount


# ---------------------------------------------------------------
# Device records (Shodan / Censys)
# ---------------------------------------------------------------

def upsert_device_records(records: list[dict]) -> int:
    """
    Bulk-upsert Shodan/Censys device records.

    Deduplication key: (source, ip, port, snapshot_week)
    On conflict: latest values win; query_ids[] is merged (union).

    Each record dict must contain:
        source, snapshot_week, snapshot_date, ip, port
    All other fields are optional.

    Returns number of rows affected.
    """
    if not records:
        return 0

    # Strip lone surrogates from all string fields (Shodan banners can
    # contain mis-decoded binary bytes that are not valid UTF-8).
    records = [_sanitize_record(r) for r in records]

    rows = [
        (
            r["source"],
            r["snapshot_week"],
            r["snapshot_date"],
            r["ip"],
            r.get("port"),
            r.get("transport"),
            r.get("protocol"),
            r.get("product"),
            r.get("version"),
            r.get("cpe") or [],
            r.get("cve_ids") or [],
            r.get("country_code"),
            r.get("asn"),
            r.get("org"),
            r.get("isp"),
            r.get("device_type", "unknown"),
            r.get("hostnames") or [],
            r.get("domains") or [],
            r.get("tags") or [],
            r.get("http_title"),
            r.get("http_server"),
            psycopg2.extras.Json(r.get("http_headers") or {}),
            psycopg2.extras.Json(r.get("ssl_cert") or {}),
            psycopg2.extras.Json(r.get("vulns") or {}),
            r.get("query_ids") or [],
            r.get("query_category"),
            r.get("raw_banner"),
            psycopg2.extras.Json(r.get("raw_data") or {}),
        )
        for r in records
    ]

    with get_connection() as conn:
        with conn.cursor() as cur:
            execute_values(
                cur,
                """
                INSERT INTO device_records (
                    source, snapshot_week, snapshot_date, ip, port,
                    transport, protocol, product, version,
                    cpe, cve_ids,
                    country_code, asn, org, isp,
                    device_type, hostnames, domains, tags,
                    http_title, http_server, http_headers, ssl_cert, vulns,
                    query_ids, query_category,
                    raw_banner, raw_data
                ) VALUES %s
                ON CONFLICT (source, ip, port, snapshot_week) DO UPDATE SET
                    snapshot_date  = GREATEST(device_records.snapshot_date,  EXCLUDED.snapshot_date),
                    transport      = COALESCE(EXCLUDED.transport,    device_records.transport),
                    protocol       = COALESCE(EXCLUDED.protocol,     device_records.protocol),
                    product        = COALESCE(EXCLUDED.product,      device_records.product),
                    version        = COALESCE(EXCLUDED.version,      device_records.version),
                    cpe            = COALESCE(EXCLUDED.cpe,          device_records.cpe),
                    cve_ids        = COALESCE(EXCLUDED.cve_ids,      device_records.cve_ids),
                    country_code   = COALESCE(EXCLUDED.country_code, device_records.country_code),
                    asn            = COALESCE(EXCLUDED.asn,          device_records.asn),
                    org            = COALESCE(EXCLUDED.org,          device_records.org),
                    isp            = COALESCE(EXCLUDED.isp,          device_records.isp),
                    device_type    = CASE
                                       WHEN EXCLUDED.device_type <> 'unknown'
                                       THEN EXCLUDED.device_type
                                       ELSE device_records.device_type
                                     END,
                    hostnames      = COALESCE(EXCLUDED.hostnames,    device_records.hostnames),
                    domains        = COALESCE(EXCLUDED.domains,      device_records.domains),
                    tags           = EXCLUDED.tags,
                    http_title     = COALESCE(EXCLUDED.http_title,   device_records.http_title),
                    http_server    = COALESCE(EXCLUDED.http_server,  device_records.http_server),
                    http_headers   = EXCLUDED.http_headers,
                    ssl_cert       = EXCLUDED.ssl_cert,
                    vulns          = EXCLUDED.vulns,
                    query_ids      = ARRAY(
                                       SELECT DISTINCT unnest(
                                           device_records.query_ids || EXCLUDED.query_ids
                                       )
                                     ),
                    query_category = COALESCE(device_records.query_category, EXCLUDED.query_category),
                    raw_banner     = COALESCE(EXCLUDED.raw_banner,   device_records.raw_banner),
                    raw_data       = EXCLUDED.raw_data
                """,
                rows,
            )
            return cur.rowcount


def record_query_run(
    run_id: str,
    source: str,
    snapshot_week: str,
    query_id: str,
    query_category: str,
    query_string: str,
    results_total: int = 0,
    results_fetched: int = 0,
    error: Optional[str] = None,
) -> None:
    """Record a single Shodan/Censys query execution for audit/reproducibility."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO shodan_query_runs
                    (run_id, source, snapshot_week, query_id, query_category,
                     query_string, results_total, results_fetched, executed_at, error)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)
                ON CONFLICT (source, snapshot_week, query_id) DO UPDATE SET
                    results_total   = EXCLUDED.results_total,
                    results_fetched = EXCLUDED.results_fetched,
                    executed_at     = NOW(),
                    error           = EXCLUDED.error
                """,
                (
                    run_id, source, snapshot_week, query_id, query_category,
                    query_string, results_total, results_fetched, error,
                ),
            )


def get_completed_query_ids(source: str, snapshot_week: str) -> set[str]:
    """Return query_ids that already completed without error for this snapshot_week.

    Used by poll_shodan / poll_censys to skip already-done queries on resume
    (SHODAN_RESUME=1), so a crashed poll can continue without re-spending credits.
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT query_id FROM shodan_query_runs
                WHERE source = %s AND snapshot_week = %s AND error IS NULL
                """,
                (source, str(snapshot_week)),
            )
            return {row[0] for row in cur.fetchall()}