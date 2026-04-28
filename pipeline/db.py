"""pipeline/db.py — PostgreSQL connection and UPSERT helpers."""
import logging
import os
import uuid
from typing import Optional

import psycopg2
import psycopg2.extras
from psycopg2.extras import execute_values
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("pipeline")


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
            e.get("raw_file_path"),
            e.get("raw_line_number"),
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
                    pipeline_run_id, raw_file_path, raw_line_number, raw_data
                ) VALUES %s
                ON CONFLICT (raw_file_path, raw_line_number, event_time)
                    WHERE raw_file_path IS NOT NULL AND raw_line_number IS NOT NULL
                DO NOTHING
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

    # Deduplicate within the batch: same (ioc_type, ioc_value) in one
    # execute_values call causes a CardinalityViolation. Merge duplicates
    # by keeping the earliest first_seen and latest last_seen.
    merged: dict[tuple, dict] = {}
    for i in iocs:
        key = (i["ioc_type"], i["ioc_value"])
        if key in merged:
            existing = merged[key]
            existing["first_seen"] = min(existing["first_seen"], i["first_seen"])
            existing["last_seen"]  = max(existing["last_seen"],  i["last_seen"])
            existing["source_honeypots"] = list(
                set(existing.get("source_honeypots", []) + i.get("source_honeypots", []))
            )
        else:
            merged[key] = dict(i)

    rows = [
        (
            v["ioc_type"],
            v["ioc_value"],
            v["first_seen"],
            v["last_seen"],
            v.get("source_honeypots", []),
        )
        for v in merged.values()
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

    # Deduplicate within the batch to avoid CardinalityViolation
    merged_creds: dict[tuple, dict] = {}
    for c in creds:
        key = (c["username"], c["password"])
        if key in merged_creds:
            existing = merged_creds[key]
            existing["first_seen"] = min(existing["first_seen"], c["first_seen"])
            existing["last_seen"]  = max(existing["last_seen"],  c["last_seen"])
        else:
            merged_creds[key] = dict(c)

    rows = [
        (c["username"], c["password"], c["first_seen"], c["last_seen"])
        for c in merged_creds.values()
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


# ---------------------------------------------------------------
# Daily churn aggregation  (T07)
# ---------------------------------------------------------------

def aggregate_churn(day: Optional[str] = None) -> int:
    """
    Aggregate honeypot_events for *day* (ISO8601 date string) into ip_activity_daily.
    If day is None, backfill all missing days from last successful run through yesterday.
    Safe to re-run — uses ON CONFLICT DO UPDATE.

    Tracks last aggregated day in PIPELINE_STATE_DIR/churn_last_day.txt for catch-up.
    Returns the total number of rows inserted or updated across all days.
    """
    import datetime as _dt
    import json as _json
    from pathlib import Path as _Path

    state_dir = _Path(os.environ.get("PIPELINE_STATE_DIR", "/tmp"))
    last_day_file = state_dir / "churn_last_day.txt"

    # Determine day(s) to aggregate
    if day is not None:
        # Manual override: specific day only
        days_to_agg = [day]
    elif os.environ.get("CHURN_DAY"):
        # Env var override: specific day only
        days_to_agg = [os.environ.get("CHURN_DAY")]
    else:
        # Auto mode: backfill missing days
        today = _dt.datetime.now(_dt.timezone.utc).date()
        yesterday = today - _dt.timedelta(days=1)

        if last_day_file.exists():
            with open(last_day_file) as f:
                last_agg_day = _dt.date.fromisoformat(f.read().strip())
        else:
            # First run: start from 7 days ago for safety
            last_agg_day = today - _dt.timedelta(days=7)

        # Generate all days from (last_agg_day + 1) to yesterday
        current_day = last_agg_day + _dt.timedelta(days=1)
        days_to_agg = []
        while current_day <= yesterday:
            days_to_agg.append(current_day.isoformat())
            current_day += _dt.timedelta(days=1)

        if not days_to_agg:
            logger.info(f"aggregate_churn: already aggregated through {last_agg_day}")
            return 0

    total_rows = 0
    with get_connection() as conn:
        for d in days_to_agg:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO ip_activity_daily
                        (day, source_ip, honeypot,
                         event_count, login_attempts, unique_sessions,
                         first_event, last_event)
                    SELECT
                        event_time::DATE            AS day,
                        source_ip,
                        honeypot,
                        COUNT(*)                    AS event_count,
                        COUNT(*) FILTER (
                            WHERE event_type LIKE 'login%%'
                        )                           AS login_attempts,
                        COUNT(DISTINCT session_id)  AS unique_sessions,
                        MIN(event_time)             AS first_event,
                        MAX(event_time)             AS last_event
                    FROM honeypot_events
                    WHERE event_time::DATE = %s::DATE
                      AND source_ip IS NOT NULL
                    GROUP BY event_time::DATE, source_ip, honeypot
                    ON CONFLICT (day, source_ip, honeypot) DO UPDATE SET
                        event_count     = EXCLUDED.event_count,
                        login_attempts  = EXCLUDED.login_attempts,
                        unique_sessions = EXCLUDED.unique_sessions,
                        first_event     = EXCLUDED.first_event,
                        last_event      = EXCLUDED.last_event
                    """,
                    (d,),
                )
                rows = cur.rowcount
                total_rows += rows
                logger.info(f"aggregate_churn: day={d}, rows={rows}")

    # Update last aggregated day
    if days_to_agg:
        state_dir.mkdir(parents=True, exist_ok=True)
        with open(last_day_file, "w") as f:
            f.write(days_to_agg[-1])

    return total_rows


# ---------------------------------------------------------------
# Graph nodes / edges / campaign clusters  (T10, T11)
# ---------------------------------------------------------------

def upsert_graph_nodes(nodes: list[dict]) -> dict[str, int]:
    """
    Insert or update graph_nodes.
    Returns {node_value: id} mapping for edge-building.
    """
    if not nodes:
        return {}

    rows = [
        (
            n["node_type"],
            n["node_value"],
            n.get("first_seen"),
            n.get("last_seen"),
            n.get("cluster_id"),
            psycopg2.extras.Json(n.get("metadata") or {}),
        )
        for n in nodes
    ]

    with get_connection() as conn:
        with conn.cursor() as cur:
            execute_values(
                cur,
                """
                INSERT INTO graph_nodes
                    (node_type, node_value, first_seen, last_seen, cluster_id, metadata)
                VALUES %s
                ON CONFLICT (node_value) DO UPDATE SET
                    last_seen  = GREATEST(graph_nodes.last_seen, EXCLUDED.last_seen),
                    cluster_id = COALESCE(EXCLUDED.cluster_id, graph_nodes.cluster_id),
                    metadata   = EXCLUDED.metadata
                RETURNING id, node_value
                """,
                rows,
                fetch=True,
            )
            return {row[1]: row[0] for row in cur.fetchall()}


def upsert_graph_edges(edges: list[dict]) -> int:
    """Insert or update graph_edges. Returns row count."""
    if not edges:
        return 0

    rows = [
        (
            e["source_node_id"],
            e["target_node_id"],
            e["edge_type"],
            e.get("weight", 1.0),
            e.get("first_seen"),
            e.get("last_seen"),
            psycopg2.extras.Json(e.get("evidence") or {}),
        )
        for e in edges
    ]

    with get_connection() as conn:
        with conn.cursor() as cur:
            execute_values(
                cur,
                """
                INSERT INTO graph_edges
                    (source_node_id, target_node_id, edge_type,
                     weight, first_seen, last_seen, evidence)
                VALUES %s
                ON CONFLICT (source_node_id, target_node_id, edge_type) DO UPDATE SET
                    weight    = EXCLUDED.weight,
                    last_seen = EXCLUDED.last_seen,
                    evidence  = EXCLUDED.evidence
                """,
                rows,
            )
            return cur.rowcount


def upsert_campaign_clusters(clusters: list[dict]) -> int:
    """Insert or update campaign_clusters. Returns row count."""
    if not clusters:
        return 0

    rows = [
        (
            c["cluster_id"],
            c.get("name"),
            c.get("first_seen"),
            c.get("last_seen"),
            c.get("active", True),
            c.get("event_count", 0),
            c.get("source_ip_count", 0),
            c.get("primary_protocol"),
            c.get("primary_creds") or [],
            c.get("c2_ips") or [],
            c.get("c2_domains") or [],
            c.get("malware_hashes") or [],
            psycopg2.extras.Json(c.get("metadata") or {}),
        )
        for c in clusters
    ]

    with get_connection() as conn:
        with conn.cursor() as cur:
            execute_values(
                cur,
                """
                INSERT INTO campaign_clusters
                    (cluster_id, name, first_seen, last_seen, active,
                     event_count, source_ip_count, primary_protocol,
                     primary_creds, c2_ips, c2_domains, malware_hashes,
                     metadata)
                VALUES %s
                ON CONFLICT (cluster_id) DO UPDATE SET
                    last_seen       = GREATEST(campaign_clusters.last_seen, EXCLUDED.last_seen),
                    active          = EXCLUDED.active,
                    event_count     = EXCLUDED.event_count,
                    source_ip_count = EXCLUDED.source_ip_count,
                    primary_creds   = EXCLUDED.primary_creds,
                    c2_ips          = EXCLUDED.c2_ips,
                    c2_domains      = EXCLUDED.c2_domains,
                    malware_hashes  = EXCLUDED.malware_hashes,
                    metadata        = EXCLUDED.metadata
                """,
                rows,
            )
            return cur.rowcount