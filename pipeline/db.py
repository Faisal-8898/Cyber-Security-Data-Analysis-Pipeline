"""pipeline/db.py — PostgreSQL connection and UPSERT helpers."""
import os
import uuid
from typing import Optional

import psycopg2
import psycopg2.extras
from psycopg2.extras import execute_values
from dotenv import load_dotenv

load_dotenv()


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
