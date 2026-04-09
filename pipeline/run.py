"""pipeline/run.py — CLI entry point.

Usage:
    python -m pipeline.run --tasks ingest,extract
    python -m pipeline.run --tasks ingest_cowrie
    python -m pipeline.run --tasks all
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from .core import logger

# ---------------------------------------------------------------------------
# Task registry
# ---------------------------------------------------------------------------

def _run_ingest_cowrie() -> list:
    from .ingest_cowrie import ingest_cowrie
    return ingest_cowrie()


def _run_ingest_opencanary() -> list:
    from .ingest_opencanary import ingest_opencanary
    return ingest_opencanary()


def _run_extract_iocs(events: list) -> tuple[int, int]:
    from .extract_iocs import extract_iocs
    return extract_iocs(events)


_INGEST_TASKS = {
    "ingest_cowrie":     _run_ingest_cowrie,
    "ingest_opencanary": _run_ingest_opencanary,
}

_ALL_INGEST = list(_INGEST_TASKS.keys())

# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

def run_pipeline(tasks: list[str]) -> int:
    """
    Execute the requested tasks in dependency order.

    Returns exit code (0 = success, 1 = any failure).
    """
    run_ingest  = any(t in tasks for t in [*_ALL_INGEST, "ingest", "all"])
    run_extract = "extract" in tasks or "all" in tasks

    # Which ingest tasks to run
    specific = [t for t in tasks if t in _INGEST_TASKS]
    if run_ingest and not specific:
        specific = _ALL_INGEST

    collected_events: list = []
    exit_code = 0

    # --- Ingest phase -------------------------------------------------------
    for task_name in specific:
        try:
            events = _INGEST_TASKS[task_name]()
            collected_events.extend(events or [])
        except Exception as exc:
            logger.error(f"Task {task_name} failed: {exc}")
            exit_code = 1

    # --- Extract phase -------------------------------------------------------
    if run_extract and collected_events:
        try:
            ioc_count, cred_count = _run_extract_iocs(collected_events)
            logger.info(f"Extract complete: {ioc_count} IOCs, {cred_count} creds")
        except Exception as exc:
            logger.error(f"extract_iocs failed: {exc}")
            exit_code = 1
    elif run_extract and not collected_events:
        logger.warning("extract_iocs requested but no events from ingest phase")

    return exit_code


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

_VALID_TASKS = [*_ALL_INGEST, "ingest", "extract", "all"]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m pipeline.run",
        description="IoT research data pipeline CLI",
    )
    parser.add_argument(
        "--tasks",
        default="all",
        help=(
            f"Comma-separated list of tasks to run. "
            f"Valid values: {', '.join(_VALID_TASKS)}. "
            f"Default: all"
        ),
    )
    parser.add_argument(
        "--check-db",
        action="store_true",
        help="Only verify DB connectivity and exit.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.check_db:
        from . import db as _db
        ok = _db.check_connection()
        if ok:
            logger.info("DB connection: OK")
            return 0
        else:
            logger.error("DB connection: FAILED")
            return 1

    tasks = [t.strip() for t in args.tasks.split(",") if t.strip()]
    unknown = [t for t in tasks if t not in _VALID_TASKS]
    if unknown:
        print(f"Unknown tasks: {unknown}. Valid: {_VALID_TASKS}", file=sys.stderr)
        return 1

    return run_pipeline(tasks)


if __name__ == "__main__":
    sys.exit(main())
