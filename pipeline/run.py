"""pipeline/run.py — CLI entry point.

Usage:
    python -m pipeline.run --tasks ingest,extract
    python -m pipeline.run --tasks ingest_cowrie
    python -m pipeline.run --tasks poll_shodan
    python -m pipeline.run --tasks poll_censys
    python -m pipeline.run --tasks poll            # shodan + censys
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


def _run_poll_shodan() -> int:
    from .poll_shodan import poll_shodan
    return poll_shodan()


def _run_poll_censys() -> int:
    from .poll_censys import poll_censys
    return poll_censys()


def _run_poll_feeds() -> int:
    from .poll_feeds import poll_feeds
    poll_feeds()
    return 0


def _run_aggregate_churn() -> int:
    from . import db as _db
    n = _db.aggregate_churn()
    logger.info(f"aggregate_churn: {n} rows written to ip_activity_daily")
    return n


def _run_build_graph():
    from .build_graph import build_networkx_graph
    return build_networkx_graph()


def _run_cluster_campaigns(G=None) -> int:
    from .build_graph import cluster_campaigns
    return cluster_campaigns(G)


_INGEST_TASKS = {
    "ingest_cowrie":     _run_ingest_cowrie,
    "ingest_opencanary": _run_ingest_opencanary,
}

_POLL_TASKS = {
    "poll_shodan":  _run_poll_shodan,
    "poll_censys":  _run_poll_censys,
    "poll_feeds":   _run_poll_feeds,
}

_GRAPH_TASKS = {
    "build_graph": _run_build_graph,
    "cluster":     _run_cluster_campaigns,
}

_ALL_INGEST = list(_INGEST_TASKS.keys())
_ALL_POLL   = list(_POLL_TASKS.keys())
_ALL_GRAPH  = list(_GRAPH_TASKS.keys())

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
    run_poll    = any(t in tasks for t in [*_ALL_POLL, "poll", "all"])
    run_churn   = "aggregate_churn" in tasks or "all" in tasks
    run_graph   = any(t in tasks for t in [*_ALL_GRAPH, "graph", "all"])

    # Which ingest tasks to run
    specific_ingest = [t for t in tasks if t in _INGEST_TASKS]
    if run_ingest and not specific_ingest:
        specific_ingest = _ALL_INGEST

    # Which poll tasks to run
    specific_poll = [t for t in tasks if t in _POLL_TASKS]
    if run_poll and not specific_poll:
        specific_poll = _ALL_POLL

    # Which graph tasks to run
    specific_graph = [t for t in tasks if t in _GRAPH_TASKS]
    if run_graph and not specific_graph:
        specific_graph = _ALL_GRAPH

    collected_events: list = []
    exit_code = 0

    # --- Ingest phase -------------------------------------------------------
    for task_name in specific_ingest:
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

    # --- Churn aggregation (T07) ---------------------------------------------
    if run_churn:
        try:
            _run_aggregate_churn()
        except Exception as exc:
            logger.error(f"aggregate_churn failed: {exc}")
            exit_code = 1

    # --- Poll phase (Shodan / Censys) ----------------------------------------
    for task_name in specific_poll:
        try:
            stored = _POLL_TASKS[task_name]()
            logger.info(f"Poll complete: {task_name} → {stored} device records stored")
        except Exception as exc:
            logger.error(f"Task {task_name} failed: {exc}")
            exit_code = 1

    # --- Graph build + cluster (T10, T11) ------------------------------------
    built_graph = None
    if "build_graph" in specific_graph:
        try:
            built_graph = _run_build_graph()
        except Exception as exc:
            logger.error(f"build_graph failed: {exc}")
            exit_code = 1

    if "cluster" in specific_graph:
        try:
            _run_cluster_campaigns(built_graph)
        except Exception as exc:
            logger.error(f"cluster_campaigns failed: {exc}")
            exit_code = 1

    return exit_code


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

_VALID_TASKS = [
    *_ALL_INGEST,
    *_ALL_POLL,
    *_ALL_GRAPH,
    "ingest",
    "extract",
    "poll",
    "aggregate_churn",
    "graph",
    "all",
]


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
