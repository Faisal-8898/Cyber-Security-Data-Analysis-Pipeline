"""tests/conftest.py — Shared pytest fixtures."""
from __future__ import annotations

import os
import json
import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Paths to fixture files
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"
COWRIE_SAMPLE    = FIXTURES / "cowrie_sample.json"
OPENCANARY_SAMPLE = FIXTURES / "opencanary_sample.json"


# ---------------------------------------------------------------------------
# Temp directory fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_state_dir(tmp_path, monkeypatch):
    """Set PIPELINE_STATE_DIR to a fresh temp dir for bookmark tests."""
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setenv("PIPELINE_STATE_DIR", str(state))
    return state


@pytest.fixture
def tmp_log_dir(tmp_path, monkeypatch):
    """Set PIPELINE_LOG_DIR to a fresh temp dir."""
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setenv("PIPELINE_LOG_DIR", str(logs))
    return logs


# ---------------------------------------------------------------------------
# Sample log file fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cowrie_log_file(tmp_path):
    """Write cowrie_sample.json lines into a temp file, return its Path."""
    src  = COWRIE_SAMPLE.read_text()
    dest = tmp_path / "cowrie.json"
    dest.write_text(src)
    return dest


@pytest.fixture
def opencanary_log_file(tmp_path):
    """Write opencanary_sample.json lines into a temp file, return its Path."""
    src  = OPENCANARY_SAMPLE.read_text()
    dest = tmp_path / "opencanary.log"
    dest.write_text(src)
    return dest


# ---------------------------------------------------------------------------
# Minimal NormalizedEvent factory for tests
# ---------------------------------------------------------------------------

@pytest.fixture
def make_test_event():
    """Return a factory that creates minimal NormalizedEvents for testing."""
    from pipeline.schema import make_event

    def _factory(**overrides):
        ev = make_event(
            source="cowrie",
            run_id="test-run-id",
            git_hash="abcdef0",
            raw_file="/tmp/test.json",
            line_no=1,
            raw={"timestamp": "2026-04-10T03:41:22.000000Z"},
        )
        ev.update(overrides)
        return ev

    return _factory
