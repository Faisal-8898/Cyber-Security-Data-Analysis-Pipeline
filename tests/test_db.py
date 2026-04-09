"""tests/test_db.py — Integration tests for pipeline.db (requires live DB).

Run only with: pytest -m integration
Needs DATABASE_URL pointing to the Docker PostgreSQL instance.
"""
from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.integration   # skip unless -m integration


def _skip_if_no_db():
    """Skip the test if DATABASE_URL is not set or DB is unreachable."""
    from pipeline import db
    if not db.check_connection():
        pytest.skip("No database connection available")


@pytest.fixture(autouse=True)
def require_db():
    _skip_if_no_db()


# ---------------------------------------------------------------------------

class TestCheckConnection:
    def test_check_connection_returns_true(self):
        from pipeline import db
        assert db.check_connection() is True


class TestPipelineRuns:
    def test_record_run_start_returns_uuid(self):
        from pipeline import db
        run_id = db.record_run_start("test_task", {"key": "val"})
        assert uuid.UUID(run_id)   # raises if not valid UUID

    def test_record_run_end_success(self):
        from pipeline import db
        run_id = db.record_run_start("test_task_end", {})
        # Should not raise
        db.record_run_end(run_id, "success", records_in=10, records_out=8,
                          source_files=["/tmp/test.log"])

    def test_record_run_end_failure(self):
        from pipeline import db
        run_id = db.record_run_start("test_task_fail", {})
        db.record_run_end(run_id, "failure")


class TestStoreEvents:
    def test_store_empty_list_returns_zero(self):
        from pipeline import db
        count = db.store_events([])
        assert count == 0

    def test_store_single_event(self):
        from pipeline import db
        from pipeline.schema import make_event

        run_id = db.record_run_start("test_store", {})
        ev = make_event("cowrie", run_id, "abc0000", "/tmp/test.json", 1,
                        {"eventid": "cowrie.login.failed",
                         "timestamp": "2026-04-10T01:00:00Z"})
        ev["event_type"]  = "login.failed"
        ev["source_ip"]   = "1.2.3.4"
        ev["source_port"] = 1234
        ev["protocol"]    = "ssh"

        count = db.store_events([ev])
        assert count == 1


class TestUpsertIocs:
    def test_upsert_ioc_new_row(self):
        from pipeline import db

        ioc = {
            "ioc_type":         "ip",
            "ioc_value":        f"192.0.2.{uuid.uuid4().int % 255}",
            "first_seen":       "2026-04-10T00:00:00+00:00",
            "last_seen":        "2026-04-10T00:00:00+00:00",
            "source_honeypots": ["cowrie"],
            "occurrence_count": 1,
        }
        count = db.upsert_iocs([ioc])
        assert count == 1

    def test_upsert_empty_list_returns_zero(self):
        from pipeline import db
        assert db.upsert_iocs([]) == 0


class TestUpsertCredentials:
    def test_upsert_credential_new_row(self):
        from pipeline import db

        cred = {
            "username":         f"user_{uuid.uuid4().hex[:8]}",
            "password":         "test123",
            "first_seen":       "2026-04-10T00:00:00+00:00",
            "last_seen":        "2026-04-10T00:00:00+00:00",
            "source_honeypots": ["cowrie"],
            "attempt_count":    1,
        }
        count = db.upsert_credentials([cred])
        assert count == 1

    def test_upsert_empty_list_returns_zero(self):
        from pipeline import db
        assert db.upsert_credentials([]) == 0
