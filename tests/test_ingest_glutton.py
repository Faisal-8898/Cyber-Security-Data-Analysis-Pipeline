"""tests/test_ingest_glutton.py — Unit + fake-attack injection tests for pipeline.ingest_glutton."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from pipeline.ingest_glutton import parse_glutton_line, ingest_glutton

RUN_ID   = "test-run-glutton"
GIT_HASH = "cafebabe"
LOG_FILE = "/tmp/glutton.log"

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(raw_dict: dict, line_no: int = 1):
    return parse_glutton_line(json.dumps(raw_dict), RUN_ID, GIT_HASH, LOG_FILE, line_no)


# ---------------------------------------------------------------------------
# Fake attack payloads (realistic IoT attacker traffic)
# ---------------------------------------------------------------------------

FAKE_TELNET_ATTACK = {
    "time": "2026-05-15T08:00:00.000000001Z",
    "level": "INFO",
    "msg": "Packet got handled by TCP handler",
    "sensorID": "vps-01",
    "dest_port": "23",
    "src_ip": "185.220.101.10",
    "src_port": "49201",
    "handler": "tcp",
    "payload_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
}

FAKE_CWMP_SCAN = {
    "time": "2026-05-15T08:01:00.000000001Z",
    "level": "INFO",
    "msg": "Packet got handled by TCP handler",
    "sensorID": "vps-01",
    "dest_port": "7547",
    "src_ip": "91.92.251.32",
    "src_port": "60000",
    "handler": "tcp",
    "payload_hash": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
}

FAKE_MIKROTIK_SCAN = {
    "time": "2026-05-15T08:02:00.000000001Z",
    "level": "INFO",
    "msg": "Packet got handled by TCP handler",
    "sensorID": "vps-01",
    "dest_port": "8728",
    "src_ip": "45.142.212.5",
    "src_port": "55001",
    "handler": "tcp",
    "payload_hash": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
}

FAKE_MQTT_PROBE = {
    "time": "2026-05-15T08:03:00.000000001Z",
    "level": "INFO",
    "msg": "Packet got handled by TCP handler",
    "sensorID": "vps-01",
    "dest_port": "1883",
    "src_ip": "203.0.113.77",
    "src_port": "40000",
    "handler": "tcp",
    "payload_hash": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
}

# Lowercase msg — older Glutton builds emit this variant
FAKE_LOWERCASE_MSG = {
    "time": "2026-05-15T08:04:00.000000001Z",
    "level": "INFO",
    "msg": "packet got handled by tcp handler",
    "sensorID": "vps-01",
    "dest_port": "8728",
    "src_ip": "45.142.212.6",
    "src_port": "55002",
    "handler": "tcp",
    "payload_hash": "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
}


# ---------------------------------------------------------------------------
# Parser unit tests
# ---------------------------------------------------------------------------

class TestParseGluttonConnection:
    def test_telnet_attack_parsed(self):
        ev = _parse(FAKE_TELNET_ATTACK)
        assert ev is not None
        assert ev["source_ip"]  == "185.220.101.10"
        assert ev["dest_port"]  == 23
        assert ev["protocol"]   == "telnet"
        assert ev["event_type"] == "connection"
        assert ev["source"]     == "glutton"

    def test_cwmp_scan_protocol(self):
        ev = _parse(FAKE_CWMP_SCAN)
        assert ev is not None
        assert ev["dest_port"] == 7547
        assert ev["protocol"]  == "tr069"

    def test_mikrotik_api_protocol(self):
        ev = _parse(FAKE_MIKROTIK_SCAN)
        assert ev is not None
        assert ev["protocol"] == "mikrotik_api"

    def test_mqtt_protocol(self):
        ev = _parse(FAKE_MQTT_PROBE)
        assert ev is not None
        assert ev["protocol"] == "mqtt"

    def test_unknown_port_falls_back_to_tcp(self):
        ev = _parse({**FAKE_TELNET_ATTACK, "dest_port": "9999"})
        assert ev is not None
        assert ev["protocol"] == "tcp"


class TestGluttonCaseInsensitiveMsgFilter:
    """Regression: lowercase 'msg' from older Glutton builds must still be parsed."""

    def test_lowercase_msg_is_accepted(self):
        ev = _parse(FAKE_LOWERCASE_MSG)
        assert ev is not None, (
            "BUG: lowercase 'packet got handled' was rejected — "
            "msg filter must be case-insensitive"
        )

    def test_startup_msg_is_rejected(self):
        ev = _parse({"time": "2026-05-15T08:00:00Z", "level": "INFO",
                     "msg": "Starting up glutton", "sensorID": "vps-01"})
        assert ev is None

    def test_payload_dump_is_rejected(self):
        ev = _parse({"time": "2026-05-15T08:00:01Z", "level": "INFO",
                     "msg": "TCP payload:\n00000000  ff fd 01", "sensorID": "vps-01"})
        assert ev is None

    def test_invalid_json_returns_none(self):
        result = parse_glutton_line("not-json!!!", RUN_ID, GIT_HASH, LOG_FILE, 1)
        assert result is None


class TestGluttonPayloadHash:
    def test_64char_hash_stored_as_file_hash(self):
        ev = _parse(FAKE_TELNET_ATTACK)
        assert ev["file_hash"] == FAKE_TELNET_ATTACK["payload_hash"]

    def test_short_hash_not_stored(self):
        ev = _parse({**FAKE_TELNET_ATTACK, "payload_hash": "tooshort"})
        assert ev["file_hash"] is None

    def test_missing_hash_not_stored(self):
        ev = _parse({k: v for k, v in FAKE_TELNET_ATTACK.items() if k != "payload_hash"})
        assert ev["file_hash"] is None


class TestGluttonProvenance:
    def test_provenance_fields_set(self):
        ev = _parse(FAKE_TELNET_ATTACK, line_no=3)
        assert ev["pipeline_run_id"]  == RUN_ID
        assert ev["pipeline_version"] == GIT_HASH
        assert ev["raw_file_path"]    == LOG_FILE
        assert ev["raw_line_number"]  == 3
        assert ev["source"]           == "glutton"

    def test_source_port_captured(self):
        ev = _parse(FAKE_TELNET_ATTACK)
        assert ev["source_port"] == 49201

    def test_timestamp_parsed(self):
        ev = _parse(FAKE_TELNET_ATTACK)
        assert ev["event_time"].startswith("2026-05-15")


# ---------------------------------------------------------------------------
# Full ingest_glutton integration (no DB — patches store_events)
# ---------------------------------------------------------------------------

class TestIngestGluttonFakeLog:
    """Inject fake attack log lines through the full ingest_glutton pipeline."""

    def _mock_db(self, monkeypatch, stored_events: list):
        import pipeline.db as _db_module

        monkeypatch.setattr(_db_module, "record_run_start",
                            lambda task, params=None: "mock-run-id")
        monkeypatch.setattr(_db_module, "record_run_end",
                            lambda run_id, status, **kw: None)
        monkeypatch.setattr(_db_module, "store_events",
                            lambda evs: (stored_events.extend(evs), len(evs))[1])

    def test_ingest_sample_fixture(self, tmp_path, monkeypatch):
        """Ingest the fixture file; expect 4 connection events (skips payload & startup)."""
        monkeypatch.setenv("PIPELINE_STATE_DIR", str(tmp_path / "state"))
        stored = []
        self._mock_db(monkeypatch, stored)

        log_file = tmp_path / "glutton.log"
        log_file.write_text((FIXTURES / "glutton_sample.log").read_text())

        events = ingest_glutton.__wrapped__(log_path=log_file, run_id="mock-run-id")
        # 4 connection lines in fixture (skips payload dump and startup message)
        assert len(events) == 4, (
            f"Expected 4 parsed events but got {len(events)}. "
            "Check fixture or msg filter."
        )

    def test_ingest_all_fake_attacks(self, tmp_path, monkeypatch):
        """All fake attack dicts must be accepted by the parser."""
        attacks = [
            FAKE_TELNET_ATTACK,
            FAKE_CWMP_SCAN,
            FAKE_MIKROTIK_SCAN,
            FAKE_MQTT_PROBE,
            FAKE_LOWERCASE_MSG,
        ]
        results = [_parse(a) for a in attacks]
        nones = [i for i, r in enumerate(results) if r is None]
        assert nones == [], (
            f"Fake attacks at indices {nones} were not parsed. "
            "Possibly msg filter is case-sensitive."
        )

    def test_ingest_skips_non_connection_lines(self, tmp_path, monkeypatch):
        """Startup and payload-dump lines must yield zero events."""
        noise = [
            {"time": "2026-05-15T09:00:00Z", "level": "INFO",
             "msg": "Starting up glutton", "sensorID": "vps-01"},
            {"time": "2026-05-15T09:00:01Z", "level": "INFO",
             "msg": "TCP payload:\n00000000  ff fd", "sensorID": "vps-01"},
            {"time": "2026-05-15T09:00:02Z", "level": "ERROR",
             "msg": "Error binding port 23", "sensorID": "vps-01"},
        ]
        results = [_parse(n) for n in noise]
        assert all(r is None for r in results), (
            "Non-connection log lines must return None from parse_glutton_line"
        )
