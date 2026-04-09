"""tests/test_ingest_opencanary.py — Unit tests for pipeline.ingest_opencanary."""
from __future__ import annotations

import json

import pytest

from pipeline.ingest_opencanary import parse_opencanary_line


RUN_ID   = "test-run-001"
GIT_HASH = "cafebabe"
LOG_FILE = "/tmp/opencanary.log"


def _parse(raw_dict: dict, line_no: int = 1):
    return parse_opencanary_line(json.dumps(raw_dict), RUN_ID, GIT_HASH, LOG_FILE, line_no)


# ---------------------------------------------------------------------------

class TestParseOpencanaryFTP:
    BASE = {
        "dst_host": "10.0.0.1", "dst_port": 21,
        "local_time": "2026-04-10 03:41:22.000000",
        "logdata": {"PASSWORD": "admin123", "USERNAME": "root"},
        "logtype": 2000, "node_id": "honeypot-01",
        "src_host": "185.220.101.45", "src_port": 51234,
    }

    def test_event_type(self):
        ev = _parse(self.BASE)
        assert ev["event_type"] == "login.attempt"

    def test_protocol_ftp(self):
        ev = _parse(self.BASE)
        assert ev["protocol"] == "ftp"

    def test_source_ip(self):
        ev = _parse(self.BASE)
        assert ev["source_ip"] == "185.220.101.45"

    def test_credentials(self):
        ev = _parse(self.BASE)
        assert ev["username"] == "root"
        assert ev["password"] == "admin123"

    def test_dest_port(self):
        ev = _parse(self.BASE)
        assert ev["dest_port"] == 21


class TestParseOpencanaryHTTP:
    BASE = {
        "dst_host": "10.0.0.1", "dst_port": 80,
        "local_time": "2026-04-10 03:43:00.000000",
        "logdata": {
            "PATH": "/admin/login.php",
            "HEADERS": {"User-Agent": "curl/7.68.0", "Host": "10.0.0.1"},
        },
        "logtype": 3000, "node_id": "honeypot-01",
        "src_host": "104.21.54.33", "src_port": 55123,
    }

    def test_event_type(self):
        ev = _parse(self.BASE)
        assert ev["event_type"] == "http.request"

    def test_protocol_http(self):
        ev = _parse(self.BASE)
        assert ev["protocol"] == "http"

    def test_http_path_captured(self):
        ev = _parse(self.BASE)
        assert ev.get("http_path") == "/admin/login.php"

    def test_user_agent_captured(self):
        ev = _parse(self.BASE)
        assert ev.get("user_agent") == "curl/7.68.0"


class TestParseOpencanaryPortScan:
    BASE = {
        "dst_host": "10.0.0.1", "dst_port": 0,
        "local_time": "2026-04-10 03:44:00.000000",
        "logdata": {}, "logtype": 17000,
        "src_host": "198.51.100.7", "src_port": 0,
    }

    def test_event_type(self):
        ev = _parse(self.BASE)
        assert ev["event_type"] == "port_scan"


class TestParseOpencanaryUnknownLogtype:
    def test_unknown_logtype_maps_to_connection(self):
        ev = _parse({
            "dst_host": "10.0.0.1", "dst_port": 9999,
            "local_time": "2026-04-10 03:44:00.000000",
            "logdata": {}, "logtype": 99999,
            "src_host": "1.2.3.4", "src_port": 1234,
        })
        assert ev["event_type"] == "connection"
        assert "unknown_" in ev["protocol"]


class TestParseOpencanaryProvenance:
    BASE = {
        "dst_host": "10.0.0.1", "dst_port": 21,
        "local_time": "2026-04-10 03:41:22.000000",
        "logdata": {}, "logtype": 2000,
        "src_host": "1.2.3.4", "src_port": 1111,
    }

    def test_provenance_fields(self):
        ev = _parse(self.BASE, line_no=3)
        assert ev["pipeline_run_id"]  == RUN_ID
        assert ev["pipeline_version"] == GIT_HASH
        assert ev["raw_file_path"]    == LOG_FILE
        assert ev["raw_line_number"]  == 3
        assert ev["source"]           == "opencanary"

    def test_invalid_json_returns_none(self):
        result = parse_opencanary_line("bad json", RUN_ID, GIT_HASH, LOG_FILE, 1)
        assert result is None
