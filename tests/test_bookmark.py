"""tests/test_bookmark.py — Unit tests for pipeline.bookmark."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from pipeline.bookmark import (
    get_bookmark,
    read_new_lines,
    reset_bookmark,
    set_bookmark,
)


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n")


def _append(path: Path, lines: list[str]) -> None:
    with path.open("a") as f:
        for line in lines:
            f.write(line + "\n")


# ---------------------------------------------------------------------------

def test_no_bookmark_returns_all_lines(tmp_state_dir, tmp_path):
    """First read with no bookmark must return every line."""
    log = tmp_path / "test.log"
    _write(log, ["line1", "line2", "line3"])

    result = read_new_lines(log, "test_log")
    assert len(result) == 3
    assert result[0] == (1, "line1")
    assert result[2] == (3, "line3")


def test_second_read_returns_only_new_lines(tmp_state_dir, tmp_path):
    """After first read, second call must return only appended lines."""
    log = tmp_path / "test.log"
    _write(log, ["line1", "line2"])

    read_new_lines(log, "test_log")          # consume first two lines
    _append(log, ["line3", "line4"])

    result = read_new_lines(log, "test_log")
    assert len(result) == 2
    assert result[0][1] == "line3"
    assert result[1][1] == "line4"


def test_empty_file_returns_empty(tmp_state_dir, tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("")
    result = read_new_lines(log, "empty_log")
    assert result == []


def test_no_new_lines_returns_empty(tmp_state_dir, tmp_path):
    """Calling read twice without new content returns empty on second call."""
    log = tmp_path / "static.log"
    _write(log, ["line1"])

    read_new_lines(log, "static_log")
    result = read_new_lines(log, "static_log")
    assert result == []


def test_reset_bookmark_rereads_all(tmp_state_dir, tmp_path):
    """reset_bookmark() causes the next read to replay from the beginning."""
    log = tmp_path / "reset.log"
    _write(log, ["a", "b", "c"])

    read_new_lines(log, "reset_log")
    reset_bookmark("reset_log")

    result = read_new_lines(log, "reset_log")
    assert len(result) == 3


def test_inode_change_triggers_reread(tmp_state_dir, tmp_path):
    """Simulating log rotation (new inode) should reread from offset 0."""
    log = tmp_path / "rotated.log"
    _write(log, ["old1", "old2"])
    read_new_lines(log, "rotated_log")

    # Simulate rotation — delete and recreate (new inode)
    log.unlink()
    _write(log, ["new1", "new2", "new3"])

    result = read_new_lines(log, "rotated_log")
    assert len(result) == 3
    assert result[0][1] == "new1"


def test_set_get_bookmark_roundtrip(tmp_state_dir):
    set_bookmark("mylog", inode=42, offset=1024)
    bm = get_bookmark("mylog")
    assert bm["inode"]  == 42
    assert bm["offset"] == 1024


def test_line_numbers_are_1_based(tmp_state_dir, tmp_path):
    log = tmp_path / "numbered.log"
    _write(log, ["a", "b", "c"])
    result = read_new_lines(log, "numbered_log")
    line_numbers = [r[0] for r in result]
    assert line_numbers == [1, 2, 3]
