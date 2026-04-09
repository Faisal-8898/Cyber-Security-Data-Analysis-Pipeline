"""pipeline/bookmark.py — Byte-offset tracker for incremental log reads.

Tracks (inode, byte_offset, head_hash) per log file so each pipeline run
reads only new lines.  Handles log rotation by detecting inode changes OR
content changes *within the already-read prefix* of the file (guards against
inode reuse when a file is deleted and immediately recreated on tmpfs/ext4).
"""
import json
import os
from pathlib import Path

_HASH_BYTES = 512   # max prefix length we compare for rotation detection


def _state_dir() -> Path:
    """Return state dir, respecting PIPELINE_STATE_DIR at call time."""
    d = Path(os.getenv("PIPELINE_STATE_DIR", "/tmp/iot-pipeline/state"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _prefix_hash(log_path: Path, n: int) -> str:
    """Return hex of the first *n* bytes — used for rotation detection.

    If n == 0 (nothing read yet) returns "" to skip the comparison.
    """
    if n <= 0:
        return ""
    try:
        with open(log_path, "rb") as f:
            return f.read(n).hex()
    except Exception:
        return ""


def get_bookmark(log_name: str) -> dict:
    path = _state_dir() / f"{log_name}.bookmark.json"
    if path.exists():
        return json.loads(path.read_text())
    return {"inode": None, "offset": 0, "head_hash": ""}


def set_bookmark(log_name: str, inode: int, offset: int, head_hash: str = "") -> None:
    path = _state_dir() / f"{log_name}.bookmark.json"
    path.write_text(json.dumps({"inode": inode, "offset": offset, "head_hash": head_hash}))


def reset_bookmark(log_name: str) -> None:
    path = _state_dir() / f"{log_name}.bookmark.json"
    if path.exists():
        path.unlink()


def read_new_lines(log_path: Path, log_name: str) -> list[tuple[int, str]]:
    """Read only lines added since the last run.

    Returns a list of (line_number, raw_line_string) tuples.
    line_number is 1-based and absolute within the file.

    Rotation detection:
    * Inode change → definitely a new/rotated file → seek to 0.
    * Inode same but first min(saved_offset, HASH_BYTES) bytes differ →
      inode was reused for a different file → seek to 0.
    * Inode same, prefix matches → normal append → seek to saved offset.
    """
    bm = get_bookmark(log_name)
    results: list[tuple[int, str]] = []

    try:
        stat = log_path.stat()
        current_inode = stat.st_ino

        saved_offset: int = bm.get("offset", 0)
        saved_hash:   str = bm.get("head_hash", "")

        if bm["inode"] != current_inode:
            seek_to = 0
        else:
            # Verify the already-read prefix hasn't changed (guards inode reuse)
            hash_n = min(saved_offset, _HASH_BYTES)
            if hash_n > 0 and saved_hash:
                current_hash = _prefix_hash(log_path, hash_n)
                seek_to = saved_offset if current_hash == saved_hash else 0
            else:
                seek_to = saved_offset

        with open(log_path, "rb") as f:
            f.seek(seek_to)
            raw_bytes = f.read()
            new_offset = f.tell()

        # Save bookmark — hash the prefix up to new_offset for next run
        new_hash = _prefix_hash(log_path, min(new_offset, _HASH_BYTES))
        set_bookmark(log_name, current_inode, new_offset, new_hash)

        # Compute absolute line number of first new line
        start_line = _lines_before_offset(log_path, seek_to)
        for i, line in enumerate(raw_bytes.decode(errors="replace").splitlines()):
            if line.strip():
                results.append((start_line + i + 1, line))

    except FileNotFoundError:
        pass  # log file not yet created (VPS not set up yet)

    return results


def _lines_before_offset(path: Path, offset: int) -> int:
    if offset == 0:
        return 0
    try:
        with open(path, "rb") as f:
            return f.read(offset).count(b"\n")
    except Exception:
        return 0
