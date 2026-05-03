#!/usr/bin/env python3
"""
scripts/fetch_sonar.py — Download and filter Rapid7 Project Sonar data for IoT research.

WHY THIS EXISTS (from WHOLE_RESEARCH.md):
  Shodan free API caps at 100 results/query (~18k devices total).
  The paper targets 100k–500k device records (RQ1 scale requirement).
  Rapid7 Project Sonar scans ALL of IPv4 weekly for free — but each port file
  is 200MB–3GB compressed. We stream-filter them in memory, keeping only
  IoT-relevant records. Target output: ≤2GB total across all ports.

ACCESS MODEL — RAPID7_API_KEY IS REQUIRED:
  Rapid7 Open Data is free but requires a (free) account:
    1. Register at https://insight.rapid7.com  (free — academic use supported)
    2. Go to https://insight.rapid7.com/platform#/apiKeyManagement → create a User Key
    3. Add to .env:  RAPID7_API_KEY=<your-key>
  The API key is used to:
    a. List available scan files for each port  (no quota cost)
    b. Generate time-limited signed download URLs (costs 1 of 30 daily quota per file)
  With 10 target ports, one full run costs 10 quota units out of 30/day.
  For IEEE IoT-J artifact review, reviewers must register their own free account.
  (Rapid7 explicitly allows academic/research use in their Terms of Service.)

STRATEGY — Only pull these port files (everything else is irrelevant):
  IoT identity ports (keep ALL records — protocol guarantees IoT):
    23    Telnet          → routers, embedded devices (filter for IoT banners)
    2323  Telnet-alt      → Mirai-era alt-Telnet, almost 100% IoT/botnet
    7547  TR-069/CWMP     → ISP CPE management — all are routers/modems
    1883  MQTT            → IoT sensors, message brokers
    554   RTSP            → IP cameras (filter for camera banners)
  Proxy/monetization ports (RQ3 — keep all, direct evidence):
    1080  SOCKS proxy     → monetization signal
    3128  Squid/HTTP      → monetization signal
    9050  Tor SOCKS       → anonymisation infrastructure
    8888  HTTP proxy alt  → monetization signal
  HTTP admin panels (filter for IoT firmware banners):
    8080  HTTP alt        → GoAhead, Boa, uc-httpd, uhttpd, MiniHTTPD

  NOT included: 22 (SSH too broad), 443 (HTTPS too broad), 25 (SMTP too broad).
  Those are covered by Shodan queries already in poll_shodan.py.

OUTPUT:
  ~/data/raw-logs/sonar/sonar_iot_YYYY-MM-DD.jsonl.gz
  ~/data/raw-logs/sonar/sonar_fetch_index.json   ← tracks what was fetched

USAGE:
  python3 scripts/fetch_sonar.py --list           # list available files, no download
  python3 scripts/fetch_sonar.py --dry-run        # show what would be downloaded + sizes
  python3 scripts/fetch_sonar.py                  # download + filter all target ports
  python3 scripts/fetch_sonar.py --port 23        # single port only
  python3 scripts/fetch_sonar.py --max-gb 2.0     # stop when output exceeds 2GB (default)
  python3 scripts/fetch_sonar.py --out-dir /path  # custom output directory

ENVIRONMENT VARIABLES:
  SONAR_DRY_RUN       set to "1" to simulate without downloading
  SONAR_MAX_GB        max output size in GB (default: 2.0)
  SONAR_OUT_DIR       output directory (default: ~/data/raw-logs/sonar)
  RAPID7_API_KEY      REQUIRED — get a free key at insight.rapid7.com
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

# ─── Configuration ────────────────────────────────────────────────────────────

RAPID7_API_BASE = "https://us.api.insight.rapid7.com/opendata/studies"
DEFAULT_MAX_GB  = 2.0
CHUNK_SIZE      = 64 * 1024        # 64KB streaming chunks
PRINT_EVERY     = 100_000          # print progress every N lines processed

# ─── Target ports + filter config ─────────────────────────────────────────────

# port → (keep_all, [keyword_list])
# keep_all=True  → store every record on that port (protocol guarantees IoT relevance)
# keep_all=False → store only if decoded banner contains at least one keyword (case-insensitive)

TARGET_PORTS: dict[int, tuple[bool, list[str]]] = {
    # IoT identity — ALL records are relevant
    2323: (True,  []),     # Telnet-alt — almost exclusively Mirai/IoT
    7547: (True,  []),     # TR-069 CWMP — only routers/modems use this
    1883: (True,  []),     # MQTT — IoT sensors/brokers
    554:  (True,  []),     # RTSP — IP cameras

    # Telnet — most are IoT but filter to reduce noise from non-IoT Linux servers
    23:   (False, [
        "busybox", "login:", "username:", "password:", "mikrotik", "openwrt",
        "dd-wrt", "tomato", "router", "modem", "gateway", "dsl", "adsl",
        "huawei", "zte", "tp-link", "tplink", "netgear", "dlink", "d-link",
        "asus", "linksys", "cisco", "ericsson", "fritz", "speedport",
        "dropbear", "embedded", "arm", "mips", "uclinux",
        # Chinese ISP devices (common in datasets)
        "xdsl", "catv", "ont", "onu", "cpe",
    ]),

    # HTTP admin panels — filter for IoT firmware fingerprints
    8080: (False, [
        "goahead", "go-ahead", "boa/", "boa ", "mini_httpd", "mini httpd",
        "uc-httpd", "uhttpd", "alphapd", "hikvision", "dahua", "axis",
        "dvr", "nvr", "ipcam", "ip camera", "netcam", "webcam",
        "router", "modem", "gateway", "tp-link", "dlink", "netgear",
        "zyxel", "firmware", "setup wizard", "admin panel",
        "rompage", "management", "cisco small", "draytek",
        # Proxy banners (RQ3)
        "squid", "tinyproxy", "3proxy", "ccproxy", "privoxy",
    ]),

    # Proxy/monetization — ALL records are direct RQ3 monetization evidence
    1080: (True,  []),     # SOCKS proxy
    3128: (True,  []),     # Squid / HTTP CONNECT proxy
    9050: (True,  []),     # Tor SOCKS
    8888: (False, [        # HTTP proxy alt — filter to avoid generic web servers
        "squid", "proxy", "socks", "http/1.0 200 connection",
        "http/1.1 200 connection", "ccproxy", "tinyproxy", "privoxy",
    ]),
}

# Source field to check for banner text (Rapid7 uses "value" or "data")
BANNER_FIELDS = ["value", "data", "banner"]

# ─── IoT device type hints for enriching output records ───────────────────────

DEVICE_TYPE_HINTS: list[tuple[list[str], str]] = [
    (["hikvision", "dvr", "nvr", "ipcam", "ip camera", "dahua", "axis", "rtsp"], "camera"),
    (["mikrotik", "routeros", "router", "gateway", "modem", "dlink", "netgear",
      "tp-link", "asus router", "linksys", "draytek", "zyxel", "fritz",
      "speedport", "huawei hg", "zte f"], "router"),
    (["mqtt", "mosquitto", "hivemq", "emqx"], "iot_mqtt"),
    (["squid", "tinyproxy", "3proxy", "ccproxy", "socks5", "socks4",
      "http/1.0 200 connection", "privoxy"], "proxy"),
    (["busybox", "openwrt", "dd-wrt", "uclinux", "embedded"], "iot_embedded"),
    (["tr-069", "cwmp", "tr069", "acs url", "acs_url", "inform"], "router"),
]


def infer_device_type(banner_lower: str, port: int) -> str:
    """Best-effort device type from banner text + port context."""
    for keywords, dtype in DEVICE_TYPE_HINTS:
        if any(kw in banner_lower for kw in keywords):
            return dtype
    if port in (1080, 3128, 9050, 8888):
        return "proxy"
    if port in (554,):
        return "camera"
    if port in (7547, 2323):
        return "router"
    if port == 1883:
        return "iot_mqtt"
    return "unknown"


# ─── Rapid7 Open Data API helpers ─────────────────────────────────────────────

# Port → filename substrings to match against Rapid7 filenames.
# Rapid7 names look like: "2026-04-21-1745183618-telnet_23.csv.gz"
#                     or: "2026-03-01-1772376733-telnet_23.csv.gz"
PORT_FILENAME_ALIASES: dict[int, list[str]] = {
    23:   ["telnet_23"],
    2323: ["telnet_2323", "2323"],
    7547: ["http_get_7547", "tr069_7547", "7547"],
    1883: ["mqtt_1883", "1883"],
    554:  ["rtsp_554", "554"],
    1080: ["socks5_1080", "socks_1080", "1080"],
    3128: ["http_get_3128", "squid_3128", "3128"],
    9050: ["socks5_9050", "tor_9050", "9050"],
    8080: ["http_get_8080", "8080"],
    8888: ["http_get_8888", "8888"],
}

_API_HEADERS = {
    "User-Agent": "iot-research-pipeline/1.0 (academic measurement study)",
}


def _api_headers(api_key: str) -> dict[str, str]:
    return {"X-Api-Key": api_key, **_API_HEADERS}


def list_sonar_files(dataset: str, api_key: str) -> list[str]:
    """
    Use Rapid7 Open Data API to list all filenames for a dataset.
    Returns a list of filename strings sorted newest-first.
    Does NOT count against the 30/day download quota.
    """
    url = f"{RAPID7_API_BASE}/{dataset}/"
    resp = requests.get(url, headers=_api_headers(api_key), timeout=30)
    if resp.status_code == 401:
        raise PermissionError("Invalid RAPID7_API_KEY — check your key at insight.rapid7.com")
    if resp.status_code == 403:
        raise PermissionError(
            "Access denied. Accept the Terms of Service at "
            "https://opendata.rapid7.com before using the API."
        )
    resp.raise_for_status()
    data = resp.json()
    filenames = data.get("sonarfile_set", [])
    return sorted(filenames, reverse=True)   # newest first


def find_latest_filename(filenames: list[str], port: int) -> str | None:
    """Find the most recent filename for a port from the full file list."""
    aliases = PORT_FILENAME_ALIASES.get(port, [str(port)])
    for name in filenames:  # already sorted newest-first
        name_lower = name.lower()
        if any(a in name_lower for a in aliases):
            return name
    return None


def get_signed_download_url(dataset: str, filename: str, api_key: str) -> str:
    """
    Request a signed time-limited download URL from the Rapid7 API.
    Costs 1 unit of your 30/day download quota.
    """
    url = f"{RAPID7_API_BASE}/{dataset}/{filename}/download/"
    resp = requests.get(url, headers=_api_headers(api_key), timeout=30)
    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After", "unknown")
        raise RuntimeError(
            f"Rapid7 daily quota (30 downloads/24h) exceeded. "
            f"Retry after {retry_after}s. Consider running with fewer ports."
        )
    resp.raise_for_status()
    signed = resp.json().get("url")
    if not signed:
        raise RuntimeError(f"API returned no download URL for {filename}: {resp.text}")
    return signed


# ─── Streaming filter ─────────────────────────────────────────────────────────

def _decode_banner(record: dict) -> str:
    """Extract and decode banner text from a Sonar record. Returns lowercase string."""
    import base64
    for field in BANNER_FIELDS:
        val = record.get(field)
        if not val:
            continue
        if isinstance(val, bytes):
            try:
                return val.decode("utf-8", errors="replace").lower()
            except Exception:
                return ""
        if isinstance(val, str):
            # Try base64 decode first (Sonar encodes binary banners in base64)
            try:
                decoded = base64.b64decode(val).decode("utf-8", errors="replace")
                return decoded.lower()
            except Exception:
                return val.lower()
    return ""
def _is_iot_relevant(record: dict, port: int) -> bool:
    """Return True if this record should be kept."""
    keep_all, keywords = TARGET_PORTS[port]
    if keep_all:
        return True
    banner = _decode_banner(record)
    if not banner:
        return False  # no banner → can't confirm IoT
    return any(kw in banner for kw in keywords)


def _enrich_record(record: dict, port: int, fetch_date: str) -> dict:
    """Add research-friendly fields to a raw Sonar record."""
    banner = _decode_banner(record)
    return {
        "source":       "sonar",
        "port":         port,
        "ip":           record.get("ip", ""),
        "protocol":     record.get("proto", "tcp"),
        "banner":       banner[:512] if banner else None,   # truncate at 512 chars
        "device_type":  infer_device_type(banner, port),
        "country":      record.get("location", {}).get("country_code") if isinstance(record.get("location"), dict) else None,
        "asn":          record.get("asn", None),
        "sonar_ts":     record.get("timestamp", None),
        "fetch_date":   fetch_date,
        "raw_fields": {                                      # keep original identifiers
            k: record[k] for k in ("ip", "port", "proto", "timestamp")
            if k in record
        },
    }


def stream_filter_port(
    url: str,
    port: int,
    out_fh,
    max_bytes: int,
    current_bytes: list[int],  # mutable counter
) -> tuple[int, int]:
    """
    Stream a gzip file from `url`, filter for IoT relevance, write to `out_fh`.

    Handles both current CSV format and legacy JSON Lines format automatically.
    Returns (lines_processed, lines_kept).
    Stops early if current_bytes[0] >= max_bytes.
    """
    fetch_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    processed = 0
    kept = 0

    print(f"  Streaming port {port} from Rapid7 Sonar...")
    print(f"  URL: {url}")

    with requests.get(url, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        with gzip.GzipFile(fileobj=resp.raw) as gz:
            # Auto-detect format: peek at first line to decide CSV vs JSON Lines
            first_line_raw = gz.readline()
            first_line = first_line_raw.decode("utf-8", errors="replace").strip()

            if first_line.startswith("{"):
                # Legacy JSON Lines format
                def _iter_records(gz_handle, first_raw):
                    yield first_raw
                    yield from gz_handle

                def _parse(raw_line):
                    return json.loads(raw_line)

                records_iter = _iter_records(gz, first_line_raw)
                parse_fn = _parse

            else:
                # Current CSV format — first_line is the header row
                header = first_line.split(",")

                def _iter_csv_records(gz_handle, hdr):
                    text_stream = io.TextIOWrapper(gz_handle, encoding="utf-8", errors="replace")
                    reader = csv.DictReader(text_stream, fieldnames=hdr)
                    yield from reader

                records_iter = _iter_csv_records(gz, header)
                parse_fn = lambda x: x  # already a dict from DictReader

            for raw in records_iter:
                if current_bytes[0] >= max_bytes:
                    print(f"  [STOP] Output size limit reached ({max_bytes / 1e9:.1f} GB). Stopping.")
                    break

                processed += 1
                if processed % PRINT_EVERY == 0:
                    kept_pct = 100 * kept / processed if processed else 0
                    out_mb = current_bytes[0] / 1e6
                    print(f"    port={port} processed={processed:,} kept={kept:,} ({kept_pct:.1f}%) out={out_mb:.1f}MB")

                try:
                    record = parse_fn(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

                if not _is_iot_relevant(record, port):
                    continue

                enriched = _enrich_record(record, port, fetch_date)
                line_bytes = (json.dumps(enriched) + "\n").encode("utf-8")
                out_fh.write(line_bytes)
                current_bytes[0] += len(line_bytes)
                kept += 1

    return processed, kept


# ─── Index file (tracks what was fetched to avoid re-downloads) ───────────────

def load_index(index_path: Path) -> dict:
    if index_path.exists():
        with open(index_path) as f:
            return json.load(f)
    return {}


def save_index(index_path: Path, index: dict) -> None:
    with open(index_path, "w") as f:
        json.dump(index, f, indent=2)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Download and filter Rapid7 Sonar data for IoT research (≤2GB output).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--list",     action="store_true", help="List available Sonar files and exit")
    parser.add_argument("--dry-run",  action="store_true", help="Show what would be downloaded, no actual fetch")
    parser.add_argument("--port",     type=int, default=None, help="Fetch a single port only")
    parser.add_argument("--max-gb",   type=float, default=float(os.environ.get("SONAR_MAX_GB", DEFAULT_MAX_GB)),
                        help=f"Stop writing when output exceeds this many GB (default: {DEFAULT_MAX_GB})")
    parser.add_argument("--out-dir",  type=str,
                        default=os.environ.get("SONAR_OUT_DIR",
                                               str(Path.home() / "data" / "raw-logs" / "sonar")),
                        help="Output directory (default: ~/data/raw-logs/sonar)")
    parser.add_argument("--force",    action="store_true",
                        help="Re-fetch ports already recorded in the index")
    args = parser.parse_args()

    # Override from env
    if os.environ.get("SONAR_DRY_RUN") == "1":
        args.dry_run = True

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    index_path = out_dir / "sonar_fetch_index.json"
    index = load_index(index_path)

    print("=" * 60)
    print("  Rapid7 Project Sonar — IoT filter")
    print(f"  Output dir:  {out_dir}")
    print(f"  Max output:  {args.max_gb:.1f} GB")
    print(f"  Dry run:     {args.dry_run}")
    api_key = os.environ.get("RAPID7_API_KEY", "").strip()
    if not api_key:
        print("\n[ERROR] RAPID7_API_KEY is not set.")
        print("  1. Register a free account at https://insight.rapid7.com")
        print("  2. Go to: https://insight.rapid7.com/platform#/apiKeyManagement")
        print("  3. Create a User Key and add to .env:  RAPID7_API_KEY=<your-key>")
        sys.exit(1)
    print(f"  API key:     set ({api_key[:8]}...)")
    print("=" * 60)

    dataset = "sonar.tcp"

    # ── Step 1: List available files via Rapid7 API ──────────────────
    print(f"\n[1/3] Fetching file list from Rapid7 Open Data API ({dataset})...")
    try:
        filenames = list_sonar_files(dataset, api_key)
    except PermissionError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
    except requests.RequestException as e:
        print(f"[ERROR] Could not reach Rapid7 API: {e}")
        sys.exit(1)

    print(f"  Found {len(filenames)} file(s).")

    if args.list:
        print(f"\nAvailable files in {dataset} (newest first):")
        for name in filenames[:50]:  # cap at 50 lines
            print(f"  {name}")
        if len(filenames) > 50:
            print(f"  ... and {len(filenames) - 50} more")
        return

    # ── Step 2: Resolve target ports → filenames + signed URLs ───────
    ports_to_fetch = [args.port] if args.port else sorted(TARGET_PORTS.keys())
    print(f"\n[2/3] Resolving files + signed download URLs for {len(ports_to_fetch)} port(s):")

    port_urls: list[tuple[int, str]] = []   # (port, signed_url)

    for port in ports_to_fetch:
        filename = find_latest_filename(filenames, port)
        if not filename:
            print(f"  port {port:5d}: NOT FOUND in dataset (no matching filename)")
            continue

        keep_all, keywords = TARGET_PORTS[port]
        filter_desc = "keep ALL" if keep_all else f"filter ({len(keywords)} keywords)"

        if args.dry_run:
            print(f"  port {port:5d}: {filename}  → {filter_desc}")
            port_urls.append((port, f"[signed-url-for:{filename}]"))
            continue

        try:
            signed_url = get_signed_download_url(dataset, filename, api_key)
        except RuntimeError as e:
            print(f"  port {port:5d}: [QUOTA ERROR] {e}")
            break

        print(f"  port {port:5d}: {filename}  → {filter_desc}")
        port_urls.append((port, signed_url))

    if not port_urls:
        print("\n[ERROR] No files resolved. Nothing to download.")
        sys.exit(1)

    if args.dry_run:
        print(f"\n  [DRY-RUN] {len(port_urls)} port(s) resolved (no files downloaded).")
        print(f"  [DRY-RUN] Quota used: 0 (signed URLs not requested in dry-run)")
        print(f"  [DRY-RUN] Re-run without --dry-run to start downloading.")
        return

    # ── Step 3: Stream + filter each port ─────────────────────────
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_file = out_dir / f"sonar_iot_{today}.jsonl.gz"
    max_bytes = int(args.max_gb * 1e9)
    current_bytes = [0]  # mutable so stream_filter_port can update it

    print(f"\n[3/3] Streaming and filtering into: {out_file}")

    total_processed = 0
    total_kept = 0
    skipped_ports = []

    with gzip.open(out_file, "wb") as out_fh:
        for port, url in port_urls:
            port_key = f"port_{port}_{today}"

            if not args.force and port_key in index:
                print(f"  port {port}: already fetched on {index[port_key]['fetched_at']} "
                      f"(kept {index[port_key]['kept']:,}) — skipping (use --force to re-fetch)")
                skipped_ports.append(port)
                continue

            if current_bytes[0] >= max_bytes:
                print(f"  [STOP] Size limit reached before port {port}. Remaining ports skipped.")
                break

            t0 = time.monotonic()
            processed, kept = stream_filter_port(url, port, out_fh, max_bytes, current_bytes)
            elapsed = time.monotonic() - t0

            total_processed += processed
            total_kept += kept

            index[port_key] = {
                "port":        port,
                "url":         url,
                "fetched_at":  datetime.now(timezone.utc).isoformat(),
                "processed":   processed,
                "kept":        kept,
                "elapsed_s":   round(elapsed, 1),
            }
            save_index(index_path, index)

            kept_pct = 100 * kept / processed if processed else 0
            print(f"  ✓ port {port}: {processed:,} scanned → {kept:,} kept ({kept_pct:.1f}%) "
                  f"in {elapsed:.0f}s  [output so far: {current_bytes[0]/1e6:.1f} MB]")

    out_size_mb = out_file.stat().st_size / 1e6 if out_file.exists() else 0

    print("\n" + "=" * 60)
    print("  DONE")
    print(f"  Total lines processed: {total_processed:,}")
    print(f"  Total lines kept:      {total_kept:,}")
    print(f"  Output file:           {out_file}")
    print(f"  Output size:           {out_size_mb:.1f} MB (compressed)")
    if skipped_ports:
        print(f"  Skipped (cached):      ports {skipped_ports}")
    print(f"  Index file:            {index_path}")
    print("=" * 60)
    print()
    print("NEXT STEPS:")
    print("  1. Ingest into DB:  python3 -m pipeline.run --tasks ingest_sonar   (to be built)")
    print("  2. Preview output:  zcat", out_file, "| head -5 | python3 -m json.tool")
    print("  3. Count records:   zcat", out_file, "| wc -l")
    print("  4. Re-run weekly:   add 'make fetch-sonar' to your Sunday cron job")


if __name__ == "__main__":
    main()
