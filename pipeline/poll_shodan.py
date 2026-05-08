"""pipeline/poll_shodan.py — Weekly Shodan snapshot collection.

Design (from shodan_instruction.md):
  - Fixed query set Q = 40 queries across categories A, B, C, E, F, H, I, L.
    Never changes between weeks so snapshots are longitudinally comparable.
  - Deduplication key: (source='shodan', ip, port, snapshot_week).
    Same IP+port appearing in multiple queries → single row, query_ids[] merged.
  - snapshot_week = Monday of the current ISO week (e.g. 2026-04-13).
  - Per-query audit row written to shodan_query_runs for full reproducibility.

Query budget (4 × Shodan Educational Member = 400 credits/month total):
  40 queries/week × 1 credit/query (100 results = 1 page) × 4 weeks
      = 160 credits/month total across 4 accounts
      = 40 credits/account/month  ← well under 100 limit  ✅

  Shodan charges 1 credit per 100-result page.
  Start with SHODAN_MAX_PER_QUERY=100 (default, 1 page = 1 credit).
  After the first pull, raise it per-query for any that consistently
  return exactly 100 results (i.e. are likely truncated).

  Categories kept and rationale (WHOLE_RESEARCH.md contributions):
    A (5)  — IoT port baseline — RQ1 scale; SSH re-added for dropbear exposure
    B (7)  — Router fingerprints — RQ1+RQ2; MikroTik + Huawei added
    C (4)  — Camera class — RQ1 device-type distribution; Hikvision + port:554 added
    E (9)  — Proxy/monetization — RQ3 CORE; tinyproxy + 3proxy added
    F (5)  — IoT infection signals — RQ1+RQ4; Gafgyt/BASHLITE added
    H (2)  — SMTP spam relay — RQ3 monetization (open relay signal)
    I (4)  — Geographic bias control — Section 6+11 reproducibility
    L (4)  — Combo cluster seeds — RQ4 campaign clustering

Environment variables:
  SHODAN_API_KEY              required
  SHODAN_MAX_PER_QUERY        max records to fetch per query  (default: 100, 1 credit)
  SHODAN_SLEEP_BETWEEN_QUERIES  seconds between queries       (default: 1.0)
  SHODAN_DRY_RUN              if "1", print queries but do not hit API
"""
from __future__ import annotations

import os
import time
from datetime import date, timedelta
from typing import Any

from dotenv import load_dotenv

load_dotenv()

from .core import get_pipeline_version, logger, task

# ---------------------------------------------------------------------------
# Snapshot week helper
# ---------------------------------------------------------------------------

def _monday_of_week(d: date | None = None) -> date:
    """Return the Monday of the given date's ISO week (default: today)."""
    d = d or date.today()
    return d - timedelta(days=d.weekday())


# ---------------------------------------------------------------------------
# Device-type inference heuristic
# ---------------------------------------------------------------------------

_CAMERA_SIGNALS = {
    "camera", "dvr", "nvr", "ipcam", "ip cam", "netcam", "webcam",
    "surveillance", "cctv", "hikvision", "dahua", "axis", "foscam",
    "vivotek", "tvt", "rtsp", "amcrest", "reolink", "uniview", "hanwha",
    "geovision", "pelco", "dlink camera", "d-link dcs",
}
_ROUTER_SIGNALS = {
    "router", "gateway", "goahead-webs", "goahead", "boa", "uhttpd",
    "mini_httpd", "rompager", "tr-069", "cwmp", "dsl-2", "mikrotik",
    "dd-wrt", "openwrt", "tp-link", "linksys", "netgear", "zyxel",
    "draytek", "huawei home", "asus router", "routerlogin", "dsl router",
    "adsl", "vdsl", "broadband router", "home gateway", "totolink",
    "tenda", "d-link router", "belkin", "motorola router",
}
# RQ3 (monetization): proxy as first-class device type.
# Signals map to Section 5.8 proxy indicators (ports 1080/3128/8080,
# banners, proxy protocol hints) and Contribution 3 measurements.
_PROXY_SIGNALS = {
    "squid", "tinyproxy", "privoxy", "3proxy", "ccproxy", "polipo",
    "iplanet-web-proxy", "sun-java-system-web-proxy", "ebay-proxy-server",
    "cdn cache server", "zscaler", "bluecoat", "forcepoint",
    "http connect", "http-connect", "socks5", "socks4",
    "http proxy", "proxy server", "open proxy",
}
_PROXY_PROTOCOLS = {"socks5-proxy", "socks4-proxy", "http-connect"}
_PROXY_PORTS     = {1080, 3128}   # 8080 shared with routers — checked last
_IOT_SIGNALS = {
    "busybox", "dropbear", "mirai", "iot", "embedded", "mips", "arm",
    "/bin/busybox", "uclibc", "mqtt", "mosquitto", "zigbee", "zwave",
    "openwrt", "lede", "padavan", "telnet",
}
_IOT_PROTOCOLS  = {"mqtt", "coap"}
_SERVER_SIGNALS = {
    "nginx", "apache", "iis", "litespeed", "caddy", "jetty",
    "tomcat", "flask", "gunicorn", "smtp", "postfix", "exim", "sendmail",
    "dovecot", "courier", "cyrus", "microsoft-iis", "openssl",
    "openssh", "samba", "smb", "mssql", "mysql", "postgresql", "redis",
    "mongodb", "elasticsearch", "memcached", "influxdb", "prometheus",
    "kubernetes", "docker",
}


def infer_device_type(
    product: str | None,
    http_server: str | None,
    http_title: str | None,
    banner: str | None,
    port: int | None,
    tags: list[str] | None,
) -> str:
    """Return camera | router | proxy | iot | server | unknown.

    Priority order is intentional:
      1. camera  — clearest IoT sub-type (RQ1 device distribution)
      2. router  — clearest IoT sub-type (RQ1)
      3. proxy   — RQ3 monetization signal; checked before generic server
      4. iot     — general embedded/infected device (RQ1)
      5. server  — conventional infrastructure
      6. unknown — no signal matched; still tracked for ablation (RQ1 Section 5.4)
    """
    combined = " ".join(
        filter(None, [product, http_server, http_title, banner, " ".join(tags or [])])
    ).lower()
    proto_lc = (product or "").lower()

    if any(k in combined for k in _CAMERA_SIGNALS) or port == 554:
        return "camera"
    if any(k in combined for k in _ROUTER_SIGNALS) or port == 7547:
        return "router"
    # proxy: banner/server match OR protocol is a proxy protocol
    # OR port is a canonical proxy port AND there is any http/socks banner
    if (
        any(k in combined for k in _PROXY_SIGNALS)
        or proto_lc in _PROXY_PROTOCOLS
        or (port in _PROXY_PORTS and combined)
    ):
        return "proxy"
    if any(k in combined for k in _IOT_SIGNALS) or proto_lc in _IOT_PROTOCOLS:
        return "iot"
    if any(k in combined for k in _SERVER_SIGNALS):
        return "server"
    return "unknown"


# ---------------------------------------------------------------------------
# Query catalogue  (categories A–L from shodan_instruction.md)
# Each entry: (query_id, category, query_string)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Query budget: Shodan Educational Member = 100 credits/month.
# 25 queries/week × 4 weeks = 100 credits/month (exactly at limit).
#
# Categories retained and rationale
# (mapped to paper contributions in WHOLE_RESEARCH.md):
#
#  A (3)  — Core IoT port baseline.  Only telnet ports + admin panel kept;
#            port:22/80/443 cut — they are dominated by servers, not IoT.
#  B (5)  — Router fingerprints (VERY IMPORTANT, Contribution 1 + 2).
#            boa + mini_httpd cut — functionally overlap with uhttpd.
#  C (2)  — Camera class for device-type distribution figure (Contribution 1).
#            port:554+RTSP already captured via L combo; webcam/netcam cut.
#  E (7)  — Proxy / monetization signals.  ALL kept — directly addresses
#            Contribution 3 (monetization measurement, paper's core claim).
#  F (4)  — IoT infection fingerprints for Contribution 1 + 4 (lifecycle).
#            wget_http / curl_http cut — not Shodan-visible banners.
#  L (4)  — Pre-filtered combo queries as graph-cluster seeds (Contribution 2).
# ---------------------------------------------------------------------------
# Query budget: 4 × edu member = 400 credits/month total.
# Default: SHODAN_MAX_PER_QUERY=100 → 1 page → 1 credit per query.
# 40 queries × 1 credit × 4 weeks = 160 total = 40 credits/account/month  ✅
# After first pull: raise SHODAN_MAX_PER_QUERY for queries that hit the 100-result
# ceiling (meaning results were truncated). Bump to 200 → 2 credits each.
#
# Query categories → paper section mapping:
#
#  A (5)  — Core IoT port baseline (RQ1, Section 6, Table 1)
#  B (7)  — Router/embedded fingerprints (RQ1+RQ2, Section 5.4+5.6)
#  C (4)  — Camera/surveillance devices (RQ1, Fig.3 device-type distribution)
#  E (9)  — Proxy/monetization signals (RQ3, Section 5.8, Fig.7) — CORE
#  F (5)  — Botnet/IoT infection fingerprints (RQ1+RQ4, Section 7+9)
#  H (2)  — SMTP open relay — spam monetization channel (Section 5.8)
#  I (4)  — Geographic sampling for bias control (Section 6, Section 11)
#  L (4)  — High-risk combo queries — campaign cluster seeds (RQ4, Section 5.7)
# ---------------------------------------------------------------------------
SHODAN_QUERIES: list[tuple[str, str, str]] = [
    # ── A: Core IoT port exposure (5) ────────────────────────────────────
    ("port_23",         "A", "port:23"),        # Telnet — #1 IoT attack vector
    ("port_2323",       "A", "port:2323"),      # Alt-Telnet — Mirai/Satori probe
    ("port_22",         "A", "port:22"),        # SSH — dropbear-exposed IoT devices
    ("port_8080",       "A", "port:8080"),      # HTTP admin panels
    ("port_81",         "A", "port:81"),        # Alt HTTP — router admin fallback

    # ── B: Router / embedded device fingerprints (7) ──────────────────────
    ("port_7547",       "B", "port:7547"),      # TR-069/CWMP — massively exploited
    ("tr069",           "B", '"TR-069"'),       # TR-069 banner fingerprint
    ("goahead_webs",    "B", '"GoAhead-Webs"'), # GoAhead web server (router class)
    ("uhttpd",          "B", '"uhttpd"'),       # OpenWrt/LEDE embedded HTTP server
    ("rompager",        "B", '"rompager"'),     # Misfortune Cookie vuln webserver
    ("mikrotik",        "B", '"MikroTik"'),     # MikroTik routers (frequently targeted)
    ("huawei_7547",     "B", 'port:7547 "Huawei"'), # Huawei TR-069 (Mirai variant target)

    # ── C: IP camera / surveillance devices (4) ───────────────────────────
    ("ip_camera",       "C", '"IP Camera"'),    # Self-identifying camera banner
    ("dvr",             "C", '"DVR"'),          # Digital Video Recorder banner
    ("port_554",        "C", "port:554"),       # RTSP stream port (standalone)
    ("hikvision",       "C", '"Hikvision"'),    # #1 global IP camera brand

    # ── E: Proxy / monetization infrastructure — RQ3 CORE (9) ────────────
    ("port_1080",       "E", "port:1080"),           # SOCKS proxy — direct monetisation
    ("port_3128",       "E", "port:3128"),           # Squid/HTTP proxy canonical port
    ("port_8080_proxy", "E", 'port:8080 "proxy"'),   # HTTP proxy on alt port
    ("socks5",          "E", '"SOCKS5"'),            # SOCKS5 protocol banner
    ("socks",           "E", '"socks"'),             # Generic SOCKS identifier
    ("proxy_server",    "E", '"proxy server"'),      # Self-identifying proxy banner
    ("squid",           "E", '"Squid"'),             # Squid HTTP proxy banner
    ("tinyproxy",       "E", '"tinyproxy"'),         # TinyProxy — common on IoT Linux
    ("three_proxy",     "E", '"3proxy"'),            # 3proxy — popular on compromised routers

    # ── F: Botnet / IoT infection signals (5) ─────────────────────────────
    ("busybox",         "F", '"busybox"'),           # BusyBox — IoT Linux baseline
    ("bin_busybox",     "F", '"/bin/busybox"'),      # Mirai dropper echo pattern
    ("mirai",           "F", '"mirai"'),             # Mirai string in banner
    ("dropbear",        "F", '"dropbear"'),          # Dropbear SSH — embedded Linux
    ("gafgyt",          "F", '"gafgyt"'),            # Gafgyt/BASHLITE botnet banner

    # ── H: SMTP / spam relay signals — RQ3 spam monetization (2) ─────────
    ("open_relay",      "H", '"Open Relay"'),        # SMTP self-identifying open relay
    ("smtp_port25",     "H", 'port:25 "SMTP"'),      # SMTP on port 25 (IoT-filtered later)

    # ── I: Geographic sampling — bias control (4) ─────────────────────────
    ("bd_telnet",       "I", "country:BD port:23"),  # Bangladesh — high IoT density
    ("in_telnet",       "I", "country:IN port:23"),  # India — major infection region
    ("cn_telnet",       "I", "country:CN port:23"),  # China — largest device pool
    ("tr_telnet",       "I", "country:TR port:23"),  # Turkey — high router compromise rate

    # ── L: High-risk combo queries — campaign-cluster seeds (4) ───────────
    ("port23_busybox",  "L", 'port:23 "busybox"'),   # Telnet+BusyBox (Mirai signature)
    ("port7547_tr069",  "L", 'port:7547 "TR-069"'),  # TR-069 router exploit surface
    ("port554_rtsp",    "L", 'port:554 "RTSP"'),     # RTSP camera stream exposed
    ("port80_goahead",  "L", 'port:80 "GoAhead"'),   # GoAhead router web UI
]
# Total: A(5) + B(7) + C(4) + E(9) + F(5) + H(2) + I(4) + L(4) = 40 queries
# Budget: 40 queries × 1 credit (100 results, 1 page) × 4 weeks = 160/month across 4 accounts
#         = 40 credits/account/month  ✅  (limit: 100/account)
# To increase data per query: set SHODAN_MAX_PER_QUERY=200 for queries that hit the cap.


# ---------------------------------------------------------------------------
# Normalisation: Shodan host dict → device_record dict
# ---------------------------------------------------------------------------

def _normalise_shodan_host(
    host: dict[str, Any],
    snapshot_week: date,
    snapshot_date: date,
    query_id: str,
    query_category: str,
    run_id: str,
) -> list[dict[str, Any]]:
    """
    Expand one Shodan host object into one device_record per (ip, port).
    A single host may advertise multiple ports; we create a row per port.
    """
    ip = host.get("ip_str") or host.get("ip")
    if not ip:
        return []

    # Top-level geo / ASN (shared across all ports on this host)
    country_code = host.get("location", {}).get("country_code") or host.get("country_code")
    asn_raw      = host.get("asn", "")         # e.g. "AS12345"
    asn_int: int | None = None
    if asn_raw and asn_raw.upper().startswith("AS"):
        try:
            asn_int = int(asn_raw[2:])
        except ValueError:
            pass
    org       = host.get("org")
    isp       = host.get("isp")
    hostnames = host.get("hostnames") or []
    domains   = host.get("domains") or []
    tags      = host.get("tags") or []

    # SSL certificate (top-level)
    ssl_cert: dict = {}
    if "ssl" in host:
        cert_data = host["ssl"].get("cert", {})
        ssl_cert = {
            "subject": cert_data.get("subject", {}),
            "issuer":  cert_data.get("issuer", {}),
            "expires": cert_data.get("expires"),
            "issued":  cert_data.get("issued"),
        }

    # Vulnerability map (CVE details)
    vulns_raw = host.get("vulns", {})
    vulns: dict = {}
    cve_ids: list[str] = []
    if isinstance(vulns_raw, dict):
        vulns = vulns_raw
        cve_ids = list(vulns_raw.keys())
    elif isinstance(vulns_raw, list):
        cve_ids = vulns_raw
        vulns = {c: {} for c in vulns_raw}

    # Transport data (list of port services).
    # search_cursor returns each match as a flat host dict where host["data"]
    # is the raw banner STRING.  Only api.host() bulk results use a list of
    # per-port service dicts.  Guard against iterating over banner characters.
    _data_raw = host.get("data")
    if isinstance(_data_raw, list) and _data_raw:
        data_items: list[dict] = _data_raw
    else:
        # banner string or missing — treat this host dict as the single service
        data_items = [host]

    records: list[dict[str, Any]] = []
    seen_ports: set[tuple] = set()

    for svc in data_items:
        port      = svc.get("port") or host.get("port")
        transport = svc.get("transport", "tcp")

        # Skip duplicates within the same host object
        if (ip, port) in seen_ports:
            continue
        seen_ports.add((ip, port))

        product    = svc.get("product")
        version    = svc.get("version")
        banner     = svc.get("data") or svc.get("banner")
        protocol   = svc.get("_shodan", {}).get("module")  # e.g. "http", "ssh"

        # CPE list
        cpe_raw = svc.get("cpe") or svc.get("cpe23") or []
        if isinstance(cpe_raw, str):
            cpe_raw = [cpe_raw]

        # HTTP sub-object
        http_obj     = svc.get("http", {}) or {}
        http_title   = http_obj.get("title") or http_obj.get("html_title") or svc.get("title")
        http_server  = (
            http_obj.get("server")
            or (http_obj.get("headers") or {}).get("server")
        )
        http_headers = {
            k: v for k, v in (http_obj.get("headers") or {}).items()
        } if http_obj.get("headers") else {}

        device_type = infer_device_type(
            product, http_server, http_title, banner, port, tags
        )

        records.append({
            "source":          "shodan",
            "snapshot_week":   snapshot_week,
            "snapshot_date":   snapshot_date,
            "ip":              ip,
            "port":            port,
            "transport":       transport,
            "protocol":        protocol,
            "product":         product,
            "version":         version,
            "cpe":             cpe_raw,
            "cve_ids":         cve_ids,
            "country_code":    country_code,
            "asn":             asn_int,
            "org":             org,
            "isp":             isp,
            "device_type":     device_type,
            "hostnames":       hostnames,
            "domains":         domains,
            "tags":            tags,
            "http_title":      http_title,
            "http_server":     http_server,
            "http_headers":    http_headers,
            "ssl_cert":        ssl_cert,
            "vulns":           vulns,
            "query_ids":       [query_id],
            "query_category":  query_category,
            "raw_banner":      banner[:4096] if banner else None,  # cap at 4 KB
            "raw_data":        {
                "ip": ip, "port": port,
                "product": product, "version": version,
                "org": org, "isp": isp,
                "asn": asn_raw, "country_code": country_code,
                "tags": tags, "hostnames": hostnames,
                "query_id": query_id,
            },
        })

    return records


# ---------------------------------------------------------------------------
# Main task
# ---------------------------------------------------------------------------

@task("poll_shodan")
def poll_shodan(
    queries: list[tuple[str, str, str]] | None = None,
    snapshot_week: date | None = None,
    run_id: str | None = None,
) -> int:
    """
    Run all Shodan queries for the current week and store to device_records.

    Args:
        queries:       Override query list (default: SHODAN_QUERIES).
        snapshot_week: Override the snapshot week date (default: Monday of today).
        run_id:        Pre-allocated pipeline_runs UUID (created if None).

    Returns:
        Total device records stored.
    """
    api_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not api_key:
        logger.error("poll_shodan: SHODAN_API_KEY is not set — skipping")
        return 0

    dry_run = os.environ.get("SHODAN_DRY_RUN", "0") == "1"

    max_per_query = int(os.environ.get("SHODAN_MAX_PER_QUERY", "100"))  # 1 page per query = 1 credit
    sleep_between = float(os.environ.get("SHODAN_SLEEP_BETWEEN_QUERIES", "1.0"))

    queries        = queries or SHODAN_QUERIES

    # Allow back-filling a missed week: SNAPSHOT_WEEK=YYYY-MM-DD overrides today's Monday.
    # The value is normalised to the Monday of whatever date is supplied so the
    # dedup key (source, ip, port, snapshot_week) always aligns to a week boundary.
    _week_override = os.environ.get("SNAPSHOT_WEEK", "").strip()
    if snapshot_week is None:
        if _week_override:
            try:
                _override_date = date.fromisoformat(_week_override)
                snapshot_week  = _monday_of_week(_override_date)
                logger.info(
                    f"poll_shodan: SNAPSHOT_WEEK override → {snapshot_week}"
                    f" (supplied: {_week_override})"
                )
            except ValueError:
                logger.warning(
                    f"poll_shodan: SNAPSHOT_WEEK={_week_override!r} is not a valid"
                    f" YYYY-MM-DD date — using current week"
                )
                snapshot_week = _monday_of_week()
        else:
            snapshot_week = _monday_of_week()

    snapshot_date  = date.today()
    git_hash       = get_pipeline_version()

    from . import db as _db
    import shodan as _shodan

    # ── Resume / start-from logic ─────────────────────────────────────────────
    # SHODAN_RESUME=1         → skip queries already done (no error) this week.
    #                           Reads shodan_query_runs; safe to re-run at any time.
    # SHODAN_START_FROM=<X>   → skip all queries before category letter X or
    #                           exact query_id X.  E.g. SHODAN_START_FROM=F
    resume     = os.environ.get("SHODAN_RESUME", "0") == "1"
    start_from = os.environ.get("SHODAN_START_FROM", "").strip()

    if resume:
        done = _db.get_completed_query_ids("shodan", str(snapshot_week))
        if done:
            before  = len(queries)
            queries = [(qid, cat, qs) for qid, cat, qs in queries if qid not in done]
            logger.info(
                f"poll_shodan RESUME: {before - len(queries)} queries already done this week,"
                f" {len(queries)} remaining"
            )
        else:
            logger.info("poll_shodan RESUME: no completed queries found — running all")

    if start_from:
        idx = next(
            (i for i, (qid, cat, _) in enumerate(queries)
             if cat == start_from or qid == start_from),
            None,
        )
        if idx is None:
            logger.warning(
                f"poll_shodan: SHODAN_START_FROM={start_from!r} did not match any"
                f" category or query_id — running all {len(queries)} queries"
            )
        else:
            logger.info(
                f"poll_shodan: START_FROM={start_from!r} — skipping {idx} queries,"
                f" starting at [{queries[idx][1]}] {queries[idx][0]!r}"
            )
            queries = queries[idx:]

    if run_id is None:
        run_id = _db.record_run_start(
            "poll_shodan",
            {
                "snapshot_week":  str(snapshot_week),
                "snapshot_date":  str(snapshot_date),
                "query_count":    len(queries),
                "max_per_query":  max_per_query,
                "pipeline_version": git_hash,
            },
        )

    if dry_run:
        logger.info(f"poll_shodan DRY RUN — {len(queries)} queries, snapshot_week={snapshot_week}")
        for qid, cat, qs in queries:
            logger.info(f"  [{cat}] {qid}: {qs}")
        _db.record_run_end(run_id, "success", records_in=0, records_out=0)
        return 0

    api = _shodan.Shodan(api_key)
    total_stored   = 0
    total_fetched  = 0
    failed_queries = 0

    for query_id, category, query_str in queries:
        logger.info(f"poll_shodan [{category}] {query_id}: {query_str!r}")
        records_this_query: list[dict] = []
        results_total = 0
        error_msg: str | None = None

        try:
            fetched = 0
            for host in api.search_cursor(query_str, minify=False):
                if fetched >= max_per_query:
                    break
                host_records = _normalise_shodan_host(
                    host, snapshot_week, snapshot_date,
                    query_id, category, run_id,
                )
                records_this_query.extend(host_records)
                fetched += 1

            results_total = fetched  # actual fetched count (total API hits may differ)
            logger.info(
                f"  → fetched={fetched} records_normalised={len(records_this_query)}"
            )

        except _shodan.APIError as exc:
            error_msg = str(exc)
            logger.warning(f"  Shodan API error for {query_id!r}: {exc}")
            failed_queries += 1

        except Exception as exc:
            error_msg = str(exc)
            logger.error(f"  Unexpected error for {query_id!r}: {exc}", exc_info=True)
            failed_queries += 1

        # Store what we have (even partial)
        if records_this_query:
            stored = _db.upsert_device_records(records_this_query)
            total_stored  += stored
            total_fetched += results_total

        # Audit row — always written (even on error)
        try:
            _db.record_query_run(
                run_id        = run_id,
                source        = "shodan",
                snapshot_week = str(snapshot_week),
                query_id      = query_id,
                query_category= category,
                query_string  = query_str,
                results_total = results_total,
                results_fetched = len(records_this_query),
                error         = error_msg,
            )
        except Exception as exc:
            logger.warning(f"  Could not write audit row for {query_id}: {exc}")

        # Respect rate limit
        if sleep_between > 0:
            time.sleep(sleep_between)

    final_status = "success" if failed_queries == 0 else "partial"
    _db.record_run_end(
        run_id,
        final_status,
        records_in  = total_fetched,
        records_out = total_stored,
    )
    logger.info(
        f"poll_shodan complete — queries={len(queries)} "
        f"fetched={total_fetched} stored={total_stored} "
        f"failed_queries={failed_queries}"
    )
    return total_stored
