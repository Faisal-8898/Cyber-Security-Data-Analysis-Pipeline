"""pipeline/poll_censys.py — Weekly Censys enrichment of Shodan-collected IPs.

Overview
--------
Censys Free plan (100 credits/month) only supports *host-lookup* endpoints —
not bulk search.  The old Legacy Search API (search.censys.io/api/v2) required
a separate API ID + Secret pair that no longer exists for new PAT-based accounts.

Strategy (Free tier — enrich mode)
------------------------------------
1. Shodan runs first and populates device_records with IPs this week.
2. poll_censys picks up those IPs and enriches each via the Platform API v3:
     GET https://api.platform.censys.io/v3/global/asset/host/{ip}
3. Enriched fields (services detail, Censys labels, ASN) are merged back into
   existing device_records rows via the same UPSERT dedup key
   (source='shodan', ip, port, snapshot_week).

This gives cross-source validation: every Shodan device is independently
confirmed and enriched with Censys data — required for the paper's ablation
study (Shodan-only vs Shodan+Censys enrichment).

Authentication
--------------
  Authorization: Bearer <Personal-Access-Token>
  Set CENSYS_API_SECRET to the full "censys_..." token from https://censys.io/account

Credit budget (Free plan = 100 credits/month, matching Shodan budget discipline)
----------------------------------------------
  Each host lookup = 1 credit.
  Weekly run: CENSYS_MAX_ENRICH=25 → 25 credits/week = 100/month  ✅
  Strategy: prioritise high-value categories (E=proxy, L=combos, F=botnet)

Environment variables
---------------------
  CENSYS_API_SECRET               required — Personal Access Token (censys_...)
  CENSYS_MAX_ENRICH               max IPs to enrich per run   (default: 25 → 100/month budget)
  CENSYS_SLEEP_BETWEEN_LOOKUPS    seconds between API calls   (default: 1.0)
  CENSYS_DRY_RUN                  "1" → print IPs, skip API

Future: search mode (Starter plan)
------------------------------------
  CENSYS_QUERIES below is kept intact for when the account is upgraded.
  Starter plan unlocks bulk search at search.censys.io/api/v2 with
  API_ID + API_SECRET credentials.
"""
from __future__ import annotations

import os
import time
from datetime import date
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

from .core import get_pipeline_version, logger, task
from .poll_shodan import _monday_of_week, infer_device_type

# ---------------------------------------------------------------------------
# Censys Platform API v3 constants
# ---------------------------------------------------------------------------

_CENSYS_V3_BASE  = "https://api.platform.censys.io/v3/global"
_CENSYS_HOST_URL = f"{_CENSYS_V3_BASE}/asset/host/{{ip}}"
_DEFAULT_TIMEOUT = 20    # seconds per request


# ---------------------------------------------------------------------------
# Query catalogue (kept for future Starter-plan search mode)
# Each entry: (query_id, category, query_string)
# ---------------------------------------------------------------------------

CENSYS_QUERIES: list[tuple[str, str, str]] = [
    # -- A: Core IoT port exposure (6) ------------------------------------
    ("port_23",         "A", "services.port=23"),
    ("port_2323",       "A", "services.port=2323"),
    ("port_22",         "A", "services.port=22"),
    ("port_80",         "A", "services.port=80"),
    ("port_8080",       "A", "services.port=8080"),
    ("port_443",        "A", "services.port=443"),

    # -- B: Router / embedded device fingerprints (8) ---------------------
    ("port_7547",       "B", "services.port=7547"),
    ("goahead_webs",    "B", 'services.http.response.headers.server="GoAhead-Webs"'),
    ("boa",             "B", 'services.http.response.headers.server="Boa"'),
    ("mini_httpd",      "B", 'services.http.response.headers.server="mini_httpd"'),
    ("uhttpd",          "B", 'services.http.response.headers.server="uhttpd"'),
    ("rompager",        "B", 'services.http.response.headers.server="RomPager"'),
    ("mikrotik",        "B", 'services.http.response.headers.server="MikroTik"'),
    ("huawei_tr069",    "B", 'services.port=7547 and services.banner="Huawei"'),

    # -- C: IP camera / surveillance devices (8) --------------------------
    ("ip_camera",       "C", 'services.http.response.html_title="IP Camera"'),
    ("port_554",        "C", "services.port=554"),
    ("rtsp",            "C", 'services.service_name="RTSP"'),
    ("webcam",          "C", 'services.http.response.html_title="webcam"'),
    ("dvr",             "C", 'services.http.response.html_title="DVR"'),
    ("netcam",          "C", 'services.http.response.html_title="Netcam"'),
    ("hikvision",       "C", 'services.http.response.html_title="Hikvision"'),
    ("dahua",           "C", 'services.http.response.html_title="Dahua"'),

    # -- D: Default credential / weak auth (4) ----------------------------
    ("default_password","D", 'services.http.response.html_title="default password"'),
    ("login_failed",    "D", 'services.banner="login failed"'),
    ("auth_failed",     "D", 'services.banner="authentication failed"'),
    ("login_page",      "D", 'services.http.response.html_title="Login Page"'),

    # -- E: Proxy / monetization infrastructure -- RQ3 CORE (7) ----------
    ("port_1080",       "E", "services.port=1080"),
    ("port_3128",       "E", "services.port=3128"),
    ("socks5",          "E", 'services.banner="SOCKS5"'),
    ("proxy_server",    "E", 'services.banner="proxy server"'),
    ("squid",           "E", 'services.banner="Squid"'),
    ("tinyproxy",       "E", 'services.banner="tinyproxy"'),
    ("three_proxy",     "E", 'services.banner="3proxy"'),

    # -- F: Botnet / IoT infection signals (6) ----------------------------
    ("busybox",         "F", 'services.banner="busybox"'),
    ("wget_http",       "F", 'services.banner="wget http"'),
    ("bin_busybox",     "F", 'services.banner="/bin/busybox"'),
    ("dropbear",        "F", 'services.banner="Dropbear"'),
    ("mirai",           "F", 'services.banner="mirai"'),
    ("gafgyt",          "F", 'services.banner="gafgyt"'),

    # -- G: C2 / suspicious control patterns (3) --------------------------
    ("bin_sh",          "G", 'services.banner="/bin/sh"'),
    ("cmd_exe",         "G", 'services.banner="cmd.exe"'),
    ("powershell",      "G", 'services.banner="powershell"'),

    # -- H: SMTP / spam relay infrastructure (3) --------------------------
    ("port_25",         "H", "services.port=25"),
    ("open_relay",      "H", 'services.banner="Open Relay"'),
    ("postfix",         "H", 'services.banner="Postfix"'),

    # -- I: Geographic sampling -- bias control (5) -----------------------
    ("bd_telnet",       "I", 'services.port=23 and location.country_code="BD"'),
    ("in_telnet",       "I", 'services.port=23 and location.country_code="IN"'),
    ("us_telnet",       "I", 'services.port=23 and location.country_code="CU"'),
    ("cn_telnet",       "I", 'services.port=23 and location.country_code="CN"'),
    ("tr_telnet",       "I", 'services.port=23 and location.country_code="TR"'),

    # -- J: Vulnerability / label-based exposure (3) ----------------------
    ("iot_label",       "J", 'labels="iot"'),
    ("vulnerable_label","J", 'labels="vulnerable"'),
    ("openssh",         "J", 'services.banner="OpenSSH"'),

    # -- K: Industrial / IoT protocols (5) --------------------------------
    ("mqtt",            "K", "services.port=1883"),
    ("coap",            "K", "services.port=5683"),
    ("modbus",          "K", "services.port=502"),
    ("ethernet_ip",     "K", "services.port=44818"),
    ("adb",             "K", "services.port=5555"),

    # -- L: High-risk combo queries -- campaign cluster seeds (6) ---------
    ("port23_busybox",  "L", 'services.port=23 and services.banner="busybox"'),
    ("port80_goahead",  "L", 'services.port=80 and services.http.response.headers.server="GoAhead"'),
    ("port8080_admin",  "L", 'services.port=8080 and services.banner="admin"'),
    ("port7547_tr069",  "L", 'services.port=7547 and services.banner="TR-069"'),
    ("port554_rtsp",    "L", 'services.port=554 and services.service_name="RTSP"'),
    ("adb_android",     "L", 'services.port=5555 and services.banner="Android"'),
]
# Total: 64 queries — available for Starter plan (search mode)


# ---------------------------------------------------------------------------
# HTTP session  (Platform API v3 — Bearer token)
# ---------------------------------------------------------------------------

def _build_session(api_secret: str) -> requests.Session:
    """Return a requests.Session authenticated with the Censys PAT."""
    session = requests.Session()
    session.headers.update({
        "Accept":        "application/json",
        "Authorization": f"Bearer {api_secret}",
    })
    return session


# ---------------------------------------------------------------------------
# Normalise Censys v3 host-lookup response into device_record patch dicts
# ---------------------------------------------------------------------------

def _normalise_v3_host(
    host: dict[str, Any],
    snapshot_week: date,
    snapshot_date: date,
    run_id: str,
) -> list[dict[str, Any]]:
    """
    Convert one Censys v3 host response into per-port device_record dicts
    stored as source='censys', independent of the Shodan rows.
    """
    resource = (host.get("result") or {}).get("resource") or host
    ip = resource.get("ip")
    if not ip:
        return []

    loc      = resource.get("location") or {}
    asn_info = resource.get("autonomous_system") or {}
    country_code = loc.get("country_code")
    asn_int      = asn_info.get("asn")
    org          = asn_info.get("name") or asn_info.get("description")
    labels: list[str] = resource.get("labels") or []

    records: list[dict] = []
    for svc in (resource.get("services") or []):
        port      = svc.get("port")
        transport = (svc.get("transport_protocol") or "tcp").lower()
        protocol  = svc.get("protocol") or svc.get("service_name")
        banner    = svc.get("banner") or ""

        http      = svc.get("http") or {}
        resp      = (http.get("response") or http.get("result") or {})
        raw_hdrs  = resp.get("headers") or {}
        server_h  = raw_hdrs.get("server")
        http_server = (server_h[0] if isinstance(server_h, list) else server_h) or None
        http_title  = resp.get("html_title") or None

        tls  = svc.get("tls") or {}
        cert = ((tls.get("certificates") or [{}])[0]) if tls.get("certificates") else {}
        ssl_cert: dict = {}
        if cert:
            ssl_cert = {
                "subject": cert.get("subject_dn"),
                "issuer":  cert.get("issuer_dn"),
                "expires": (cert.get("validity") or {}).get("end"),
            }

        device_type = infer_device_type(
            product=protocol,
            http_server=http_server,
            http_title=http_title,
            banner=banner,
            port=port,
            tags=labels,
        )

        records.append({
            "source":         "censys",
            "snapshot_week":  snapshot_week,
            "snapshot_date":  snapshot_date,
            "ip":             ip,
            "port":           port,
            "transport":      transport,
            "protocol":       protocol,
            "country_code":   country_code,
            "asn":            asn_int,
            "org":            org,
            "tags":           labels,
            "device_type":    device_type,
            "http_title":     http_title,
            "http_server":    http_server,
            "ssl_cert":       ssl_cert,
            "query_ids":      ["censys_enrich"],
            "query_category": "censys",
            "raw_banner":     banner or None,
            "raw_data":       {"censys_v3": svc},
        })

    # No services found — still record that we checked
    if not records:
        records.append({
            "source":         "censys",
            "snapshot_week":  snapshot_week,
            "snapshot_date":  snapshot_date,
            "ip":             ip,
            "port":           None,
            "country_code":   country_code,
            "asn":            asn_int,
            "org":            org,
            "tags":           labels,
            "query_ids":      ["censys_enrich"],
            "query_category": "censys",
            "raw_data":       {"censys_v3_checked": True},
        })

    return records


# ---------------------------------------------------------------------------
# Helper: fetch IPs to enrich from device_records (Shodan rows this week)
# ---------------------------------------------------------------------------

def _get_shodan_ips_this_week(snapshot_week: date, limit: int) -> list[str]:
    """Return up to `limit` distinct Shodan IPs for this week,
    prioritising high-value categories (E=proxy, F=botnet, L=combos)."""
    from . import db as _db
    with _db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT ip FROM (
                  SELECT DISTINCT ip,
                    CASE
                      WHEN query_category = ANY(ARRAY['E','L','F']) THEN 0
                      WHEN query_category = ANY(ARRAY['B','C','H']) THEN 1
                      ELSE 2
                    END AS priority
                  FROM device_records
                  WHERE source = 'shodan'
                    AND snapshot_week = %s
                  ORDER BY priority, ip
                  LIMIT %s
                ) AS ranked
                """,
                (str(snapshot_week), limit),
            )
            return [row[0] for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Main task
# ---------------------------------------------------------------------------

@task("poll_censys")
def poll_censys(
    snapshot_week: date | None = None,
    run_id: str | None = None,
) -> int:
    """
    Enrich Shodan-collected IPs with Censys Platform API v3 host-lookup data.

    Reads the IPs already in device_records for this snapshot_week (from Shodan),
    calls the Censys v3 host-lookup endpoint for each, and merges richer
    service/label/ASN data back into the same rows.

    Free plan: 100 credits/month.  Default CENSYS_MAX_ENRICH=80.

    Returns total device record rows updated.
    """
    api_secret = os.environ.get("CENSYS_API_SECRET", "").strip()
    if not api_secret:
        logger.error("poll_censys: CENSYS_API_SECRET is not set — skipping")
        return 0

    dry_run    = os.environ.get("CENSYS_DRY_RUN", "0") == "1"
    max_enrich = int(os.environ.get("CENSYS_MAX_ENRICH", "40"))
    sleep_s    = float(os.environ.get("CENSYS_SLEEP_BETWEEN_LOOKUPS", "1.0"))

    snapshot_week = snapshot_week or _monday_of_week()
    snapshot_date = date.today()
    git_hash      = get_pipeline_version()

    from . import db as _db

    logger.info(
        f"poll_censys enrich | snapshot_week={snapshot_week}"
        f" | max_enrich={max_enrich}"
    )

    ips = _get_shodan_ips_this_week(snapshot_week, max_enrich)
    if not ips:
        logger.warning(
            "poll_censys: no Shodan IPs found for this week — "
            "run make poll-shodan first, then make poll-censys"
        )
        return 0

    logger.info(f"poll_censys: {len(ips)} IPs to enrich")

    if run_id is None:
        run_id = _db.record_run_start(
            "poll_censys",
            {
                "snapshot_week":    str(snapshot_week),
                "snapshot_date":    str(snapshot_date),
                "mode":             "enrich_v3",
                "ips_to_enrich":    len(ips),
                "max_enrich":       max_enrich,
                "pipeline_version": git_hash,
            },
        )

    if dry_run:
        logger.info(f"poll_censys DRY RUN — would enrich {len(ips)} IPs:")
        for ip in ips[:10]:
            logger.info(f"  {ip}")
        if len(ips) > 10:
            logger.info(f"  ... and {len(ips) - 10} more")
        _db.record_run_end(run_id, "success", records_in=0, records_out=0)
        return 0

    session      = _build_session(api_secret)
    total_stored = 0
    total_fetched = 0
    failed       = 0

    for i, ip in enumerate(ips, 1):
        logger.info(f"poll_censys [enrich {i}/{len(ips)}] {ip}")
        error_msg: str | None = None
        records: list[dict] = []

        try:
            resp = session.get(
                _CENSYS_HOST_URL.format(ip=ip),
                timeout=_DEFAULT_TIMEOUT,
            )
            if resp.status_code == 404:
                logger.info(f"  → not in Censys index (404)")
            elif resp.status_code == 422:
                error_msg = f"HTTP 422: {resp.json().get('errors',[{}])[0].get('message','insufficient balance')}"
                logger.warning(f"  → {error_msg} — credits exhausted, stopping")
                failed += 1
                break   # no point continuing — out of credits
            elif resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", "30"))
                logger.warning(f"  → rate-limited — sleeping {wait}s")
                time.sleep(wait)
                # retry once
                resp = session.get(_CENSYS_HOST_URL.format(ip=ip), timeout=_DEFAULT_TIMEOUT)
                if resp.ok:
                    records = _normalise_v3_host(resp.json(), snapshot_week, snapshot_date, run_id)
                else:
                    error_msg = f"HTTP {resp.status_code} after retry"
                    failed += 1
            elif not resp.ok:
                error_msg = f"HTTP {resp.status_code}: {resp.text[:120]}"
                logger.warning(f"  → {error_msg}")
                failed += 1
            else:
                records = _normalise_v3_host(resp.json(), snapshot_week, snapshot_date, run_id)

        except requests.RequestException as exc:
            error_msg = str(exc)
            logger.warning(f"  → request error: {exc}")
            failed += 1

        stored_this_ip = 0
        if records:
            # Censys occasionally returns duplicate port entries for the same IP.
            # Deduplicate by (ip, port) before upserting — last entry wins.
            seen: dict[tuple, dict] = {}
            for r in records:
                seen[(r.get("ip"), r.get("port"))] = r
            records = list(seen.values())
            stored_this_ip = _db.upsert_device_records(records)
            total_stored += stored_this_ip
            total_fetched += 1
            ports = [r.get("port") for r in records if r.get("port")]
            logger.info(
                f"  → services={len(records)} ports={ports} stored={stored_this_ip}"
            )

        try:
            _db.record_query_run(
                run_id          = run_id,
                source          = "censys",
                snapshot_week   = str(snapshot_week),
                query_id        = f"enrich_{ip.replace('.', '_')}",
                query_category  = "censys",
                query_string    = f"host/{ip}",
                results_total   = 1,
                results_fetched = len(records),
                error           = error_msg,
            )
        except Exception:
            pass

        if sleep_s > 0 and i < len(ips):
            time.sleep(sleep_s)

    _db.record_run_end(
        run_id,
        "success" if failed == 0 else "partial",
        records_in  = total_fetched,
        records_out = total_stored,
    )
    logger.info(
        f"poll_censys complete — enriched={total_fetched}/{len(ips)}"
        f" stored={total_stored} failed={failed}"
    )
    return total_stored
