# cs-data-pipeline

IoT honeypot data pipeline for IEEE IoT Journal research.  
Collects from Cowrie + OpenCanary honeypot logs, extracts IOCs, and performs
**weekly Shodan + Censys snapshots** for longitudinal IoT device exposure measurement.

---

## Quick Start

```bash
# 1. Copy env file and fill in values
cp .env.example .env

# 2. Install Python dependencies
make install

# 3. Start PostgreSQL (Docker, port 5453)
make db-up

# 4. Verify DB connection
make check-db

# 5. Run full pipeline (honeypot ingest + IOC extract)
make run

# 6. Run Shodan + Censys weekly poll  ← new
make poll
```

---

## Project Structure

```
infra/
  docker-compose.yml    # PostgreSQL 16 on port 5453
  init.sql              # Full schema (auto-applied on first DB start)
  migrate_v2.sql        # Migration for existing DBs (adds Shodan/Censys columns)

pipeline/
  core.py               # @task decorator, logger, git version
  schema.py             # NormalizedEvent TypedDict
  bookmark.py           # Incremental log reader (byte-offset tracking)
  db.py                 # PostgreSQL helpers (insert, upsert, device records)
  ingest_cowrie.py      # Parse Cowrie SSH/Telnet JSON logs
  ingest_opencanary.py  # Parse OpenCanary multi-protocol logs
  extract_iocs.py       # Extract IPs, URLs, hashes, credentials
  poll_shodan.py        # Shodan weekly snapshot (44 queries, categories A–L)
  poll_censys.py        # Censys weekly snapshot (Bearer token or API ID+Secret)
  run.py                # CLI entry point

tests/
  conftest.py
  fixtures/             # Sample log lines (no live honeypot needed)
```

---

## Make Targets

| Target | Description |
|---|---|
| `make db-up` | Start Docker PostgreSQL |
| `make db-down` | Stop container |
| `make db-reset` | Drop + recreate DB (fresh schema) |
| `make db-migrate` | Apply v2 migration to existing DB (Shodan/Censys columns) |
| `make install` | `pip install -r requirements.txt` |
| `make test` | Unit tests (no DB needed) |
| `make test-all` | Unit + integration tests (DB required) |
| `make cov` | Coverage report |
| `make check-db` | Verify DB connectivity |
| `make run` | Full pipeline (honeypot ingest + IOC extract) |
| `make run-ingest` | Ingest honeypot logs only |
| `make run-extract` | Extract IOCs from last ingest only |
| `make poll` | Run Shodan + Censys both (consumes credits) |
| `make poll-shodan` | Run Shodan weekly poll only |
| `make poll-censys` | Run Censys weekly poll only |
| `make poll-shodan-dry` | Dry run: print all 44 Shodan queries, zero API calls |
| `make poll-censys-dry` | Dry run: print all Censys queries, zero API calls |

---

## Honeypot Log Sources

Logs are rsync'd from the VPS sensor to `/data/raw-logs/` before each run.
Override paths via env vars:

| Env var | Default |
|---|---|
| `COWRIE_LOG_PATH` | `/data/raw-logs/cowrie/cowrie.json` |
| `OPENCANARY_LOG_PATH` | `/data/raw-logs/opencanary/opencanary.log` |

---

## Shodan + Censys Setup

### 1. Get API credentials

**Shodan**
- Free API key: https://account.shodan.io → *My Account* → copy **API Key**
- Free tier gives ~100 results/query, 1 search credit/query

**Censys — personal token (most common)**
- Go to https://search.censys.io/account/api
- Copy your **API Secret** (format: `censys_xxxxxxxx_...`)
- No API ID is needed — set only `CENSYS_API_SECRET`; the pipeline uses Bearer token auth

**Censys — service account**
- If you have an API ID + secret pair: set both `CENSYS_API_ID` and `CENSYS_API_SECRET`
- The pipeline auto-detects: if `CENSYS_API_ID` is set → Basic auth; otherwise → Bearer

### 2. Set environment variables in `.env`

```dotenv
# Shodan
SHODAN_API_KEY=your_shodan_api_key_here

# Censys — personal token only (no CENSYS_API_ID needed)
CENSYS_API_SECRET=censys_xxxxxxxx_your_personal_token

# Censys — service account (set both if you have an API ID)
# CENSYS_API_ID=your_censys_api_id
# CENSYS_API_SECRET=your_censys_api_secret

# Optional tuning (safe defaults shown)
SHODAN_MAX_PER_QUERY=500           # records per query (free tier cap: 100)
SHODAN_SLEEP_BETWEEN_QUERIES=1.0   # seconds between Shodan queries
CENSYS_MAX_PER_QUERY=200           # records per query
CENSYS_SLEEP_BETWEEN_QUERIES=2.0   # seconds between Censys queries
CENSYS_SLEEP_BETWEEN_PAGES=0.5     # seconds between pagination requests
```

### 3. Test without spending credits (dry run)

```bash
# Prints all 44 Shodan query strings — does NOT call the API
make poll-shodan-dry

# Prints all Censys query strings — does NOT call the API
make poll-censys-dry
```

### 4. Run a snapshot poll

```bash
# Shodan only
make poll-shodan

# Censys only
make poll-censys

# Both at once (recommended for the weekly cron)
make poll

# Or via CLI directly
python -m pipeline.run --tasks poll_shodan
python -m pipeline.run --tasks poll_censys
python -m pipeline.run --tasks poll
```

### 5. Query catalogue — 44 Shodan + 48 Censys queries (categories A–L)

| Cat | Focus | Example queries |
|-----|-------|----------------|
| **A** | IoT device exposure | `port:23`, `port:2323`, `port:22`, `port:8080` |
| **B** | Router/embedded exploitation | `port:7547`, `"TR-069"`, `"GoAhead-Webs"`, `"Boa"`, `"uhttpd"` |
| **C** | IP camera / surveillance | `"IP Camera"`, `port:554`, `"RTSP"`, `"DVR"` |
| **D** | Default credentials / weak auth | `"admin:admin"`, `"default password"`, `"Login Page"` |
| **E** | Proxy / monetization **(CRITICAL for paper)** | `port:1080`, `port:3128`, `"SOCKS5"`, `"Squid"` |
| **F** | Botnet / malware signals | `"busybox"`, `"mirai"`, `"dropbear"`, `"/bin/busybox"` |
| **G** | C2 / suspicious patterns | `"/bin/sh"`, `"cmd.exe"`, `"powershell"`, `"panel"` |
| **H** | SMTP / spam infrastructure | `port:25`, `"Open Relay"`, `"Postfix"` |
| **I** | Geographic sampling (bias control) | `country:BD port:23`, `country:CN port:23` |
| **J** | Vulnerability exposure | `"cve"`, `"vulnerable"`, `"OpenSSH"`, `"Apache"` |
| **K** | Industrial / IoT protocols | `port:1883` (MQTT), `port:502` (Modbus), `port:5555` (ADB) |
| **L** | High-risk IoT combos | `port:23 "busybox"`, `port:7547 "TR-069"`, `port:554 "RTSP"` |

> **The query set never changes between weeks** — intentional for longitudinal comparability.  
> Full lists in `pipeline/poll_shodan.py:SHODAN_QUERIES` and `pipeline/poll_censys.py:CENSYS_QUERIES`.

### 6. Cron schedule

Add to your local crontab (`crontab -e`):

```cron
# ── Rsync honeypot logs from VPS sensor (every 30 min) ───────────────────────
5,35 * * * *   rsync -az -e "ssh -p 2222" cowrie@YOUR_VPS:/home/cowrie/var/log/cowrie/cowrie.json /data/raw-logs/cowrie/
5,35 * * * *   rsync -az -e "ssh -p 2222" root@YOUR_VPS:/var/tmp/opencanary.log /data/raw-logs/opencanary/

# ── Honeypot ingest + IOC extract (every 30 min, 10-min offset) ──────────────
10,40 * * * *  cd /path/to/cs-data-pipeline && .venv/bin/python -m pipeline.run --tasks ingest,extract >> /tmp/iot-pipeline/logs/cron.log 2>&1

# ── Shodan + Censys weekly snapshot (Sunday 02:00 UTC) ───────────────────────
0 2 * * 0      cd /path/to/cs-data-pipeline && .venv/bin/python -m pipeline.run --tasks poll >> /tmp/iot-pipeline/logs/shodan_censys.log 2>&1
```

### 7. Migrate an existing database (schema v2)

Run this once if your database was created before the Shodan/Censys columns were added:

```bash
# Option A — via Make
make db-migrate

# Option B — direct psql
psql "$DATABASE_URL" -f infra/migrate_v2.sql
```


---

## Device Records Schema

`device_records` stores one row per `(source, ip, port, snapshot_week)`.
When the same IP+port is returned by multiple queries in the same week,
the row is **updated in-place** and `query_ids[]` is merged (array union).

| Column | Description |
|--------|-------------|
| `source` | `shodan` or `censys` |
| `snapshot_week` | Monday of the ISO week — longitudinal anchor |
| `ip` | Device IP address |
| `port` | Service port |
| `device_type` | Inferred: `router` \| `camera` \| `iot` \| `server` \| `unknown` |
| `query_ids` | All query IDs that matched this `(ip, port)` this week |
| `query_category` | Primary category letter (A–L) |
| `tags` | Shodan tags / Censys labels (`iot`, `malware`, `vpn`, …) |
| `http_title` | HTTP page title — admin panel detection |
| `http_server` | Server header (`GoAhead`, `Boa`, `uhttpd`, …) |
| `vulns` | CVE detail map from Shodan |
| `cve_ids` | CVE ID list |
| `raw_data` | Compact provenance JSONB |

`shodan_query_runs` records every individual query execution (query string,
total API hits, records stored, errors) — **full reproducibility guarantee**.

---

## Useful Analysis Queries

```sql
-- Weekly device count by source
SELECT source, snapshot_week, COUNT(*) AS devices
FROM device_records
GROUP BY source, snapshot_week ORDER BY snapshot_week DESC;

-- Device type distribution this week
SELECT device_type, COUNT(*) AS n
FROM device_records
WHERE snapshot_week = DATE_TRUNC('week', NOW())
GROUP BY device_type ORDER BY n DESC;

-- Proxy / monetization candidates (category E)
SELECT ip, port, org, country_code, product, http_server
FROM device_records
WHERE 'port_1080'    = ANY(query_ids)
   OR 'port_3128'    = ANY(query_ids)
   OR 'socks5'       = ANY(query_ids)
   OR 'proxy_server' = ANY(query_ids)
ORDER BY snapshot_week DESC LIMIT 100;

-- High-risk routers with TR-069 open (category B)
SELECT ip, port, org, country_code, version, snapshot_week
FROM device_records
WHERE device_type = 'router' AND 'tr069' = ANY(query_ids)
ORDER BY snapshot_week DESC;

-- IoT compromise linkage: IPs in both honeypot events AND device_records
SELECT dr.ip, dr.device_type, dr.org, dr.country_code,
       COUNT(DISTINCT he.session_id) AS attack_sessions
FROM device_records dr
JOIN honeypot_events he ON he.source_ip = dr.ip
GROUP BY dr.ip, dr.device_type, dr.org, dr.country_code
ORDER BY attack_sessions DESC LIMIT 50;

-- Query run audit (reproducibility check)
SELECT query_id, query_category, results_total, results_fetched,
       executed_at, error
FROM shodan_query_runs
WHERE source = 'shodan'
  AND snapshot_week = DATE_TRUNC('week', NOW())
ORDER BY query_category, query_id;
```

---

## Implementation Checklist

- [x] PostgreSQL schema (9 core tables + 2 Shodan/Censys tables, monthly partitions)
- [x] Bookmark-based incremental reads (handles log rotation)
- [x] Cowrie ingest (login, command, file_download events)
- [x] OpenCanary ingest (FTP, SSH, HTTP, Telnet, port scan)
- [x] IOC extraction (IP, URL, SHA256, MD5, domain, credentials)
- [x] Provenance tracking (`pipeline_runs` table, git hash per row)
- [x] **Shodan weekly poll** (44 queries across categories A–L, `device_type` inference)
- [x] **Censys weekly poll** (48 queries, personal Bearer token + Basic auth auto-detect)
- [x] **Multi-query UPSERT** (one row per ip+port+week, `query_ids[]` merged)
- [x] **`shodan_query_runs`** audit table (per-query reproducibility)
- [x] **Schema migration v2** (`infra/migrate_v2.sql` for existing DBs)
- [ ] Graph analysis / campaign clustering (Phase 3)
- [ ] VPS rsync automation + full cron wiring
