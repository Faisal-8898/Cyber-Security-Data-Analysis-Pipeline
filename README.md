# IoT Honeypot Research Pipeline

Collects honeypot events (Cowrie + OpenCanary + Glutton), extracts IOCs, runs weekly Shodan/Censys snapshots, builds an attacker graph, and clusters campaigns. Feeds an IEEE IoT-J paper on IoT compromise → monetization infrastructure.

**Architecture**: VPS = pure sensor (logs only). Local machine = PostgreSQL + pipeline + analysis.

---

## Setup (one-time)

```bash
# 1. Python 3.12 venv
make venv

# 2. Copy env and fill in values
cp .env.example .env
# Required: DATABASE_URL, SHODAN_API_KEY, CENSYS_API_SECRET
# Optional: COWRIE_LOG_PATH, OPENCANARY_LOG_PATH (override /data/raw-logs/ defaults)

# 3. Start PostgreSQL (Docker on port 5453)
make db-up

# 4. Smoke-test DB
make check-db
```

> Full VPS build → [Docs/VPS_SETUP.md](Docs/VPS_SETUP.md)  
> Log sync setup → [Docs/DATA_PULL.md](Docs/DATA_PULL.md)

---

## Make Targets

### Database

| Target | What it does |
|---|---|
| `make db-up` | Start Docker PostgreSQL (port 5453) |
| `make db-down` | Stop container |
| `make db-reset` | Drop + recreate (fresh schema from `init.sql`) |
| `make db-migrate` | Apply `migrate_v2.sql` to an existing DB |
| `make check-db` | Verify DB connectivity |

### Python Environment

| Target | What it does |
|---|---|
| `make venv` | Create `.venv` with Python 3.12 and install all deps |
| `make install` | Re-install deps into existing `.venv` |

### Tests

| Target | What it does |
|---|---|
| `make test` | Unit tests (no DB required) |
| `make test-all` | Unit + integration tests (DB must be running) |
| `make cov` | Coverage report |

### Pipeline

| Target | What it does |
|---|---|
| `make run` | Full pipeline: ingest + extract IOCs |
| `make run-ingest` | Ingest honeypot logs only |
| `make run-extract` | Extract IOCs from already-ingested events |
| `make aggregate-churn` | Aggregate yesterday into `ip_activity_daily` |
| `make aggregate-churn-date DAY=2026-04-10` | Aggregate a specific date |

### Shodan / Censys

| Target | What it does |
|---|---|
| `make poll` | Shodan + Censys both (weekly — consumes credits) |
| `make poll-shodan` | Shodan weekly snapshot |
| `make poll-censys` | Censys weekly enrichment |
| `make poll-shodan-dry` | Print all 40 queries, zero API calls |
| `make poll-censys-dry` | Print all Censys queries, zero API calls |
| `make poll-shodan-resume` | Resume crashed poll (skips completed queries) |
| `make poll-shodan-from FROM=E` | Resume from a specific category/query_id |
| `make poll-censys-resume` | Resume crashed Censys enrichment |
| `make poll-censys-from FROM=20` | Resume Censys from a specific IP index |
| `make check-balance` | Remaining Shodan API credits |
| `make censys-balance` | Remaining Censys API credits |
| `make query-summary` | Per-category query counts + monthly credit budget |

### Graph / Clustering

| Target | What it does |
|---|---|
| `make build-graph` | Build NetworkX graph + cluster campaigns |
| `make build-graph-dry` | Dry run — stats only, no DB writes |
| `make graph-only` | Graph build only, skip clustering |
| `make cluster` | Campaign clustering only |

---

## CLI Reference

```bash
.venv/bin/python3 -m pipeline.run --tasks ingest,extract
.venv/bin/python3 -m pipeline.run --tasks ingest_cowrie
.venv/bin/python3 -m pipeline.run --tasks ingest_opencanary
.venv/bin/python3 -m pipeline.run --tasks poll_shodan
.venv/bin/python3 -m pipeline.run --tasks poll_censys
.venv/bin/python3 -m pipeline.run --tasks poll
.venv/bin/python3 -m pipeline.run --tasks aggregate_churn
.venv/bin/python3 -m pipeline.run --tasks build_graph,cluster
.venv/bin/python3 -m pipeline.run --tasks all
```

---

## Cron Schedule (local machine)

```cron
# Pull logs every 30 min
*/30 * * * *  rsync -az --quiet -e "ssh -p 2222 -i ~/.ssh/research_key" \
    cowrie@167.172.187.18:/home/cowrie/cowrie/var/log/cowrie/ \
    /data/raw-logs/cowrie/ >> /var/log/iot-pipeline/sync.log 2>&1

*/30 * * * *  rsync -az --quiet -e "ssh -p 2222 -i ~/.ssh/research_key" \
    cowrie@167.172.187.18:/var/tmp/opencanary.log \
    /data/raw-logs/opencanary/ >> /var/log/iot-pipeline/sync.log 2>&1

*/30 * * * *  rsync -az --quiet -e "ssh -p 2222 -i ~/.ssh/research_key" \
    cowrie@167.172.187.18:/var/tmp/glutton.log \
    /data/raw-logs/glutton/ >> /var/log/iot-pipeline/sync.log 2>&1

# Ingest + extract (5-min offset lets rsync finish first)
5,35 * * * *  cd /path/to/pipeline && .venv/bin/python3 -m pipeline.run \
    --tasks ingest,extract >> /var/log/iot-pipeline/run.log 2>&1

# Daily churn aggregation: 01:00 UTC
0 1 * * *     cd /path/to/pipeline && .venv/bin/python3 -m pipeline.run \
    --tasks aggregate_churn >> /var/log/iot-pipeline/daily.log 2>&1

# Shodan + Censys: Sunday 02:00 UTC
0 2 * * 0     cd /path/to/pipeline && .venv/bin/python3 -m pipeline.run \
    --tasks poll >> /var/log/iot-pipeline/weekly.log 2>&1

# Graph + clustering: Sunday 04:00 UTC
0 4 * * 0     cd /path/to/pipeline && .venv/bin/python3 -m pipeline.run \
    --tasks build_graph,cluster >> /var/log/iot-pipeline/weekly.log 2>&1
```

---

## `.env` Variables

```dotenv
DATABASE_URL=postgresql://pipeline:pipepipe@localhost:5453/iot_research

COWRIE_LOG_PATH=/data/raw-logs/cowrie/cowrie.json
OPENCANARY_LOG_PATH=/data/raw-logs/opencanary/opencanary.log

SHODAN_API_KEY=your_key_here
CENSYS_API_SECRET=censys_xxxxxxxx_your_token

# Optional
PIPELINE_LOG_DIR=/var/log/iot-pipeline
PIPELINE_STATE_DIR=/var/lib/iot-pipeline
```

---

## Project Structure

```
pipeline/
  core.py               # @task decorator, logger, git hash
  schema.py             # NormalizedEvent TypedDict
  bookmark.py           # Incremental reads (byte-offset + inode rotation guard)
  db.py                 # All PostgreSQL helpers
  ingest_cowrie.py      # Cowrie SSH/Telnet JSON parser
  ingest_opencanary.py  # OpenCanary multi-protocol parser
  extract_iocs.py       # IP, URL, SHA256, MD5, domain, credential, HASSH
  poll_shodan.py        # Shodan snapshot (40 queries, categories A–L)
  poll_censys.py        # Censys enrichment (host lookup, Bearer auth)
  build_graph.py        # NetworkX graph + Louvain clustering
  run.py                # CLI entry point

infra/
  docker-compose.yml    # PostgreSQL 16, port 5453
  init.sql              # Full schema (auto-applied on first start)
  migrate_v2.sql        # One-time migration for existing DBs

Docs/
  VPS_SETUP.md          # Step-by-step VPS build
  DATA_PULL.md          # SSH key + rsync pull + cron wiring
```

---

## Shodan Query Categories

| Cat | Focus | Paper section |
|-----|-------|---------------|
| A | IoT port baseline | RQ1, Table 1 |
| B | Router fingerprints | RQ1+RQ2 |
| C | IP cameras / surveillance | RQ1, Fig. 3 |
| E | Proxy / monetization **(core)** | RQ3, Fig. 7 |
| F | Botnet / infection signals | RQ1+RQ4 |
| H | SMTP open relay | RQ3 |
| I | Geographic bias control | Sections 6+11 |
| L | High-risk combo cluster seeds | RQ4 |

Full list: `pipeline/poll_shodan.py:SHODAN_QUERIES`

---

## Checklist

- [x] PostgreSQL schema (9 tables + monthly partitions)
- [x] Bookmark-based incremental reads (log rotation safe)
- [x] Cowrie ingest (login, command, file_download)
- [x] OpenCanary ingest (FTP, SSH, HTTP, Telnet, port scan)
- [x] IOC extraction (IP, URL, SHA256, MD5, domain, credential, HASSH)
- [x] Provenance tracking (`pipeline_runs`, git hash per row)
- [x] Shodan weekly poll (40 queries, `device_type` inference)
- [x] Censys weekly enrichment (host-lookup, Bearer + Basic auto-detect)
- [x] Multi-query UPSERT (`query_ids[]` merged per ip+port+week)
- [x] `shodan_query_runs` audit table
- [x] Schema migration v2
- [x] Daily churn aggregation (`ip_activity_daily`)
- [x] NetworkX graph build + Louvain community detection
- [x] Campaign clustering (`campaign_clusters` UPSERT)
- [ ] Rsync SSH key wired (see [Docs/DATA_PULL.md](Docs/DATA_PULL.md))
- [ ] Cron installed on local machine
