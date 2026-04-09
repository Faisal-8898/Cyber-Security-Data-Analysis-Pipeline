# cs-data-pipeline

IoT honeypot data pipeline for IEEE IoT Journal research.
Collects from Cowrie + OpenCanary logs, extracts IOCs, stores to PostgreSQL.

---

## Quick Start

```bash
# 1. Copy env file and fill in values
cp .env.example .env

# 2. Install Python dependencies
make install

# 3. Start PostgreSQL (Docker, port 5433)
make db-up

# 4. Verify DB connection
make check-db

# 5. Run full pipeline
make run
```

---

## Project Structure

```
infra/
  docker-compose.yml   # PostgreSQL 16 on port 5433
  init.sql             # Full schema (auto-applied on first start)

pipeline/
  core.py              # @task decorator, logger, git version
  schema.py            # NormalizedEvent TypedDict
  bookmark.py          # Incremental log reader (byte-offset tracking)
  db.py                # PostgreSQL helpers (insert, upsert)
  ingest_cowrie.py     # Parse Cowrie SSH/Telnet JSON logs
  ingest_opencanary.py # Parse OpenCanary multi-protocol logs
  extract_iocs.py      # Extract IPs, URLs, hashes, credentials
  run.py               # CLI entry point

tests/
  conftest.py
  fixtures/            # Sample log lines (no live honeypot needed)
  test_bookmark.py
  test_ingest_cowrie.py
  test_ingest_opencanary.py
  test_extract_iocs.py
  test_db.py           # Integration tests (need live DB)
```

---

## Make Targets

| Target | Description |
|---|---|
| `make db-up` | Start Docker PostgreSQL |
| `make db-down` | Stop container |
| `make db-reset` | Drop + recreate DB (fresh schema) |
| `make install` | `pip install -r requirements.txt` |
| `make test` | Unit tests (no DB needed) |
| `make test-all` | Unit + integration tests (DB required) |
| `make cov` | Coverage report |
| `make check-db` | Verify DB connectivity |
| `make run` | Full pipeline (ingest + extract) |
| `make run-ingest` | Ingest only |
| `make run-extract` | Extract IOCs from last ingest |

---

## Log Sources

Logs are rsync'd from the VPS to `/data/raw-logs/` before each run.
Override paths via env vars:

| Env var | Default |
|---|---|
| `COWRIE_LOG_PATH` | `/data/raw-logs/cowrie/cowrie.json` |
| `OPENCANARY_LOG_PATH` | `/data/raw-logs/opencanary/opencanary.log` |

---

## Implementation Checklist

- [x] PostgreSQL schema (9 tables, monthly partitions)
- [x] Bookmark-based incremental reads (handles log rotation)
- [x] Cowrie ingest (login, command, file_download events)
- [x] OpenCanary ingest (FTP, SSH, HTTP, Telnet, port scan)
- [x] IOC extraction (IP, URL, SHA256, MD5, domain, credentials)
- [x] Provenance tracking (pipeline_runs table, git hash per row)
- [ ] Shodan/Censys collection (Phase 2)
- [ ] Graph analysis (Phase 3)
- [ ] VPS deployment + rsync automation
# Cyber-Security-Data-Analysis-Pipeline
