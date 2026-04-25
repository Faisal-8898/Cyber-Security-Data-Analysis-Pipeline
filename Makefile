.PHONY: db-up db-down db-reset db-migrate db-migrate-feeds export-data import-data venv install test test-all cov run check-db \
        poll-shodan poll-censys poll run-ingest run-extract \
        poll-shodan-resume poll-shodan-from \
        poll-censys-resume poll-censys-from \
        poll-shodan-max poll-censys-max poll-max \
        poll-censys-paper poll-paper \
        poll-feeds \
        check-balance censys-balance censys-test query-summary \
        reclassify \
        aggregate-churn aggregate-churn-date \
        build-graph build-graph-dry graph-only cluster

# ─── Docker PostgreSQL ────────────────────────────────────────────────────────

db-up:
	docker compose -f infra/docker-compose.yml up -d
	@echo "Waiting for DB to be ready..."
	@sleep 3
	@docker compose -f infra/docker-compose.yml ps

db-down:
	docker compose -f infra/docker-compose.yml down

db-reset:
	docker compose -f infra/docker-compose.yml down -v
	docker compose -f infra/docker-compose.yml up -d
	@echo "DB reset complete — schema re-applied from init.sql"

# Apply schema migration v2 to an existing database (adds Shodan/Censys columns)
db-migrate:
	@echo "Applying schema migration v2 (Shodan/Censys columns)..."
	@echo "  Checking if Docker container is running..."
	@if docker compose -f infra/docker-compose.yml ps postgres | grep -q 'Up'; then \
		echo "  Found running postgres container — piping migration..."; \
		cat infra/migrate_v2.sql | docker compose -f infra/docker-compose.yml exec -T postgres psql -U pipeline -d iot_research; \
	else \
		echo "  Docker container not found — trying psql on \$$DATABASE_URL..."; \
		psql "$$DATABASE_URL" -f infra/migrate_v2.sql; \
	fi
	@echo "Migration complete."

# Export device_records, pipeline_runs, shodan_query_runs to data/ (Git-tracked)
# Can be pushed to GitHub and pulled on Mac
export-data:
	@chmod +x scripts/export_to_mac.sh
	@scripts/export_to_mac.sh

# Import device_records, pipeline_runs, shodan_query_runs from data/
import-data:
	@chmod +x scripts/import_from_linux.sh
	@scripts/import_from_linux.sh data/device_records_*.sql data/pipeline_runs_*.sql data/shodan_query_runs_*.sql 2>/dev/null || echo "No data files found in data/ — run 'make export-data' first"

# ─── Python environment ──────────────────────────────────────────────────────

# Create venv with Python 3.12 (system default) and install all dependencies
venv:
	python3.12 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt

install:
	.venv/bin/pip install -r requirements.txt

# ─── Tests ────────────────────────────────────────────────────────────────────

# Unit tests only (no DB required)
test:
	.venv/bin/pytest -m "not integration"

# Unit + integration tests (DB must be running)
test-all:
	.venv/bin/pytest

# Coverage report
cov:
	.venv/bin/pytest -m "not integration" --cov=pipeline --cov-report=term-missing

# ─── Pipeline ────────────────────────────────────────────────────────────────

check-db:
	.venv/bin/python3 -m pipeline.run --check-db

run:
	.venv/bin/python3 -m pipeline.run --tasks all

run-ingest:
	.venv/bin/python3 -m pipeline.run --tasks ingest

run-extract:
	.venv/bin/python3 -m pipeline.run --tasks extract

# ─── Shodan / Censys polling ──────────────────────────────────────────────────

# Dry-run: print queries, do NOT hit API (safe to test at any time)
poll-shodan-dry:
	SHODAN_DRY_RUN=1 .venv/bin/python3 -m pipeline.run --tasks poll_shodan

poll-censys-dry:
	CENSYS_DRY_RUN=1 .venv/bin/python3 -m pipeline.run --tasks poll_censys

# Real runs — consume API credits
poll-shodan:
	.venv/bin/python3 -m pipeline.run --tasks poll_shodan

poll-censys:
	.venv/bin/python3 -m pipeline.run --tasks poll_censys

# Resume an interrupted Censys enrichment run — re-enriches any IPs not yet stored this week
poll-censys-resume:
	CENSYS_RESUME=1 .venv/bin/python3 -m pipeline.run --tasks poll_censys

# Start enrichment from a specific IP index, e.g.: make poll-censys-from FROM=20
poll-censys-from:
	@test -n "$(FROM)" || (echo "Usage: make poll-censys-from FROM=<ip_index>  e.g. FROM=20"; exit 1)
	CENSYS_START_FROM=$(FROM) .venv/bin/python3 -m pipeline.run --tasks poll_censys

# Resume a crashed poll — skips queries already completed this week (reads DB audit table)
poll-shodan-resume:
	SHODAN_RESUME=1 .venv/bin/python3 -m pipeline.run --tasks poll_shodan

# Start from a specific category or query_id, e.g.: make poll-shodan-from FROM=F
poll-shodan-from:
	@test -n "$(FROM)" || (echo "Usage: make poll-shodan-from FROM=<category|query_id>  e.g. FROM=F"; exit 1)
	SHODAN_START_FROM=$(FROM) .venv/bin/python3 -m pipeline.run --tasks poll_shodan

# Both in one go (recommended for the weekly Sunday 02:00 UTC cron)
poll:
	.venv/bin/python3 -m pipeline.run --tasks poll

# ─── Max-credit runs — use ALL available credits in one go ───────────────────

# Shodan: fetch 200 results/query (2 pages = 2 credits) × 40 queries = 80 credits
# Raises per-query cost; best used after you know which queries hit the 100-result cap.
poll-shodan-max:
	SHODAN_MAX_PER_QUERY=200 .venv/bin/python3 -m pipeline.run --tasks poll_shodan

# Censys: enrich up to 100 IPs (= 100 credits, the full monthly Free allowance) in one run
poll-censys-max:
	CENSYS_MAX_ENRICH=100 .venv/bin/python3 -m pipeline.run --tasks poll_censys

# Paper-focused enrichment: RQ3 (monetization linkage) + RQ4 (campaign clustering) signals
#
# Research alignment (from WHOLE_RESEARCH.md Section 5.8 + 5.7):
#   RQ3: Proxy/DDoS/SMTP monetization signals
#     - Ports: 1080 (SOCKS), 3128 (Squid), 8080 (HTTP proxy), 25 (SMTP)
#   RQ4: Campaign infrastructure clustering seeds
#     - Combo queries: port23+busybox, port7547+TR069, port554+RTSP, port80+GoAhead
#   Cross-cutting: Botnet infection + device type (router/camera/iot)
#
# Credits: 60 enrichments/week × 4 weeks = 240/month (sustainable over 100cr/wk avg)
# Data quality: Prioritise E,L,F,H categories for research novelty
#
poll-censys-paper:
	CENSYS_MAX_ENRICH=60 \
	CENSYS_PRIORITY_CATEGORIES=E,L,F,H \
	CENSYS_PRIORITY_PORTS=1080,3128,8080,25,7547,23,2323,554 \
	CENSYS_PRIORITY_DEVICE_TYPES=router,camera,iot \
	.venv/bin/python3 -m pipeline.run --tasks poll_censys

# ────── RECOMMENDED: One-command weekly research collection ──────────────────
# Collects:
#   - All Shodan queries (40) with 200 results/query for device baseline (RQ1)
#   - All 40+ high-value Shodan IPs via Censys enrichment (60 credits)
#   - Total: ~400 device_records with cross-source validation
#   - Total credits: 80 Shodan (40q × 2cr) + 60 Censys = 140/week
poll-paper:
	@echo "───────────────────────────────────────────────────────────────────"
	@echo "  Collecting for IEEE IoT-Journal paper (RQ1-RQ4)"
	@echo "  - Shodan: 40 queries × 200 results = 80 credits (device baseline)"
	@echo "  - Censys: 60 high-value IPs (monetization + campaigns)"
	@echo "  - Total: ~400 device_records with cross-source validation"
	@echo "  - Credit cost: 140/week (sustainable over 4 weeks)"
	@echo "───────────────────────────────────────────────────────────────────"
	SHODAN_MAX_PER_QUERY=200 .venv/bin/python3 -m pipeline.run --tasks poll_shodan
	@echo "  ✅ Shodan snapshot complete"
	$(MAKE) poll-censys-paper
	@echo "  ✅ Censys enrichment complete"
	@echo "───────────────────────────────────────────────────────────────────"

# Both max-credit runs back-to-back (extreme: use all budget in one week)
poll-max:
	SHODAN_MAX_PER_QUERY=200 .venv/bin/python3 -m pipeline.run --tasks poll_shodan
	CENSYS_MAX_ENRICH=100 \
	CENSYS_PRIORITY_CATEGORIES=E,L,F,H \
	CENSYS_PRIORITY_PORTS=1080,3128,8080,25,7547,23,2323,554 \
	CENSYS_PRIORITY_DEVICE_TYPES=router,camera,iot \
	.venv/bin/python3 -m pipeline.run --tasks poll_censys

# Check remaining Shodan API credits for the configured SHODAN_API_KEY
check-balance:
	@.venv/bin/python3 scripts/check_balance.py

# Check remaining Censys API credits for the configured CENSYS_API_SECRET
censys-balance:
	@.venv/bin/python3 scripts/censys_balance.py

# Quick test: validate Censys PAT using the free credit-balance endpoint (costs 0 credits)
censys-test:
	@.venv/bin/python3 scripts/censys_balance.py

# Print per-category query counts and monthly credit budget
query-summary:
	@.venv/bin/python3 scripts/query_summary.py

# Reclassify existing device_records using the latest infer_device_type() signals.
# Safe to run repeatedly — only touches rows currently labelled 'unknown'.
# Adds 'proxy' as a first-class type (RQ3 monetization evidence, Section 5.8).
reclassify:
	@echo "Reclassifying unknown device records in DB..."
	@psql "postgresql://pipeline:pipepipe@localhost:5453/iot_research" \
	     -f scripts/reclassify_device_types.sql

# Apply feed_iocs migration (adds ThreatFox/URLhaus table + cross-match views)
db-migrate-feeds:
	@psql "postgresql://pipeline:pipepipe@localhost:5453/iot_research" \
	     -f infra/migrate_v3_feeds.sql

# Pull ThreatFox C2 IOCs + URLhaus malicious URLs, store in feed_iocs, print RQ2 cross-match
poll-feeds:
	.venv/bin/python3 -m pipeline.run --tasks poll_feeds

# ─── Daily churn aggregation ─────────────────────────────────────────────────
aggregate-churn:
	.venv/bin/python3 -m pipeline.run --tasks aggregate_churn

aggregate-churn-date:
	@test -n "$(DAY)" || (echo "Usage: make aggregate-churn-date DAY=YYYY-MM-DD"; exit 1)
	CHURN_DAY=$(DAY) .venv/bin/python3 -m pipeline.run --tasks aggregate_churn

# ─── Graph build + campaign clustering ───────────────────────────────────────
build-graph-dry:
	GRAPH_DRY_RUN=1 .venv/bin/python3 -m pipeline.run --tasks build_graph,cluster

build-graph:
	.venv/bin/python3 -m pipeline.run --tasks build_graph,cluster

graph-only:
	.venv/bin/python3 -m pipeline.run --tasks build_graph

cluster:
	.venv/bin/python3 -m pipeline.run --tasks cluster
