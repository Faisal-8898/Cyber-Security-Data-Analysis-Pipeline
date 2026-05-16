.PHONY: db-up db-down db-reset db-migrate db-migrate-feeds export-data import-data venv install test test-all cov run check-db \
        poll-shodan poll-censys poll run-ingest run-extract \
        poll-shodan-resume poll-shodan-from \
        poll-censys-resume poll-censys-from \
        poll-shodan-max poll-censys-max poll-max \
        poll-censys-paper poll-paper \
        poll-feeds \
        poll-shodan-week poll-censys-week poll-week \
        check-balance censys-balance censys-test query-summary \
        reclassify \
        aggregate-churn aggregate-churn-date \
        build-graph build-graph-dry graph-only cluster \
        check-new-data pull-cowrie pull-opencanary pull-glutton pull-dionaea pull-logs ingest-honeypot \
        fetch-sonar fetch-sonar-dry fetch-sonar-list

# ─── VPS sync configuration ───────────────────────────────────────────────────
# Override on the command line if your paths differ:
#   make pull-logs KEY=~/.ssh/other_key LOCAL_DATA=/custom/path
VPS        := 167.172.187.18
VPS_PORT   := 8443
KEY        := $(HOME)/.ssh/research_key
KEY_ROOT   := $(HOME)/.ssh/cs-datapipe
LOCAL_DATA := $(HOME)/data
LOG_DIR    := $(HOME)/data/iot-pipeline/logs
SSH_OPTS   := ssh -p $(VPS_PORT) -i $(KEY)
SSH_ROOT   := ssh -p $(VPS_PORT) -i $(KEY_ROOT)

# ─── Log sync from VPS ───────────────────────────────────────────────────────
#
# rsync is already incremental: it transfers ONLY new bytes since your last pull.
# Running after 15 days picks up exactly the 15 days of new data — nothing older
# is re-downloaded. The pipeline bookmark then ingests only the new bytes into DB.
#
# check-new-data: dry-run to see how much new data exists on the VPS (no transfer)
# pull-cowrie / pull-opencanary / pull-glutton: sync one source individually
# pull-logs: sync all three sources in one shot
# ingest-honeypot: pull-logs → ingest → extract IOCs → churn aggregation (fully ready)

check-new-data:
	@echo "=== Checking new data on VPS (dry-run, no transfer) ==="
	@echo ""
	@echo "--- Cowrie SSH/Telnet ---"
	@rsync --dry-run -av --stats \
	    -e "$(SSH_OPTS)" \
	    cowrie@$(VPS):/home/cowrie/cowrie/var/log/cowrie/ \
	    $(LOCAL_DATA)/raw-logs/cowrie/ 2>&1 \
	    | grep -E 'cowrie\.json|bytes|Number of'
	@echo ""
	@echo "--- OpenCanary multi-protocol ---"
	@rsync --dry-run -av --stats \
	    -e "$(SSH_OPTS)" \
	    cowrie@$(VPS):/var/tmp/opencanary.log \
	    $(LOCAL_DATA)/raw-logs/opencanary/ 2>&1 \
	    | grep -E 'opencanary\.log|bytes|Number of'
	@echo ""
	@echo "--- Glutton catch-all TCP ---"
	@rsync --dry-run -av --stats \
	    -e "$(SSH_OPTS)" \
	    cowrie@$(VPS):/var/tmp/glutton.log \
	    $(LOCAL_DATA)/raw-logs/glutton/ 2>&1 \
	    | grep -E 'glutton\.log|bytes|Number of'
	@echo ""
	@echo "--- Local line counts (already ingested mirror) ---"
	@printf "  cowrie.json:      "; wc -l < $(LOCAL_DATA)/raw-logs/cowrie/cowrie.json 2>/dev/null || echo "0 (file missing)"
	@printf "  opencanary.log:   "; wc -l < $(LOCAL_DATA)/raw-logs/opencanary/opencanary.log 2>/dev/null || echo "0 (file missing)"
	@printf "  glutton.log:      "; wc -l < $(LOCAL_DATA)/raw-logs/glutton/glutton.log 2>/dev/null || echo "0 (file missing)"

pull-cowrie:
	@echo "Pulling Cowrie logs from VPS..."
	@mkdir -p $(LOCAL_DATA)/raw-logs/cowrie $(LOG_DIR)
	@rsync -az --inplace --quiet \
	    -e "$(SSH_OPTS)" \
	    cowrie@$(VPS):/home/cowrie/cowrie/var/log/cowrie/ \
	    $(LOCAL_DATA)/raw-logs/cowrie/ >> $(LOG_DIR)/sync.log 2>&1
	@printf "Done. cowrie.json (live): "; wc -l < $(LOCAL_DATA)/raw-logs/cowrie/cowrie.json 2>/dev/null || echo "0"
	@printf "Done. ALL rotated files:  "; cat $(LOCAL_DATA)/raw-logs/cowrie/cowrie.json* 2>/dev/null | wc -l || echo "0"
pull-opencanary:
	@echo "Pulling OpenCanary logs from VPS..."
	@mkdir -p $(LOCAL_DATA)/raw-logs/opencanary $(LOG_DIR)
	@rsync -az --inplace --quiet \
	    -e "$(SSH_OPTS)" \
	    cowrie@$(VPS):/var/tmp/opencanary.log \
	    $(LOCAL_DATA)/raw-logs/opencanary/ >> $(LOG_DIR)/sync.log 2>&1
	@printf "Done. opencanary.log: "; wc -l < $(LOCAL_DATA)/raw-logs/opencanary/opencanary.log 2>/dev/null || echo "0 lines"

pull-glutton:
	@echo "Pulling Glutton logs from VPS..."
	@mkdir -p $(LOCAL_DATA)/raw-logs/glutton $(LOG_DIR)
	@rsync -az --inplace --quiet \
	    -e "$(SSH_OPTS)" \
	    cowrie@$(VPS):/var/tmp/glutton.log \
	    $(LOCAL_DATA)/raw-logs/glutton/ >> $(LOG_DIR)/sync.log 2>&1
	@printf "Done. glutton.log: "; wc -l < $(LOCAL_DATA)/raw-logs/glutton/glutton.log 2>/dev/null || echo "0 lines"

pull-dionaea:
	@echo "Pulling Dionaea captures from VPS..."
	@mkdir -p $(LOCAL_DATA)/raw-logs/dionaea $(LOG_DIR)
	@rsync -az --quiet --ignore-errors \
	    -e "$(SSH_ROOT)" \
	    root@$(VPS):/var/lib/dionaea/ \
	    $(LOCAL_DATA)/raw-logs/dionaea/ >> $(LOG_DIR)/sync.log 2>&1 || true
	@printf "Dionaea SQLite DBs pulled: "; find $(LOCAL_DATA)/raw-logs/dionaea -name "*.sqlite" 2>/dev/null | wc -l
	@printf "Dionaea binaries pulled:   "; ls $(LOCAL_DATA)/raw-logs/dionaea/binaries/ 2>/dev/null | wc -l || echo "0"

# ─── Rapid7 Project Sonar — IoT scale dataset (free, no API credit limit) ────
#
# fetch-sonar:      stream-filter all target IoT ports into ~/data/raw-logs/sonar/
# fetch-sonar-dry:  show what would be downloaded + sizes (no actual transfer)
# fetch-sonar-list: list all files currently available in Rapid7 sonar.tcp dataset
#
# Requires: RAPID7_API_KEY in .env  (free at https://opendata.rapid7.com/)
# Output:   ~/data/raw-logs/sonar/sonar_iot_YYYY-MM-DD.jsonl.gz  (≤2 GB compressed)
# Run:      once per week (Sunday cron alongside poll-paper)
fetch-sonar-list:
	.venv/bin/python3 scripts/fetch_sonar.py --list

fetch-sonar-dry:
	.venv/bin/python3 scripts/fetch_sonar.py --dry-run

fetch-sonar:
	.venv/bin/python3 scripts/fetch_sonar.py --max-gb 2.0

# Pull all three honeypot sources in one command
pull-logs: pull-cowrie pull-opencanary pull-glutton pull-dionaea
	@echo "All honeypot logs synced."

# Full honeypot data pipeline: sync → ingest → extract IOCs → aggregate churn
# After this completes, the DB has all new events, IOCs extracted, and daily churn updated.
# NOTE: ingest and extract run in ONE process invocation so in-memory events are
#       handed directly to extract_iocs without a DB round-trip.
ingest-honeypot:
	@echo "=== Step 1/4: Pulling logs from VPS (Cowrie + OpenCanary + Glutton + Dionaea) ==="
	$(MAKE) pull-logs
	@echo ""
	@echo "=== Step 2-3/4: Ingesting raw events + Extracting IOCs (single process) ==="
	.venv/bin/python3 -m pipeline.run --tasks ingest,extract
	@echo ""
	@echo "=== Step 4/4: Aggregating daily churn ==="
	.venv/bin/python3 -m pipeline.run --tasks aggregate_churn
	@echo ""
	@echo "Honeypot data fully ready."

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

# ─── Back-fill a missed Saturday — MAX DATA ──────────────────────────────────
#
# Use when you missed your scheduled Saturday poll.
# Stores data under the CORRECT snapshot_week (not the current week) so the
# longitudinal time-series stays intact.
#
# Uses MAXIMUM settings: 200 results/Shodan query + all 100 Censys credits
# with priority on high-value categories (E=proxy, L=combos, F=botnet, H=spam).
#
# ── LAST SATURDAY (May 2, 2026) → Monday 2026-04-27 ─────────────────────────
#   make poll-week WEEK=2026-05-02        ← back-fill last Sat (today: May 5)
#
# ── GENERAL USAGE ────────────────────────────────────────────────────────────
#   make poll-week        WEEK=YYYY-MM-DD  ← any date in the missed week
#   make poll-shodan-week WEEK=YYYY-MM-DD  ← Shodan only
#   make poll-censys-week WEEK=YYYY-MM-DD  ← Censys only (after Shodan)
#
# WEEK is auto-normalised to that week's Monday. Safe to re-run (UPSERT).
# Credits: 80 Shodan (40q × 2cr) + 100 Censys = 180 total for the back-fill.
# ─────────────────────────────────────────────────────────────────────────────

poll-shodan-week:
	@test -n "$(WEEK)" || (echo "Usage: make poll-shodan-week WEEK=YYYY-MM-DD  (e.g. WEEK=2026-05-02 for last Saturday)"; exit 1)
	SNAPSHOT_WEEK=$(WEEK) SHODAN_MAX_PER_QUERY=200 \
	SHODAN_RESUME=1 \
	.venv/bin/python3 -m pipeline.run --tasks poll_shodan --week $(WEEK)

poll-censys-week:
	@test -n "$(WEEK)" || (echo "Usage: make poll-censys-week WEEK=YYYY-MM-DD  (e.g. WEEK=2026-05-02 for last Saturday)"; exit 1)
	SNAPSHOT_WEEK=$(WEEK) \
	CENSYS_MAX_ENRICH=100 \
	CENSYS_PRIORITY_CATEGORIES=E,L,F,H \
	CENSYS_PRIORITY_PORTS=1080,3128,8080,25,7547,23,2323,554 \
	CENSYS_PRIORITY_DEVICE_TYPES=router,camera,iot \
	.venv/bin/python3 -m pipeline.run --tasks poll_censys --week $(WEEK)

poll-week:
	@test -n "$(WEEK)" || (echo "Usage: make poll-week WEEK=YYYY-MM-DD  (e.g. WEEK=2026-05-02 for last Saturday)"; exit 1)
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo "  Back-fill: week containing $(WEEK) → snapshot_week auto-set to its Monday"
	@echo "  Shodan:  200 results/query × 40 queries = 80 credits"
	@echo "  Censys:  100 enrichments, priority: E,L,F,H categories"
	@echo "  Total credits: 180"
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo "  [1/2] Shodan snapshot..."
	SNAPSHOT_WEEK=$(WEEK) SHODAN_MAX_PER_QUERY=200 \
	.venv/bin/python3 -m pipeline.run --tasks poll_shodan --week $(WEEK)
	@echo "  [2/2] Censys enrichment (reads Shodan IPs stored for that week)..."
	SNAPSHOT_WEEK=$(WEEK) \
	CENSYS_MAX_ENRICH=100 \
	CENSYS_PRIORITY_CATEGORIES=E,L,F,H \
	CENSYS_PRIORITY_PORTS=1080,3128,8080,25,7547,23,2323,554 \
	CENSYS_PRIORITY_DEVICE_TYPES=router,camera,iot \
	.venv/bin/python3 -m pipeline.run --tasks poll_censys --week $(WEEK)
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo "  Back-fill complete for week containing $(WEEK)."
	@echo "═══════════════════════════════════════════════════════════════════"

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
