.PHONY: db-up db-down db-reset db-migrate install test test-all run check-db \
        poll-shodan poll-censys poll run-ingest run-extract \
        poll-shodan-resume poll-shodan-from \
        poll-censys-resume poll-censys-from \
        check-balance censys-balance censys-test query-summary

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

# ─── Python environment ──────────────────────────────────────────────────────

install:
	pip install -r requirements.txt

# ─── Tests ────────────────────────────────────────────────────────────────────

# Unit tests only (no DB required)
test:
	pytest -m "not integration"

# Unit + integration tests (DB must be running)
test-all:
	pytest

# Coverage report
cov:
	pytest -m "not integration" --cov=pipeline --cov-report=term-missing

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

# Check remaining Shodan API credits for the configured SHODAN_API_KEY
check-balance:
	@.venv/bin/python3 scripts/check_balance.py

# Check remaining Censys API credits for the configured CENSYS_API_SECRET
censys-balance:
	@.venv/bin/python3 scripts/censys_balance.py

# Quick test: validate Censys PAT with a v3 host lookup of 1.1.1.1 (costs 1 credit)
censys-test:
	@.venv/bin/python3 scripts/censys_balance.py

# Print per-category query counts and monthly credit budget
query-summary:
	@.venv/bin/python3 scripts/query_summary.py
