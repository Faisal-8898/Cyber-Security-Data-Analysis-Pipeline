.PHONY: db-up db-down db-reset install test test-all run check-db

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
	python -m pipeline.run --check-db

run:
	python -m pipeline.run --tasks all

run-ingest:
	python -m pipeline.run --tasks ingest

run-extract:
	python -m pipeline.run --tasks extract
