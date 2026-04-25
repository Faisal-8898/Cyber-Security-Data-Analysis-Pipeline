-- =============================================================
-- Migration v2 — Shodan/Censys enhanced device_records schema
-- Run this ONCE against an existing database:
--   psql $DATABASE_URL -f infra/migrate_v2.sql
-- Safe to re-run (all statements use IF NOT EXISTS / DO NOTHING).
-- =============================================================

-- Step 1: Add snapshot_week column (the new longitudinal anchor)
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS snapshot_week DATE;

-- Backfill snapshot_week from snapshot_date for existing rows
UPDATE device_records
SET snapshot_week = snapshot_date - EXTRACT(DOW FROM snapshot_date)::INT
                   + CASE WHEN EXTRACT(DOW FROM snapshot_date)::INT = 0 THEN -6 ELSE 1 END
WHERE snapshot_week IS NULL;

-- Make it NOT NULL after backfill
ALTER TABLE device_records ALTER COLUMN snapshot_week SET NOT NULL;
ALTER TABLE device_records ALTER COLUMN snapshot_week SET DEFAULT CURRENT_DATE;

-- Step 2: Add IoT identification columns
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS device_type    VARCHAR(30)  DEFAULT 'unknown';
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS hostnames      TEXT[]       DEFAULT '{}';
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS domains        TEXT[]       DEFAULT '{}';
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS tags           TEXT[]       DEFAULT '{}';
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS http_title     TEXT;
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS http_server    TEXT;
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS http_headers   JSONB        DEFAULT '{}';
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS ssl_cert       JSONB        DEFAULT '{}';
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS vulns          JSONB        DEFAULT '{}';

-- Step 3: Add query provenance columns
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS query_ids      TEXT[]       DEFAULT '{}';
ALTER TABLE device_records ADD COLUMN IF NOT EXISTS query_category VARCHAR(10);

-- Step 4: Drop old unique index and create new one on snapshot_week
DROP INDEX IF EXISTS idx_dr_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_dr_unique      ON device_records (source, ip, port, snapshot_week);

-- Step 5: Add new performance indexes
CREATE INDEX IF NOT EXISTS idx_dr_week        ON device_records (snapshot_week DESC);
CREATE INDEX IF NOT EXISTS idx_dr_source_week ON device_records (source, snapshot_week DESC);
CREATE INDEX IF NOT EXISTS idx_dr_device_type ON device_records (device_type);
CREATE INDEX IF NOT EXISTS idx_dr_asn         ON device_records (asn)  WHERE asn IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_dr_country     ON device_records (country_code) WHERE country_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_dr_port        ON device_records (port) WHERE port IS NOT NULL;

-- Step 6: Create new shodan_query_runs tracking table
CREATE TABLE IF NOT EXISTS shodan_query_runs (
    id              BIGSERIAL    PRIMARY KEY,
    run_id          UUID         NOT NULL,
    source          VARCHAR(10)  NOT NULL,
    snapshot_week   DATE         NOT NULL,
    query_id        VARCHAR(100) NOT NULL,
    query_category  VARCHAR(10)  NOT NULL,
    query_string    TEXT         NOT NULL,
    results_total   INT          DEFAULT 0,
    results_fetched INT          DEFAULT 0,
    executed_at     TIMESTAMPTZ  DEFAULT NOW(),
    error           TEXT,
    UNIQUE (source, snapshot_week, query_id)
);

-- Step 7: Add dedup columns to honeypot_events
-- These allow ON CONFLICT DO NOTHING to prevent duplicate ingestion.
ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS raw_file_path   TEXT;
ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS raw_line_number INT;

-- Dedup index: (file + line + event_time). event_time must be included because
-- PostgreSQL requires unique indexes on partitioned tables to include partition key.
CREATE UNIQUE INDEX IF NOT EXISTS idx_he_dedup
    ON honeypot_events (raw_file_path, raw_line_number, event_time)
    WHERE raw_file_path IS NOT NULL AND raw_line_number IS NOT NULL;

\echo 'Migration v2 complete.'
