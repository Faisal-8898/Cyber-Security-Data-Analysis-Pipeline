# Data Transfer: Linux Server → Mac Local

## Overview

You have:
- **Linux server** (current): 18K+ device_records, pipeline_runs, shodan_query_runs
- **Mac local**: Same DB schema but missing most data (only 5-6 pipeline_runs, rest empty)

This guide exports data from Linux and imports into Mac.

---

## Step 1: Export data from Linux (this machine)

```bash
make export-data
```

This creates 3 SQL files in `./exports/`:
- `device_records_YYYYMMDD_HHMMSS.sql` (~18K rows)
- `pipeline_runs_YYYYMMDD_HHMMSS.sql` (all runs)
- `shodan_query_runs_YYYYMMDD_HHMMSS.sql` (audit records)

**File sizes** (approximate):
- device_records: 15–20 MB
- pipeline_runs: <1 MB
- shodan_query_runs: 1–2 MB

---

## Step 2: Transfer files to Mac

Choose one method:

### Option A: SCP (if you have SSH access between machines)
```bash
scp exports/*.sql user@mac.local:~/Downloads/
```

### Option B: USB/AirDrop
1. Connect USB drive to Linux
2. Copy `exports/*.sql` to USB
3. Plug USB into Mac, copy to `~/Downloads/`

### Option C: Cloud (Dropbox, Google Drive, etc.)
1. Upload `exports/*.sql` to cloud
2. Download on Mac to `~/Downloads/`

### Option D: Just show me the files
```bash
ls -lh exports/
cat exports/device_records_*.sql | head -20  # preview first few rows
```

---

## Step 3: Import data into Mac

On your Mac, navigate to the project directory and run:

```bash
# Option 1: Use the import script (easiest)
chmod +x scripts/import_from_linux.sh
./scripts/import_from_linux.sh ~/Downloads/device_records_*.sql \
                                ~/Downloads/pipeline_runs_*.sql \
                                ~/Downloads/shodan_query_runs_*.sql

# Option 2: Manual import (one by one)
psql "$DATABASE_URL" < ~/Downloads/device_records_YYYYMMDD_HHMMSS.sql
psql "$DATABASE_URL" < ~/Downloads/pipeline_runs_YYYYMMDD_HHMMSS.sql
psql "$DATABASE_URL" < ~/Downloads/shodan_query_runs_YYYYMMDD_HHMMSS.sql
```

---

## Step 4: Verify import succeeded on Mac

```bash
# Check row counts
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM device_records;"
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM pipeline_runs;"
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM shodan_query_runs;"

# Spot-check device data
psql "$DATABASE_URL" -c "SELECT ip, port, device_type, source FROM device_records LIMIT 5;"

# Check pipeline run history
psql "$DATABASE_URL" -c "SELECT task_name, status, records_out FROM pipeline_runs ORDER BY started_at DESC LIMIT 10;"
```

---

## Handling Duplicates

Your Mac already has 5–6 pipeline_runs. The import will **skip duplicates** based on `run_id` (PRIMARY KEY), so no conflicts.

To verify:
```bash
psql "$DATABASE_URL" -c "SELECT COUNT(DISTINCT run_id) FROM pipeline_runs;"
```

---

## Troubleshooting

### Error: "database does not exist"
- Ensure `.env` on Mac points to the correct PostgreSQL
- Verify `DATABASE_URL` is set: `echo $DATABASE_URL`

### Error: "column X does not exist"
- Schema on Mac is out of sync
- Run: `make db-migrate` (applies v2 Shodan/Censys columns)
- Then: `make db-migrate-feeds` (applies feed_iocs table)

### Error: "permission denied" on scripts
- Run: `chmod +x scripts/export_to_mac.sh scripts/import_from_linux.sh`

### Import is slow
- Normal for 18K rows — typically 30–60 seconds
- Use `tail -f` on another terminal to watch progress

---

## Advanced: Incremental Sync (after first import)

If you want to run `make poll-paper` on Linux again and only transfer *new* records:

```bash
# On Linux, export only records after a certain date
psql "$DATABASE_URL" -c "
  COPY (SELECT * FROM device_records WHERE ingested_at > NOW() - INTERVAL '1 day')
  TO STDOUT;
" > exports/device_records_incremental.sql

# Transfer to Mac and import
```

---

## Data Consistency Notes

- **device_records deduplication**: Uses (source, ip, port, snapshot_week) — duplicates across weeks are expected
- **pipeline_runs**: Keyed by `run_id` (UUID), so safe to re-import
- **shodan_query_runs**: Audit table, no dedup — safe to append

---

## Next Steps

Once data is on Mac:

1. Verify counts match: `make query-summary`
2. Run analysis notebooks locally
3. For next week's collection: run `make poll-paper` on Linux again, re-export, re-import

---

## Need help?

```bash
# Show schema of tables being exported
psql "$DATABASE_URL" -c "\d device_records"
psql "$DATABASE_URL" -c "\d pipeline_runs"
psql "$DATABASE_URL" -c "\d shodan_query_runs"

# Count total rows being exported
psql "$DATABASE_URL" -c "
  SELECT
    'device_records' as table_name, COUNT(*) as rows UNION ALL
  SELECT 'pipeline_runs', COUNT(*) UNION ALL
  SELECT 'shodan_query_runs', COUNT(*)
  FROM (SELECT * FROM device_records) x, (SELECT * FROM pipeline_runs) y, (SELECT * FROM shodan_query_runs) z
"
```
