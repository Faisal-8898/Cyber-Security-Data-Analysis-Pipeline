#!/bin/bash
# Export device_records, pipeline_runs, shodan_query_runs to data/ (Git-tracked)
#
# Usage: make export-data
#        Exports 3 SQL files to ./data/
#        Push to GitHub: git add data/*.sql && git commit && git push
#        Pull on Mac: git pull && make import-data

set -e

EXPORT_DIR="data"
DB_URL="${DATABASE_URL:-postgresql://pipeline:pipepipe@localhost:5453/iot_research}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$EXPORT_DIR"

echo "Exporting tables from: $DB_URL"
echo "Export directory: $EXPORT_DIR"
echo ""

# ─── 1. device_records (all rows) ───────────────────────────────────────────
echo "[1/3] Exporting device_records (~18K rows)..."
psql "$DB_URL" \
  --pset footer=off \
  --command "COPY device_records TO STDOUT;" \
  > "$EXPORT_DIR/device_records_${TIMESTAMP}.sql"

DEVICE_COUNT=$(psql "$DB_URL" -t -c "SELECT COUNT(*) FROM device_records;")
echo "      ✓ $DEVICE_COUNT rows exported"

# ─── 2. pipeline_runs (only new ones, exclude what's already on Mac) ──────────
# Strategy: if your Mac has 5-6 runs, export all and let the Mac deduplicate by run_id
echo "[2/3] Exporting pipeline_runs..."
psql "$DB_URL" \
  --pset footer=off \
  --command "COPY pipeline_runs TO STDOUT;" \
  > "$EXPORT_DIR/pipeline_runs_${TIMESTAMP}.sql"

PIPELINE_COUNT=$(psql "$DB_URL" -t -c "SELECT COUNT(*) FROM pipeline_runs;")
echo "      ✓ $PIPELINE_COUNT rows exported"

# ─── 3. shodan_query_runs (all audit records) ────────────────────────────────
echo "[3/3] Exporting shodan_query_runs..."
psql "$DB_URL" \
  --pset footer=off \
  --command "COPY shodan_query_runs TO STDOUT;" \
  > "$EXPORT_DIR/shodan_query_runs_${TIMESTAMP}.sql"

SHODAN_COUNT=$(psql "$DB_URL" -t -c "SELECT COUNT(*) FROM shodan_query_runs;")
echo "      ✓ $SHODAN_COUNT rows exported"

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "✅ Export complete!"
echo ""
echo "Files created:"
ls -lh "$EXPORT_DIR"/*.sql | awk '{print "   " $9 " (" $5 ")"}'
echo ""
echo "Next steps:"
echo "  1. Stage for Git:"
echo "     git add $EXPORT_DIR/*.sql"
echo "     git commit -m 'Export device data: $DEVICE_COUNT devices, $PIPELINE_COUNT pipeline runs'"
echo "     git push"
echo ""
echo "  2. On Mac, pull and import:"
echo "     git pull"
echo "     make import-data"
