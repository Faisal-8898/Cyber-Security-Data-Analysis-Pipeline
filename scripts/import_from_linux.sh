#!/bin/bash
# Import SQL dump files into the Mac's database
#
# Usage: ./scripts/import_from_linux.sh ~/Downloads/device_records_*.sql ~/Downloads/pipeline_runs_*.sql ~/Downloads/shodan_query_runs_*.sql
# Or:    ./scripts/import_from_linux.sh ~/Downloads/*.sql

DB_URL="${DATABASE_URL:-postgresql://pipeline:pipepipe@localhost:5453/iot_research}"

if [ $# -eq 0 ]; then
  echo "Usage: $0 <file1.sql> [<file2.sql> ...]"
  echo "Example:"
  echo "  $0 ~/Downloads/device_records_*.sql"
  exit 1
fi

echo "🔄 Importing from files:"
echo ""

for file in "$@"; do
  if [ ! -f "$file" ]; then
    echo "⚠️  File not found: $file"
    continue
  fi

  filename=$(basename "$file")
  echo "  → $filename"

  # Detect which table from filename
  if [[ "$filename" =~ device_records ]]; then
    TABLE="device_records"
  elif [[ "$filename" =~ pipeline_runs ]]; then
    TABLE="pipeline_runs"
  elif [[ "$filename" =~ shodan_query_runs ]]; then
    TABLE="shodan_query_runs"
  else
    echo "    ⚠️  Cannot determine table from filename. Skipping."
    continue
  fi

  # Import using COPY FROM (reverse of export)
  # device_records: Linux server has columns in migration order (snapshot_week/device_type
  # were added via ALTER TABLE ADD COLUMN, so they appear at position 18/19 not 3/17).
  # Must specify explicit column list matching Linux physical order.
  if [[ "$TABLE" == "device_records" ]]; then
    COLS="(id, source, snapshot_date, ip, port, transport, protocol, product, version, cpe, cve_ids, country_code, asn, org, isp, raw_banner, raw_data, snapshot_week, device_type, hostnames, domains, tags, http_title, http_server, http_headers, ssl_cert, vulns, query_ids, query_category)"
    psql "$DB_URL" \
      --command "COPY $TABLE $COLS FROM STDIN;" \
      < "$file"
    # Fix sequence after bulk import so new inserts don't collide
    psql "$DB_URL" -c "SELECT setval('device_records_id_seq', (SELECT MAX(id) FROM device_records));" > /dev/null
  else
    psql "$DB_URL" \
      --command "COPY $TABLE FROM STDIN;" \
      < "$file"
    # Fix sequence after bulk import so new inserts don't collide with imported ids
    if [[ "$TABLE" == "shodan_query_runs" ]]; then
      psql "$DB_URL" -c "SELECT setval('shodan_query_runs_id_seq', (SELECT MAX(id) FROM shodan_query_runs));" > /dev/null
    fi
  fi

  COUNT=$(psql "$DB_URL" -t -c "SELECT COUNT(*) FROM $TABLE;")
  echo "    ✓ $TABLE now has $COUNT total rows"
  echo ""
done

echo "✅ Import complete!"
echo ""
echo "Verify on Mac:"
echo "  psql \"\$DATABASE_URL\" -c \"SELECT COUNT(*) as device_records FROM device_records;\""
echo "  psql \"\$DATABASE_URL\" -c \"SELECT COUNT(*) as pipeline_runs FROM pipeline_runs;\""
echo "  psql \"\$DATABASE_URL\" -c \"SELECT COUNT(*) as shodan_query_runs FROM shodan_query_runs;\""
