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
  psql "$DB_URL" \
    --command "COPY $TABLE FROM STDIN;" \
    < "$file"

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
