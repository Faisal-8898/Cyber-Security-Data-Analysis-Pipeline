cd /home/faisal/Documents/project/cs-data-pipeline && psql "postgresql://pipeline:pipepipe@localhost:5453/iot_research" << 'EOF'
\echo '📊 Data Collection Summary'
\echo '──────────────────────────────────────────────────'

SELECT 
  'Total records' as metric,
  COUNT(*)::text as value
FROM device_records;

\echo ''
\echo 'By Week & Source:'
\echo '──────────────────────────────────────────────────'

SELECT 
  snapshot_week,
  source,
  COUNT(*) as records
FROM device_records
GROUP BY snapshot_week, source
ORDER BY snapshot_week DESC, source;

\echo ''
\echo 'Device Types:'
\echo '──────────────────────────────────────────────────'

SELECT 
  device_type,
  COUNT(*) as count
FROM device_records
GROUP BY device_type
ORDER BY count DESC;
EOF