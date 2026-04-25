#!/bin/bash
# Analyze unknown devices to help improve classification

cd /home/faisal/Documents/project/cs-data-pipeline && psql "postgresql://pipeline:pipepipe@localhost:5453/iot_research" << 'EOF'
\echo '📊 Unknown Device Analysis'
\echo '──────────────────────────────────────────────────'

\echo ''
\echo '1. Unknown Count by Source:'
\echo '──────────────────────────────────────────────────'
SELECT 
  source,
  COUNT(*) as unknown_count,
  COUNT(*) * 100.0 / (SELECT COUNT(*) FROM device_records WHERE source = device_records.source)::float as pct_of_source
FROM device_records
WHERE device_type = 'unknown'
GROUP BY source
ORDER BY unknown_count DESC;

\echo ''
\echo '2. Unknown by Port (Top 20):'
\echo '──────────────────────────────────────────────────'
SELECT 
  port,
  COUNT(*) as count,
  COUNT(DISTINCT ip) as unique_ips
FROM device_records
WHERE device_type = 'unknown' AND port IS NOT NULL
GROUP BY port
ORDER BY count DESC
LIMIT 20;

\echo ''
\echo '3. Unknown by Protocol (Top 20):'
\echo '──────────────────────────────────────────────────'
SELECT 
  protocol,
  COUNT(*) as count,
  COUNT(DISTINCT ip) as unique_ips
FROM device_records
WHERE device_type = 'unknown' AND protocol IS NOT NULL
GROUP BY protocol
ORDER BY count DESC
LIMIT 20;

\echo ''
\echo '4. Unknown by HTTP Server (Top 15):'
\echo '──────────────────────────────────────────────────'
SELECT 
  http_server,
  COUNT(*) as count,
  COUNT(DISTINCT ip) as unique_ips
FROM device_records
WHERE device_type = 'unknown' AND http_server IS NOT NULL
GROUP BY http_server
ORDER BY count DESC
LIMIT 15;

\echo ''
\echo '5. Unknown by Tags (Top 20 most frequent tags):'
\echo '──────────────────────────────────────────────────'
SELECT 
  tag,
  COUNT(*) as records_with_tag,
  COUNT(DISTINCT ip) as unique_ips
FROM device_records, jsonb_to_text(tags) as tag
WHERE device_type = 'unknown' AND tags IS NOT NULL
GROUP BY tag
ORDER BY records_with_tag DESC
LIMIT 20;

\echo ''
\echo '6. Unknown by Port + Protocol Combo (Top 20):'
\echo '──────────────────────────────────────────────────'
SELECT 
  port,
  protocol,
  COUNT(*) as count,
  COUNT(DISTINCT ip) as unique_ips
FROM device_records
WHERE device_type = 'unknown' 
  AND port IS NOT NULL 
  AND protocol IS NOT NULL
GROUP BY port, protocol
ORDER BY count DESC
LIMIT 20;

\echo ''
\echo '7. Unknown Sample (5 diverse examples):'
\echo '──────────────────────────────────────────────────'
SELECT 
  ip,
  port,
  protocol,
  http_server,
  tags,
  raw_banner
FROM device_records
WHERE device_type = 'unknown'
LIMIT 5;

EOF
