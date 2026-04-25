-- reclassify_device_types.sql
-- Backfills device_type for existing records using the same priority logic
-- as the updated infer_device_type() in poll_shodan.py.
--
-- Priority: camera > router > proxy > iot > server > unknown  (matches Python)
-- Run via: make reclassify   OR   psql ... -f scripts/reclassify_device_types.sql
--
-- Paper context: Section 5.4 (IoT device identification), Section 5.8 (monetization
-- detection — proxy is a first-class type tied to RQ3 proxy-abuse linkage).

BEGIN;

-- ── 0. Snapshot before ──────────────────────────────────────────────────────
\echo '── Before reclassification ──'
SELECT device_type, COUNT(*) FROM device_records GROUP BY device_type ORDER BY COUNT(*) DESC;

-- ── 1. CAMERA ──────────────────────────────────────────────────────────────
UPDATE device_records
SET device_type = 'camera'
WHERE device_type = 'unknown'
  AND (
    port = 554
    OR LOWER(COALESCE(protocol,'') || ' ' || COALESCE(http_server,'') || ' ' ||
             COALESCE(http_title,'') || ' ' || COALESCE(raw_banner,''))
       ~ '(camera|dvr|nvr|ipcam|ip cam|netcam|webcam|surveillance|cctv|hikvision|dahua|axis|foscam|vivotek|tvt|rtsp|amcrest|reolink|uniview|hanwha|geovision|pelco|d-link dcs)'
  );

-- ── 2. ROUTER ───────────────────────────────────────────────────────────────
UPDATE device_records
SET device_type = 'router'
WHERE device_type = 'unknown'
  AND (
    port = 7547
    OR LOWER(COALESCE(protocol,'') || ' ' || COALESCE(http_server,'') || ' ' ||
             COALESCE(http_title,'') || ' ' || COALESCE(raw_banner,''))
       ~ '(router|gateway|goahead-webs|goahead|uhttpd|mini_httpd|rompager|tr-069|cwmp|dsl-2|mikrotik|dd-wrt|openwrt|tp-link|linksys|netgear|zyxel|draytek|huawei home|asus router|routerlogin|dsl router|adsl|vdsl|broadband router|home gateway|totolink|tenda|belkin)'
  );

-- ── 3. PROXY (RQ3 monetization) ─────────────────────────────────────────────
-- Matches: squid, tinyproxy, socks banners, proxy protocol, canonical proxy ports
-- with any non-empty banner (to avoid false-positives on blank port-23 hits).
UPDATE device_records
SET device_type = 'proxy'
WHERE device_type = 'unknown'
  AND (
    -- Banner/server/title contains proxy product name
    LOWER(COALESCE(http_server,'') || ' ' || COALESCE(http_title,'') || ' ' ||
          COALESCE(raw_banner,''))
      ~ '(squid|tinyproxy|privoxy|3proxy|ccproxy|polipo|iplanet-web-proxy|sun-java-system-web-proxy|ebay-proxy-server|cdn cache server|zscaler|bluecoat|forcepoint|http connect|http-connect|socks5|socks4|http proxy|proxy server|open proxy)'
    -- OR Shodan/Censys protocol field is a proxy protocol
    OR LOWER(COALESCE(protocol,'')) IN ('socks5-proxy','socks4-proxy','http-connect')
    -- OR canonical proxy port AND there is any banner (not a silent scan hit)
    OR (port IN (1080, 3128) AND COALESCE(raw_banner,'') <> '')
    OR (port IN (1080, 3128) AND COALESCE(http_server,'') <> '')
  );

-- ── 4. IOT (embedded / infected devices) ───────────────────────────────────
UPDATE device_records
SET device_type = 'iot'
WHERE device_type = 'unknown'
  AND (
    LOWER(COALESCE(protocol,'')) IN ('mqtt','coap')
    OR LOWER(COALESCE(protocol,'') || ' ' || COALESCE(http_server,'') || ' ' ||
             COALESCE(http_title,'') || ' ' || COALESCE(raw_banner,''))
       ~ '(busybox|dropbear|mirai|embedded|/bin/busybox|uclibc|mqtt|mosquitto|zigbee|zwave|padavan|lede)'
  );

-- ── 5. SERVER (conventional infrastructure) ─────────────────────────────────
UPDATE device_records
SET device_type = 'server'
WHERE device_type = 'unknown'
  AND (
    LOWER(COALESCE(protocol,'') || ' ' || COALESCE(http_server,'') || ' ' ||
          COALESCE(http_title,'') || ' ' || COALESCE(raw_banner,''))
      ~ '(nginx|apache|\biis\b|litespeed|caddy|jetty|tomcat|flask|gunicorn|postfix|exim|sendmail|dovecot|courier|cyrus|microsoft-iis|samba|\bsmb\b|mssql|mysql|postgresql|redis|mongodb|elasticsearch|memcached|influxdb|prometheus|kubernetes|docker)'
    OR LOWER(COALESCE(protocol,'')) IN ('smtp','imap','imap-ssl','smb','mssql','ssh','pop3')
  );

-- ── 6. Snapshot after ───────────────────────────────────────────────────────
\echo ''
\echo '── After reclassification ──'
SELECT device_type, COUNT(*) FROM device_records GROUP BY device_type ORDER BY COUNT(*) DESC;

\echo ''
\echo '── Rows still unknown ──'
SELECT COUNT(*) AS still_unknown FROM device_records WHERE device_type = 'unknown';

\echo ''
\echo '── Unknown sample (top ports remaining) ──'
SELECT port, protocol, COUNT(*) AS cnt
FROM device_records
WHERE device_type = 'unknown' AND port IS NOT NULL
GROUP BY port, protocol
ORDER BY cnt DESC
LIMIT 15;

COMMIT;
