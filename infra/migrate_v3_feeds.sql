-- migrate_v3_feeds.sql
-- Adds feed_iocs table for malware intelligence feed storage.
-- Run via: make db-migrate-feeds
--
-- Paper context:
--   RQ2: cross-match honeypot IOC IPs against ThreatFox C2 records
--   Section 5.8: multi-vantage linkage evidence (ThreatFox + URLhaus)

CREATE TABLE IF NOT EXISTS feed_iocs (
    id              BIGSERIAL    PRIMARY KEY,
    source          VARCHAR(50)  NOT NULL,          -- threatfox | urlhaus | malwarebazaar | otx
    ioc_type        VARCHAR(50)  NOT NULL,           -- ip:port | domain | url | md5 | sha256
    ioc_value       TEXT         NOT NULL,           -- the actual IOC string
    ip              INET,                            -- parsed IP (if ioc_type = ip:port)
    port            INT,                             -- parsed port (if ioc_type = ip:port)
    malware_family  VARCHAR(100),                    -- mirai | gafgyt | mozi | etc.
    confidence      INT          DEFAULT 0,          -- 0-100 confidence score from feed
    tags            TEXT[]       DEFAULT '{}',
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    snapshot_date   DATE         NOT NULL DEFAULT CURRENT_DATE,
    raw_data        JSONB        DEFAULT '{}',
    ingested_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    UNIQUE (source, ioc_value)
);

CREATE INDEX IF NOT EXISTS idx_feed_iocs_ip        ON feed_iocs (ip);
CREATE INDEX IF NOT EXISTS idx_feed_iocs_source    ON feed_iocs (source);
CREATE INDEX IF NOT EXISTS idx_feed_iocs_family    ON feed_iocs (malware_family);
CREATE INDEX IF NOT EXISTS idx_feed_iocs_date      ON feed_iocs (snapshot_date DESC);
CREATE INDEX IF NOT EXISTS idx_feed_iocs_ioc_value ON feed_iocs (ioc_value);

-- Cross-match view: honeypot IOC IPs that appear in ThreatFox C2 records
-- Used directly in paper Section 8 (Results II) for RQ2 linkage numbers.
CREATE OR REPLACE VIEW v_honeypot_threatfox_matches AS
SELECT
    ir.ioc_value                      AS honeypot_ip,
    ir.id                             AS ioc_record_id,
    fi.malware_family,
    fi.confidence,
    fi.tags                           AS feed_tags,
    fi.first_seen                     AS c2_first_seen,
    fi.last_seen                      AS c2_last_seen
FROM ioc_records ir
JOIN feed_iocs fi
    ON ir.ioc_value = fi.ip::text
WHERE ir.ioc_type  = 'ip'
  AND fi.source    = 'threatfox';

-- Cross-match view: honeypot download URLs confirmed in URLhaus
CREATE OR REPLACE VIEW v_honeypot_urlhaus_matches AS
SELECT
    ir.ioc_value                      AS honeypot_url,
    ir.id                             AS ioc_record_id,
    fi.malware_family,
    fi.tags                           AS feed_tags,
    fi.first_seen                     AS urlhaus_first_seen
FROM ioc_records ir
JOIN feed_iocs fi
    ON ir.ioc_value = fi.ioc_value
WHERE ir.ioc_type  = 'url'
  AND fi.source    = 'urlhaus';

-- Cross-match view: honeypot SHA256 hashes confirmed in MalwareBazaar
CREATE OR REPLACE VIEW v_honeypot_malwarebazaar_matches AS
SELECT
    ir.ioc_value                      AS honeypot_sha256,
    ir.id                             AS ioc_record_id,
    fi.malware_family,
    fi.confidence,
    fi.tags                           AS feed_tags,
    fi.first_seen                     AS mb_first_seen,
    fi.last_seen                      AS mb_last_seen,
    fi.raw_data->>'file_type'         AS file_type,
    fi.raw_data->>'file_size'         AS file_size
FROM ioc_records ir
JOIN feed_iocs fi
    ON ir.ioc_value = fi.ioc_value
WHERE ir.ioc_type  = 'sha256'
  AND fi.source    = 'malwarebazaar';

-- Cross-match view: honeypot IOC IPs that appear in OTX pulse indicators
CREATE OR REPLACE VIEW v_honeypot_otx_matches AS
SELECT
    ir.ioc_value                      AS honeypot_ip,
    ir.id                             AS ioc_record_id,
    fi.malware_family,
    fi.tags                           AS pulse_tags,
    fi.confidence,
    fi.first_seen                     AS otx_first_seen,
    fi.raw_data->>'pulse_name'        AS pulse_name,
    fi.raw_data->>'pulse_id'          AS pulse_id
FROM ioc_records ir
JOIN feed_iocs fi
    ON ir.ioc_value = fi.ip::text
WHERE ir.ioc_type  = 'ip'
  AND fi.source    = 'otx';

-- Aggregate cross-match summary (used directly in paper Section 8 RQ2)
CREATE OR REPLACE VIEW v_rq2_linkage_summary AS
SELECT
    'threatfox'      AS feed,
    COUNT(DISTINCT honeypot_ip)  AS matched_honeypot_iocs,
    COUNT(DISTINCT malware_family) AS malware_families
FROM v_honeypot_threatfox_matches
UNION ALL
SELECT
    'urlhaus',
    COUNT(DISTINCT honeypot_url),
    NULL
FROM v_honeypot_urlhaus_matches
UNION ALL
SELECT
    'malwarebazaar',
    COUNT(DISTINCT honeypot_sha256),
    COUNT(DISTINCT malware_family)
FROM v_honeypot_malwarebazaar_matches
UNION ALL
SELECT
    'otx',
    COUNT(DISTINCT honeypot_ip),
    COUNT(DISTINCT malware_family)
FROM v_honeypot_otx_matches;

\echo 'feed_iocs table and cross-match views created.'
