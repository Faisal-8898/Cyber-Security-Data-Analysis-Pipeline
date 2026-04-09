-- =============================================================
-- IoT Research Database Schema
-- PostgreSQL 16  |  init runs once on first container start
-- =============================================================

-- ---------------------------------------------------------------
-- 1. PIPELINE RUNS  (provenance — every task execution recorded)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id           UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    task_name        VARCHAR(100) NOT NULL,
    started_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at     TIMESTAMPTZ,
    status           VARCHAR(20)  NOT NULL DEFAULT 'running', -- running|success|failed
    records_in       INT          DEFAULT 0,
    records_out      INT          DEFAULT 0,
    source_files     TEXT[],
    pipeline_version VARCHAR(64),          -- git short hash
    parameters       JSONB        DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pipeline_runs_task_time
    ON pipeline_runs (task_name, started_at DESC);

-- ---------------------------------------------------------------
-- 2. HONEYPOT EVENTS  (partitioned by month)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS honeypot_events (
    id              BIGSERIAL,
    record_id       UUID,                  -- app-level ID from NormalizedEvent
    event_time      TIMESTAMPTZ  NOT NULL,
    ingested_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    source_ip       INET,
    source_port     INT,
    dest_port       INT,
    honeypot        VARCHAR(20),           -- cowrie | opencanary | glutton
    protocol        VARCHAR(20),           -- ssh | telnet | http | ftp | mqtt
    event_type      VARCHAR(100),          -- login.failed | login.success | command.input | file.download
    session_id      VARCHAR(100),
    username        TEXT,
    password        TEXT,
    command_str     TEXT,
    download_url    TEXT,
    file_hash       VARCHAR(64),           -- SHA256
    hassh           VARCHAR(64),           -- SSH client fingerprint
    user_agent      TEXT,
    http_path       TEXT,
    pipeline_run_id UUID,                  -- logical ref to pipeline_runs(run_id)
    raw_data        JSONB        NOT NULL DEFAULT '{}'
) PARTITION BY RANGE (event_time);

-- Monthly partitions: April – September 2026
CREATE TABLE IF NOT EXISTS honeypot_events_2026_04 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE IF NOT EXISTS honeypot_events_2026_05 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE IF NOT EXISTS honeypot_events_2026_06 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE IF NOT EXISTS honeypot_events_2026_07 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS honeypot_events_2026_08 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS honeypot_events_2026_09 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE IF NOT EXISTS honeypot_events_2026_10 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');

CREATE INDEX IF NOT EXISTS idx_he_event_time  ON honeypot_events (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_he_source_ip   ON honeypot_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_he_type        ON honeypot_events (honeypot, event_type);
CREATE INDEX IF NOT EXISTS idx_he_session     ON honeypot_events (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_he_run         ON honeypot_events (pipeline_run_id) WHERE pipeline_run_id IS NOT NULL;

-- ---------------------------------------------------------------
-- 3. SOURCE IP METADATA
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS source_ips (
    ip              INET         PRIMARY KEY,
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    event_count     INT          DEFAULT 0,
    country_code    CHAR(2),
    asn             BIGINT,
    org             TEXT,
    reverse_dns     TEXT,
    is_tor          BOOLEAN      DEFAULT FALSE,
    is_vpn          BOOLEAN      DEFAULT FALSE,
    abuse_score     FLOAT,
    tags            TEXT[],
    updated_at      TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sip_asn     ON source_ips (asn);
CREATE INDEX IF NOT EXISTS idx_sip_country ON source_ips (country_code);

-- ---------------------------------------------------------------
-- 4. NORMALIZED IOCs
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ioc_records (
    id               BIGSERIAL    PRIMARY KEY,
    ioc_type         VARCHAR(30)  NOT NULL,  -- ip|domain|url|sha256|credential|command|hassh
    ioc_value        TEXT         NOT NULL,
    first_seen       TIMESTAMPTZ  NOT NULL,
    last_seen        TIMESTAMPTZ  NOT NULL,
    occurrence_count INT          DEFAULT 1,
    source_honeypots TEXT[],
    confidence       FLOAT        DEFAULT 1.0,
    tags             TEXT[],
    metadata         JSONB        DEFAULT '{}',
    created_at       TIMESTAMPTZ  DEFAULT NOW(),
    UNIQUE (ioc_type, ioc_value)
);

CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc_records (ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_seen ON ioc_records (first_seen DESC);

-- ---------------------------------------------------------------
-- 5. CREDENTIALS DICTIONARY
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS credentials (
    id              BIGSERIAL    PRIMARY KEY,
    username        TEXT         NOT NULL DEFAULT '',
    password        TEXT         NOT NULL DEFAULT '',
    first_seen      TIMESTAMPTZ  NOT NULL,
    last_seen       TIMESTAMPTZ  NOT NULL,
    attempt_count   INT          DEFAULT 1,
    success_count   INT          DEFAULT 0,
    source_ip_count INT          DEFAULT 0,
    UNIQUE (username, password)
);

CREATE INDEX IF NOT EXISTS idx_cred_count    ON credentials (attempt_count DESC);
CREATE INDEX IF NOT EXISTS idx_cred_username ON credentials (username);

-- ---------------------------------------------------------------
-- 6. DEVICE RECORDS  (Shodan / Censys weekly snapshots)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS device_records (
    id              BIGSERIAL    PRIMARY KEY,
    source          VARCHAR(10)  NOT NULL,   -- shodan | censys
    snapshot_date   DATE         NOT NULL,
    ip              INET         NOT NULL,
    port            INT,
    transport       VARCHAR(5),
    protocol        VARCHAR(30),
    product         TEXT,
    version         TEXT,
    cpe             TEXT[],
    cve_ids         TEXT[],
    country_code    CHAR(2),
    asn             BIGINT,
    org             TEXT,
    isp             TEXT,
    raw_banner      TEXT,
    raw_data        JSONB        NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_dr_unique   ON device_records (source, ip, port, snapshot_date);
CREATE INDEX        IF NOT EXISTS idx_dr_date     ON device_records (snapshot_date DESC);
CREATE INDEX        IF NOT EXISTS idx_dr_ip       ON device_records (ip);

-- ---------------------------------------------------------------
-- 7. GRAPH  (nodes + edges)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS graph_nodes (
    id          BIGSERIAL    PRIMARY KEY,
    node_type   VARCHAR(30)  NOT NULL,   -- ip|domain|url|c2|malware_hash
    node_value  TEXT         NOT NULL    UNIQUE,
    first_seen  TIMESTAMPTZ,
    last_seen   TIMESTAMPTZ,
    degree_in   INT          DEFAULT 0,
    degree_out  INT          DEFAULT 0,
    cluster_id  VARCHAR(100),
    metadata    JSONB        DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_gn_type    ON graph_nodes (node_type);
CREATE INDEX IF NOT EXISTS idx_gn_cluster ON graph_nodes (cluster_id);

CREATE TABLE IF NOT EXISTS graph_edges (
    id              BIGSERIAL    PRIMARY KEY,
    source_node_id  BIGINT       NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    target_node_id  BIGINT       NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    edge_type       VARCHAR(50)  NOT NULL,  -- downloads_from|resolves_to|same_campaign|c2_for
    weight          FLOAT        DEFAULT 1.0,
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    evidence        JSONB        DEFAULT '{}',
    UNIQUE (source_node_id, target_node_id, edge_type)
);

CREATE INDEX IF NOT EXISTS idx_ge_src  ON graph_edges (source_node_id);
CREATE INDEX IF NOT EXISTS idx_ge_tgt  ON graph_edges (target_node_id);
CREATE INDEX IF NOT EXISTS idx_ge_type ON graph_edges (edge_type);

-- ---------------------------------------------------------------
-- 8. CAMPAIGN CLUSTERS
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS campaign_clusters (
    id               BIGSERIAL    PRIMARY KEY,
    cluster_id       VARCHAR(100) UNIQUE NOT NULL,
    name             TEXT,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    active           BOOLEAN      DEFAULT TRUE,
    event_count      INT          DEFAULT 0,
    source_ip_count  INT          DEFAULT 0,
    primary_protocol VARCHAR(20),
    primary_creds    TEXT[],
    c2_ips           INET[],
    c2_domains       TEXT[],
    malware_hashes   TEXT[],
    metadata         JSONB        DEFAULT '{}'
);

-- ---------------------------------------------------------------
-- 9. IP ACTIVITY DAILY  (pre-aggregated for churn / survival)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_activity_daily (
    day             DATE         NOT NULL,
    source_ip       INET         NOT NULL,
    honeypot        VARCHAR(20)  NOT NULL,
    event_count     INT          DEFAULT 0,
    login_attempts  INT          DEFAULT 0,
    unique_sessions INT          DEFAULT 0,
    first_event     TIMESTAMPTZ,
    last_event      TIMESTAMPTZ,
    PRIMARY KEY (day, source_ip, honeypot)
);

CREATE INDEX IF NOT EXISTS idx_iad_day ON ip_activity_daily (day DESC);
CREATE INDEX IF NOT EXISTS idx_iad_ip  ON ip_activity_daily (source_ip);
