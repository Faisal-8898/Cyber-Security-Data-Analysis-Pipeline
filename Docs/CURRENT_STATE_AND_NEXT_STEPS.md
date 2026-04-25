# Current State & Next Steps

---

## What You Have Right Now

| Source | Local File | Lines | Status |
|---|---|---|---|
| Cowrie (SSH/Telnet) | `~/data/raw-logs/cowrie/cowrie.json` | **104 events** | Ready to ingest |
| OpenCanary | `~/data/raw-logs/opencanary/opencanary.log` | 0 | Not capturing — fix below |
| Glutton | `~/data/raw-logs/glutton/glutton.log` | 0 | Not capturing — fix below |
| PostgreSQL | `localhost:5453` | Running 44h | Healthy, schema applied |
| Shodan/Censys | Another machine's Docker | — | Import when ready — skip for now |

---

## How Data Flows Into the Database

### Honeypot Data (Cowrie / OpenCanary / Glutton)

```
VPS log file  →  rsync pull  →  ~/data/raw-logs/  →  pipeline.run ingest  →  PostgreSQL
```

**Table mapping:**

| What | DB Table | Written by |
|---|---|---|
| Every raw event (connection, login attempt, command, download) | `honeypot_events` | `ingest_cowrie` / `ingest_opencanary` |
| Unique attacker IPs (first/last seen, country, ASN) | `source_ips` | updated during ingest |
| Extracted IOCs (URLs, domains, hashes, credentials, commands) | `ioc_records` | `extract_iocs` task |
| Username/password pairs seen across all attacks | `credentials` | `extract_iocs` task |
| Daily per-IP activity rollup (for churn/survival analysis) | `ip_activity_daily` | `aggregate_churn` task (daily) |
| Audit trail of every pipeline run | `pipeline_runs` | every task, automatically |

**Key design facts:**
- Every write is `INSERT ... ON CONFLICT DO UPDATE` — re-running is always safe.
- `raw_file_path + raw_line_number + event_time` is the dedup key — same log line never double-inserted.
- `raw_data JSONB` column stores the original JSON verbatim — nothing is lost.
- Table is partitioned by month (`honeypot_events_2026_04`, `_05`, etc.).

### Shodan / Censys Data (when it arrives)

```
Other machine's Docker export  →  import into local PostgreSQL  →  device_records
```

**Table mapping:**

| What | DB Table |
|---|---|
| Every IP:port scan result with banner, device type, CVEs, ASN | `device_records` |
| Log of each query run (for reproducibility) | `shodan_query_runs` |

`device_records` dedup key: `(source, ip, port, snapshot_week)` — same device appearing in multiple queries in the same week is merged via UPSERT.

### Graph + Campaigns (later, after both datasets are in)

```
honeypot_events + ioc_records + device_records  →  build_graph  →  graph_nodes + graph_edges + campaign_clusters
```

**Do not run this yet** — graph is only meaningful with Shodan/Censys data included.

---

## Commands to Run Right Now

### Step 1 — Pull latest Cowrie logs from VPS

```bash
rsync -avz \
    -e "ssh -p 8443 -i ~/.ssh/research_key" \
    cowrie@167.172.187.18:/home/cowrie/cowrie/var/log/cowrie/ \
    ~/data/raw-logs/cowrie/
```

### Step 2 — Ingest Cowrie data into PostgreSQL

```bash
cd /Users/faisal/Documents/Me_and_Myself/varsity-Course/488cse/Cyber-Security-Data-Analysis-Pipeline
.venv/bin/python3 -m pipeline.run --tasks ingest_cowrie,extract
```

### Step 3 — Run daily churn aggregation

```bash
.venv/bin/python3 -m pipeline.run --tasks aggregate_churn
```

### Step 4 — Verify what went in

```bash
psql "postgresql://pipeline:pipepipe@localhost:5453/iot_research" -c "
SELECT honeypot, event_type, COUNT(*) as n
FROM honeypot_events
GROUP BY honeypot, event_type
ORDER BY n DESC;
"
```

```bash
psql "postgresql://pipeline:pipepipe@localhost:5453/iot_research" -c "
SELECT ioc_type, COUNT(*) as n FROM ioc_records GROUP BY ioc_type ORDER BY n DESC;
"
```

---

## Is the Data Worth It? (Quick Evaluation After Ingest)

Run these queries after Step 2–3 above:

```sql
-- How many unique attacker IPs?
SELECT COUNT(DISTINCT source_ip) FROM honeypot_events;

-- Top 10 credentials attempted
SELECT username, password, attempt_count
FROM credentials ORDER BY attempt_count DESC LIMIT 10;

-- Any malware download URLs captured?
SELECT ioc_value, occurrence_count
FROM ioc_records WHERE ioc_type = 'url' ORDER BY occurrence_count DESC LIMIT 10;

-- Any post-login commands captured? (Mirai-style)
SELECT ioc_value FROM ioc_records WHERE ioc_type = 'command' LIMIT 20;

-- Event timeline
SELECT date_trunc('day', event_time) as day, COUNT(*) as events
FROM honeypot_events GROUP BY 1 ORDER BY 1;
```

**Minimum viable data thresholds for a conference paper:**
- 500+ unique attacker IPs across the collection window — you're on your way
- At least one captured download URL or command string — qualitative IoC content
- 2+ weeks of events — enough for a churn curve

104 lines from one pull is a start. Let it run for 2–4 more weeks.

---

## Fixing OpenCanary and Glutton (Zero Data Problem)

Check on the VPS:

```bash
ssh -p 8443 -i ~/.ssh/research_key cowrie@167.172.187.18 \
    'ls -la /var/tmp/opencanary.log /var/tmp/glutton.log'
```

If files don't exist or are empty:

```bash
# On the VPS — check if services are running
ssh -p 2222 -i ~/.ssh/YOUR_ADMIN_KEY root@167.172.187.18 \
    'systemctl status opencanary glutton'
```

If services are down, restart them and ensure `chmod 644` on the logs:

```bash
# On VPS
systemctl restart opencanary
chmod 644 /var/tmp/opencanary.log
```

---

## Future: Fixing the 30-Minute Pull (Laptop Problem)

The cron approach breaks when the laptop sleeps. Two fixes:

### Option A — macOS `launchd` (recommended for laptop)

`launchd` wakes the job when the machine wakes up, catching up on missed intervals. Create `/Library/LaunchDaemons/com.iot.logsync.plist` (runs as root) or `~/Library/LaunchAgents/com.iot.logsync.plist` (runs as your user):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.iot.logsync</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/zsh</string>
        <string>-c</string>
        <string>
rsync -az --quiet -e "ssh -p 8443 -i /Users/faisal/.ssh/research_key" \
    cowrie@167.172.187.18:/home/cowrie/cowrie/var/log/cowrie/ \
    /Users/faisal/data/raw-logs/cowrie/ >> /Users/faisal/data/iot-pipeline/logs/sync.log 2>&1 &amp;&amp;
rsync -az --quiet -e "ssh -p 8443 -i /Users/faisal/.ssh/research_key" \
    cowrie@167.172.187.18:/var/tmp/opencanary.log \
    /Users/faisal/data/raw-logs/opencanary/ >> /Users/faisal/data/iot-pipeline/logs/sync.log 2>&1
        </string>
    </array>
    <key>StartInterval</key>
    <integer>1800</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/Users/faisal/data/iot-pipeline/logs/launchd-sync-error.log</string>
</dict>
</plist>
```

Load it:

```bash
launchctl load ~/Library/LaunchAgents/com.iot.logsync.plist
launchctl start com.iot.logsync
```

### Option B — Pull manually before each work session (simplest, acceptable for research)

The VPS **keeps all logs forever** — you never lose data. Pulling once a day or even once a week is fine. Just run the rsync + ingest commands at the start of each session. The bookmark system ensures only new bytes are processed.

```bash
# One-command session start
cd /Users/faisal/Documents/Me_and_Myself/varsity-Course/488cse/Cyber-Security-Data-Analysis-Pipeline

rsync -avz -e "ssh -p 8443 -i ~/.ssh/research_key" \
    cowrie@167.172.187.18:/home/cowrie/cowrie/var/log/cowrie/ \
    ~/data/raw-logs/cowrie/ && \
.venv/bin/python3 -m pipeline.run --tasks ingest_cowrie,extract,aggregate_churn
```

---

## What to Skip Until Shodan/Censys Data Arrives

- `poll_shodan` / `poll_censys` tasks — only run after importing from the other machine
- `build_graph` / `cluster` tasks — meaningless without device_records populated
- Any monetization/proxy overlap analysis — needs both datasets

---

## Complete Sequence (When Shodan/Censys Data Arrives)

1. Export `device_records` from the other machine's PostgreSQL:
   ```bash
   pg_dump -h localhost -U pipeline -d iot_research -t device_records -t shodan_query_runs \
       --data-only -F c -f device_records_export.dump
   ```
2. Import here:
   ```bash
   pg_restore -h localhost -p 5453 -U pipeline -d iot_research device_records_export.dump
   ```
3. Then run graph build:
   ```bash
   .venv/bin/python3 -m pipeline.run --tasks build_graph,cluster
   ```
