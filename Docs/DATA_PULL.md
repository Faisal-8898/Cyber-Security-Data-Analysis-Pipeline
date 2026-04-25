# Data Pull — Log Sync from VPS to Local Machine

Everything in the pipeline starts here. Raw logs are generated on the VPS by Cowrie, OpenCanary, and Glutton. The local machine pulls them over SSH via rsync every 30 minutes. No pipeline code runs on the VPS.

---

## Architecture

```
VPS (167.172.187.18, port 8443)              Local Machine
─────────────────────────────────            ──────────────────────────────
/home/cowrie/cowrie/var/log/cowrie/  ──rsync──▶  /data/raw-logs/cowrie/
/var/tmp/opencanary.log              ──rsync──▶  /data/raw-logs/opencanary/
/var/tmp/glutton.log                 ──rsync──▶  /data/raw-logs/glutton/
```

- All three pulls use the same `cowrie` user over SSH port 8443.
- The SSH key is restricted to rsync-only (`command="/usr/bin/rrsync -ro /"`) — no shell access.
- OpenCanary and Glutton logs are `chmod 644` (set via `ExecStartPost` in their systemd units) so the `cowrie` user can read them despite those services running as root.

---

## One-Time Setup

### Step 1 — Generate the sync key on your local Mac

```bash
ssh-keygen -t ed25519 -f ~/.ssh/research_key -C "iot-sync"

# Display the public key — you will paste this on the VPS
cat ~/.ssh/research_key.pub
```

### Step 2 — Add the key to the VPS (do this on the VPS)

```bash
# Already done if VPS_SETUP.md Step 9 is complete.
# If not: paste the public key with rrsync restriction:
echo 'command="/usr/bin/rrsync -ro /",no-pty,no-agent-forwarding,no-port-forwarding <PASTE_PUBLIC_KEY>' \
    >> /home/cowrie/.ssh/authorized_keys
chmod 600 /home/cowrie/.ssh/authorized_keys
```

### Step 3 — Create local target directories

**On macOS:**
```bash
mkdir -p ~/data/raw-logs/cowrie \
         ~/data/raw-logs/opencanary \
         ~/data/raw-logs/glutton \
         ~/data/iot-pipeline/logs
```

**On Linux (if running locally):**
```bash
sudo mkdir -p /data/raw-logs/cowrie \
              /data/raw-logs/opencanary \
              /data/raw-logs/glutton \
              /var/log/iot-pipeline
sudo chown -R $(whoami) /data/raw-logs /var/log/iot-pipeline
```

Then update your `.env`:
```dotenv
# macOS paths
COWRIE_LOG_PATH=~/data/raw-logs/cowrie/cowrie.json
OPENCANARY_LOG_PATH=~/data/raw-logs/opencanary/opencanary.log
PIPELINE_LOG_DIR=~/data/iot-pipeline/logs

# Linux paths (if applicable)
# COWRIE_LOG_PATH=/data/raw-logs/cowrie/cowrie.json
# OPENCANARY_LOG_PATH=/data/raw-logs/opencanary/opencanary.log
# PIPELINE_LOG_DIR=/var/log/iot-pipeline
```

### Step 4 — Pre-accept the VPS host key (prevents cron from blocking)

```bash
ssh -p 8443 -i ~/.ssh/research_key \
    -o StrictHostKeyChecking=accept-new \
    cowrie@167.172.187.18 exit 2>/dev/null || true
```

Run this once manually. After this, all automated pulls proceed without prompts.

---

## Manual Pull Commands

Use these for debugging, first-run verification, or ad-hoc syncs. Use `-avz` (verbose) instead of `-az --quiet` to see transfer progress.

```bash
VPS_IP=167.172.187.18
LOCAL_DATA_DIR=~/data  # macOS; on Linux use /data

# Pull Cowrie logs (entire directory mirror)
rsync -avz \
    -e "ssh -p 8443 -i ~/.ssh/research_key" \
    cowrie@${VPS_IP}:/home/cowrie/cowrie/var/log/cowrie/ \
    ${LOCAL_DATA_DIR}/raw-logs/cowrie/

# Pull OpenCanary log (single file)
rsync -avz \
    -e "ssh -p 8443 -i ~/.ssh/research_key" \
    cowrie@${VPS_IP}:/var/tmp/opencanary.log \
    ${LOCAL_DATA_DIR}/raw-logs/opencanary/

# Pull Glutton log (single file)
rsync -avz \
    -e "ssh -p 8443 -i ~/.ssh/research_key" \
    cowrie@${VPS_IP}:/var/tmp/glutton.log \
    ${LOCAL_DATA_DIR}/raw-logs/glutton/
```

---

## Automated Pull Commands (Cron / Pipeline)

For cron and pipeline use `-az --quiet` — no verbose output to prevent log bloat.

```bash
VPS_IP=167.172.187.18
KEY=~/.ssh/research_key
LOCAL_DATA_DIR=~/data          # macOS; on Linux use /data
LOG_DIR=~/data/iot-pipeline/logs  # macOS; on Linux use /var/log/iot-pipeline
SSH_OPTS="-e \"ssh -p 8443 -i ${KEY}\""

rsync -az --quiet ${SSH_OPTS} \
    cowrie@${VPS_IP}:/home/cowrie/cowrie/var/log/cowrie/ \
    ${LOCAL_DATA_DIR}/raw-logs/cowrie/ >> ${LOG_DIR}/sync.log 2>&1

rsync -az --quiet ${SSH_OPTS} \
    cowrie@${VPS_IP}:/var/tmp/opencanary.log \
    ${LOCAL_DATA_DIR}/raw-logs/opencanary/ >> ${LOG_DIR}/sync.log 2>&1

rsync -az --quiet ${SSH_OPTS} \
    cowrie@${VPS_IP}:/var/tmp/glutton.log \
    ${LOCAL_DATA_DIR}/raw-logs/glutton/ >> ${LOG_DIR}/sync.log 2>&1
```

**rsync flags explained:**
- `-a` (archive): preserves file timestamps — critical because `collected_at` in the DB is set from file mtime
- `-z`: compress in transit — reduces bandwidth on large log files
- `--quiet`: suppress non-error output — keeps cron/pipeline logs clean
- `-v` / `--verbose`: use this interactively for debugging

---

## Cron Wiring

Add to your local crontab (`crontab -e`). Replace variables as needed:

```cron
VPS=167.172.187.18
KEY=/Users/faisal/.ssh/research_key
PIPELINE_PATH=/Users/faisal/Documents/Me_and_Myself/varsity-Course/488cse/Cyber-Security-Data-Analysis-Pipeline
LOCAL_DATA=~/data
LOG_DIR=~/data/iot-pipeline/logs

# ── Pull logs from VPS every 30 minutes ──────────────────────────────────────
*/30 * * * *  rsync -az --quiet -e "ssh -p 8443 -i ${KEY}" \
    cowrie@${VPS}:/home/cowrie/cowrie/var/log/cowrie/ \
    ${LOCAL_DATA}/raw-logs/cowrie/ >> ${LOG_DIR}/sync.log 2>&1

*/30 * * * *  rsync -az --quiet -e "ssh -p 8443 -i ${KEY}" \
    cowrie@${VPS}:/var/tmp/opencanary.log \
    ${LOCAL_DATA}/raw-logs/opencanary/ >> ${LOG_DIR}/sync.log 2>&1

*/30 * * * *  rsync -az --quiet -e "ssh -p 8443 -i ${KEY}" \
    cowrie@${VPS}:/var/tmp/glutton.log \
    ${LOCAL_DATA}/raw-logs/glutton/ >> ${LOG_DIR}/sync.log 2>&1

# ── Ingest + extract (5-min offset: rsync runs at :00/:30, ingest at :05/:35) ─
5,35 * * * *  cd ${PIPELINE_PATH} && \
    .venv/bin/python3 -m pipeline.run --tasks ingest,extract \
    >> ${LOG_DIR}/run.log 2>&1

# ── Daily churn aggregation: 01:00 UTC ───────────────────────────────────────
0 1 * * *     cd ${PIPELINE_PATH} && \
    .venv/bin/python3 -m pipeline.run --tasks aggregate_churn \
    >> ${LOG_DIR}/daily.log 2>&1

# ── Shodan + Censys weekly snapshot: Sunday 02:00 UTC ────────────────────────
0 2 * * 0     cd ${PIPELINE_PATH} && \
    .venv/bin/python3 -m pipeline.run --tasks poll \
    >> ${LOG_DIR}/weekly.log 2>&1

# ── Graph build + campaign clustering: Sunday 04:00 UTC ──────────────────────
0 4 * * 0     cd ${PIPELINE_PATH} && \
    .venv/bin/python3 -m pipeline.run --tasks build_graph,cluster \
    >> ${LOG_DIR}/weekly.log 2>&1
```

> **Why :05 and :35?** The rsync runs at :00 and :30. The 5-minute offset ensures rsync finishes before the ingest task reads the local mirror. This prevents reading a partially-written file mid-transfer.

---

## Log Sources Reference

| Log | VPS path | Local mirror | Updated by |
|-----|----------|--------------|------------|
| Cowrie (SSH/Telnet) | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` | `~/data/raw-logs/cowrie/cowrie.json` | Cowrie (JSONL, appended per event) |
| OpenCanary (multi-protocol) | `/var/tmp/opencanary.log` | `/data/raw-logs/opencanary/opencanary.log` | OpenCanary (JSONL, appended per event) |
| Glutton (catch-all TCP) | `/var/tmp/glutton.log` | `/data/raw-logs/glutton/glutton.log` | Glutton (TPROXY, appended per connection) |

All logs are **append-only** — rsync (without `--delete`) never removes bytes already pulled.

---

## Bookmark System

The pipeline uses byte-offset bookmarks stored in `PIPELINE_STATE_DIR` (default: `/var/lib/iot-pipeline`). Each run reads only new bytes appended since the last run.

```
/var/lib/iot-pipeline/
  cowrie.bookmark.json       {"inode": 12345, "offset": 219847, "head_hash": "a3f9..."}
  opencanary.bookmark.json   {"inode": 67890, "offset": 45123,  "head_hash": "b7c2..."}
```

**Rotation detection**: If the inode changes or the first 512 bytes of the file differ from the saved hash, the bookmark resets to offset 0 and re-reads from the beginning. This handles rsync log rotation on the VPS gracefully.

**Recovery**: If a pipeline run crashes mid-read, simply re-run. The bookmark was not yet updated for the failed lines, so they will be re-processed. All DB writes use `INSERT ... ON CONFLICT DO UPDATE` (idempotent) — re-processing a line is always safe.

---

## Troubleshooting

### SSH connection fails

```bash
# Test the key manually
ssh -p 8443 -i ~/.ssh/research_key cowrie@167.172.187.18 exit
# Expected: exits immediately (no prompt — forced rrsync command runs then exits)
# If you see: "Permission denied" → public key not in authorized_keys on VPS
# If you see: "Connection refused" → VPS sshd is down; check ssh.socket on VPS
# If you see: "banner line contains invalid characters" → Glutton is intercepting;
#   add iptables -t mangle -I PREROUTING -p tcp --dport 8443 -j RETURN on VPS
```

### rsync exits with error 23 (partial transfer)

```bash
# Check the VPS log permissions
ssh -p 8443 -i ~/.ssh/research_key cowrie@167.172.187.18 \
    'ls -la /var/tmp/opencanary.log /var/tmp/glutton.log'
# Both must show -rw-r--r-- (644). If not, on the VPS:
chmod 644 /var/tmp/opencanary.log /var/tmp/glutton.log
```

### No new events appearing

```bash
LOCAL_DATA=~/data

# 1. Are logs actually growing on the VPS?
ssh -p 8443 -i ~/.ssh/research_key -o StrictHostKeyChecking=yes \
    cowrie@167.172.187.18 'wc -l /home/cowrie/cowrie/var/log/cowrie/cowrie.json'

# 2. Is the local mirror up to date?
wc -l ${LOCAL_DATA}/raw-logs/cowrie/cowrie.json

# 3. What does the pipeline think the bookmark is?
cat $(python3 -c 'import os; print(os.environ.get("PIPELINE_STATE_DIR", "/var/lib/iot-pipeline"))')/cowrie.bookmark.json

# 4. Force a manual pull
rsync -avz -e "ssh -p 8443 -i ~/.ssh/research_key" \
    cowrie@167.172.187.18:/home/cowrie/cowrie/var/log/cowrie/ \
    ${LOCAL_DATA}/raw-logs/cowrie/
```

### Reset bookmark (re-ingest from beginning)

```bash
BOOKMARK_DIR=$(python3 -c 'import os; print(os.environ.get("PIPELINE_STATE_DIR", "/var/lib/iot-pipeline"))')
rm "${BOOKMARK_DIR}/cowrie.bookmark.json"
rm "${BOOKMARK_DIR}/opencanary.bookmark.json"
# Next pipeline run will re-read all lines. DB writes are idempotent — safe.
```

### Check what the pipeline last processed

```bash
# Query the pipeline_runs provenance table
psql "$DATABASE_URL" -c "
SELECT task_name, started_at, status, records_in, records_out, source_files
FROM pipeline_runs
ORDER BY started_at DESC
LIMIT 10;
"
```

---

## Security Notes

- The VPS SSH key (`research_key`) should have `chmod 600`.
- The `command=` restriction on the VPS means the key cannot open a shell — only rsync reads are permitted.
- Never add this key to `ssh-agent` with unlimited lifetime; prefer `AddKeysToAgent confirm` in `~/.ssh/config`.
- The key is separate from your admin key — losing it means editing `authorized_keys` on the VPS and regenerating, with no broader access impact.
