# Dionaea Installation Plan for Ubuntu 24.04 VPS

**Date**: May 5, 2026  
**VPS**: `167.172.187.18` (Ubuntu 24.04, 1GB RAM)  
**Goal**: Deploy Dionaea honeypot to capture HTTP/SMB/MySQL malware binaries on ports not covered by Cowrie  
**Logrotate status**: ✅ FIXED — `su cowrie cowrie` directive applied, rotating correctly as of May 5 15:00

---

## 0. Logrotate Confirmed Working

```
rotating pattern: cowrie.json  after 1 days (90 rotations)
switching euid from 0 to 1000 and egid from 0 to 1000  ← su directive worked
log does not need rotating (log has already been rotated)  ← already rotated today at 15:00
```

No further action needed on logrotate. Data retention is now 90 days.

---

## 1. Will Docker Conflict With Existing Services?

**Short answer: No — Docker itself does not conflict. Port conflicts might, and we handle them.**

Docker containers run in isolation. Running Dionaea in Docker on the same VPS as Cowrie is standard practice. The only conflicts to worry about:

### Current port ownership (check before starting):

```bash
# Run this on the VPS to see what's already bound:
ss -tlnp | grep -E ':21 |:80 |:445 |:1433 |:3306 '
```

Expected results and how to handle each:

| Port | Expected owner     | Conflict? | Resolution                               |
|------|-------------------|-----------|------------------------------------------|
| 21   | OpenCanary (FTP)  | YES       | Skip port 21 in Dionaea — leave OpenCanary |
| 80   | Nothing           | No        | Safe for Dionaea                         |
| 445  | Nothing           | No        | Safe for Dionaea                         |
| 1433 | Nothing           | No        | Safe for Dionaea                         |
| 3306 | Nothing (DB is on 5453) | No  | Safe for Dionaea                         |

> **Port 21 note**: Do NOT fight OpenCanary over port 21. Dionaea FTP adds minimal value compared to HTTP/SMB capture. Skip it.

---

## 2. Installation Options

### Option A — Docker (RECOMMENDED)

**Why Docker**: No build dependencies, no Ubuntu 24.04 packaging issues, isolated process, easy to remove.

**Does it require you to have set up Docker before?** No. As long as Docker is installed (`docker --version`), you can run Dionaea in a container without having used Docker for anything else on this VPS.

**Check Docker first**:
```bash
docker --version   # needs to succeed — if not, see install step below
docker ps          # shows any existing containers (e.g., your PostgreSQL DB)
```

**If Docker is not installed**:
```bash
apt install -y docker.io
systemctl enable --now docker
docker --version   # verify
```

---

### Option B — Build From Source (ALTERNATIVE if Docker unavailable)

Dionaea is NOT in Ubuntu 24.04 apt repos and NOT on PyPI. Building from source takes ~20 minutes but works on Ubuntu 24.04.

```bash
# Install all build dependencies
apt install -y \
  cmake check cython3 \
  libcurl4-openssl-dev libev-dev libglib2.0-dev \
  libnl-3-dev libnl-genl-3-dev libpcap-dev libssl-dev \
  libtool libudns-dev python3 python3-dev \
  python3-bson python3-yaml git ninja-build pkg-config

# libemu (shellcode emulation) — must build from source, not in Ubuntu 24.04 repos
cd /opt
git clone https://github.com/buffer/libemu.git
cd libemu
autoreconf -vi
./configure --prefix=/opt/libemu
make install
export PKG_CONFIG_PATH=/opt/libemu/lib/pkgconfig:$PKG_CONFIG_PATH

# Build Dionaea
cd /opt
git clone https://github.com/DinoTools/dionaea.git
cd dionaea
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/opt/dionaea \
      -DEMU_INCLUDE_DIRS=/opt/libemu/include \
      -DEMU_LIBRARIES=/opt/libemu/lib/libemu.so \
      ..
make -j2   # use 2 cores on 1GB VPS — -j4 may OOM
make install

# Create runtime dirs
mkdir -p /opt/dionaea/var/{log/dionaea,lib/dionaea/binaries,run}
```

> **Source build verdict**: Works but adds ~500MB of build deps and takes 20 min. Docker is cleaner. Only use source if Docker is unavailable.

---

## 3. Complete Docker Installation (Step-by-Step)

### Step 1 — Check current port state

```bash
ss -tlnp | grep -E ':21 |:80 |:445 |:1433 |:3306 '
# Note down what is bound vs free
```

### Step 2 — Create Dionaea data directories

```bash
mkdir -p /var/lib/dionaea/{binaries,bistreams,rtp}
mkdir -p /var/log/dionaea
```

### Step 3 — Pull and run Dionaea container

```bash
docker pull dinotools/dionaea

docker run -d \
  --name dionaea \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -p 445:445 \
  -p 1433:1433 \
  -p 3306:3306 \
  -v /var/lib/dionaea:/opt/dionaea/var/dionaea \
  -v /var/log/dionaea:/opt/dionaea/var/log/dionaea \
  dinotools/dionaea

# NOTE: Port 21 intentionally omitted — OpenCanary already owns it
```

### Step 4 — Verify it started

```bash
docker ps | grep dionaea
# Should show "Up X seconds"

docker logs dionaea --tail 30
# Look for: "dionaea ready" or listener startup messages
# If it crashed: docker logs dionaea --tail 100  (check error)

# Verify port bindings
ss -tlnp | grep -E ':80 |:445 |:3306 |:1433 '
# Should now show docker-proxy for each
```

### Step 5 — Add iptables RETURN rules

Dionaea ports must be excluded from Glutton's TPROXY catch-all or Glutton will intercept them:

```bash
iptables -t mangle -I PREROUTING 1 -p tcp --dport 80   -j RETURN
iptables -t mangle -I PREROUTING 1 -p tcp --dport 443  -j RETURN
iptables -t mangle -I PREROUTING 1 -p tcp --dport 445  -j RETURN
iptables -t mangle -I PREROUTING 1 -p tcp --dport 3306 -j RETURN
iptables -t mangle -I PREROUTING 1 -p tcp --dport 1433 -j RETURN

# Save so they survive reboot
netfilter-persistent save

# Verify — Dionaea RETURN rules should now appear at lines 1-5 (before TPROXY MARK rule)
iptables -t mangle -L PREROUTING -n --line-numbers | head -15
```

### Step 6 — Open UFW if active

```bash
# Check if UFW is active
ufw status

# If active, open Dionaea ports:
ufw allow 80/tcp   comment "Dionaea HTTP"
ufw allow 443/tcp  comment "Dionaea HTTPS"
ufw allow 445/tcp  comment "Dionaea SMB"
ufw allow 3306/tcp comment "Dionaea MySQL"
ufw allow 1433/tcp comment "Dionaea MSSQL"
ufw reload
```

### Step 7 — Wait 10 minutes then check captures

```bash
# Check if anything has been logged
ls -la /var/log/dionaea/

# Check for any SQLite activity (Dionaea logs to sqlite by default)
find /var/lib/dionaea -name "*.sqlite" -o -name "*.json" 2>/dev/null

# Check live logs
docker logs dionaea -f --tail 20
```

---

## 4. Dionaea Log Format and Where Files Are

Dionaea stores data in two forms:

### 4a — SQLite (default — all connection metadata)
```bash
# Location inside volume:
ls /var/lib/dionaea/*.sqlite   # or inside bistreams/

# Query directly:
sqlite3 /var/lib/dionaea/logsql.sqlite \
  "SELECT * FROM connections ORDER BY connection_timestamp DESC LIMIT 10;"
```

### 4b — Captured binaries
```bash
ls /var/lib/dionaea/binaries/
# Files are named by SHA256 hash: e.g., a3b4c5...ef.bin
```

### 4c — JSON log (for pipeline ingestion)
The `dinotools/dionaea` Docker image may not write JSON by default. To check:
```bash
ls /var/log/dionaea/
docker exec dionaea ls /opt/dionaea/var/log/dionaea/
```

If no JSON, query the SQLite DB directly in the pipeline ingestor.

---

## 5. Logrotate for Dionaea Logs

```bash
cat > /etc/logrotate.d/dionaea <<'EOF'
/var/log/dionaea/*.log {
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
```

---

## 6. Pull Dionaea Captures to Local Mac

Add to `Makefile` on local machine:

```makefile
pull-dionaea:
	@mkdir -p $(LOCAL_DATA)/raw-logs/dionaea
	@rsync -az --quiet \
	    -e "$(SSH_OPTS)" \
	    root@$(VPS):/var/lib/dionaea/ \
	    $(LOCAL_DATA)/raw-logs/dionaea/ >> $(LOG_DIR)/sync.log 2>&1
	@printf "Dionaea binaries pulled: "; ls $(LOCAL_DATA)/raw-logs/dionaea/binaries/ 2>/dev/null | wc -l
```

---

## 7. Troubleshooting

### Container exits immediately
```bash
docker logs dionaea   # read full output
# Common causes:
#   - Port already bound (another process owns :80 or :445)
#   - Volume mount permissions issue
```

### Port conflict — container won't start
```bash
# Find what owns the port:
ss -tlnp | grep ':80 '
# If OpenCanary is on port 80, edit opencanary config to move it, then retry
```

### Dionaea starts but no captures after 1 hour
```bash
# Confirm iptables RETURN rules are in place:
iptables -t mangle -L PREROUTING -n --line-numbers | grep -E 'dpt:80|dpt:445|dpt:3306'
# These must appear at LOWER line numbers than the TPROXY MARK rule

# Confirm ports are reachable from outside:
# From your Mac:
nc -zv 167.172.187.18 80
nc -zv 167.172.187.18 445
```

### Check Docker container resource usage
```bash
docker stats dionaea --no-stream
# On 1GB VPS: Dionaea should use < 100MB RAM
```

---

## 8. Expected Results Within 24 Hours

Once running, Dionaea should capture:

| Port | Attack type | Expected captures |
|------|-------------|-------------------|
| 445  | SMB scanner (Mirai SMB, EternalBlue) | Connection attempts within minutes |
| 3306 | MySQL credential brute-force | Login attempts within 1-2 hours |
| 80   | HTTP malware dropper (if attacker scans it) | Varies — may be slow |
| 1433 | MSSQL credential brute-force | Less common on IoT VPS |

**SMB (port 445) will show activity fastest** — Mirai variants and ransomware scanners hit 445 constantly.

---

## 9. Summary Checklist

```
[ ] docker --version   (Docker installed)
[ ] ss -tlnp   (confirm 80, 445, 3306, 1433 are free)
[ ] mkdir -p /var/lib/dionaea/{binaries,bistreams,rtp} /var/log/dionaea
[ ] docker pull dinotools/dionaea
[ ] docker run -d --name dionaea ... (Step 3 command above)
[ ] docker ps | grep dionaea   (confirm running)
[ ] iptables RETURN rules added for 80, 443, 445, 3306, 1433
[ ] netfilter-persistent save
[ ] ufw allow for Dionaea ports (if UFW active)
[ ] Wait 10 min, check: docker logs dionaea && ls /var/lib/dionaea/binaries/
[ ] Add pull-dionaea target to Makefile
```
