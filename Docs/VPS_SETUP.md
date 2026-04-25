# VPS Setup — DigitalOcean Droplet (1 GB RAM · Ubuntu)

> **You are on the VPS root now. Follow steps in order. Do not skip hardening before honeypots.**

---

## STEP 1 — Harden the VPS First

### 1.0 Set root password (console emergency access)

> **Do this first — before touching SSH.** The DO web console authenticates via Linux root password, which is **locked by default** on Ubuntu 24.04 droplets regardless of what you set at droplet creation (that password goes to the `ubuntu` user, not `root`). Without this, the console shows "All configured authenticate methods failed" and you have no fallback if SSH ever breaks.

```bash
passwd root
# Set a strong password and store it in your password manager.

# Clear any pam_faillock failures accumulated before the password was set.
# Ubuntu 24.04 PAM locks accounts after failed console attempts — this resets it.
faillock --user root --reset

# Verify it works: open DO console → log in as root with that password.
```

---

### 1.1 Move real SSH off port 22 (Cowrie will own port 22)

> **Do this while connected via the DigitalOcean console (not SSH) on first setup.**

```bash
# Add your SSH public key FIRST (paste your local ~/.ssh/YOUR_KEY.pub content)
mkdir -p /root/.ssh
chmod 700 /root/.ssh
echo 'PASTE_YOUR_PUBLIC_KEY_HERE' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Rewrite sshd_config cleanly with sed (no manual nano — avoids typos)
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cat > /etc/ssh/sshd_config <<'EOF'
Port 2222
PermitRootLogin yes
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

# Create an independent sshd service — avoids all Ubuntu 24.04 ssh.socket issues.
# Do NOT touch ssh.service or ssh.socket. Just create a new unit that reads
# sshd_config directly (Port 2222 is already set there).
cat > /etc/systemd/system/sshd-admin.service <<'EOF'
[Unit]
Description=Admin SSH on port 2222
After=network.target

[Service]
Type=notify
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sshd-admin

# Verify sshd is up on 2222
ss -tlnp | grep ':2222'
```

> **Warning**: Open a second terminal and verify `ssh -i ~/.ssh/YOUR_KEY -p 2222 root@YOUR_VPS_IP` works BEFORE continuing.

> **Why `PermitRootLogin yes`**: Using `prohibit-password` with a fresh key risks lockout if the key isn't in place yet. Set to `yes` initially, change to `prohibit-password` after confirming key login works.

> **Why a new service instead of modifying ssh.service**: Ubuntu 24.04's `ssh.service` has `BindsTo=ssh.socket` and `Also=ssh.socket`. Masking `ssh.socket` while using `ssh.service` causes an unresolvable "Unit ssh.socket is masked" error regardless of drop-ins or copies. Creating `sshd-admin.service` as an independent unit bypasses the entire socket activation system — it simply runs `/usr/sbin/sshd -D` which reads `sshd_config` (Port 2222 already set). The original `ssh.service`/`ssh.socket` are left untouched.

---

### 1.2 UFW Firewall

```bash
ufw default deny incoming
ufw default allow outgoing

# Real SSH
ufw allow 2222/tcp  comment "real SSH"

# Honeypot attack surface (intentionally exposed)
ufw allow 22/tcp    comment "Cowrie SSH"
ufw allow 23/tcp    comment "Cowrie Telnet"
ufw allow 80/tcp    comment "OpenCanary HTTP"
ufw allow 8080/tcp  comment "OpenCanary HTTP-alt / IoT admin panel"
ufw allow 21/tcp    comment "OpenCanary FTP"
ufw allow 25/tcp    comment "OpenCanary SMTP"
ufw allow 7547/tcp  comment "TR-069/CWMP router exploit"
ufw allow 5555/tcp  comment "ADB Android/IoT"
ufw allow 1883/tcp  comment "MQTT IoT broker"
ufw allow 1080/tcp  comment "SOCKS proxy — monetization signal"
ufw allow 3128/tcp  comment "HTTP proxy — monetization signal"
ufw allow 48101/tcp comment "Mirai C2 variant port"

ufw enable
ufw status verbose
```

---

### 1.3 Swapfile (OOM protection)

```bash
fallocate -l 1G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
sysctl vm.swappiness=10
echo 'vm.swappiness=10' >> /etc/sysctl.conf
```

---

### 1.4 Fail2Ban on real SSH

```bash
apt install -y fail2ban python3-systemd

cat > /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled  = true
port     = 2222
filter   = sshd
backend  = systemd
maxretry = 3
bantime  = 3600
findtime = 600
EOF

systemctl enable --now fail2ban
```

---

### 1.5 Auto security updates

```bash
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
# Select "Yes" when prompted
```

Edit `/etc/apt/apt.conf.d/50unattended-upgrades` and set:
```
Unattended-Upgrade::Automatic-Reboot "false";
```

---

## STEP 2 — Install Cowrie (SSH/Telnet Honeypot)

```bash
# python3-venv (NOT python3-virtualenv), libpython3-dev, authbind are required by official Cowrie docs
apt install -y git python3-venv python3-pip libssl-dev libffi-dev build-essential python3-dev libpython3-dev python3-minimal authbind

# Suppress needrestart from trying to restart the broken ssh.service on every apt install
# (needrestart fires after apt and always attempts to restart ssh.service which fails — harmless but noisy)
sed -i 's/#$nrconf{restart} = .*/\$nrconf{restart} = '"'"'a'"'"';/' /etc/needrestart/needrestart.conf

# Create dedicated non-root user
adduser --disabled-password --gecos "" cowrie

# Install as cowrie user
sudo -u cowrie bash -c "
    cd /home/cowrie
    git clone https://github.com/cowrie/cowrie
    cd cowrie
    python3 -m venv cowrie-env
    source cowrie-env/bin/activate
    pip install --upgrade pip
    pip install -e .
"
```

Create clean Cowrie config at `/home/cowrie/cowrie/etc/cowrie.cfg`:
```bash
sudo -u cowrie tee /home/cowrie/cowrie/etc/cowrie.cfg > /dev/null <<'EOF'
[honeypot]
hostname = nas-disk-station
download_limit_size = 10485760
fake_addr = 10.0.0.1

[ssh]
listen_endpoints = tcp:22:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:23:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json

[output_mysql]
enabled = false
EOF
```

Create systemd service file `/etc/systemd/system/cowrie.service`:
```bash
cat > /etc/systemd/system/cowrie.service <<'EOF'
[Unit]
Description=A SSH and Telnet honeypot service
After=network.target
Before=sshd-admin.service

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/cowrie

ExecStart=/home/cowrie/cowrie/cowrie-env/bin/twistd \
    --nodaemon \
    --umask=0022 \
    --pidfile=/home/cowrie/cowrie/var/run/cowrie.pid \
    -l /home/cowrie/cowrie/var/log/cowrie/cowrie.log \
    cowrie

Restart=always
RestartSec=10
MemoryMax=250M
CPUQuota=25%
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=/home/cowrie/cowrie/var

[Install]
WantedBy=multi-user.target
EOF
```

**CRITICAL — patch cowrie.cfg.dist before starting** (it has active `listen_endpoints = tcp:2222` lines that steal your admin SSH port):
```bash
# Comment out the active default port lines in .dist file
sed -i 's/^listen_endpoints = tcp:2222:interface=0.0.0.0/# listen_endpoints = tcp:2222:interface=0.0.0.0/' \
    /home/cowrie/cowrie/etc/cowrie.cfg.dist
sed -i 's/^listen_endpoints = tcp:2223:interface=0.0.0.0/# listen_endpoints = tcp:2223:interface=0.0.0.0/' \
    /home/cowrie/cowrie/etc/cowrie.cfg.dist

# Verify no active listen_endpoints remain in .dist (must return NO output)
grep '^listen_endpoints' /home/cowrie/cowrie/etc/cowrie.cfg.dist
```

Start the service:
```bash
rm -f /home/cowrie/cowrie/var/run/cowrie.pid /home/cowrie/cowrie/twistd.pid
systemctl daemon-reload
systemctl enable cowrie
systemctl restart cowrie
sleep 5
systemctl status cowrie
ss -tlnp | grep -E ':22 |:23 '

# Confirm port 2222 is still sshd (NOT cowrie)
ss -tlnp | grep ':2222'
# Expected: users:(("sshd",...))  — if it shows twistd, cowrie.cfg.dist patch failed
```

Expected output: twistd on ports 22+23, sshd on 2222.

---

## STEP 3 — Install OpenCanary (Multi-Protocol Alerting)

```bash
apt install -y python3-pip python3-dev python3-venv

# Install in a dedicated venv (global pip install breaks due to apt-managed packages)
python3 -m venv /opt/opencanary-env
/opt/opencanary-env/bin/pip install --upgrade pip
/opt/opencanary-env/bin/pip install opencanary

# Generate default config (creates /etc/opencanaryd/)
/opt/opencanary-env/bin/opencanaryd --copyconfig
```

Replace `/etc/opencanaryd/opencanary.conf` with:
```bash
cat > /etc/opencanaryd/opencanary.conf <<'EOF'
{
    "device.node_id": "iot-honeypot-do-01",
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
    "mysql.enabled": false,
    "smtp.enabled": true,
    "smtp.port": 25,
    "snmp.enabled": false,
    "telnet.enabled": true,
    "telnet.port": 2323,
    "ssh.enabled": false
}
EOF
```

> Note: `mysql.enabled` is false — port 3306 is not in UFW rules and is noisy.

```bash
cat > /etc/systemd/system/opencanary.service <<'EOF'
[Unit]
Description=OpenCanary Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/opt/opencanary-env/bin/opencanaryd --dev
ExecStartPost=/bin/bash -c 'touch /var/tmp/opencanary.log && chmod 644 /var/tmp/opencanary.log'
Restart=always
RestartSec=10
MemoryMax=50M

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now opencanary
sleep 3
systemctl status opencanary
ss -tlnp | grep -E ':21\b|:2323\b|:8080\b'
```

✅ **OpenCanary is now running** — ports 21 (FTP), 2323 (Telnet), 8080 (HTTP) bound successfully.

> **Note on SMTP (port 25)**: OpenCanary v0.9.7 has limited SMTP support and does not reliably bind to port 25 despite config settings. FTP, Telnet (2323), and HTTP (8080) are fully functional. If needed, Glutton (STEP 4) will catch port 25 traffic on unclaimed ports via TPROXY, so coverage is not lost.

---

## STEP 4 — Install Glutton (Catch-All TCP)

### Build Glutton from Source

`go install` does not work for Glutton — it requires CGO (libpcap) and a Makefile. The binary is named `server`, not `glutton`.

```bash
apt install -y golang-go gcc libpcap-dev iptables

# Detect primary network interface (usually eth0 on DigitalOcean)
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
echo "Interface: $IFACE"        # Verify before proceeding

git clone https://github.com/mushorg/glutton.git /opt/glutton
cd /opt/glutton
make build

# Verify binary
bin/server --version
```

### Set Up Kernel Routing for TPROXY

TPROXY only *marks* packets — the kernel also needs routing rules to deliver marked packets to the local Glutton socket. Without these, marked packets are silently dropped.

```bash
ip rule add fwmark 0x1/0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

# Verify
ip rule show | grep 100
ip route show table 100
```

Persist routing rules via a oneshot systemd unit (these are not saved by `netfilter-persistent`):

```bash
cat > /etc/systemd/system/honeypot-routing.service <<'EOF'
[Unit]
Description=TPROXY Routing Rules for Glutton
Before=glutton.service
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "\
  ip rule add fwmark 0x1/0x1 lookup 100 2>/dev/null || true; \
  ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true"

[Install]
WantedBy=multi-user.target
EOF

systemctl enable honeypot-routing
```

### Protect Cowrie and OpenCanary from Glutton's TPROXY

Glutton appends a single mangle PREROUTING rule that redirects ALL TCP except one excluded port (`--ssh 22`) to itself. Without RETURN rules inserted beforehand, Glutton will silently hijack traffic arriving at ports 23, 21, 25, 8080 and 2323 — breaking Cowrie and OpenCanary.

Insert RETURN rules first (order matters — these must run before Glutton starts each boot):

```bash
apt install -y iptables-persistent

# Skip known honeypot ports — Glutton catches everything else
iptables -t mangle -I PREROUTING -p tcp --dport 2222 -j RETURN  # Real SSH
iptables -t mangle -I PREROUTING -p tcp --dport 23   -j RETURN  # Cowrie Telnet
iptables -t mangle -I PREROUTING -p tcp --dport 21   -j RETURN  # OpenCanary FTP
iptables -t mangle -I PREROUTING -p tcp --dport 25   -j RETURN  # OpenCanary SMTP
iptables -t mangle -I PREROUTING -p tcp --dport 8080 -j RETURN  # OpenCanary HTTP
iptables -t mangle -I PREROUTING -p tcp --dport 2323 -j RETURN  # OpenCanary Telnet
# Port 22 is already excluded by Glutton's own --ssh 22 flag

netfilter-persistent save
```

### Create Systemd Service

```bash
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

cat > /etc/systemd/system/glutton.service <<EOF
[Unit]
Description=Glutton Catch-All TCP Honeypot
After=network.target honeypot-routing.service

[Service]
Type=simple
WorkingDirectory=/opt/glutton
ExecStart=/opt/glutton/bin/server --interface ${IFACE} --ssh 22 --logpath /var/tmp/glutton.log --var-dir /var/lib/glutton
ExecStartPost=/bin/bash -c 'touch /var/tmp/glutton.log && chmod 644 /var/tmp/glutton.log'
Restart=always
RestartSec=10
MemoryMax=50M

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /var/lib/glutton

systemctl daemon-reload
systemctl enable honeypot-routing glutton
systemctl start honeypot-routing
systemctl start glutton
sleep 3
systemctl status glutton
```

✅ **Glutton is now running** — catch-all TCP listener active on eth0, TPROXY routing in place.

> Glutton must run as root — it requires `CAP_NET_ADMIN`/`CAP_NET_RAW` for TPROXY socket operations. `User=nobody` or `NoNewPrivileges=yes` will cause immediate failure.

---

## STEP 5 — Outbound Firewall for Cowrie (block malware propagation)

```bash
# Allow Cowrie to do reverse DNS lookups on attacker IPs
iptables -A OUTPUT -m owner --uid-owner cowrie -p udp --dport 53 -j ACCEPT
# Allow Cowrie to download malware samples
iptables -A OUTPUT -m owner --uid-owner cowrie -p tcp --dport 80  -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner cowrie -p tcp --dport 443 -j ACCEPT
# Block all other outbound from Cowrie (prevent propagation)
iptables -A OUTPUT -m owner --uid-owner cowrie -p tcp             -j DROP
iptables -A OUTPUT -m owner --uid-owner cowrie -p udp             -j DROP

netfilter-persistent save
```

> The final DROP rules are protocol-specific (`-p tcp` / `-p udp`). Without this, a bare `-j DROP` would also block Cowrie's DNS lookups (UDP/53), causing log delays and hostname resolution failures.

---

## STEP 6 — Process Watchdog (Monit)

```bash
apt install -y monit

cat > /etc/monit/conf.d/honeypots <<'EOF'
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

check process glutton
    matching "glutton/bin/server"
    start program = "/bin/systemctl start glutton"
    stop program  = "/bin/systemctl stop glutton"
    if not exist then restart
EOF

systemctl enable --now monit
```

---

## STEP 7 — Health Check Script

```bash
cat > /usr/local/bin/honeypot_healthcheck.py <<'PYEOF'
#!/usr/bin/env python3
import json, time
from datetime import datetime, timedelta, timezone
from pathlib import Path

COWRIE_LOG     = Path("/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
OPENCANARY_LOG = Path("/var/tmp/opencanary.log")
GLUTTON_LOG    = Path("/var/tmp/glutton.log")
HEALTH_LOG     = Path("/var/log/honeypot_health.log")

def check_freshness(path, max_age_min=30):
    if not path.exists():
        return f"MISSING: {path}"
    age = time.time() - path.stat().st_mtime
    if age > max_age_min * 60:
        return f"STALE ({age/60:.0f}m): {path.name}"
    return f"OK: {path.name} ({age:.0f}s ago)"

def count_recent_events(path, minutes=60):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    count = 0
    try:
        for line in open(path):
            try:
                if json.loads(line).get("timestamp","") > cutoff:
                    count += 1
            except Exception:
                pass
    except Exception:
        pass
    return count

ts = datetime.now().isoformat()
HEALTH_LOG.parent.mkdir(parents=True, exist_ok=True)
with open(HEALTH_LOG, "a") as f:
    f.write(f"[{ts}] Cowrie={check_freshness(COWRIE_LOG)} | "
            f"Canary={check_freshness(OPENCANARY_LOG)} | "
            f"Glutton={check_freshness(GLUTTON_LOG)} | "
            f"Events/1h={count_recent_events(COWRIE_LOG)}\n")
PYEOF

chmod +x /usr/local/bin/honeypot_healthcheck.py
```

---

## STEP 8 — VPS Crontab

```bash
crontab -e
```

Add:
```cron
# Honeypot health check every 5 minutes
*/5 * * * *   python3 /usr/local/bin/honeypot_healthcheck.py
```

---

## STEP 9 — Set Up Log Sync (rsync from local machine)

The **local machine** pulls all three log sources via a dedicated SSH key scoped to the `cowrie` user. The `ExecStartPost` chmod lines added in STEP 3 and STEP 4 ensure OpenCanary and Glutton logs are world-readable, so the `cowrie` user can access them despite those services running as root.

| Log | Path |
|-----|------|
| Cowrie | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` |
| OpenCanary | `/var/tmp/opencanary.log` (chmod 644 via ExecStartPost) |
| Glutton | `/var/tmp/glutton.log` (chmod 644 via ExecStartPost) |

### On the VPS

```bash
# DO NOT set nologin shell for cowrie — OpenSSH executes forced commands via
# the user's shell (`shell -c "command"`). nologin ignores all args and exits 1,
# which silently breaks the rsync pull. Security comes from the command= restriction below.

# rrsync is a read-only rsync wrapper shipped with the rsync package
apt install -y rsync
which rrsync || ls /usr/share/doc/rsync/scripts/rrsync* 2>/dev/null

# Ensure .ssh directory exists for cowrie
mkdir -p /home/cowrie/.ssh
chmod 700 /home/cowrie/.ssh
chown cowrie:cowrie /home/cowrie/.ssh
```

### On your LOCAL machine

```bash
# Generate a dedicated key for log pulling
ssh-keygen -t ed25519 -f ~/.ssh/research_key -C "iot-sync"

# Display the public key — copy the output
cat ~/.ssh/research_key.pub
```

### Back on the VPS — add the key with rrsync restriction

```bash
# Paste your public key in place of <PUBLIC_KEY_HERE>
# Full path required — forced SSH commands do not inherit a full PATH
echo 'command="/usr/bin/rrsync -ro /",no-pty,no-agent-forwarding,no-port-forwarding <PUBLIC_KEY_HERE>' \
    >> /home/cowrie/.ssh/authorized_keys
chmod 600 /home/cowrie/.ssh/authorized_keys
chown cowrie:cowrie /home/cowrie/.ssh/authorized_keys
```

> `/usr/bin/rrsync -ro /` allows read-only rsync of any path on the VPS. The full binary path is required because forced SSH `command=` directives do not inherit a user PATH. The `command=` restriction means this key can never open an interactive shell — only rsync pulls.

### On your LOCAL machine — pull commands (add to pipeline runner)

```bash
VPS_IP=167.172.187.18

# Create local target dirs if they don't exist (rsync will fail otherwise)
mkdir -p /data/raw-logs/cowrie /data/raw-logs/opencanary /data/raw-logs/glutton

# Accept the VPS host key on first connect (prevents interactive prompt breaking cron/pipeline)
ssh -p 2222 -i ~/.ssh/research_key -o StrictHostKeyChecking=accept-new \
    cowrie@${VPS_IP} exit 2>/dev/null || true

# Pull Cowrie logs (-az --quiet: compress + archive, no verbose output for automation)
rsync -az --quiet -e "ssh -p 2222 -i ~/.ssh/research_key" \
    cowrie@${VPS_IP}:/home/cowrie/cowrie/var/log/cowrie/ \
    /data/raw-logs/cowrie/

# Pull OpenCanary log
rsync -az --quiet -e "ssh -p 2222 -i ~/.ssh/research_key" \
    cowrie@${VPS_IP}:/var/tmp/opencanary.log \
    /data/raw-logs/opencanary/

# Pull Glutton log
rsync -az --quiet -e "ssh -p 2222 -i ~/.ssh/research_key" \
    cowrie@${VPS_IP}:/var/tmp/glutton.log \
    /data/raw-logs/glutton/
```

> For manual/interactive use, replace `-az --quiet` with `-avz` to see transfer progress.

---

## STEP 10 — Verify Everything Is Live

```bash
# Ports bound by Cowrie and OpenCanary (Glutton uses TPROXY — no bound port)
ss -tlnp | grep -E ':22\b|:23\b|:21\b|:25\b|:8080\b|:2323\b'

# Service statuses (all four)
systemctl status cowrie opencanary glutton monit

# Verify Glutton is catching unclaimed ports (run from your local machine)
# nc -w 2 46.101.253.208 9999 || true
# Then on VPS:
tail -5 /var/tmp/glutton.log

# Watch Cowrie events in real time (attacks should appear within 10-15 min)
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json | python3 -m json.tool

# Count events in the last hour
awk -v d="$(date -u -d '1 hour ago' '+%Y-%m-%dT%H')" '$0 > d' \
    /home/cowrie/cowrie/var/log/cowrie/cowrie.json | wc -l

# Check health log
tail -20 /var/log/honeypot_health.log
```

---

## Files That Live on the VPS

| Path | What It Is |
|------|-----------|
| `/home/cowrie/cowrie/` | Cowrie installation + logs |
| `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` | **Primary data file** — rsync'd by local machine |
| `/var/tmp/opencanary.log` | OpenCanary events — rsync'd by local machine |
| `/var/tmp/glutton.log` | Glutton catch-all events — rsync'd by local machine |
| `/etc/opencanaryd/opencanary.conf` | OpenCanary config |
| `/home/cowrie/cowrie/etc/cowrie.cfg` | Cowrie config |
| `/usr/local/bin/honeypot_healthcheck.py` | Health check script |
| `/var/log/honeypot_health.log` | Health check output |
| `/swapfile` | 1 GB swap |

**No pipeline code, no PostgreSQL, no API keys live on the VPS.** The VPS is a pure sensor.

---

## Files That Live on Local Machine Only

| Path | What It Is |
|------|-----------|
| `/data/raw-logs/cowrie/` | Mirror of Cowrie logs (rsync target) |
| `/data/raw-logs/opencanary/` | Mirror of OpenCanary logs |
| `Cyber-Security-Data-Analysis-Pipeline/` | Full pipeline code |
| `.env` | API keys (Shodan, Censys) — **never on VPS** |
| PostgreSQL DB | All processed data, IOCs, device records |

---

## Expected RAM Usage on VPS

| Component | At Idle | Under Attack Storm |
|-----------|---------|-------------------|
| Ubuntu OS | ~220 MB | ~220 MB |
| Cowrie | ~100 MB | ~250 MB (capped by systemd) |
| OpenCanary | ~25 MB | ~25 MB |
| Glutton | ~15 MB | ~15 MB |
| Monit | ~5 MB | ~5 MB |
| **Total** | **~365 MB** | **~515 MB / 1 024 MB** |
| Swapfile | 1 GB on-disk | OOM safety net |
