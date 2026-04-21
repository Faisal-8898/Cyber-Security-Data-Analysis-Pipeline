You ONLY want security-relevant device exposure signals

Think:
👉 “What makes this device relevant to compromise + monetization?”

Core Shodan fields you SHOULD extract
1. Device identity layer (mandatory)

These are essential for your IoT + botnet mapping:

ip
port
transport (tcp/udp)
hostnames
domains
asn
org / isp
country

👉 maps directly to:

device_records
source_ips
graph_nodes
2. Service fingerprint (VERY important for IoT detection)

From Shodan banner:

product
version
cpe
cpe23
device_type (if available)
os (sometimes)
http.title
http.server
http.headers

👉 This is your:

IoT classification + vulnerability surface

3. Exposure signals (critical for monetization link)

These matter most for your Q1 novelty:

open ports:
23 (telnet)
22 (ssh)
80/443 (web admin panels)
8080/3128/1080 (proxy indicators)
7547 (TR-069 routers) ← VERY IMPORTANT IoT abuse vector
3389 (RDP exposure)
25 (SMTP abuse potential)

👉 These map directly to:

proxy abuse
botnet infection vector
monetization channels
4. Banner / response metadata (light but useful)
raw_banner
http.html
ssl.cert.subject
ssl.cert.issuer

👉 used for:

fingerprinting campaigns
clustering infra reuse
5. Vulnerability signals (optional but powerful for Q1)
vulns / cves
last_update
tags

👉 helps you show:

“why these devices get recruited into monetization infrastructure”

❌ What you should NOT store from Shodan

Avoid:

full raw scan responses (huge JSON blobs)
irrelevant HTTP pages
screenshots / HTML dumps
redundant repeated banner strings without processing
everything Shodan gives by default



High-quality Shodan query set (30+ research-grade queries)

I’m giving you a paper-ready curated set, not random queries.

I grouped them like a real IoT measurement system.

🔴 A. IoT device exposure (core dataset)
port:23
port:2323
port:22
port:80
port:8080
port:81
port:443
🔴 B. Router / embedded device exploitation (VERY IMPORTANT)
port:7547
"TR-069"
"GoAhead-Webs"
"Boa"
"mini_httpd"
"uhttpd"
"rompager"
🔴 C. IP camera / surveillance devices
"IP Camera"
port:554
"RTSP"
"webcam"
"DVR"
"Netcam"
🔴 D. Default credential / weak auth surfaces
"default password"
"admin:admin"
"login failed"
"authentication failed"
"Login Page"
🔴 E. Proxy / monetization infrastructure (CRITICAL FOR YOUR PAPER)
port:1080
port:3128
port:8080
"socks"
"SOCKS5"
"proxy server"
"Squid"
🔴 F. Botnet / malware-related infrastructure signals
"mirai"
"busybox"
"wget http"
"curl http"
"/bin/busybox"
"dropbear"
🔴 G. C2 / suspicious control patterns (indirect but useful)
"/bin/sh"
"cmd.exe"
"powershell"
"bot"
"panel"
"login.php"
🔴 H. SMTP / spam infrastructure (monetization channel)
port:25
"SMTP"
"ESMTP"
"Postfix"
"Open Relay"
🔴 I. Geographic sampling (for bias control)

(important for paper rigor)

country:BD port:23
country:IN port:23
country:US port:23
country:CN port:23
🔴 J. Vulnerability exposure signals
"cpe:"
"cve"
"vulnerable"
"Apache"
"nginx"
"OpenSSH"
🔴 K. Industrial / IoT protocol exposure
port:1883   # MQTT
port:5683   # CoAP
port:502    # Modbus
port:44818  # Ethernet/IP
🔴 L. High-risk IoT combo queries (VERY GOOD for clustering)
port:23 "busybox"
port:80 "GoAhead"
port:8080 "admin"
port:7547 "TR-069"
port:554 "RTSP"
👉 Total: ~40 strong queries

These are enough for:

100k+ device snapshots
clustering
longitudinal analysis
3) Weekly snapshot sampling strategy (Q1-level design)

This is VERY important — reviewers care more about this than model.

🧠 Core idea

You are NOT “collecting data”

You are doing:

📊 “time-series measurement of global IoT exposure and abuse infrastructure”

✔️ Recommended design: 7-day snapshot cycle
📅 Step 1 — fixed query set (DO NOT change weekly)

You define:

Q = {q1, q2, ..., q40}

Same queries every week.

✔ This ensures:

comparability
longitudinal consistency
no dataset drift bias
📅 Step 2 — weekly execution schedule

Example:

Week	Action
Mon	run Shodan queries
Tue	ingest results
Wed	deduplicate + normalize
Thu	enrich (ASN, geo, tags)
Fri	build graph snapshot
Sat	compute metrics
Sun	backup + archive
📅 Step 3 — snapshot structure

Each week you store:

snapshot_week = {
    snapshot_date,
    query_id,
    ip,
    port,
    banner,
    product,
    asn,
    org,
    country,
    raw_data
}
📅 Step 4 — deduplication rule (VERY IMPORTANT)

Same IP appears multiple times:

You MUST define:

Rule:
same (ip + port + week) → keep latest or merge
📅 Step 5 — longitudinal tracking model

Track:

IP lifecycle:
first_seen
last_seen
active_weeks
churn rate
Campaign lifecycle:
cluster stability over weeks
node persistence
📅 Step 6 — sampling strategy (important for bias control)

You should explicitly say in paper:

Strategy:

✔ stratified query sampling:

IoT exposure (ports)
proxy signals
router exploitation
cameras
region-based

This avoids:

“Shodan bias toward specific services”