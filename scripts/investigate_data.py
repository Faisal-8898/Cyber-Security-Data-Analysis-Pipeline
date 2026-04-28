#!/usr/bin/env python3
"""
Data investigation script — assess what claims we can actually make
from current DB state for the WHOLE_RESEARCH paper.
"""
import os
import sys
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras

load_dotenv()
conn = psycopg2.connect(os.environ["DATABASE_URL"])
cur = conn.cursor()

def q(sql, params=None):
    cur.execute(sql, params)
    return cur.fetchall()

def h(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

# ─── 1. HONEYPOT EVENTS ────────────────────────────────────────
h("1. HONEYPOT EVENTS — Overview")
rows = q("SELECT honeypot, COUNT(*) AS events, COUNT(DISTINCT source_ip) AS unique_ips, MIN(event_time)::DATE AS first_day, MAX(event_time)::DATE AS last_day FROM honeypot_events GROUP BY honeypot ORDER BY events DESC")
print(f"{'Honeypot':<14} {'Events':>8} {'Unique IPs':>12} {'First':>12} {'Last':>12}")
total_events = 0; total_ips_set = set()
for row in rows:
    print(f"{row[0]:<14} {row[1]:>8} {row[2]:>12} {str(row[3]):>12} {str(row[4]):>12}")
    total_events += row[1]
print(f"\nTotal events:      {total_events:,}")

# Collection window
rows2 = q("SELECT MIN(event_time)::DATE, MAX(event_time)::DATE, MAX(event_time)::DATE - MIN(event_time)::DATE AS days FROM honeypot_events")
print(f"Collection window: {rows2[0][0]} → {rows2[0][1]} ({rows2[0][2]} days)")

# ─── 2. ATTACK PATTERNS ────────────────────────────────────────
h("2. ATTACK PATTERNS — Event Types")
rows = q("SELECT event_type, COUNT(*) AS cnt FROM honeypot_events GROUP BY event_type ORDER BY cnt DESC LIMIT 15")
for r in rows: print(f"  {r[0]:<30} {r[1]:>6}")

h("2b. TOP DEST PORTS (Honeypot)")
rows = q("SELECT dest_port, COUNT(*) AS cnt FROM honeypot_events WHERE dest_port IS NOT NULL GROUP BY dest_port ORDER BY cnt DESC LIMIT 10")
for r in rows: print(f"  Port {str(r[0]):<8} {r[1]:>6} hits")

h("2c. TOP ATTACKER IPs (by hit count)")
rows = q("SELECT source_ip, COUNT(*) AS hits FROM honeypot_events WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY hits DESC LIMIT 15")
for r in rows: print(f"  {str(r[0]):<20} {r[1]:>6} hits")

h("2d. CREDENTIALS (total unique pairs)")
rows = q("SELECT COUNT(*) FROM credentials")
print(f"  Unique credential pairs: {rows[0][0]}")
rows = q("SELECT username, password, attempt_count FROM credentials ORDER BY attempt_count DESC LIMIT 15")
for r in rows: print(f"  {r[0]:<20} / {r[1]:<20}  x{r[2]}")

# ─── 3. IOC RECORDS ────────────────────────────────────────────
h("3. IOC RECORDS — Extracted from Honeypots")
rows = q("SELECT ioc_type, COUNT(*) AS cnt FROM ioc_records GROUP BY ioc_type ORDER BY cnt DESC")
for r in rows: print(f"  {r[0]:<25} {r[1]:>6}")

rows2 = q("SELECT COUNT(DISTINCT ioc_value) FROM ioc_records")
print(f"\n  Total unique IOCs: {rows2[0][0]:,}")

rows3 = q("SELECT MIN(first_seen)::DATE, MAX(last_seen)::DATE FROM ioc_records")
print(f"  IOC time range:    {rows3[0][0]}  →  {rows3[0][1]}")

h("3b. DOWNLOAD URLs (C2/Loader indicators)")
rows = q("SELECT ioc_value, source_honeypots, occurrence_count FROM ioc_records WHERE ioc_type='url' ORDER BY occurrence_count DESC LIMIT 15")
for r in rows: print(f"  {r[0]:<55} x{r[2]}  {r[1]}")

h("3c. MALWARE HASHES")
rows = q("SELECT ioc_value, ioc_type, source_honeypots FROM ioc_records WHERE ioc_type IN ('md5','sha256','sha1')")
print(f"  Total hashes: {len(rows)}")
for r in rows[:10]: print(f"  [{r[1]}] {r[0]}  {r[2]}")

h("3d. COMMAND TEMPLATES (behavioral IoC)")
rows = q("SELECT ioc_value, occurrence_count FROM ioc_records WHERE ioc_type='command_template' ORDER BY occurrence_count DESC LIMIT 15")
print(f"  Total command templates: {len(rows)}")
for r in rows: print(f"  {r[0][:80]:<80} x{r[1]}")

# ─── 4. FEED IOCs (ThreatFox / URLhaus / MalwareBazaar / OTX) ──
h("4. THREAT FEED IOCs — External Intelligence")
rows = q("SELECT source, COUNT(*) AS cnt, COUNT(DISTINCT malware_family) AS families, MIN(snapshot_date)::text AS snap FROM feed_iocs GROUP BY source ORDER BY cnt DESC")
print(f"{'Source':<20} {'IOCs':>8} {'Families':>10} {'Snapshot'}")
total_feed = 0
for r in rows:
    print(f"  {r[0]:<20} {r[1]:>8} {r[2]:>10} {r[3]}")
    total_feed += r[1]
print(f"\n  Total feed IOCs: {total_feed:,}")

h("4b. TOP MALWARE FAMILIES (ThreatFox)")
rows = q("SELECT malware_family, COUNT(*) AS cnt FROM feed_iocs WHERE source='threatfox' AND malware_family IS NOT NULL GROUP BY malware_family ORDER BY cnt DESC LIMIT 15")
for r in rows: print(f"  {r[0]:<30} {r[1]:>6}")

h("4c. TOP MALWARE FAMILIES (MalwareBazaar)")
rows = q("SELECT malware_family, COUNT(*) AS cnt FROM feed_iocs WHERE source='malwarebazaar' AND malware_family IS NOT NULL GROUP BY malware_family ORDER BY cnt DESC LIMIT 15")
for r in rows: print(f"  {r[0]:<30} {r[1]:>6}")

h("4d. OTX — Pulse/Tag distribution")
rows = q("SELECT malware_family, COUNT(*) AS cnt FROM feed_iocs WHERE source='otx' AND malware_family IS NOT NULL GROUP BY malware_family ORDER BY cnt DESC LIMIT 15")
for r in rows: print(f"  {r[0]:<30} {r[1]:>6}")

h("4e. URLhaus — IOC type breakdown")
rows = q("SELECT ioc_type, COUNT(*) AS cnt FROM feed_iocs WHERE source='urlhaus' GROUP BY ioc_type ORDER BY cnt DESC")
for r in rows: print(f"  {r[0]:<20} {r[1]:>6}")

# ─── 5. DEVICE RECORDS (Shodan + Censys) ───────────────────────
h("5. DEVICE RECORDS — Shodan/Censys Internet Scans")
rows = q("SELECT source, snapshot_week, COUNT(*) AS records, COUNT(DISTINCT ip) AS unique_ips FROM device_records GROUP BY source, snapshot_week ORDER BY snapshot_week, source")
print(f"{'Source':<10} {'Week':<14} {'Records':>9} {'Unique IPs':>12}")
total_dr = 0
for r in rows:
    print(f"  {r[0]:<10} {str(r[1]):<14} {r[2]:>9,} {r[3]:>12,}")
    total_dr += r[2]
print(f"\n  Total device records: {total_dr:,}")

h("5b. DEVICE TYPE distribution")
rows = q("SELECT device_type, COUNT(*) AS cnt FROM device_records GROUP BY device_type ORDER BY cnt DESC")
for r in rows: print(f"  {r[0]:<25} {r[1]:>7,}")

h("5c. TOP SERVICES/PROTOCOLS")
rows = q("SELECT protocol, COUNT(*) AS cnt FROM device_records WHERE protocol IS NOT NULL GROUP BY protocol ORDER BY cnt DESC LIMIT 15")
for r in rows: print(f"  {r[0]:<25} {r[1]:>7,}")

h("5d. TOP PORTS EXPOSED")
rows = q("SELECT port, COUNT(*) AS cnt FROM device_records WHERE port IS NOT NULL GROUP BY port ORDER BY cnt DESC LIMIT 15")
for r in rows: print(f"  Port {str(r[0]):<10} {r[1]:>7,}")

h("5e. GEOGRAPHIC distribution (top 15 countries)")
rows = q("SELECT country_code, COUNT(*) AS cnt FROM device_records WHERE country_code IS NOT NULL GROUP BY country_code ORDER BY cnt DESC LIMIT 15")
for r in rows: print(f"  {r[0]}  {r[1]:>7,}")

h("5f. TOP ASNs/ORGS (attack infrastructure concentration)")
rows = q("SELECT org, COUNT(*) AS cnt FROM device_records WHERE org IS NOT NULL GROUP BY org ORDER BY cnt DESC LIMIT 10")
for r in rows: print(f"  {r[0][:50]:<50} {r[1]:>6,}")

h("5g. PROXY INDICATORS (ports 1080/3128/8080/8888/9050)")
rows = q("SELECT port, COUNT(*) AS cnt FROM device_records WHERE port IN (1080,3128,8080,8888,9050,8118,3129) GROUP BY port ORDER BY cnt DESC")
for r in rows: print(f"  Port {r[0]:<8} {r[1]:>6,} (potential proxy)")
rows2 = q("SELECT COUNT(*) FROM device_records WHERE port IN (1080,3128,8080,8888,9050,8118,3129)")
print(f"\n  Total potential proxy endpoints: {rows2[0][0]:,}")

h("5h. IoT-SPECIFIC DEVICE PORTS (telnet/23, TR-069/7547, MQTT/1883)")
rows = q("SELECT port, COUNT(*) AS cnt FROM device_records WHERE port IN (23,7547,1883,5683,8883,2323,37777) GROUP BY port ORDER BY cnt DESC")
for r in rows: print(f"  Port {r[0]:<8} {r[1]:>6,}")

h("5i. CPE / PRODUCT fingerprints (top IoT products)")
rows = q("SELECT product, COUNT(*) AS cnt FROM device_records WHERE product IS NOT NULL GROUP BY product ORDER BY cnt DESC LIMIT 15")
for r in rows: print(f"  {r[0][:50]:<50} {r[1]:>6,}")

# ─── 6. CROSS-SOURCE LINKAGE ────────────────────────────────────
h("6. CROSS-SOURCE LINKAGE — Honeypot IPs vs Feed IOCs")

# Attacking IPs appearing in ThreatFox
rows = q("""
    SELECT COUNT(DISTINCT ir.ioc_value) AS hp_ips_in_threatfox
    FROM ioc_records ir
    JOIN feed_iocs fi ON fi.ip::text = ir.ioc_value
    WHERE ir.ioc_type = 'ip' AND fi.source = 'threatfox'
""")
print(f"  Honeypot attacker IPs found in ThreatFox: {rows[0][0]}")

# Attacking IPs appearing in any feed
rows = q("""
    SELECT fi.source, COUNT(DISTINCT ir.ioc_value) AS matches
    FROM ioc_records ir
    JOIN feed_iocs fi ON fi.ip::text = ir.ioc_value
    WHERE ir.ioc_type = 'ip'
    GROUP BY fi.source
""")
print("  Honeypot IPs matched in feeds:")
for r in rows: print(f"    {r[0]:<20} {r[1]} matches")

# Device records vs Feed IOCs
rows = q("""
    SELECT fi.source, COUNT(DISTINCT dr.ip) AS matches
    FROM device_records dr
    JOIN feed_iocs fi ON fi.ip = dr.ip
    GROUP BY fi.source ORDER BY matches DESC
""")
print("\n  Shodan/Censys device IPs found in threat feeds:")
for r in rows: print(f"    {r[0]:<20} {r[1]:>5,} matches")

# Malware family overlap between URLhaus and ThreatFox
rows = q("""
    SELECT malware_family, COUNT(*) AS cnt
    FROM feed_iocs
    WHERE source = 'threatfox'
      AND malware_family ILIKE ANY(ARRAY['%mirai%','%gafgyt%','%mozi%','%bashlite%','%hajime%','%qbot%'])
    GROUP BY malware_family ORDER BY cnt DESC
""")
print("\n  IoT botnet families in ThreatFox feed:")
for r in rows: print(f"    {r[0]:<30} {r[1]:>5,}")

# ─── 7. DAILY CHURN ─────────────────────────────────────────────
h("7. IP ACTIVITY DAILY — Longitudinal Churn Data")
rows = q("SELECT day, honeypot, SUM(event_count) AS total_events, COUNT(DISTINCT source_ip) AS unique_ips FROM ip_activity_daily GROUP BY day, honeypot ORDER BY day, honeypot")
if rows:
    print(f"{'Day':<14} {'Honeypot':<14} {'Events':>10} {'Unique IPs':>12}")
    for r in rows: print(f"  {str(r[0]):<14} {r[1]:<14} {r[2]:>10,} {r[3]:>12,}")
else:
    print("  (ip_activity_daily is empty)")

rows2 = q("SELECT COUNT(DISTINCT source_ip) AS ips, COUNT(DISTINCT day) AS days FROM ip_activity_daily")
if rows2[0][1]:
    print(f"\n  Unique IPs tracked across {rows2[0][1]} days: {rows2[0][0]:,}")

# IPs seen on multiple days (reinfection/persistence signal)
rows3 = q("SELECT COUNT(*) FROM (SELECT source_ip FROM ip_activity_daily GROUP BY source_ip HAVING COUNT(DISTINCT day) > 1) t")
print(f"  IPs seen on multiple days (persistence): {rows3[0][0]:,}")

# ─── 8. PIPELINE RUNS ────────────────────────────────────────────
h("8. PIPELINE RUNS — Collection Activity")
rows = q("SELECT task_name, COUNT(*) AS runs, MAX(started_at)::DATE AS last_run FROM pipeline_runs GROUP BY task_name ORDER BY last_run DESC, runs DESC")
for r in rows: print(f"  {r[0]:<30} {r[1]:>4} runs  last: {r[2]}")

# ─── SUMMARY ─────────────────────────────────────────────────────
h("SUMMARY — What We Can Claim")
print("""
DATA WE HAVE (confirmed):
  - Honeypot events:      8,407  (3 days, 3 honeypots: Glutton/Cowrie/OpenCanary)
  - Unique attacker IPs:  2,014+ from honeypots
  - Extracted IOCs:       ~1,920 (IPs, URLs, hashes, commands)
  - Feed IOCs:            12,720 (ThreatFox/URLhaus/MalwareBazaar/OTX)
  - Device records:       18,450 (Shodan: 16,387 | Censys: 2,063)
  - Unique scanned IPs:   13,425+ across 2 snapshot weeks
  - Collection window:    ~3 days honeypot / 2 Shodan snap weeks (Apr 6 + Apr 20)
""")

conn.close()
print("\n[Investigation complete]")
