# Shodan + Censys Data Pull Analysis

## Project Overview — How Data Flows

```
WEEKLY SNAPSHOT MODEL (Longitudinal Anchor: Monday of ISO week)
                      
    Monday 2026-04-06 ← All 44 Shodan queries run
         ↓             All 55 Censys queries run
         ↓             
    ONE ROW PER (ip, port) stored to device_records
         ↓
    snapshot_week = 2026-04-06
    query_ids[] = [which queries matched this ip:port]
    
    
    Monday 2026-04-13 ← Run again (new week, new snapshot)
         ↓
    NEW ROW (or UPSERT if same ip:port) with snapshot_week=2026-04-13
         ↓
    This allows: LONGITUDINAL TRACKING across 26 weeks
    (Same device exposed → appears in multiple weekly snapshots)
```

---

## Query Volume Breakdown

### SHODAN — 25 queries (Budget-tuned: 100 credits/month ✅)

| Category | Count | Focus | Rationale |
|----------|-------|-------|-----------|
| **A** | 3 | Core IoT ports | `port:23`, `port:2323`, `port:8080` only — port:22/80/443 cut (server-heavy) |
| **B** | 5 | Router fingerprints | `port:7547`, `TR-069`, `GoAhead-Webs`, `uhttpd`, `rompager` — VERY IMPORTANT |
| **C** | 2 | IP cameras | `IP Camera`, `DVR` — port:554+RTSP captured via L combo |
| **D** | ~~5~~ **0** | ~~Weak auth~~ | **CUT** — login page banners are server-heavy HTTP strings, not IoT |
| **E** | 7 | **Proxy/Monetization** | ALL KEPT — paper's core claim (Contribution 3) |
| **F** | 4 | Botnet signals | `busybox`, `/bin/busybox`, `mirai`, `dropbear` — wget/curl cut (not banner-visible) |
| **G** | ~~6~~ **0** | ~~C2 patterns~~ | **CUT** — generic/Windows-focused; honeypot covers C2 contact evidence better |
| **H** | ~~5~~ **0** | ~~SMTP/spam~~ | **CUT** — port:25 dominated by servers; spam relay evidence from honeypot |
| **I** | ~~4~~ **0** | ~~Geographic~~ | **CUT** — geo breakdown is analysis step (ASN/country already in every row) |
| **J** | ~~6~~ **0** | ~~Vulnerabilities~~ | **CUT** — Apache/nginx/OpenSSH are server banners, not IoT fingerprints |
| **K** | ~~5~~ **0** | ~~Industrial IoT~~ | **CUT** — MQTT/Modbus peripheral to router+camera research focus |
| **L** | 4 | Combo cluster seeds | `port:23+busybox`, `port:7547+TR-069`, `port:554+RTSP`, `port:80+GoAhead` |
| **TOTAL** | **25** | — | **25 q/week × 4 weeks = 100 credits/month** ✅ |

---

### CENSYS — 55 queries (Categories A–L)

| Category | Count | Focus | Example Query |
|----------|-------|-------|----------------|
| **A** | 6 | Core ports | `services.port=23`, `services.port=80` |
| **B** | 6 | Router exploitation | `services.port=7547`, `services.http.response.headers.server="GoAhead"` |
| **C** | 6 | IP cameras | `services.port=554`, `services.service_name="RTSP"` |
| **D** | 4 | Weak auth | `services.banner="login failed"` |
| **E** | 5 | Proxy signals | `services.port=1080`, `services.banner="SOCKS5"` |
| **F** | 5 | Botnet | `services.banner="busybox"`, `services.banner="Dropbear"` |
| **G** | 3 | C2 patterns | `services.banner="/bin/sh"` |
| **H** | 3 | SMTP | `services.port=25`, `services.banner="Postfix"` |
| **I** | 4 | Geographic | `services.port=23 and location.country_code="BD"` |
| **J** | 3 | Vulnerabilities | `labels="iot"`, `labels="vulnerable"` |
| **K** | 5 | Industrial IoT | `services.port=1883`, `services.port=502` |
| **L** | 5 | High-risk combos | `services.port=23 and services.banner="busybox"` |
| **TOTAL** | **55** | — | — |

---

## API Limits & Quota Analysis

### SHODAN — Educational Member

**Current Setup (after tuning):**
```env
SHODAN_API_KEY=<your_key>
SHODAN_MAX_PER_QUERY=100          # Corrected: edu-tier cap is 100 results/query
SHODAN_SLEEP_BETWEEN_QUERIES=1.0
```

**Educational Member Quota:**
- **Search queries**: Typically **100 credits/month** for edu members
- **Cost per search**: **1 credit per search** (regardless of result count)
- **Max results per query**: **100 results** on edu tier (was wrongly set to 500)

**Quota Consumption (tuned to 25 queries):**
```
Week 1 (Monday):
  25 queries × 1 credit/query = 25 credits

Week 2, 3, 4 (each Monday):
  25 credits each

Monthly total:
  25 credits × 4 weeks = 100 credits

STATUS: ✅ EXACTLY AT LIMIT — 100 = 100 credits/month
```

**Previous problem was**: 69 queries × 4 weeks = 276 credits → overflow by 176 credits. **Fixed.**

### CENSYS — Normal Personal Account

**Your Current Setup:**
```env
CENSYS_API_SECRET=censys_7aXCAEH1_ESSHDdG9Df6q5aafDBJnRs7A  # Bearer token
CENSYS_MAX_PER_QUERY=200                                      # Results per query
CENSYS_SLEEP_BETWEEN_QUERIES=2.0                              # Rate limit protection
CENSYS_SLEEP_BETWEEN_PAGES=0.5
```

**Personal Account Quota:**
- **Query limit**: **10 queries/minute** (API-enforced rate limit)
- **Results per query**: Up to **10,000+** (depends on index size)
- **No monthly credit limit** (free tier = unlimited queries within rate limit)

**Quota Consumption (55 Censys queries):**
```
Rate limit check:
  55 queries × (1 query executed)
  ÷ 10 queries/minute
  = 5.5 minutes minimum runtime
  
With SLEEP_BETWEEN_QUERIES=2.0 seconds:
  55 queries × 2.0 sec = 110 seconds = ~2 minutes sleep PLUS execution time
  Total: ~7-8 minutes
  
STATUS: ✅ SAFE — Well within 10 queries/min rate limit
```

---

## What Data Do You Expect Today?

### If You Pull Right Now (Friday, 2026-04-11)

**Shodan:**
- `snapshot_week` will be **2026-04-06** (Monday of this week)
- Expect **~500–1000 device_records rows** from 69 queries
  - High-volume queries: `port:80`, `port:22`, `port:23` → 100+ results each
  - Specific queries: `"mirai"`, `"TR-069"` → 1–10 results each
  - **Estimated total**: 500–800 unique (ip, port) pairs

**Censys:**
- `snapshot_week` will be **2026-04-06** (same Monday)
- Expect **~300–600 device_records rows** from 55 queries
  - Censys is more selective (requires active service discovery)
  - Some queries may return 0–5 results

**Total for this week:**
- **~800–1400 device records** (some IPs/ports appear in both Shodan AND Censys → merged into 1 row with `query_ids[]` = both)
- **Actual unique IPs**: ~200–400 (many have multiple ports)

---

## If You Pull Tomorrow (Saturday, 2026-04-12)

**Shodan:**
- `snapshot_week` will **STILL BE 2026-04-06** (same ISO week)
- Same 69 queries will execute **AGAIN**
- Results are likely **95% identical** to today

**Deduplication (multi-query UPSERT):**
```sql
INSERT ... ON CONFLICT (source, ip, port, snapshot_week) DO UPDATE SET
  query_ids = ARRAY(SELECT DISTINCT unnest(old_ids || new_ids))
```

**Result**: If tomorrow's query finds the same `(ip, port)` pair:
- **No new row** is created
- **Existing row is updated** with `query_ids[]` merged
- Example: If `port:23 "busybox"` finds 10.0.0.1:23
  - Already in DB from `port:23` query? → Just add `"busybox"` to query_ids[]
  - **No duplication**

**Net change**: ~0–5% new IPs (devices that came online in 24 hours)

---

## If You Pull Next Week (Monday, 2026-04-13)

**Shodan:**
- `snapshot_week` will **CHANGE TO 2026-04-13** (new ISO week)
- Same 69 queries will execute **AGAIN**
- Results may have **~10–30% turnover** (devices come/go in a week)

**What you get in DB:**
```sql
-- Old week (2026-04-06)
SELECT * FROM device_records 
WHERE source='shodan' AND snapshot_week='2026-04-06'
-- Returns: 500–800 records

-- New week (2026-04-13)
SELECT * FROM device_records 
WHERE source='shodan' AND snapshot_week='2026-04-13'
-- Returns: 450–850 records (some churn)

-- Overlap (same device visible 2 weeks in a row)
SELECT dr1.ip FROM device_records dr1
JOIN device_records dr2 ON dr1.ip = dr2.ip AND dr1.port = dr2.port
WHERE dr1.snapshot_week = '2026-04-06'
  AND dr2.snapshot_week = '2026-04-13'
  AND dr1.source = 'shodan'
-- Returns: ~400–700 IPs (device persistence)
```

**Longitudinal insight**: You can now measure **"device lifetime"** — how many weeks does a device stay exposed?

---

## Query Limit Tuning (Applied)

### Status After Fix
| API | Status | Detail |
|-----|--------|--------|
| **Shodan Edu** | ✅ FIXED | 25 queries × 4 weeks = **100 credits/month** (was 276, overflow by 176) |
| **Censys Personal** | ✅ SAFE | 10 queries/min limit easily met, no changes needed |

### What Was Implemented (aligned to WHOLE_RESEARCH.md contributions)

| Category | Count | Maps to Research | Cut reason |
|----------|-------|------------------|-----------|
| A — Core IoT ports | 3 | Contribution 1: device exposure baseline | port:22/80/443/81 cut — server-dominated |
| B — Router fingerprints | 5 | Contribution 1+2: router identification + graph nodes | boa/mini_httpd cut — overlap with uhttpd |
| C — IP cameras | 2 | Contribution 1: device-type distribution figure | port:554+RTSP in L combo; webcam/netcam too niche |
| E — Proxy/monetization | 7 | **Contribution 3: CRITICAL** — paper's core claim | All 7 kept |
| F — Botnet signals | 4 | Contribution 1+4: infection + lifecycle tracking | wget_http/curl_http cut — not Shodan banners |
| L — Combo queries | 4 | Contribution 2: campaign cluster seeds | port8080+admin cut — generic, high FP rate |
| D, G, H, I, J, K | 0 | Not needed for core contributions | See detailed rationale below |

**Cut categories — detailed rationale:**
- **D** (login banners): HTTP strings like `"login failed"` are server-side text, not IoT fingerprints
- **G** (C2 patterns): `"cmd.exe"`, `"powershell"` are Windows-focused; IoT C2 evidence comes from honeypot connections
- **H** (SMTP): port:25 returns millions of mail servers; spam relay evidence comes from honeypot SMTP logs
- **I** (geographic samples): `country:BD port:23` duplicates global data; geographic breakdown is a query-time analysis step (ASN + country columns are already stored per-row)
- **J** (vulnerability banners): `"Apache"`, `"nginx"`, `"OpenSSH"` are pure server fingerprints, not IoT
- **K** (industrial IoT): MQTT/Modbus/CoAP are peripheral to the router+camera research focus

---

## Implementation: Weekly Schedule

### Current Cron (fits 69 Shodan queries)
```cron
# Every Sunday at 02:00 UTC
0 2 * * 0  cd /path && python -m pipeline.run --tasks poll
```

### For Pruned Setup (20 Shodan + 55 Censys = 75 queries total)
No changes needed — same cron works, just fewer results.

---

## Analysis Queries: What Can You Measure?

### Longitudinal Churn (device persistence)
```sql
-- Which IPs appear in consecutive weeks?
SELECT ip, 
       COUNT(DISTINCT snapshot_week) AS weeks_visible,
       MIN(snapshot_week) AS first_seen,
       MAX(snapshot_week) AS last_seen
FROM device_records
WHERE source='shodan' AND device_type IN ('router','camera','iot')
GROUP BY ip
ORDER BY weeks_visible DESC;
```

### Proxy Exposure Growth Over Time
```sql
SELECT snapshot_week, COUNT(DISTINCT ip) AS proxy_ips
FROM device_records
WHERE source='shodan' 
  AND ('port_1080' = ANY(query_ids) 
       OR 'port_3128' = ANY(query_ids)
       OR 'socks5' = ANY(query_ids))
GROUP BY snapshot_week ORDER BY snapshot_week;
```

### Shodan vs Censys Coverage (bias analysis)
```sql
SELECT 
  (SELECT COUNT(*) FROM device_records WHERE source='shodan') AS shodan_total,
  (SELECT COUNT(*) FROM device_records WHERE source='censys') AS censys_total,
  (SELECT COUNT(DISTINCT ip) FROM device_records WHERE source='shodan') AS shodan_unique_ips,
  (SELECT COUNT(DISTINCT ip) FROM device_records WHERE source='censys') AS censys_unique_ips;
```

---

## Summary: What You Need to Know

| Question | Answer |
|----------|--------|
| **How much data per pull?** | ~500–1400 device records per week (Shodan 500–800, Censys 300–600) |
| **Pulling tomorrow vs today?** | ~95% same (multi-query UPSERT prevents duplication) |
| **Pulling next week?** | ~30% new devices, ~70% overlap (device churn visible) |
| **Shodan quota overflow?** | ✅ YES — 69 queries × 1 credit = 69/month, but 276/month weekly = **OVERFLOW** |
| **Censys quota overflow?** | ✅ NO — Rate-limited at 10 queries/min, you do ~55/week, easily fits |
| **Fix overflow?** | Reduce to 20 critical queries (Categories B, E, L) = 80 credits/month, **SAFE** |
| **Best cadence?** | Weekly (Sunday 02:00 UTC), keeps `snapshot_week` stable for reproducibility |

---

## Recommended Action

1. **For immediate use**: Keep 69 Shodan queries, run **once/month** instead of weekly
2. **For research-grade**: Use 20-query pruned set (Categories B, E, L only) + weekly schedule
3. **Censys**: No changes needed, keep 55 queries weekly
4. **Document**: Add to README which query tier you're using, for reproducibility

