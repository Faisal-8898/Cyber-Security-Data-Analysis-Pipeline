# Research Alignment: Data Pipeline → IEEE IoT-Journal Paper

**Paper Title**: From Infection to Monetization: Measuring Compromised IoT Devices in Cybercrime Infrastructure

**Research Questions (RQ)**:
- **RQ1**: How can compromised IoT devices be reliably identified at internet scale?
- **RQ2**: How can compromised IoT devices be linked to cybercrime infrastructure?
- **RQ3**: What quantitative evidence demonstrates contribution to monetization infrastructure?
- **RQ4**: Do linked IoT devices form distinct infrastructure clusters (campaigns)?

---

## Data Collection Strategy: `make poll-paper` (Recommended)

### One Command, Two Stages

```bash
make poll-paper    # Runs both stages with research alignment
```

#### Stage 1: Shodan Baseline (RQ1 — Device Identification)
- **Queries**: 40 across categories A–L
- **Data**: ~500–1000 device records/week
- **Focus**: Device-type distribution (router/camera/unknown)
- **Credits**: 40/week × 4 weeks = 160/month per account
- **Maps to**: WHOLE_RESEARCH.md Section 6 (Dataset Overview), Section 7 (Infection Infrastructure)

| Category | Purpose | Example | Paper Section |
|----------|---------|---------|---|
| A | Core IoT ports | port:23, port:2323, port:22 | RQ1 baseline |
| B | Router fingerprints | port:7547, GoAhead, uhttpd | RQ1 device-type |
| C | IP cameras | port:554, RTSP, Hikvision | RQ1 device-type |
| E | **Proxy/monetization** | port:1080, port:3128, SOCKS5 | **RQ3 core** |
| F | Botnet signals | busybox, dropbear, mirai | RQ4 clustering |
| H | SMTP spam relay | port:25, Open Relay | RQ3 alt monetization |
| I | Geographic bias | country:BD port:23, etc. | Methodology bias control |
| L | High-risk combos | port23+busybox, port7547+TR069 | **RQ4 campaign seeds** |

#### Stage 2: Censys Enrichment (RQ3/RQ4 — Monetization & Campaigns)
- **Enrichments**: 60 IPs/week (prioritised from Shodan)
- **Credits**: 60/week × 4 weeks = 240/month (sustainable)
- **Prioritisation** (novelty-first):
  1. **Category E (Proxy)**: ports 1080, 3128, 8080 — **RQ3 signal**
  2. **Category L (Combos)**: multi-signal queries — **RQ4 seeds**
  3. **Category F (Botnet)**: infection fingerprints — cross-validation
  4. **Category H (SMTP)**: spam relay signals — **RQ3 alt channel**
- **Device-type bias**: prioritise `router`, `camera`, `iot` (not generic servers)
- **Maps to**: WHOLE_RESEARCH.md Section 5.8 (Monetization Detection), Section 5.7 (Campaign Clustering)

### Data Volume

| Source | Records/Week | Cross-Validation |
|--------|--------------|---|
| Shodan | ~500–1000 | All 40 queries |
| Censys (paper mode) | ~60 enriched | 60 high-value IPs |
| **Combined** | **~160 rows** | **Shodan + Censys** |

### Timeline
- **Week 1**: Shodan baseline snapshot
- **Week 2+**: Weekly repeats for longitudinal tracking (RQ4 churn/campaigns)
- **Month 4**: Ablation study (Shodan-only vs +Censys for journal quality)

---

## Research Novelty Mapping

### Why These Priorities (from WHOLE_RESEARCH.md)?

#### 1. Monetization Linkage (RQ3) — Paper's Core Claim
**Section 5.8**: Monetization detection and linkage metrics
- Proxy indicators: **ports 1080/3128/8080, banners, proxy protocol hints**
- DDoS indicators: attack-command strings observed in honeypots
- Spam indicators: **SMTP exposure signals** via scan datasets

**Our Priority**:
- ✅ E category: `port_1080`, `port_3128`, `port_8080_proxy`, SOCKS5, Squid, tinyproxy, 3proxy
- ✅ H category: `port_25`, `open_relay`, Postfix
- ✅ Port list: [1080, 3128, 8080, 25] — direct monetization signals

**Expected Findings**:
- Proxy overlap: % of compromised IoT devices matching proxy indicators
- Time-to-monetization: lag from compromise signal → proxy exposure
- Concentration: ASN/hosting-provider clustering (if high-value proxies reuse infrastructure)

---

#### 2. Campaign Infrastructure (RQ4) — Graph Clustering Seeds
**Section 5.7**: Campaign clustering
- Similarity signals: **shared download host, shared command template, shared C2/ASN**
- **Method**: simple baseline first (connected components / Louvain / label propagation)

**Our Priority**:
- ✅ L category: Pre-filtered combos (port23+busybox, port7547+TR069, port554+RTSP, port80+GoAhead)
- ✅ F category: Botnet fingerprints (busybox, dropbear, mirai, gafgyt)
- ✅ Device-type: `router`, `camera`, `iot` (excludes generic servers)

**Expected Findings**:
- Campaign size distribution
- Infrastructure graph: loader/C2/proxy reuse
- Stability: cluster stability across weekly snapshots

---

#### 3. Infection-to-Monetization Bridge (Cross-RQ)
**Section 5.6**: Infrastructure graph construction
- Nodes: IP, domain, URL, hash, ASN, device-type
- Edges: download, C2-contact, dns-resolve, **proxy-exposes**, attack-command

**Our Priority**:
- Shodan devices (F category) hit by botnets + checked for Censys monetization signals
- Enables: "Of Shodan-identified compromised devices, X% also appear in proxy infrastructure"

---

## Alternative Modes

### For Specific RQs Only

```bash
# If only collecting RQ3 (monetization) data
make poll-censys-paper    # 60 Censys enrichments, E,L,F,H prioritised

# If only collecting RQ1 (device baseline)
make poll-shodan          # 40 Shodan queries only

# If need maximum data volume (research depth)
make poll-max             # 40 Shodan (200 results each) + 100 Censys enrichments
                          # Cost: 80 Shodan + 100 Censys = 180/week (high)
```

---

## Validation & Ablations (Journal Quality)

From WHOLE_RESEARCH.md Section 5.10: Validation and robustness
- Cross-source validation: honeypot IOC ↔ passive DNS ↔ feeds
- Ablations: **Shodan-only vs Shodan+Censys vs +honeypot IOCs**

### After 4 Weeks of `make poll-paper` Runs

1. **Shodan-only baseline**: ~500 devices/week × 4 weeks
2. **+Censys enrichment**: ~60 devices enriched/week × 4 weeks
3. **Honeypot cross-check**: Extract IOCs (C2, URLs, credentials)
4. **Ablation**: Compare Shodan categories alone vs with Censys validation

---

## Summary Table

| Goal | Command | Data Quality | Volume | Credits | RQ Focus |
|------|---------|---|---|---|---|
| **Paper (recommended)** | `make poll-paper` | ⭐⭐⭐⭐⭐ High (novelty) | ~160/wk | 100/wk | RQ1,3,4 |
| Monetization deep-dive | `make poll-censys-paper` | ⭐⭐⭐⭐⭐ High (RQ3) | ~60/wk | 60/wk | RQ3 |
| Device baseline | `make poll-shodan` | ⭐⭐⭐ Medium | ~500/wk | 40/wk | RQ1 |
| Maximum volume | `make poll-max` | ⭐⭐ Volume-focused | ~600/wk | 180/wk | All (expensive) |
| Budget testing | `make poll` | ⭐⭐ Default | ~150/wk | 65/wk | RQ1,2 |

---

## Quick Start

```bash
# Initial setup
make db-up
make install
source .venv/bin/activate

# First week: baseline
make poll-paper

# Weekly repeat (e.g., Sunday 02:00 UTC cron)
0 2 * * 0    cd /path/to/cs-data-pipeline && make poll-paper

# Check progress
make query-summary
make censys-balance
make check-balance

# Analyze after 4 weeks
python3 -c "import pandas as pd; print(pd.read_sql('SELECT COUNT(DISTINCT ip), device_type FROM device_records WHERE source=\\'shodan\\' GROUP BY device_type', 'postgresql://...'))"
```

---

**See Also**:
- [WHOLE_RESEARCH.md](Docs/WHOLE_RESEARCH.md) — Full research plan
- [README.md](README.md) — Query catalogue details
- [Makefile](Makefile) — All available commands
