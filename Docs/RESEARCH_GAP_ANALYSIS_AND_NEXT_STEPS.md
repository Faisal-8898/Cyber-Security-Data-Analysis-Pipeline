# Research Gap Analysis: Ground Reality and Q1 Publication Path

**Date**: May 4, 2026  
**Purpose**: Replace assumptions with verified state, then define the shortest path to a publishable Q1-level measurement paper.

---

## 1. Ground Reality (Verified)

This project currently has **two different realities**:

1. **Raw collection reality** (local pulled logs)  
2. **Database/pipeline reality** (what is actually ingested, queryable, and reproducible)

### 1.1 Raw Collection Reality (Strong)

From local Cowrie rotated files (`~/data/raw-logs/cowrie/cowrie.json*`):

- Total events: **178,518**
- Unique attacker IPs: **2,077**
- Command events: **4,447**
- File downloads: **1,015**
- Successful logins: **4,131**
- Download URLs: **6 unique**
- Payload hashes: **8 unique SHA256**

Interpretation: the honeypot is now operational and producing campaign-grade data.

### 1.2 Database/Pipeline Reality (Currently Limiting)

From PostgreSQL tables:

- `device_records`: **18,450** rows (snapshot range: 2026-04-06 to 2026-04-20)
- `honeypot_events`: **51,989** rows
- `ioc_records`: **2,022** rows (`2,021 ip`, `1 sha256`)
- `feed_iocs`: **18,923** rows
  - threatfox: 9,542
  - urlhaus: 5,881
  - otx: 1,995
  - malwarebazaar: 1,505
- `graph_nodes`: **0**
- `graph_edges`: **0**
- `campaign_clusters`: **0**

Interpretation: paper-scale raw data exists, but the pipeline outputs required for Q1 claims (graph + clusters + full IOC extraction) are not yet built in DB.

### 1.3 Critical Ingestion/Execution Issues

1. `make ingest-honeypot` is not fully healthy:
   - OpenCanary ingest fails on null-byte JSON content (`\u0000` in payload).
2. Cowrie ingestion currently reads one default live file path, while your data value is mostly in rotated files.
3. `extract` was executed in a separate process from `ingest`, so no in-memory event handoff occurred during that run.
4. As a result, DB reflects only a partial subset of true collected data.

---

## 2. Original Plan vs. Actual Status

| Metric | Original Target | Ground Reality | Status |
|--------|-----------------|----------------|--------|
| Scan records | 100k-500k | 18,450 | Under target |
| Honeypot events (collected) | 50k-500k | 178,518 | Met |
| Honeypot events (ingested/queryable) | 50k-500k | 51,989 | Met lower bound, incomplete ingest |
| Credential evidence | top-N dictionary | strong (4,131 success + 12k failed in raw) | Met |
| Command templates | needed for clustering | 117 templates in raw, only 79 command rows in DB | Partial |
| Download URL diversity | 1k+ aspirational | 6 unique (raw) | Low diversity |
| Hash intelligence linkage | expected | 8 hashes captured, limited DB extraction | Partial |
| Graph + campaign clustering | required | not built (0 nodes/edges/clusters) | Not done |

Key point: **collection recovered, analytics pipeline not yet caught up.**

---

## 3. Can This Still Become a Q1 Publication?

Short answer: **Yes, but only with a scope correction and 2-4 weeks of disciplined execution.**

### 3.1 What is already Q1-usable

1. Multi-vantage design exists (honeypot + scan + feeds).
2. Real attacker interaction evidence exists (credentials, commands, downloads).
3. A concrete campaign case exists (`176.65.139.177` multi-arch infrastructure pattern).
4. Feed corpus is already in DB (`feed_iocs` ~19k rows), enabling linkage analysis.

### 3.2 What blocks Q1 today

1. Reproducibility gap between raw logs and DB outputs.
2. No graph results (`graph_nodes/edges = 0`).
3. No campaign clustering results (`campaign_clusters = 0`).
4. Limited temporal scan window (only through April 20).
5. Low URL diversity for large-scale cluster-count claims.

### 3.3 Q1 positioning that is realistic

Do **not** position as "large-scale 100k-500k statistical campaign census."  
Position as:

**"Multi-vantage IoT compromise-to-infrastructure linkage with deep campaign case studies and reproducible pipeline."**

This is still strong for Q1 if methods + validation are tight.

---

## 4. What To Do Next (Priority Order)

## 4.1 Week 1: Make the pipeline truthful and reproducible

1. Fix OpenCanary null-byte ingestion (`\u0000` sanitization before DB insert).
2. Ensure Cowrie ingest supports rotated files (`cowrie.json*`) or loop all files explicitly.
3. Run ingest and extract in one consistent workflow and verify counts after run.
4. Reconcile raw-vs-DB parity with a verification table:
   - raw events
   - ingested events
   - extracted IOCs (ip/url/hash)

Exit criteria for Week 1:
- `honeypot_events` close to raw total window
- `ioc_records` includes URL/hash volume expected from Cowrie downloads
- ingestion job completes without silent partial failures

## 4.2 Week 2: Produce core paper artifacts

1. Run graph build + clustering:
   - `make build-graph`
2. Validate non-zero outputs:
   - `graph_nodes`
   - `graph_edges`
   - `campaign_clusters`
3. Generate 2-4 defensible campaign archetypes from cluster output.
4. Run feed linkage queries against captured URLs/hashes/C2 IPs.

Exit criteria for Week 2:
- one infrastructure graph figure
- one clustering results table
- one feed-linkage results table

## 4.3 Weeks 3-4: Strengthen external validity

1. Resume weekly scan pulls (`poll-paper` cadence).
2. Extend observation window for churn/survival analysis.
3. (Optional high impact) add Dionaea to increase malware URL/hash diversity.
4. Lock paper claims to what is measured, not aspirational.

---

## 5. Immediate Paper Claim Strategy

Use two claim tiers:

### Tier A (claim now, with current evidence)

1. Honeypot became operational after credential policy correction.
2. Captured attack flow includes login -> command -> payload download.
3. Observed multi-architecture payload delivery behavior from active infrastructure.

### Tier B (claim after 1-2 weeks of pipeline completion)

1. Quantified cross-feed overlap rates (URL/hash/IP).
2. Campaign cluster distribution and representative cluster case studies.
3. Longitudinal churn characteristics from expanded weekly scan snapshots.

---

## 6. Hard-Nosed Conclusion

The project is **not failed**.  
The honeypot collection objective is now successful.  
The current weakness is engineering maturity of the ingest-to-analysis path.

If you execute the Week 1 and Week 2 actions above, this can become a credible Q1 submission with:

1. Strong methodology narrative (multi-vantage, reproducible pipeline)
2. Defensible empirical findings (commands/downloads/infrastructure linkage)
3. Honest scope (case-study-heavy measurement paper rather than inflated scale claim)

If you do not close the raw-vs-DB gap and graph outputs, the paper will remain below Q1 threshold regardless of raw data volume.
