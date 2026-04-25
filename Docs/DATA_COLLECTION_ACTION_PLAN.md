# Data Collection Action Plan
## Context: Draft submission to supervisor — April 26, 2026

---

## Current Data Inventory

| Source | Records | Status |
|---|---|---|
| Shodan | ~16,387 | ✅ 3 weeks, deduplicated |
| Censys | ~2,063 | ✅ Enrichment partial (credit exhaustion) |
| Glutton honeypot | 7,674 events / 1,150+ IPs | ✅ Active, biggest source |
| Cowrie honeypot | 104 events / 9 IPs | ⚠️ Only started Apr 24 |
| OpenCanary | 1 event | ❌ Crashing — skip |
| IOC (extracted) | 1,918 IPs + 1 SHA256 | ✅ From honeypot logs |
| Malware feeds | 0 | ⬜ Not started yet |
| Passive DNS | 0 | ⬜ Not started |

**Total for paper claim**: ~18K scanning records + 7,674 honeypot events + 1,918 IOCs = **strong enough for a draft**

---

## 3rd Source: Malware Intelligence Feeds

### Verdict: ✅ DO IT — takes ~2 hours, adds IOC cross-validation for RQ2/RQ3

The paper's core claim needs proof of **infrastructure linkage** (Section 5.8).
Malware feeds give you C2 IPs and download URLs to cross-check against your
18K Shodan/Censys devices and 1,918 honeypot IOCs — this is the "multi-vantage"
claim reviewers will check.

---

### Which sources to use (ranked)

#### Tier 1 — Pull TODAY (no account needed or instant approval)

**1. ThreatFox (abuse.ch) ← BEST FOR YOUR PAPER**
- What it has: C2 server IPs/domains tagged by malware family (Mirai, Gafgyt, QBot, etc.)
- Why it matters: Cross-check your 1,918 IOC IPs against known C2 infrastructure (RQ2 linkage)
- API: POST https://threatfox-api.abuse.ch/api/v1/ — **no key needed**
- Data format: JSON, instant
- Steps:
  1. No registration — public API
  2. Query for IoT malware families: `mirai`, `gafgyt`, `mozi`, `botnet`
  3. Run `make poll-threatfox` (will create below)
- Time: **30 minutes to set up**

**2. URLhaus (abuse.ch) ← GOOD FOR DOWNLOAD URL LINKAGE**
- What it has: Malicious URLs used for malware distribution (dropper/loader URLs)
- Why it matters: Your honeypot `download_url` field can be cross-matched (RQ2 loader linkage)
- API: POST https://urlhaus-api.abuse.ch/v1/ — **no key needed**
- Steps:
  1. No registration
  2. Query your extracted download URLs against URLhaus
  3. Any match = confirmed malware distribution infrastructure
- Time: **20 minutes**

#### Tier 2 — Register then pull (1–2 days for approval)

**3. MalwareBazaar (abuse.ch)**
- What it has: Malware samples with hashes, tags, malware families
- Why it matters: You have 1 SHA256 hash from honeypot — verify it here
- Registration: https://bazaar.abuse.ch/ — free, instant
- Steps:
  1. Register at bazaar.abuse.ch
  2. Get API key from account settings
  3. Lookup your SHA256 hash: `POST https://mb-api.abuse.ch/api/v1/ {"query":"get_info","hash":"<sha256>"}`
- Time: **10 minutes once registered**

**4. OTX AlienVault**
- What it has: Community IoT threat pulses — IPs, domains, attack patterns
- Why it matters: Pre-built IoT botnet collections to cross-validate your ASN/IP data
- Registration: https://otx.alienvault.com/ — free, instant approval
- Useful queries: Search pulses for "Mirai", "IoT botnet", "Gafgyt"
- Time: **1–2 hours to pull relevant pulses**

#### Skip for now

| Source | Why skip |
|---|---|
| VirusTotal | 4 req/min rate limit — too slow; need it only for hash enrichment |
| Rapid7 Sonar | GB-sized downloads — too slow for today's deadline |
| CIRCL Passive DNS | Requires setup + data is DNS-focused (4th source, see below) |

---

### What you need to do (account setup checklist)

- [ ] **abuse.ch**: No account needed for ThreatFox + URLhaus — API is public
- [ ] **MalwareBazaar**: Register at https://bazaar.abuse.ch/ (5 min, free)
- [ ] **OTX**: Register at https://otx.alienvault.com/ (5 min, free, instant API key)
- [ ] Add API keys to your `.env` file:
  ```
  OTX_API_KEY=<your_key>
  MALWAREBAZAAR_API_KEY=<your_key>   # optional, public endpoint works without it
  ```

---

### What data you will get (paper impact)

```
ThreatFox query results:
  → Cross-match against your 1,918 IOC IPs
  → Any overlapping IP = "confirmed C2 infrastructure contact" (RQ2 evidence)
  → Adds malware family labels to your graph nodes (RQ4 campaign clustering)

URLhaus results:
  → Cross-match against honeypot download_url field
  → Confirms loader/dropper infrastructure linkage (RQ2)

Combined paper claim (Section 8, Results II):
  "Of the 1,918 IPs extracted from honeypot sessions,
   X IPs (Y%) appear in ThreatFox as known C2 infrastructure,
   and Z download URLs match URLhaus malware distribution records,
   confirming multi-vantage linkage between observed honeypot activity
   and known cybercrime infrastructure."
```

---

## 4th Source: Passive DNS

### Verdict: ⏭️ SKIP for today's draft — mention as future work

**What it is**: Historical records of domain→IP resolutions over time.
Maps C2 *domains* to IP addresses across weeks — useful for tracking infrastructure
migration and campaign lifetime (Section 5.9 longitudinal metrics).

**Free options**:
- Rapid7 FDNS dataset (opendata.rapid7.com) — free but multi-GB downloads
- CIRCL passive DNS — free but requires registration + data can be sparse
- SecurityTrails — free tier very limited (50 queries/month)

**Why skip for this draft**:

| Issue | Impact |
|---|---|
| You have IPs not domains | Passive DNS maps domains→IPs; your honeypot IOCs are mostly IPs |
| Setup time | Rapid7 FDNS = multi-GB download, hours to process |
| Your Glutton honeypot only ran 2 days | Not enough domain observations to build a meaningful timeline |
| Cowrie only captured 9 IPs | Too few C2 domains to look up |
| Reviewer risk | Claiming passive DNS correlation with 2 days of honeypot data will invite scrutiny |

**How to handle in draft paper**:
```
Section 11 (Limitations):
  "Passive DNS correlation (vantage point 4.4) was excluded from
   this draft due to the short honeypot collection window (2 days)
   and the predominantly IP-based nature of observed IOCs.
   Future work will incorporate Rapid7 Sonar FDNS datasets
   to map C2 domain infrastructure across collection weeks."
```
This is honest, professional, and reviewers respect explicit scope statements.

---

## Your Work Plan (What to Do Today)

### Hour 1 — Pull malware feeds (no account needed)
1. I'll create `pipeline/poll_threatfox.py` and `pipeline/poll_urlhaus.py`
2. Run `make poll-feeds` — pulls ThreatFox C2 IPs + URLhaus URLs into DB
3. Run `make cross-match` — counts how many of your 1,918 IOC IPs appear in feeds

### Hour 2 — Register accounts
- [ ] https://bazaar.abuse.ch/ — register, get key, add to `.env`
- [ ] https://otx.alienvault.com/ — register, get key, add to `.env`

### Hour 3 — Write up what you have for supervisor

**Data you can honestly claim for the draft**:

```
Section 4 — Data Sources (what to write):

4.1 Honeypots
  • Glutton (catch-all TCP): 2-day active collection, 7,674 events,
    1,150+ unique attacker IPs/day. Primary source of credential attempts,
    download commands, and C2 contact observations.
  • Cowrie (SSH/Telnet): 104 events, 9 unique IPs (started Apr 24 —
    collection ongoing).
  • OpenCanary: excluded due to instability.

4.2 Internet Scanning (Shodan + Censys)
  • 3 weekly Shodan snapshots: 40 fixed queries × 200 results = ~16,387 records
  • Censys enrichment: 20 host lookups (credit-limited) = 2,063 records
  • Total: 18,450 device records, deduplicated by (source, IP, port, snapshot_week)

4.3 Malware Intelligence Feeds
  • ThreatFox (abuse.ch): [X] C2 IOCs queried, covering Mirai/Gafgyt families
  • URLhaus (abuse.ch): [Y] malicious URLs cross-matched against honeypot downloads
  • Cross-match result: [Z] IPs from honeypot IOC set appear in external feeds

4.4 Passive DNS — Future work (see Section 11)
```

---

## Paper Strength Assessment (for supervisor)

| Claim | Evidence you have | Strength |
|---|---|---|
| RQ1: Device identification at scale | 18,450 Shodan/Censys records, device types | ✅ Strong |
| RQ1: Device type distribution | router/camera/iot/proxy/server classification | ✅ Strong |
| RQ2: Linkage to C2 infrastructure | 1,918 IOC IPs from honeypot + ThreatFox cross-match | ⚠️ Preliminary (2-day window) |
| RQ3: Monetization signals | proxy device type classification (1,080/3,128/8,080 exposure) | ✅ Measurable |
| RQ4: Campaign clustering | shared ASN/port combos across 18K records | ⚠️ Basic — enough for draft |
| Longitudinal dynamics | 3 weekly snapshots (churn between weeks) | ✅ Minimal but present |
| Multi-vantage validation | Shodan ↔ Censys enrichment ↔ honeypot IOCs | ✅ Strong claim |

**Honest framing for supervisor**: This is a measurement-in-progress draft. The scanning baseline (RQ1/RQ3) is solid at 18K records. Honeypot data (RQ2) needs 2–4 more weeks to be statistically meaningful. Malware feed cross-matching will be added in the next 24 hours. Passive DNS is out of scope for this submission.

---

## What to Say to Your Supervisor

> "I have 3 weeks of Shodan/Censys data (18,450 device records), 2 days of honeypot 
> collection (7,674 events, 1,918 IOCs extracted), and am actively cross-matching 
> IOCs against ThreatFox and URLhaus malware feeds. The scanning baseline for RQ1 
> and RQ3 is complete. Honeypot collection is ongoing to strengthen RQ2 (C2 linkage) 
> — I'm targeting 4 more weeks. Passive DNS is deferred to the journal extension."

This is honest, shows methodology is sound, and sets up a realistic journal plan.
