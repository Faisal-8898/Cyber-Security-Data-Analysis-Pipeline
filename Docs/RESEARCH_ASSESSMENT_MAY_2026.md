# Research Assessment — May 6, 2026
## *From Infection to Monetization: Measuring Compromised IoT Devices in Cybercrime Infrastructure*

---

## Part 1: What We Originally Set Out to Prove

The original vision in `WHOLE_RESEARCH.md` was a **measurement + linkage + lifecycle** paper targeting IEEE IoT-J (Q1). The central promise in the title — "From Infection to Monetization" — required empirical proof of the full chain:

```
IoT device (Shodan/Censys) → compromised (honeypot signal) → repurposed (proxy/C2) → monetized
```

The plan had **four explicit contributions**:

| Contribution | What it requires |
|-------------|-----------------|
| C1: Large-scale measurement | 100k–500k IPs, 3–6 months of collection, multi-vantage |
| C2: Infrastructure graph + campaign clustering | Campaign clusters (50–200), graph with 6 edge types, community detection |
| C3: Monetization linkage | Direct, quantitative evidence: what % of Shodan IoT devices appear in proxy/C2/attack infrastructure |
| C4: Lifecycle dynamics | Survival curves, reinfection cadence, campaign lifetime across weeks |

Four **research questions**:

- **RQ1**: How are compromised IoT devices identified at internet scale? What is their prevalence?
- **RQ2**: Can they be linked to downstream cybercrime infrastructure (loaders, C2, proxies)?
- **RQ3**: What fraction of the observed population participates in monetization infrastructure?
- **RQ4**: Do they form distinct campaign clusters? What differentiates campaigns?

The paper was explicitly warned in `WHOLE_RESEARCH.md §16`:
> *"Right now your paper measures infection infrastructure. But your title promises monetization. You must prove economic exploitation... Without that, reviewers will say: 'This is just another IoT botnet measurement paper.'"*

---

## Part 2: What We Actually Tried

| Step | Planned | Attempted |
|------|---------|-----------|
| Deploy honeypots | Cowrie + HTTP + TR-069 | Cowrie ✅ + Glutton ✅ + OpenCanary ✅, Dionaea deployed May 5 |
| Shodan/Censys snapshots | Weekly, 3–6 months | 3 snapshots (Apr 11 / Apr 23 / May 5) |
| Malware feeds | MalwareBazaar, URLhaus, OTX, ThreatFox | All 4 pulled ✅, 18,923 IOCs |
| IOC extraction | URLs, hashes, C2 domains | URLs ✅, SHA256 ✅ (after fix), IPs ✅ |
| Feed cross-match | Find IOC overlaps | Run ✅ |
| Infrastructure graph | NetworkX + Louvain | Not yet run (dependencies confirmed) |
| Campaign clusters | Louvain community detection | Not yet run |
| Monetization linkage | Shodan device IP ↔ attacker IP overlap | Run ✅ |
| Survival/churn curves | Kaplan–Meier on ip_activity_daily | Not yet plotted |
| Passive DNS | Farsight / SecurityTrails / Rapid7 | **Not implemented at all** |
| Risk scoring model | Random Forest / survival model | Not implemented |

**Pipeline bugs fixed along the way** (May 5–6, 2026):
1. NUL-byte crash in `upsert_credentials()` — fixed
2. Rotated Cowrie log files never ingested — fixed (1,803 → 207,908 events)
3. SHA256 hashes not reaching `ioc_records` — fixed (1 → 116 IOCs)

---

## Part 3: What We Actually Found

### What's confirmed and in the DB

| Finding | Evidence | Paper value |
|---------|----------|-------------|
| Active SSH-injection botnet documented end-to-end | 1,063 identical key-injection commands, 1,074 `chattr` commands | **High** — complete campaign case study, directly citable |
| Multi-arch malware delivery (`iran.mips`, `iran.aarch64`, etc.) | 7 download URLs, 1,112 file download events | **High** — Mirai/Gafgyt distribution pattern, IoT architecture targeting confirmed |
| Unreported C2 / distribution servers | `176.65.139.177` and `85.11.167.220` — 0 hits in URLhaus | **High** — novel threat intelligence contribution |
| Novel malware hashes | 116 SHA256s, 0 in any feed | **High** — first-seen timestamp, submit to MalwareBazaar |
| Same-subnet scanner + C2 (`176.65.132.0/24`) | 15,686 events from this /24 + download URLs hosted there | **High** — scanner pool and distribution infrastructure are co-located |
| GPON router targeting (CVE-2018-10561 still active in 2026) | `AdminGPON / ALC#FGU` credential in 5,537-router dataset | **Medium** — vulnerability lifecycle data point |
| Proxy infrastructure at scale exists (Shodan) | 2,617 SOCKS/HTTP-proxy-port IoT devices | **Medium** — validates monetization opportunity, but not linked to attackers yet |
| SMTP relay exposure | 732 devices on port 25 | **Medium** — spam infrastructure overlap signal |

### What's NOT found (and why it matters)

| Claim we set out to make | Query result | Root cause |
|--------------------------|-------------|-----------|
| Attacker IPs appear in threat feeds | 0 matches | Scanning IPs ≠ C2 infrastructure IPs — expected, not a problem |
| Honeypot SHA256s match known malware | 0 matches | **Novel malware** — hashes are not yet indexed. This is a finding |
| Honeypot URLs match URLhaus | 0 matches | **Novel infrastructure** — servers are not yet reported. Submit them |
| Shodan device IPs appear as attacker IPs (RQ3) | 0 matches | **13-day window is too short** for the compromise → repurpose lifecycle |
| Campaign clusters | 0 (not run) | Graph not built yet — ready to run today |

---

## Part 4: Do We Need to Modify the Research Questions?

**Short answer: modify RQ3, reframe RQ2, keep RQ1 and RQ4 as-is.**

### RQ1 — Keep as written ✅
**Original**: "How can compromised IoT devices be reliably identified at internet scale?"
**Status**: Fully answerable. We have 25,428 device records (routers, cameras, proxy-port devices), 266k+ honeypot events, 4 threat feeds, multi-vantage pipeline operational.
**Data gap**: 3 Shodan snapshots vs. 8–10 needed for a strong §6 dataset characterization. Fixable with the 4th snapshot (`make poll-week WEEK=2026-05-04`) and continued weekly pulls.

---

### RQ2 — Reframe from "linkage" to "infrastructure mapping" ⚠️
**Original**: "Can compromised IoT devices be systematically linked to downstream cybercrime infrastructure?"
**Problem**: We found the infection → C2 chain, but the C2 → proxy backend linkage is 0 in 13 days.
**Reframe**: Narrow RQ2 to what we can prove directly:
> *"RQ2 (revised): What downstream cybercrime infrastructure — loaders, C2 distribution servers, and malware payloads — is empirically observable through multi-vantage honeypot measurement, and what does this reveal about campaign organization?"*

This is answerable now. We have: 7 C2/distribution URLs, 116 hashes, the `iran.*` multi-arch loader pattern, the same-subnet scanner+distribution co-location finding. The graph (once built) will add the campaign cluster structure.

---

### RQ3 — Must be modified or explicitly scoped ⚠️
**Original**: "What fraction of the observed population participates in monetization infrastructure?"
**Problem**: Direct IP overlap is 0. In 13 days, the device compromise → proxy repurposing lifecycle has not completed for any observed device. The paper's central promise cannot be quantitatively delivered at the individual IP level.

**Two honest options**:

**Option A — Reframe as opportunity structure (write NOW)**:
> *"RQ3 (revised): What is the scale of observable monetization-ready infrastructure (proxy-exposed IoT devices) relative to the population actively targeted, and what does this imply about the economic viability of IoT botnet-based proxy abuse?"*
> 
> Answer: 2,617 proxy-port IoT devices observed, 4,369 successful logins in 13 days into a pool of ~7,628 unique attackers. The opportunity structure exists — monetization-ready devices coexist in the same address space as active targeting. Direct IP overlap is absent in a 13-day window, consistent with a multi-week compromise → repurpose lifecycle.

This is publishable. It is honest. It is backed by the data. Reviewers will accept "we cannot prove individual device reuse in 13 days but we show the opportunity structure quantitatively" — especially if you cite prior work on device compromise-to-monetization timelines (typically 2–6 weeks for IoT botnet operators).

**Option B — Wait 30–40 days and re-run (write LATER)**:
If direct IP overlap is the claim you need, extend collection to 6–8 weeks total. Re-run the Shodan device IP ↔ ioc_records join every 48h. When a device from a prior Shodan snapshot shows up in the attacker IP list OR as a C2/download host, you have your direct chain of evidence. This is the "full paper" version but requires waiting.

---

### RQ4 — Keep, but rename "attacker groups" not "campaigns" ✅
**Original**: "Do linked IoT devices form distinct infrastructure clusters corresponding to coordinated campaigns?"
**Status**: Buildable immediately (`make build-graph && make cluster`). The credential co-occurrence signal (5,717 pairs, 7,628 IPs) is the strongest input. HASSH fingerprint reuse will add a second dimension.
**Caveat**: Clusters are Louvain communities (statistical groupings), not ground-truth APT attributions. Name them "attacker groups" or "campaign-like clusters" in the paper, not "campaigns."

---

## Part 5: Should You Wait 30–40 Days or Start Writing Now?

### The case for waiting 30–40 days

| Gap | What waiting fixes |
|-----|-------------------|
| RQ3 = 0 | 30–40 days brings total to 43–53 days. Device compromise → proxy repurpose lifecycle is typically 2–6 weeks. IP overlap may appear. |
| 3 Shodan snapshots | 7–9 snapshots → meaningful churn/survival curves (Kaplan–Meier is not credible at 3 data points) |
| Dionaea data = 0 | 30 days of Dionaea → HTTP malware drop URLs → URLhaus-matchable IOCs → feed cross-match goes from 0 to non-zero |
| MalwareBazaar submissions not indexed yet | 30 days → hashes + URLs submitted now will be indexed → re-run cross-match to get malware family IDs |
| Graph clusters (once built) tested for stability | Need ≥3 weekly snapshots of attacker activity to test if cluster membership is stable |

**If you wait 30–40 days and actively collect**, you get:
- ~7 Shodan snapshots → survival curves ready for §9
- Potential RQ3 IP overlap (the single finding that makes the monetization promise real)
- Malware family identification via MalwareBazaar → converts "novel hashes" from "finding" to "named threat actor" (much stronger)
- Dionaea HTTP data → richer graph edges, more URLhaus matches
- Campaign cluster stability evidence across weeks

### The case for starting writing NOW

| What you have today | Paper section it fills |
|--------------------|----------------------|
| 266k+ events, 3 honeypots, 4 feeds, 3 Shodan snapshots | §4 Data Sources + §6 Dataset Overview (Table 1) |
| Full SSH-injection campaign documented (1,063 instances) | §7 Results I — campaign case study (strongest section in the paper) |
| 7 novel C2 URLs + 116 novel SHA256s (0 feed matches) | §7 Results I — infrastructure novelty |
| `iran.*` multi-arch malware pattern | §7 Results I — payload analysis |
| `176.65.132.0/24` scanner+C2 co-location | §7 Results I — infrastructure topology |
| 2,617 proxy-port IoT devices (Shodan) | §8 Results II — monetization opportunity structure |
| GPON CVE-2018-10561 still exploited in 2026 | §9 Results III — vulnerability lifecycle |
| Graph ready to build (campaign clusters coming) | §7 Results I — cluster count + archetypes |

**What would be missing:**
- §8 Results II is thin (opportunity structure only, no direct linkage number)
- §9 Results III needs more Shodan snapshots (survival curves weak at 3 points)
- §11 Limitations will be long (short window, no passive DNS, no ablation)

### Recommendation: **Parallel strategy — write and collect simultaneously**

Do not pick one or the other. Do both:

1. **Write now** — Start §4, §5, §6, §7 today. These sections are fully data-locked and the §7 SSH-injection campaign case study is genuinely strong. Use writing time to identify exactly what numbers you need for §8 and §9.

2. **Keep collecting** — 30 more days of honeypot + weekly Shodan snapshots runs passively. Make the 4th Shodan snapshot (`make poll-week WEEK=2026-05-04`) today. Submit hashes and URLs to MalwareBazaar/URLhaus now so they have 30 days to be indexed. Run `make build-graph && make cluster` today.

3. **Set a hard cutoff** — June 15, 2026 (≈40 days from now). At that point you have ~53 days of collection. Re-run all cross-linkage queries on that date. If RQ3 still = 0, commit to Option A framing (opportunity structure). If RQ3 > 0, you have your monetization number. Either way, paper is written and ready to finalize.

---

## Part 6: What Steps Are Needed to Reach Peak Novelty

The paper's current novelty ceiling depends on what you do in the next 40 days. Here are the levers ranked by impact:

### Tier 1 — High impact, low effort (do today)

**1. Run `make build-graph && make cluster`**
This is the single most overdue action. With 5,717 credential pairs and 7,628 attacker IPs, you will get:
- Quantitative campaign cluster count (a novel metric no prior IoT measurement paper produces from first principles)
- HASSH fingerprint reuse: how many IPs share the same scanning binary
- The `176.65.132.0/24` cluster will dominate — confirming scanner pool + C2 co-location structurally

```bash
cd /Users/faisal/Documents/.../Cyber-Security-Data-Analysis-Pipeline
make build-graph && make cluster
```

**2. Submit SHA256 hashes and URLs to MalwareBazaar / URLhaus**
Submitting the `a8460f446be540...` hash to MalwareBazaar today takes 5 minutes and could return a malware family name within days. If it comes back as `Mirai.Satori`, `Moobot`, or `Gafgyt` variant, that single result converts your paper from "we found unknown payloads" to "we documented an active Mirai-variant campaign before it appeared in public feeds." That is a first-seen disclosure, which is a genuine threat intelligence contribution that reviewers will recognize.

**3. Make the 4th Shodan snapshot**
```bash
make poll-week WEEK=2026-05-04
```
30 seconds. Without this, your survival curve analysis is 3 data points. With it, it's 4. You need 7–8 for publication quality.

**4. Run the HASSH query**
Before building the graph, check what the HASSH coverage looks like:
```sql
SELECT hassh, COUNT(DISTINCT source_ip) AS ip_count
FROM honeypot_events
WHERE hassh IS NOT NULL
GROUP BY hassh ORDER BY ip_count DESC LIMIT 20;
```
If hundreds of IPs share a single HASSH value, that is strong coordinated botnet evidence and goes into §7 immediately.

---

### Tier 2 — Medium impact, passive (set up today, wait)

**5. Keep collecting for 30 more days**
Every day of data after today adds:
- More Shodan snapshots (weekly)
- More download events → more hashes → more potential feed matches
- More time for a compromised Shodan device to appear as an attacker IP (RQ3)

**6. Pull Dionaea data in 24–48h**
```bash
make ingest-honeypot
```
Dionaea captures HTTP malware downloads at the network level. These will produce fully-formed download URLs that are directly matchable against URLhaus. Even 10 matches would change the "0 feed matches" narrative significantly.

**7. Re-run feed cross-match after MalwareBazaar/URLhaus indexes your submissions**
Give it 7–14 days after submission, then:
```sql
SELECT ir.ioc_value, fi.source, fi.malware_family
FROM ioc_records ir JOIN feed_iocs fi ON lower(ir.ioc_value) = lower(fi.ioc_value)
WHERE ir.ioc_type = 'sha256';
```

---

### Tier 3 — High impact, significant effort (journal-quality additions)

**8. Add ASN/hosting provider analysis**
The top 5 attacking /24 subnets — check their ASN, country, and hosting provider using a MaxMind or ip-api lookup. If `176.65.132.0/24` is a known bulletproof hosting provider, that is a direct connection to the cybercrime infrastructure thesis. This takes 1–2 hours and produces a table for §7.

**9. Normalize and query `feed_iocs.ioc_type` inconsistency**
`feed_iocs` has both `sha256` (2,298) and `sha256_hash` (101) as type values. Fix this:
```sql
UPDATE feed_iocs SET ioc_type = 'sha256' WHERE ioc_type = 'sha256_hash';
UPDATE feed_iocs SET ioc_type = 'md5' WHERE ioc_type = 'md5_hash';
UPDATE feed_iocs SET ioc_type = 'sha1' WHERE ioc_type = 'sha1_hash';
```
Then re-run cross-match. May convert some "0 matches" to non-zero.

**10. Ablation: Shodan-only vs. Shodan+honeypot**
Required for journal quality (explicitly listed in `WHOLE_RESEARCH.md §5.10`). Show that adding honeypot IOCs changes the set of detected infrastructure. Even if the overlap is 0, the ablation table shows what each vantage point uniquely contributes.

---

## Part 7: Honest Paper Assessment by Section

| Paper section | State today | State in 40 days |
|--------------|-------------|-----------------|
| §1 Introduction + RQs | ✅ Writable (with RQ2/RQ3 rewrites) | ✅ Same |
| §4 Data Sources | ✅ Writable now | ✅ Same |
| §5 Methodology | ✅ Writable now | ✅ Same |
| §6 Dataset Overview | ⚠️ Weak (3 Shodan snapshots) | ✅ Strong (7+ snapshots) |
| §7 Results I — Campaign Infra | ✅ Writable NOW (strongest section) | ✅ Even stronger (malware family ID + stable clusters) |
| §8 Results II — Monetization | ⚠️ Opportunity structure only | **Depends on RQ3 result** — could become strong |
| §9 Results III — Lifecycle | ❌ Blocked (3-point survival curve not credible) | ✅ Writable (7+ data points) |
| §10 Discussion | ⚠️ Writable but thin | ✅ Full |
| §11 Limitations | ⚠️ Will be long (honest) | ⚠️ Still long but shorter |
| §12 Artifact | ✅ Ready | ✅ Same |

---

## Part 8: The Novelty Ceiling — What Makes This Paper Stand Out

If you do everything in Tier 1 + Tier 2 over the next 30–40 days, here is what the paper's novelty argument looks like:

**Novelty claim 1 (strongest, available now)**: We documented active malware distribution infrastructure (`176.65.139.177`, `85.11.167.220`) and associated multi-arch IoT payloads (`iran.*`) **before** they appeared in any public threat feed. We provide first-seen timestamps, download event counts, and multi-architecture evidence consistent with an active Mirai/Gafgyt variant campaign.

**Novelty claim 2 (needs graph build, available today)**: We produce the first data-driven campaign cluster taxonomy from a live multi-honeypot deployment using Louvain community detection on credential co-occurrence + HASSH fingerprint signals. Prior work clusters campaigns by hand or by IP range. We cluster by behavioral evidence.

**Novelty claim 3 (needs 30 days)**: We demonstrate that monetization-ready IoT infrastructure (2,617+ proxy-port devices) and active targeting infrastructure (7,628 attacking IPs) coexist at scale in the same measurement window, establishing the empirical opportunity structure for IoT proxy abuse — whether or not direct IP overlap is observed in a 13-day window.

**Novelty claim 4 (needs 40 days + MalwareBazaar result)**: If the top SHA256 hash returns a known family name, we add: "We trace an active [Mirai variant] campaign from initial credential stuffing through payload delivery and establish that its distribution infrastructure was unindexed in public threat feeds at time of collection."

**The claim the paper CANNOT make without more time**: "X% of compromised IoT devices in our Shodan dataset were subsequently observed in botnet/proxy infrastructure." That requires the RQ3 direct IP overlap. If it stays 0 through June 15, use the opportunity structure framing — it is publishable, it is honest, and it is backed by the data.

---

## Part 9: Immediate Action Checklist (Today)

- [ ] `make build-graph` → then `make cluster`
- [ ] Run HASSH query (SQL above) — report results in §7
- [ ] `make poll-week WEEK=2026-05-04` — 4th Shodan snapshot
- [ ] Submit `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` to MalwareBazaar
- [ ] Submit `http://176.65.139.177/cat.sh` and `http://85.11.167.220/loader.sh` to URLhaus
- [ ] Normalize `feed_iocs.ioc_type` (`sha256_hash` → `sha256`)
- [ ] Start writing §4 (Data Sources) and §5 (Methodology) — these are locked today

**In 48h**:
- [ ] `make ingest-honeypot` (Dionaea first capture)
- [ ] Check MalwareBazaar for hash family ID

**Weekly (every Monday)**:
- [ ] `make poll-shodan` + `make ingest`
- [ ] Re-run all cross-linkage queries
- [ ] Log results — first non-zero match is a paper milestone

**Hard cutoff: June 15, 2026**
- Freeze data. Run all final queries. Finalize §8 (RQ3 framing based on actual result). Complete §9 (survival curves). Submit.
