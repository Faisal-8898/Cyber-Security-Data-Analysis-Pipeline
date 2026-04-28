# Research & Publication Plan (Low Budget)

## Final Title (IEEE IoT Journal, Q1 — confirmed Apr 2026)

**A Multi-Vantage Empirical Measurement of Internet-Exposed IoT Threat Infrastructure: Device Exposure, Attack Characterisation, and Proxy-Based Monetisation Indicators**

> **Title design rationale:**
> - "Multi-Vantage" — signals the methodological contribution (three independent data sources: honeypots + scan + feeds)
> - "Empirical Measurement" — positions as internet-measurement paper (not a proposal/framework), matching IEEE IoT Journal editorial preference
> - "Device Exposure … Attack Characterisation … Proxy-Based Indicators" — the three RQ families reflected directly in the subtitle
> - Dropped "monetization" from top-level to avoid over-claiming; replaced with "Proxy-Based Monetisation Indicators" which is data-grounded (327 SOCKS5 confirmed, 1,825 proxy-port devices)
> - British spellings ("Characterisation", "Monetisation") match IEEE IoT journal house style for international papers

> **Previous working titles (archived):**
> - "Characterizing IoT Threat Infrastructure: A Multi-Vantage Measurement of Exposed Devices, Attack Campaigns, and Monetization Indicators" — dropped (too vague in subtitle)
> - "From Infection to Monetization: Measuring Compromised IoT Devices in Cybercrime Infrastructure" — dropped (over-claims causal chain not evidenced by our data)


# Q1 Journal Paper Outline (IEEE Internet of Things Journal target)

## Paper type and positioning (important for IoT-J)
- **Type**: Internet-scale *security measurement* + *infrastructure mapping* paper (not a “framework/proposal” paper).
- **Core claim**: measurable, multi-vantage evidence that a significant fraction of internet-exposed IoT devices exhibit monetization-consistent indicators (open proxy ports, proxy-type banners, botnet-affiliated network ranges) and that attack activity captured by honeypots aligns temporally with active IoT malware families tracked in public threat feeds.
- **Scope clarification (data-grounded):** We do NOT claim to observe a complete infection→monetization pipeline end-to-end; we claim *infrastructure-level co-occurrence* and *indicator overlap* across three independent vantage points.


## Recommended section flow (journal-ready)

### Title + Abstract + Index Terms
- **Abstract**: (i) problem + gap, (ii) what you measured (sources + window + scale), (iii) how (linkage/graph/metrics), (iv) key quantitative findings (top 3), (v) contributions + artifact.
- **Index Terms**: IoT security, measurement, botnets, cybercrime infrastructure, proxy abuse, longitudinal analysis, graph analytics.

### 1. Introduction
- Motivation: why “infection → monetization” matters and what prior IoT botnet papers typically miss.
- Clear **research questions (RQs)** (data-grounded, Apr 2026):
	- RQ1: What is the prevalence and device-type distribution of internet-exposed IoT infrastructure, as observed across two Shodan/Censys snapshot weeks, and how do exposure patterns differ by protocol, port, and geography? *(answerable: 18,450 device records, 2 snapshot weeks, 40+ countries)*
	- RQ2: What attack patterns do honeypot sensors targeting IoT-relevant services capture, and how do observed attacker IPs relate to known IoT botnet threat intelligence? *(answerable: 8,407 events, 2,014 unique IPs, cross-reference against 12,418 feed IOCs)*
	- RQ3: To what extent do internet-exposed IoT devices exhibit indicators consistent with proxy-based monetization infrastructure (open proxy ports, SOCKS5 banners, proxy-type device classification)? *(answerable: 1,825 proxy-port devices, 327 SOCKS5, 2,687 proxy-type; 9.9% of scanned population)*
	- RQ4: What short-term longitudinal patterns (IP persistence, churn, attack volume variation) are observable within a 3-day honeypot window and across two scanning snapshots two weeks apart? *(answerable: 317 IPs seen on multiple days, Apr 6 vs Apr 20 Shodan comparison)*

	> **REMOVED RQs (insufficient data):**
	> - ~~"What fraction of observed devices can be directly linked to downstream C2/loader infrastructure?"~~ — requires download URL/command extraction; current dataset has 0 URLs and 0 command templates from honeypot.
	> - ~~"Do compromised devices form distinct campaign clusters?"~~ — requires graph construction and clustering; infrastructure not yet built.
- 2–4 bullet **contributions** (each must map to a method + a result section).
- Paper roadmap.

### 2. Background and Related Work
- IoT botnet and malware/Compromise measurement (Mirai-family, credential attacks, C2/loader infra).
    Mirai, credential scanning, exploitation patterns
    Prior large-scale measurement studies
    Limitation: focus on infection, not post-compromise usage
- Cybercrime Infrastructure and Botnet Services
    C2 servers, loaders, DDoS-for-hire
    Botnet service economy
    Limitation: IoT devices treated as resources, not tracked into usage
- Proxy ecosystems and monetization infrastructure (open proxies, residential proxies, abuse signals).
    Open proxies, residential proxy networks
    Abuse use-cases (fraud, scraping, anonymity)
    Critical gap: Lack of empirical linkage between IoT compromise and monetization ecosystems
- Internet measurement methodology: 
    Bias (scanning, passive data limitations)
    Ethics (probing concerns)
    Longitudinal challenges
    Entity resolution (IP ≠ device)
This defends your methodology before reviewers attack it
- Graph-Based Cybercrime Infrastructure Analysis
    Prior work on clustering / infrastructure graphs
    Campaign identification approaches
    Limitation: rarely applied to IoT → monetization linkage



how Our work differs (multi-vantage linkage + monetization metrics + lifecycle).
Existing work has extensively studied IoT compromise and botnet infrastructure, as well as proxy-based monetization ecosystems in isolation. However, there is limited empirical evidence linking compromised IoT devices to monetization infrastructure at scale, particularly using multi-vantage measurement and longitudinal analysis.
This paper addresses this gap by...
multi-vantage linkage
monetization metrics
lifecycle analysis

### 3. Ethics, Safety, and Responsible Measurement
- Measurement principles: **no exploitation**, **no malware execution/propagation**, **no unauthorized scanning** beyond using existing datasets.
- Honeypot containment: minimal interaction, logging only, safe storage, access controls.
- Data minimization: what you store (metadata/IOCs) and what you do not store (sensitive payloads).
- Disclosure/sanitization plan for artifacts.
- IRB/ethics approval statement (if available).

### 4. Data Sources and Collection Design
Make this concrete and auditable.
- **Collection window**: Honeypot: Apr 23–25 2026 (3 days continuous). Scanning: two snapshot weeks — week of Apr 6 2026 and week of Apr 20 2026. Threat feeds: single pull Apr 25 2026 (7-day look-back window per feed API).
- **Vantage points** (subsections):
	- 4.1 Honeypots — Glutton (8,302 events, 2,014 unique IPs), Cowrie SSH/Telnet (104 events, 9 IPs), OpenCanary (1 event). Captured: source IPs, destination ports, login attempts (10 credential pairs observed), 1 file hash. **Note:** No download URLs or command templates were captured in the current 3-day window — these require longer exposure and active payload delivery sessions.
	- 4.2 Shodan and Censys snapshots — 16,387 Shodan records (3,855 unique IPs for Apr 6 week; 9,510 for Apr 20 week) and 2,063 Censys records (60 unique IPs). Fields: banner, port, transport, protocol, product/version, CPE, CVE IDs, country, ASN, org, ISP, device_type, hostnames, HTTP title/server, SSL cert, Shodan tags.
	- 4.3 Malware intelligence feeds — ThreatFox (5,013 IOCs, 63 malware families), URLhaus (4,235: 4,081 URLs + 154 SHA256 hashes), MalwareBazaar (1,505 samples, 10 IoT families), OTX AlienVault (1,665 IOCs). Total: **12,418 feed IOCs**.
	- 4.4 Passive DNS — **SKIP: deferred to future work.** No PDNS source was configured in this collection cycle. Mention as limitation.
- **Representativeness and bias**: what populations you might miss.

### 5. Methodology (the “heart” of an IEEE IoT-J measurement paper)
This section should read like a pipeline with definitions, not like architecture marketing.
- 5.1 **Definitions**: “compromise signal”, “campaign”, “monetization signal”, “entity lifetime/churn”.
- 5.2 **Data normalization**: schema, timestamps, deduplication.
- 5.3 **Entity resolution**: unify IP/domain/URL/hash/ASN/device; handle dynamic IP caveats.
- 5.4 **IoT device identification**: rules for router/camera labeling using banner/fingerprint features; manual spot-check protocol for precision estimate.
- 5.5 **IOC extraction from honeypot logs**: regex/parsers for URLs/domains/IPs/command templates; attacker fingerprint features (credential dictionaries, command families).
- 5.6 **Infrastructure graph construction**:
	- Nodes: IP, domain, URL, hash, ASN, device-type.
	- Edges (typed): download, C2-contact (observed), dns-resolve, scan-exposes, proxy-exposes, attack-command.
	- Graph snapshots over time (weekly) to support longitudinal analysis.
- 5.7 **Campaign clustering** — *DEFERRED / FUTURE WORK in current draft*
	- Requires: download URLs, command templates, or C2 IP extractions — none present in the current 3-day honeypot window.
	- Can still build a partial graph using device-record ASN co-occurrence and feed family co-occurrence, but full campaign clustering is not credible with current data. Flag explicitly as "preliminary infrastructure" in paper.
- 5.8 **Monetization detection and linkage metrics** — *REDUCED SCOPE (passive indicators only)*
	- Proxy indicators measurable from scan data: **1,825 devices with proxy ports (8080/3128/1080/8888/9050)**, **327 SOCKS5-protocol devices**, **2,687 devices classified as proxy-type**, **407 Squid proxy installations**, **9.9% of the scanned population**. This is the strongest monetization signal we have.
	- DDoS indicators: ~~attack-command strings observed in honeypots~~ **REMOVED** — 0 command templates extracted; cannot claim DDoS observation.
	- Spam indicators: SMTP (port 25/458 devices from scan), Postfix installs (105) — can claim exposure signal, not confirmed abuse.
	- Cross-match result: 1 Shodan/Censys device matched ThreatFox; 0 honeypot attacker IPs matched feeds. Frame carefully as measurement limitation, not methodology failure.
	- ~~time-to-monetization distribution~~ **REMOVED** — requires direct linkage chain not available in current data.
- 5.9 **Longitudinal metrics** — *REDUCED SCOPE*
	- 3-day honeypot window: **317 IPs seen on multiple days** (persistence/persistence signal). Framed as preliminary churn observation, not full survival analysis.
	- Two Shodan snapshot weeks (Apr 6 vs Apr 20, 2 weeks apart): compare device counts, device type shifts, new/disappeared IPs. This is the primary longitudinal signal.
	- ~~Survival curves~~ **REMOVED** — requires weeks of data; current window too short. Mention as future work.
- 5.10 **Validation and robustness**:
	- Cross-source validation: Shodan device IPs vs ThreatFox/URLhaus/MalwareBazaar/OTX (1 match found; document as measurement finding on population difference).
	- Ablation: Shodan-only vs Shodan+Censys comparison (can do for Apr 20 week data). Replace passive DNS ablation with feed-source ablation (ThreatFox only vs all 4 feeds).
	- ~~Shodan+Censys+honeypot IOC ablation~~ **REDUCED** — honeypot IOC set is predominantly source IPs (2,021 IPs, 1 hash, 0 URLs), making a joint-ablation with scan data uninformative in current form.

### 6. Dataset Overview and Characterization
- Scale summary table: counts per source and per week. **Use these confirmed numbers:**

  | Source | Records | Unique IPs | Window |
  |---|---|---|---|
  | Shodan (Apr 6 wk) | 6,002 | 3,855 | 1 snapshot |
  | Shodan (Apr 20 wk) | 10,385 | 9,510 | 1 snapshot |
  | Censys (Apr 20 wk) | 2,063 | 60 | 1 snapshot |
  | Glutton honeypot | 8,302 events | 2,014 IPs | 3 days |
  | Cowrie honeypot | 104 events | 9 IPs | 1 day |
  | OpenCanary | 1 event | 1 IP | — |
  | ThreatFox | 5,013 IOCs | 63 malware families | 7-day window |
  | URLhaus | 4,235 IOCs (4,081 urls + 154 hashes) | 57 tag families | 7-day window |
  | OTX | 1,665 IOCs | 5 pulse families | 7-day window |
  | MalwareBazaar | 1,505 samples | 10 IoT families | 7-day window |
  | **TOTAL** | **~38,280** | **~15,500+** | **Apr 6 – Apr 25** |

- Device-type distribution (from scan data): router (3,901 / 21.1%), proxy (2,687 / 14.6%), camera (2,436 / 13.2%), server (2,392 / 13.0%), IoT-classified (1,867 / 10.1%), unknown (5,167 / 28.0%).
- Ports/services: Telnet/port 23 (2,335), TR-069/port 7547 (1,401), Telnet alt/port 2323 (551), MQTT/1883 (14), RTSP camera (800 records).
- Top identified products: Hikvision IP Camera (641), Squid proxy (407), BusyBox telnetd (466 combined), MikroTik router (259), GoAhead embedded web (363 combined), Cisco router telnetd (86).
- Honeypot attack characterization: 8,303 TCP connection events (dominant), 15 login failures, 10 unique credential pairs observed (**note: weak credential dictionary — insufficient for top-N credential analysis**).
- Geographic/ASN distribution: top ASNs — Alibaba (2,631 combined entries), Amazon AWS (652), Charter Communications (711 combined), Akamai/Linode (926 combined).
- ~~top command families~~ **REMOVED** — 0 command templates extracted.

### 7. Results I — Exposure and Attack Infrastructure *(renamed from "Infection and Campaign" — data-grounded)*
- IoT device exposure distribution: device types, services, ports, products by source and snapshot week.
- Attack pattern characterization: event types, top attacker IPs, destination port targeting behavior (port 8728 Winbox/MikroTik: 608 hits, port 5432 PostgreSQL: 201, port 443: 139, port 22 SSH: 103).
- Feed-based botnet family landscape: IoT-relevant families in ThreatFox — **elf.mirai (866 C2s), elf.mozi (549), elf.bashlite (190)**; in MalwareBazaar — **hajime (654), tsunami (321), mirai (273), xorddos (110)**; in OTX — **muhstik (236), mirai (222), xorddos (124)**. Position as corroborating context for the attack traffic observed.
- ~~Campaign size distribution and C2 reuse~~ **REMOVED** — no C2 URLs/commands extracted from honeypot; campaign clustering not completed.
- ~~Graph analytics / community structure~~ **DEFERRED** — infrastructure graph not built yet; move to future work or Phase 2.
- Case-study vignette (1, reduced from 2–3): describe one representative attacker IP cluster (e.g., the 85.11.167.11 host with 475 hits) using feed cross-reference and device record context.

### 8. Results II — Monetization-Consistent Exposure Indicators *(reframed from "Proxy/DDoS/Spam Linkage")*
- **Proxy exposure measurement (primary result):** 1,825 devices with proxy-indicative ports (8,080: 955, 1080: 443, 3128: 414 others: 13); 327 confirmed SOCKS5-protocol devices; 2,687 device records classified proxy-type (14.6% of all scanned devices); 407 Squid proxy installs identified by banner. These represent the strongest monetization-consistent signal in our data.
- **SMTP/spam exposure:** 458 SMTP-protocol devices, 105 Postfix installs — signals potential spam relay infrastructure; describe as exposure indicator only.
- ~~Time-lag analysis: compromise-signal → proxy exposure~~ **REMOVED** — requires temporal linkage of honeypot attack timestamps to proxy exposure timestamps on the same IPs; current data does not support this (0 cross-matches between honeypot attacker IPs and scanned device IPs).
- ~~DDoS linkage~~ **REMOVED** — no attack commands extracted from honeypot logs.
- Concentration analysis: proxy-port devices concentrated in hosting/cloud ASNs (Alibaba, Akamai/Linode, Amazon) vs residential ISPs (Charter, Korea Telecom) — valid finding from scan data alone.
- Sensitivity: show proxy count with strict definition (only ports 1080+3128+SOCKS5 banner) vs. broad definition (any proxy-indicative port) — both sets computable from current data.

### 9. Results III — Longitudinal Dynamics *(scope reduced to match available data)*
- **Two-week Shodan snapshot comparison (Apr 6 vs Apr 20):** 3,855 unique IPs observed in week 1 vs. 9,510 in week 2 — significant expansion (likely broader query coverage). Overlap/churn between the two weeks: compute IPs present in both vs. only one snapshot. This is a valid 2-point longitudinal signal.
- **3-day honeypot IP persistence:** 317 of 1,918 tracked IPs (16.5%) seen on multiple days — indicates persistent scanning infrastructure, not one-off attackers.
- Attack volume trend: Apr 23 (541 Glutton events) → Apr 24 (3,688) → Apr 25 (3,445) — show as daily attack volume bar chart.
- ~~Survival curves~~ **REMOVED** — requires weeks of continuous honeypot data; 3 days insufficient for Kaplan-Meier style analysis. Reframe as "persistence rate" (% IPs reappearing daily) instead.
- ~~Reinfection cadence~~ **REMOVED** — requires confirmed device identity across sessions; not resolvable from current data.
- ~~Cluster stability across weeks~~ **REMOVED** — no clusters built.

### 10. Discussion and Implications
- Implications for defenders: practical detection/risk scoring ideas derived from your measured signals.
- What is new vs known: connect back to RQs and related work.
- Operational recommendations: what telemetry is most valuable and low-cost.

### 11. Limitations
- **Short collection window:** Honeypot data covers only 3 days (Apr 23–25); scanning spans two snapshots 2 weeks apart. Cannot support long-term trend claims or survival analysis.
- **Minimal credential capture:** Only 10 unique credential pairs — insufficient for top-N credential dictionary analysis or brute-force pattern characterization. Attribute to Glutton's protocol-level capture (connections, not full session auth flows).
- **No download URLs or command templates:** 0 download URLs and 0 command templates extracted from honeypot logs in this window. The infection→payload→C2 chain cannot be directly demonstrated from current data.
- **Zero direct IP cross-matches (honeypot ↔ feeds):** Expected due to population difference: honeypot captures scanning bots (infected devices), while threat feeds track C2 servers (operator infrastructure). Explained in paper; not a methodology failure.
- **Only 1 Shodan/Censys device matched ThreatFox:** Suggests that mass-scanning IoT infrastructure uses different IPs than known malware C2s, confirming separation of botnet roles.
- **No passive DNS:** Domain-to-IP mapping over time not collected. Flag explicitly and propose as future work.
- Dataset bias (Shodan/Censys visibility), NAT/dynamic IP issues, banner ambiguity — unchanged.
- Proxy false positives/negatives; inability to prove revenue directly — unchanged.
- Ethics constraints limiting ground truth — unchanged.

### 12. Reproducibility and Artifact
- Release plan: sanitized indicators, schema, queries, code pipeline, and ethics statement.
- What is withheld and why.

### 13. Conclusion
- One paragraph summarizing measurable findings + contributions.

## “Reviewer expectation” checklist (use during writing)
- Every RQ has: method → metric → figure/table → finding.
- Every major claim has a number attached (with confidence/limitations).
- Ethics is not an afterthought (a full section).
- At least one robustness/ablation analysis.

## Figures and tables you should plan early (IoT-J papers are figure-driven)
- **Fig. 1:** End-to-end measurement pipeline (sources → processing → analyses). ✅ *Drawable now.*
- **Fig. 2:** Dataset timeline and event volume (daily attack counts Apr 23–25; scanning weeks Apr 6 and Apr 20). ✅ *Data available.*
- **Fig. 3:** Device-type + service exposure distributions — stacked bar: router/camera/proxy/server/IoT/unknown; pie of top services (telnet/http/rtsp/ssh/smtp). ✅ *Data available.*
- ~~Fig. 4: Honeypot credential dictionary distribution~~ **REMOVED** — only 10 pairs, no meaningful distribution.
- **Fig. 4 (renumbered):** Top attacker IPs by hit count + destination port targeting heatmap. ✅ *Data available (8,407 events).*
- **Fig. 5:** Proxy exposure analysis — stacked bar of proxy-indicative port counts (955+443+414+…) + device_type=proxy breakdown by ASN/country. ✅ *Data available (1,825 devices).*
- **Fig. 6:** Botnet family landscape — grouped bar: ThreatFox families (mirai/mozi/bashlite) + MalwareBazaar IoT families + OTX families. Framed as threat intelligence context. ✅ *Data available.*
- **Fig. 7:** Two-snapshot Shodan comparison (Apr 6 vs Apr 20) — device count, device type shifts, top products. ✅ *Data available.*
- ~~Fig. 5: Infrastructure graph / Fig. 6: Campaign size~~ **DEFERRED** — requires graph construction; future work.
- ~~Fig. 7: Time-to-monetization plot~~ **REMOVED** — no direct linkage chain.
- ~~Fig. 8: Survival curves~~ **REPLACED** with IP persistence bar chart (3-day window, 317 persistent IPs / 16.5% rate).
- **Table 1:** Data sources + fields + collection schedule. ✅ *Fillable with confirmed numbers above.*
- **Table 2:** Definitions/metrics (exposure indicator, proxy indicator, persistence, IoT device classification). ✅
- **Table 3:** Summary of key quantitative findings — use the confirmed numbers from investigation script.


# Initial Plan
## 2) What a Q1 reviewer will look for (your checklist)
You need at least **two** of these three to look strong:
1) **Large-scale empirical evidence**: thousands of IPs / long-enough collection window / multiple vantage points (Shodan + Censys + honeypot).
2) **Clear novelty**: a new measurement methodology, a new linkage analysis (botnet ↔ proxy monetization), or a new risk scoring/detection model.
3) **Reproducibility**: transparent pipeline, ethics, dataset release, and ablation studies.


## 3) Scope definition
### Core research question
How are compromised IoT devices (routers and IP cameras) **recruited, controlled, and monetized** as cybercrime infrastructure


## gaps can be presented


1) **Linkage analysis**: quantify overlap between (a) IoT compromise signals and (b) proxy infrastructure signals.
2) **Infrastructure graph + clustering**: cluster C2 / distribution URLs / credential-attempt fingerprints into campaigns.
3) **Proxy-abuse detection model (low-cost)(optional)**: a lightweight classifier or risk score using passive features (banner, AS type, device fingerprint hints, port/protocol exposure, churn).
4) **Longitudinal dynamics**: how fast nodes churn, re-infection cadence, and campaign lifetimes.
5) **Reproducible dataset**: release (sanitized) indicators + methodology + code.


## What to cover in the paper 
deliverables:
- **Dataset**: Shodan/Censys snapshots + honeypot logs (weeks) + extracted IOCs (download URLs, hashes, C2 domains/IPs if safely observed).


- **Measurement results**:
 - device categories (router/camera) and exposed services distribution
 - infection attempt patterns (usernames/password dictionaries *observed on honeypot*)






- **technical novelty** (choose one):
 - campaign clustering (C2 / dropper / TTP patterns)
 - infrastructure graph with community detection
 - proxy-abuse detection heuristic (not full ML yet)
- **Ethics & safety** section that looks professional.


## What to add for the journal 
Journal-only additions (pick several):
- **Dataset**: Shodan/Censys snapshots + honeypot logs (weeks) + extracted IOCs (download URLs, hashes, C2 domains/IPs if safely observed).
- **Longitudinal collection**: extend monitoring window; add repeated measurements and survival/churn analysis.
- **Ablations**: show which features/signals matter (e.g., only Shodan vs Shodan+Censys vs +honeypot).
 - malware family indicators (strings/commands if you can’t safely execute)
- **Formal threat model / risk scoring**:
 - define a score $R = f(\text{exposure}, \text{botnet indicators}, \text{proxy indicators}, \text{churn})$
 - validate against held-out time windows (predict future abuse)
- **Better clustering**:
 - combine network IOCs + behavioral fingerprints
 - evaluate cluster stability
- **Public artifact**:
 - sanitized dataset + code + exact queries + ethics statement


## 8) Realistic execution plan (3 months conference)
### Week 1–2: research framing + pipeline setup
- Lock scope + claims (2–3 contributions max for conference).
- Build data pipeline skeleton:
 - Shodan/Censys export parsing
 - honeypot deployment (telnet/ssh + simple HTTP)
 - storage (SQLite/Postgres) and analysis notebooks/scripts
- Write a 1-page ethics plan.


### Week 3–5: data collection (start early)
- Run honeypots continuously.
- Pull Shodan/Censys snapshots weekly (same queries each time).
- Start IOC extraction (download URLs, hashes, C2 endpoints observed on honeypots).


### Week 6–8: analysis + first results
- Campaign clustering (start simple):
 - group by download URL host, file hash, command string, or destination IP/ASN.
- Build infrastructure graph:
 - nodes: IPs/domains/URLs
 - edges: observed relationships
- Produce the “core plots” (conference-ready):
 - timeline (events/day)
 - top credentials attempted (from honeypot)
 - geographic/ASN distributions (coarse)
 - churn curves for observed IPs


### Week 9–10: write the conference paper
- Draft figures first, then narrative.
- Keep contributions explicit and limited.


### Week 11–12: polish + reproducibility
- Clean up code, produce artifact appendix.
- Double-check ethics wording.
- Prepare submission + backup venue.


## 9) Journal extension plan (2 months after conference submission)
### Month 4 (Weeks 13–16): scale + rigor
- Extend monitoring and repeat measurements.
- Add ablation experiments and stability tests.
- Implement risk scoring / lightweight classifier.


### Month 5 (Weeks 17–20): journal writing + artifact
- Rewrite introduction and related work (journal depth).
- Add formal threat model + validation.
- Package dataset (sanitized) + code + documentation.


## 10) Low-budget stack
- 1–2 low-cost VPS instances (or university machines) for honeypots.
- Open-source tools:
 - Cowrie (SSH/Telnet honeypot) or equivalent
 - Zeek + tcpdump for traffic metadata
 - Python: pandas, scikit-learn, network
 - Optional: Docker Compose to keep it reproducible










# Descriptive plan:

Contribution 1 — Multi-vantage measurement
Measure internet-exposed IoT devices and attack activity using:
- Shodan (2 snapshot weeks)
- Censys (1 snapshot week)
- 3 honeypots (Glutton/Cowrie/OpenCanary)
- 4 threat intelligence feeds (ThreatFox/URLhaus/MalwareBazaar/OTX)
~~passive DNS~~ — deferred to future work

Actual scale (Apr 2026 data):
- **18,450 device records** (not 100k — do not overclaim)
- **13,425+ unique scanned IPs**
- **8,407 honeypot events**, 2,014 unique attacker IPs
- **12,418 feed IOCs** across 4 sources
- Window: ~3 weeks total (2 scan snapshots + 3-day honeypot)

> ⚠️ **Claim ceiling:** "internet-scale" is borderline; prefer "multi-vantage" as the strength. Scale is substantive for a conference paper but not extraordinary for a journal. Flag ongoing collection.

Contribution 2 — Infrastructure mapping
Build a cybercrime infrastructure graph:
IoT device
↓
loader server
↓
malware host
↓
C2
↓
proxy network
↓
abuse service
Graph nodes:
IP
domain
ASN
malware hash












Contribution 3 — Monetization-consistent exposure measurement *(reframed)*
Measure indicators consistent with monetization infrastructure among the scanned IoT population.

What we CAN claim:
- **Proxy exposure:** 1,825 devices with proxy-indicative ports (9.9% of scanned population); 327 confirmed SOCKS5-protocol; 2,687 proxy-type classified; 407 Squid installations
- **SMTP exposure:** 458 SMTP-protocol devices, 105 Postfix installs
- **Concentration analysis:** cloud vs. residential proxy distribution by ASN

What we CANNOT claim (insufficient data):
- ~~DDoS-for-hire attack traffic~~ — 0 attack commands in honeypot logs
- ~~Confirmed credential stuffing automation~~ — only 10 credential pairs observed
- ~~HTTP automation signals~~ — no web session data captured
- ~~Revenue measurement~~ — no direct monetization chain observed

> Frame as: *"We measure the fraction of exposed IoT devices that exhibit infrastructure characteristics consistent with proxy-based monetization, as a lower-bound estimate of monetization-capable infrastructure."*


Contribution 4 — Preliminary longitudinal dynamics *(scope reduced)*
Measure observable temporal patterns within current data window:

What we CAN claim:
- **Attack volume trend:** 541 → 3,688 → 3,445 events over 3 consecutive days (Apr 23–25)
- **IP persistence rate:** 317 / 1,918 IPs (16.5%) seen on multiple days — persistent scanning infrastructure
- **Two-week scanning delta:** Apr 6 vs Apr 20 Shodan snapshot comparison (device counts, type distribution, new/disappeared IPs)

What we CANNOT claim (insufficient window):
- ~~Infection time measurement~~ — no confirmed per-device infection timestamps
- ~~Campaign lifetime~~ — no campaigns built
- ~~Reinfection rate~~ — 3 days insufficient; identity resolution across sessions not done
- ~~Full churn/survival curves~~ — insufficient time series depth

> Frame as: *"preliminary longitudinal signals within a 3-day window and 2-point scanning comparison; extended longitudinal characterization is ongoing."*





