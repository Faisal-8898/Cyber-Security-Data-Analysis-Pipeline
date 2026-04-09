# Research & Publication Plan (Low Budget)
## Working title (conference/journal-ready)
From Infection to Monetization: Measuring Compromised IoT Devices in Cybercrime Infrastructure


# Q1 Journal Paper Outline (IEEE Internet of Things Journal target)

## Paper type and positioning (important for IoT-J)
- **Type**: Internet-scale *security measurement* + *infrastructure mapping* paper (not a “framework/proposal” paper).
- **Core claim**: measurable, multi-vantage evidence that compromised IoT devices participate in (or strongly overlap with) monetization infrastructure (e.g., proxy abuse) and show characteristic lifecycle dynamics Monetization linkage of compromised IoT devices


## Recommended section flow (journal-ready)

### Title + Abstract + Index Terms
- **Abstract**: (i) problem + gap, (ii) what you measured (sources + window + scale), (iii) how (linkage/graph/metrics), (iv) key quantitative findings (top 3), (v) contributions + artifact.
- **Index Terms**: IoT security, measurement, botnets, cybercrime infrastructure, proxy abuse, longitudinal analysis, graph analytics.

### 1. Introduction
- Motivation: why “infection → monetization” matters and what prior IoT botnet papers typically miss.
- Clear **research questions (RQs)** (example):
	- RQ1: How can compromised IoT devices be reliably identified at internet scale using multi-vantage signals, and what is their prevalence across device types and networks?
	- RQ2: To what extent can compromised IoT devices be systematically linked to downstream cybercrime infrastructure (e.g., loaders, C2 servers, proxy backends) using observable network interactions?
	- RQ3: What quantitative evidence demonstrates that compromised IoT devices contribute to monetization infrastructure, and what fraction of the observed population participates in such activities?
	- RQ4: Do linked IoT devices form distinct infrastructure clusters corresponding to coordinated campaigns, and what characteristics differentiate these campaigns?
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
- **Collection window**: dates, duration, snapshot frequency.
- **Vantage points** (subsections):
	- 4.1 Honeypots (SSH/Telnet/HTTP/TR-069): what is captured (credentials attempted, commands, URLs, C2 endpoints).
	- 4.2 Shodan and Censys snapshots: query themes, fields used (ports, banners, fingerprints, geo/ASN).
	- 4.3 Malware intelligence feeds: what you extract (domains, IPs, hashes) and constraints.
	- 4.4 Passive DNS: mapping domains → IPs over time.
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
- 5.7 **Campaign clustering**:
	- Similarity signals: shared download host, shared command template, shared C2/ASN, shared hash (if present).
	- Method: simple baseline first (connected components / Louvain / label propagation), then stability checks.
- 5.8 **Monetization detection and linkage metrics**:
	- Proxy indicators: ports (1080/3128/8080), banners, proxy protocol hints.
	- DDoS indicators: attack-command strings observed in honeypots (no execution).
	- Spam indicators: SMTP exposure signals via scan datasets.
	- Linkage metrics: overlap %, conditional probabilities, time-to-monetization distribution, campaign-level overlap.
- 5.9 **Longitudinal metrics**:
	- Churn (appearance/disappearance), survival curves, reinfection cadence, campaign lifetime.
- 5.10 **Validation and robustness**:
	- Cross-source validation (honeypot IOC ↔ passive DNS ↔ feeds).
	- Ablations: Shodan-only vs Shodan+Censys vs +honeypot IOCs (at least one ablation for journal quality).

### 6. Dataset Overview and Characterization
- Scale summary table: counts per source and per week.
- Device-type distribution (router/camera/unknown), ports/services distribution.
- Honeypot attack characterization: login attempts/day, top credentials, top command families.
- Geographic/ASN distribution (coarse, avoid overclaiming attribution).

### 7. Results I — Infection and Campaign Infrastructure
- Campaign size distribution and top infrastructure patterns (loader/C2 reuse, hosting ASNs).
- Graph analytics: component sizes, centrality highlights (interpreted cautiously), community structure.
- Case-study vignettes (2–3) of representative campaign archetypes (sanitized).

### 8. Results II — Monetization: Proxy/DDoS/Spam Linkage
- Proxy overlap: fraction of candidate compromised IoT devices that match proxy indicators; campaign-level overlap.
- Time-lag analysis: compromise-signal → proxy exposure.
- Concentration: where overlap clusters (AS types, hosting vs residential, etc.) without “blame” language.
- Sensitivity analysis: how results change when using stricter proxy definitions.

### 9. Results III — Lifecycle and Longitudinal Dynamics
- Churn/survival curves for devices and campaigns.
- Reinfection cadence: repeated compromise signals over time.
- Stability of clusters/campaigns across weeks.

### 10. Discussion and Implications
- Implications for defenders: practical detection/risk scoring ideas derived from your measured signals.
- What is new vs known: connect back to RQs and related work.
- Operational recommendations: what telemetry is most valuable and low-cost.

### 11. Limitations
- Dataset bias (Shodan/Censys visibility), NAT/dynamic IP issues, banner ambiguity.
- Proxy false positives/negatives; inability to prove revenue directly (be explicit about what you can/cannot claim).
- Ethics constraints limiting ground truth.

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
- Fig. 1: End-to-end measurement pipeline (sources → processing → analyses).
- Fig. 2: Dataset timeline and event volume.
- Fig. 3: Device-type + service exposure distributions.
- Fig. 4: Honeypot credential dictionary distribution.
- Fig. 5: Infrastructure graph visualization (sanitized) + graph stats.
- Fig. 6: Campaign size distribution.
- Fig. 7: Proxy overlap + time-to-monetization plot.
- Fig. 8: Churn/survival curves.
- Table 1: Data sources + fields + collection schedule.
- Table 2: Definitions/metrics (compromise, campaign, monetization, churn).
- Table 3: Summary of key quantitative findings.


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

Contribution 1 — Large-scale measurement
Measure compromised routers and cameras using:
Shodan
Censys
honeypots
passive DNS
malware feeds
Scale:
100k+ IPs
3–6 months

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












Contribution 3 — Monetization analysis
Measure how compromised IoT devices generate revenue.
Examples:
monetization
measurement
residential proxy
open proxy signals
DDoS-for-hire
attack traffic
spam relay
SMTP abuse
credential stuffing
HTTP automation


Contribution 4 — Infrastructure lifecycle
Measure:
infection time
campaign lifetime
reinfection rate
device churn
This is very valuable to defenders.
















7. Data collection architecture (stronger)
You need 4 vantage points.
1 Honeypots
Deploy:
Cowrie (SSH/Telnet)
HTTP admin panel honeypot
TR-069 port
Collect:
credential attempts
download commands
C2 endpoints
malware URLs

2 Internet scanning datasets
Use APIs:
Shodan
Censys
BinaryEdge (optional)
Collect:
banners
open ports
device fingerprints

3 Malware intelligence feeds
Public sources:
MalwareBazaar
VirusTotal
Abuse.ch
Extract:
C2 servers
download domains
malware families

4 Passive DNS
Use:
Farsight
SecurityTrails
Rapid7 DNS datasets
Map:
C2 domains → IP infrastructure

8. Infrastructure graph model
Create graph:
Nodes:
IP
domain
malware hash
ASN
device

Edges:
download
C2
scan
proxy
attack
Then run:
community detection
campaign clustering
centrality analysis
Tools:
NetworkX
Neo4j
Graph-tool

9. Monetization detection (critical section)
You need real monetization evidence.
Signals:
Proxy indicators
ports 1080
3128
8080
socks banner

DDoS infrastructure
Look for:
attack commands
UDP flood
TCP flood
in honeypot logs.

Spam infrastructure
Look for:
SMTP open relays
port 25 abuse

Credential stuffing
Look for:
high HTTP automation

10. Risk model (journal part)
Your formula idea is good but needs improvement.
Instead of simple heuristic:
R = f(exposure, botnet signals, proxy signals, churn)
Use survival analysis + ML.
Example features:
device type
ASN
port exposure
credential dictionary
C2 reuse
reinfection rate
Model:
Random Forest
or Gradient Boosting

11. Key figures (reviewers love this)
Your paper should contain 10+ figures.
Examples:
Figure 1
IoT infection pipeline

Figure 2
device distribution
routers vs cameras

Figure 3
attack timeline

Figure 4
campaign size distribution

Figure 5
cybercrime infrastructure graph

Figure 6
proxy monetization overlap

Figure 7
device churn survival curve

12. Expected dataset scale
Target numbers or can be more:
Shodan/Censys devices: 100k–500k
honeypot attacks: 50k–500k
C2 domains: 1k+
campaign clusters: 50–200

13. Ethical considerations (VERY important)
Must include:
no exploitation
no malware propagation
no unauthorized scanning
only passive measurement
Also:
IRB / ethics approval
if possible.




15. Step-by-step work plan (realistic)
Phase 1 — Literature review (2 weeks)
Read 30 papers.
Categories:
IoT botnets
residential proxies
cybercrime infrastructure
Internet measurement

Phase 2 — Infrastructure setup (2 weeks)
Deploy:
honeypots
data pipeline
storage

Phase 3 — Data collection (8 weeks)
Collect:
Shodan snapshots
honeypot logs
malware feeds

Phase 4 — Infrastructure graph (4 weeks)
Build:
IOC extraction
graph
campaign clustering

Phase 5 — Monetization analysis (3 weeks)
Measure:
proxy overlap
attack infrastructure

Phase 6 — Modeling (3 weeks)
Build:
risk scoring
classifier

Phase 7 — Writing (4 weeks)
Write sections:
methodology
analysis
results

16. The most important improvement you must make
Right now your paper measures:
infection infrastructure
But your title promises:
monetization
You must prove economic exploitation.
Examples:
proxy traffic resale
DDoS-for-hire
spam relays
Without that, reviewers will say:
“This is just another IoT botnet measurement paper.”


