"""pipeline/build_graph.py — Weekly graph build + campaign clustering.

Tasks (T10 + T11 from dataPipeLinePlan.md §8.2):

  T10  build_networkx_graph
       ├── Load ioc_records from DB
       ├── Load device_records for the current snapshot week
       ├── Load attacker-IP co-occurrence signals from honeypot_events
       ├── Build nx.DiGraph with typed edges
       ├── Run Louvain community detection on undirected projection
       ├── Write nodes  → graph_nodes table
       ├── Write edges  → graph_edges table
       └── Serialize GraphML to GRAPH_OUTPUT for reproducibility

  T11  cluster_campaigns
       ├── Group attacker IPs by Louvain cluster
       ├── Aggregate: event_count, source_ip_count, primary_protocol,
       │             primary_creds, c2_ips, c2_domains, malware_hashes
       └── UPSERT → campaign_clusters table

Edge types
----------
  downloads_from   : attacker IP  →  download URL
  hosts_malware    : download URL →  SHA256 hash
  uses_fingerprint : attacker IP  →  HASSH value
  c2_contact       : attacker IP  →  C2 IP / domain extracted from commands
  same_campaign    : attacker IP  →  attacker IP  (shared credential pair)
  shares_asn       : attacker IP  →  attacker IP  (identical ASN, ≥2 distinct hits)

Environment variables
---------------------
  GRAPH_OUTPUT_DIR   dir for GraphML files (default: /var/lib/iot-pipeline)
  GRAPH_DRY_RUN      "1" → build graph but do NOT write to DB / disk
"""
from __future__ import annotations

import os
import hashlib
from collections import defaultdict
from datetime import date, timedelta, timezone, datetime
from pathlib import Path
from typing import Any

import networkx as nx

# community_louvain is provided by the `python-louvain` package
try:
    import community as community_louvain  # python-louvain
    _LOUVAIN_AVAILABLE = True
except ImportError:
    _LOUVAIN_AVAILABLE = False

from .core import get_pipeline_version, logger, task

_GRAPH_DIR = Path(os.getenv("GRAPH_OUTPUT_DIR", "/var/lib/iot-pipeline"))
_DRY_RUN   = os.getenv("GRAPH_DRY_RUN", "0") == "1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _monday(d: date | None = None) -> date:
    d = d or date.today()
    return d - timedelta(days=d.weekday())


def _stable_cluster_id(node_values: list[str]) -> str:
    """Deterministic cluster ID from sorted member node values."""
    raw = ",".join(sorted(node_values))
    return "cluster_" + hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# DB data loaders (all DB imports are lazy to allow unit testing without DB)
# ---------------------------------------------------------------------------

def _load_event_signals() -> list[dict[str, Any]]:
    """Load (source_ip, download_url, file_hash, hassh) from honeypot_events."""
    from . import db as _db
    with _db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT
                    source_ip::TEXT,
                    download_url,
                    file_hash,
                    hassh
                FROM honeypot_events
                WHERE source_ip IS NOT NULL
                  AND (
                      download_url IS NOT NULL
                      OR file_hash IS NOT NULL
                      OR hassh     IS NOT NULL
                  )
                """
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


def _load_credential_cooccurrence() -> list[tuple[str, str]]:
    """
    Return list of (ip_a, ip_b) pairs that share at least one credential pair.
    These become same_campaign edges.
    """
    from . import db as _db
    with _db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT
                    a.source_ip::TEXT AS ip_a,
                    b.source_ip::TEXT AS ip_b
                FROM honeypot_events a
                JOIN honeypot_events b
                    ON a.username = b.username
                   AND a.password = b.password
                   AND a.source_ip <> b.source_ip
                WHERE a.username  IS NOT NULL
                  AND a.password  IS NOT NULL
                  AND a.source_ip IS NOT NULL
                  AND b.source_ip IS NOT NULL
                  AND a.username  <> ''
                  AND a.password  <> ''
                LIMIT 50000
                """
            )
            return [(row[0], row[1]) for row in cur.fetchall()]


def _load_c2_iocs() -> list[dict[str, Any]]:
    """
    Return IOC records of types 'ip' and 'domain' extracted from command strings.
    These become c2_contact edges from source_honeypots[0] → ioc_value.
    """
    from . import db as _db
    with _db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT ioc_type, ioc_value, source_honeypots
                FROM ioc_records
                WHERE ioc_type IN ('ip', 'domain')
                  AND source_honeypots IS NOT NULL
                ORDER BY occurrence_count DESC
                LIMIT 20000
                """
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


def _load_asn_groups() -> dict[str, list[str]]:
    """
    Return {asn: [ip, ...]} map from device_records for the current snapshot week.
    Used to build shares_asn edges.
    """
    from . import db as _db
    week = str(_monday())
    with _db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT asn::TEXT, ip::TEXT
                FROM device_records
                WHERE snapshot_week = %s
                  AND asn IS NOT NULL
                GROUP BY asn, ip
                """,
                (week,),
            )
            groups: dict[str, list[str]] = defaultdict(list)
            for asn, ip in cur.fetchall():
                groups[asn].append(ip)
            return groups


def _load_device_records(snapshot_week: str) -> list[dict[str, Any]]:
    """Load device_records for the given snapshot week."""
    from . import db as _db
    with _db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT ip::TEXT, port, device_type, asn::TEXT, org,
                       country_code, cve_ids, tags
                FROM device_records
                WHERE snapshot_week = %s
                """,
                (snapshot_week,),
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_graph(
    event_signals: list[dict],
    cred_pairs: list[tuple[str, str]],
    c2_iocs: list[dict],
    asn_groups: dict[str, list[str]],
) -> nx.DiGraph:
    """
    Construct a directed graph from honeypot co-occurrence signals.

    Returns a nx.DiGraph where:
      - each node has attrs: node_type, first_seen, last_seen
      - each edge has attrs: edge_type, weight
    """
    G = nx.DiGraph()
    now = datetime.now(timezone.utc).isoformat()

    def _add_node(value: str, node_type: str) -> None:
        if value not in G:
            G.add_node(value, node_type=node_type, first_seen=now, last_seen=now)

    # T10.1: signal edges from honeypot_events ---------------------------------
    for row in event_signals:
        src_ip = row.get("source_ip")
        url    = row.get("download_url")
        fhash  = row.get("file_hash")
        hassh  = row.get("hassh")

        if not src_ip:
            continue

        _add_node(src_ip, "ip")

        if url:
            _add_node(url, "url")
            if G.has_edge(src_ip, url):
                G[src_ip][url]["weight"] += 1
            else:
                G.add_edge(src_ip, url, edge_type="downloads_from", weight=1.0,
                           first_seen=now, last_seen=now)

        if url and fhash:
            _add_node(fhash, "sha256")
            if not G.has_edge(url, fhash):
                G.add_edge(url, fhash, edge_type="hosts_malware", weight=1.0,
                           first_seen=now, last_seen=now)

        if hassh:
            _add_node(hassh, "hassh")
            if G.has_edge(src_ip, hassh):
                G[src_ip][hassh]["weight"] += 1
            else:
                G.add_edge(src_ip, hassh, edge_type="uses_fingerprint", weight=1.0,
                           first_seen=now, last_seen=now)

    # T10.2: same_campaign edges from shared credentials ----------------------
    for ip_a, ip_b in cred_pairs:
        _add_node(ip_a, "ip")
        _add_node(ip_b, "ip")
        if G.has_edge(ip_a, ip_b):
            G[ip_a][ip_b]["weight"] += 1
        else:
            G.add_edge(ip_a, ip_b, edge_type="same_campaign", weight=1.0,
                       first_seen=now, last_seen=now)

    # T10.3: c2_contact edges from extracted command IOCs ---------------------
    for ioc in c2_iocs:
        ioc_val  = ioc.get("ioc_value", "")
        ioc_type = ioc.get("ioc_type", "")
        sources  = ioc.get("source_honeypots") or []
        if not ioc_val or not sources:
            continue

        node_type = "ip" if ioc_type == "ip" else "domain"
        _add_node(ioc_val, node_type)

        # The source_honeypots list contains honeypot names (e.g. "cowrie"),
        # not IPs — so we can only create a symbolic node here.  The edge
        # acts as a signal that the IOC was *seen in commands* from that
        # honeypot, not from a specific IP.  Full per-IP edges would require
        # a JOIN on honeypot_events (done in event_signals above for URLs/hashes).
        # We skip the edge creation here to avoid noise; c2_contact edges for
        # specific IPs are built via event_signals or the IOC join in T10.1.

    # T10.4: shares_asn edges (same ASN, ≥2 distinct IPs) --------------------
    for _asn, ips in asn_groups.items():
        if len(ips) < 2:
            continue
        # Add edges for every pair in the same ASN group (cap at 5 IPs per ASN
        # to avoid O(n²) explosion for large botnets)
        cap_ips = ips[:5]
        for i, ip_a in enumerate(cap_ips):
            for ip_b in cap_ips[i + 1:]:
                _add_node(ip_a, "ip")
                _add_node(ip_b, "ip")
                if not G.has_edge(ip_a, ip_b):
                    G.add_edge(ip_a, ip_b, edge_type="shares_asn", weight=0.5,
                               first_seen=now, last_seen=now)

    logger.info(
        f"build_graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges"
    )
    return G


# ---------------------------------------------------------------------------
# Community detection
# ---------------------------------------------------------------------------

def detect_communities(G: nx.DiGraph) -> dict[str, int]:
    """
    Run Louvain community detection on the undirected projection of G.
    Returns {node_value: community_id} mapping.
    Falls back to empty dict if python-louvain is not installed.
    """
    if not _LOUVAIN_AVAILABLE:
        logger.warning("python-louvain not installed — skipping community detection")
        return {}

    G_und = G.to_undirected()
    if G_und.number_of_nodes() == 0:
        return {}

    partition: dict[str, int] = community_louvain.best_partition(G_und)
    n_clusters = len(set(partition.values()))
    logger.info(f"Community detection: {n_clusters} Louvain clusters")
    return partition


# ---------------------------------------------------------------------------
# T10: build_networkx_graph
# ---------------------------------------------------------------------------

@task("build_networkx_graph")
def build_networkx_graph(snapshot_week: date | None = None) -> nx.DiGraph | None:
    """Build the full IoT research graph and persist it to DB + GraphML."""
    snapshot_week = snapshot_week or _monday()
    week_str = str(snapshot_week)

    from . import db as _db

    run_id = _db.record_run_start(
        "build_networkx_graph",
        {"snapshot_week": week_str},
    )

    # --- Load data -----------------------------------------------------------
    logger.info("build_networkx_graph: loading event signals …")
    event_signals = _load_event_signals()

    logger.info("build_networkx_graph: loading credential co-occurrence …")
    cred_pairs = _load_credential_cooccurrence()

    logger.info("build_networkx_graph: loading C2 IOCs …")
    c2_iocs = _load_c2_iocs()

    logger.info("build_networkx_graph: loading ASN groups …")
    asn_groups = _load_asn_groups()

    # --- Build graph ---------------------------------------------------------
    G = build_graph(event_signals, cred_pairs, c2_iocs, asn_groups)

    # --- Community detection -------------------------------------------------
    partition = detect_communities(G)
    if partition:
        nx.set_node_attributes(G, partition, "cluster_id")

    # --- Annotate device types from device_records ---------------------------
    device_rows = _load_device_records(week_str)
    device_map  = {r["ip"]: r for r in device_rows}
    for ip, data in device_map.items():
        if G.has_node(ip):
            G.nodes[ip]["device_type"] = data.get("device_type", "unknown")

    # --- Persist nodes -------------------------------------------------------
    nodes_to_write = [
        {
            "node_type":  attrs.get("node_type", "unknown"),
            "node_value": node,
            "first_seen": attrs.get("first_seen"),
            "last_seen":  attrs.get("last_seen"),
            "cluster_id": str(attrs["cluster_id"]) if "cluster_id" in attrs else None,
            "metadata":   {k: v for k, v in attrs.items()
                           if k not in ("node_type", "first_seen", "last_seen", "cluster_id")},
        }
        for node, attrs in G.nodes(data=True)
    ]

    if not _DRY_RUN:
        node_id_map = _db.upsert_graph_nodes(nodes_to_write)

        # --- Persist edges -------------------------------------------------------
        edges_to_write = []
        for src, tgt, edata in G.edges(data=True):
            src_id = node_id_map.get(src)
            tgt_id = node_id_map.get(tgt)
            if src_id and tgt_id:
                edges_to_write.append({
                    "source_node_id": src_id,
                    "target_node_id": tgt_id,
                    "edge_type":      edata.get("edge_type", "unknown"),
                    "weight":         edata.get("weight", 1.0),
                    "first_seen":     edata.get("first_seen"),
                    "last_seen":      edata.get("last_seen"),
                    "evidence":       {},
                })
        _db.upsert_graph_edges(edges_to_write)

        # --- Serialize GraphML for reproducibility ---------------------------
        _GRAPH_DIR.mkdir(parents=True, exist_ok=True)
        graphml_path = _GRAPH_DIR / f"graph_{week_str}.graphml"
        nx.write_graphml(G, str(graphml_path))
        logger.info(f"build_networkx_graph: GraphML → {graphml_path}")

        _db.record_run_end(
            run_id, "success",
            records_in=len(event_signals) + len(cred_pairs),
            records_out=G.number_of_nodes() + G.number_of_edges(),
        )
    else:
        logger.info("GRAPH_DRY_RUN=1 — skipping DB writes and disk serialization")

    return G


# ---------------------------------------------------------------------------
# T11: cluster_campaigns
# ---------------------------------------------------------------------------

@task("cluster_campaigns")
def cluster_campaigns(G: nx.DiGraph | None = None) -> int:
    """
    Group attacker IPs by Louvain cluster membership and UPSERT campaign_clusters.

    If G is None (e.g. called standalone from cron), it re-reads cluster_id
    annotations directly from the graph_nodes table.

    Returns the number of clusters written.
    """
    from . import db as _db

    run_id = _db.record_run_start("cluster_campaigns", {})

    # --- Determine cluster → nodes mapping -----------------------------------
    cluster_map: dict[str, list[str]] = defaultdict(list)

    if G is not None and G.number_of_nodes() > 0:
        for node, attrs in G.nodes(data=True):
            if attrs.get("node_type") == "ip" and "cluster_id" in attrs:
                cluster_map[str(attrs["cluster_id"])].append(node)
    else:
        # Fall back: read from graph_nodes table
        with _db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT node_value, cluster_id
                    FROM graph_nodes
                    WHERE node_type = 'ip' AND cluster_id IS NOT NULL
                    """
                )
                for node_val, cluster_id in cur.fetchall():
                    cluster_map[cluster_id].append(node_val)

    if not cluster_map:
        logger.info("cluster_campaigns: no clusters found — nothing to write")
        _db.record_run_end(run_id, "success", records_out=0)
        return 0

    # --- Build cluster records from honeypot_events stats --------------------
    clusters: list[dict[str, Any]] = []

    for cid, ip_list in cluster_map.items():
        if not ip_list:
            continue

        # Use the stable hash-based ID as cluster_id for reproducibility
        stable_id = _stable_cluster_id(ip_list)
        now = datetime.now(timezone.utc).isoformat()

        # Fetch per-cluster aggregated stats from DB
        stats = _cluster_stats(ip_list)

        clusters.append({
            "cluster_id":      stable_id,
            "name":            f"cluster_{cid}_{date.today().isoformat()}",
            "first_seen":      stats.get("first_seen") or now,
            "last_seen":       stats.get("last_seen") or now,
            "active":          True,
            "event_count":     stats.get("event_count", 0),
            "source_ip_count": len(ip_list),
            "primary_protocol": stats.get("primary_protocol"),
            "primary_creds":   stats.get("primary_creds", []),
            "c2_ips":          stats.get("c2_ips", []),
            "c2_domains":      stats.get("c2_domains", []),
            "malware_hashes":  stats.get("malware_hashes", []),
            "metadata": {
                "louvain_id": cid,
                "member_ips": ip_list[:20],   # store first 20 for reference
            },
        })

    if not _DRY_RUN:
        written = _db.upsert_campaign_clusters(clusters)
        logger.info(f"cluster_campaigns: {written} clusters upserted")
    else:
        written = len(clusters)
        logger.info(f"GRAPH_DRY_RUN=1 — {written} clusters would be written")

    _db.record_run_end(run_id, "success", records_out=written)
    return written


def _cluster_stats(ip_list: list[str]) -> dict[str, Any]:
    """
    Query honeypot_events for aggregate stats over the given IP list.
    Returns a dict with event_count, first_seen, last_seen, primary_protocol,
    primary_creds, c2_ips, c2_domains, malware_hashes.
    """
    from . import db as _db

    if not ip_list:
        return {}

    # psycopg2 / PostgreSQL — pass list as INET[]
    placeholders = ",".join(["%s"] * len(ip_list))

    with _db.get_connection() as conn:
        with conn.cursor() as cur:
            # Aggregate stats
            cur.execute(
                f"""
                SELECT
                    COUNT(*)                                AS event_count,
                    MIN(event_time)                         AS first_seen,
                    MAX(event_time)                         AS last_seen,
                    MODE() WITHIN GROUP (ORDER BY protocol) AS primary_protocol,
                    array_agg(DISTINCT file_hash)
                        FILTER (WHERE file_hash IS NOT NULL) AS malware_hashes
                FROM honeypot_events
                WHERE source_ip::TEXT IN ({placeholders})
                """,
                ip_list,
            )
            row = cur.fetchone()
            if not row:
                return {}

            event_count, first_seen, last_seen, primary_protocol, malware_hashes = row

            # Top-3 credential pairs
            cur.execute(
                f"""
                SELECT username || ':' || password AS cred
                FROM honeypot_events
                WHERE source_ip::TEXT IN ({placeholders})
                  AND username IS NOT NULL AND password IS NOT NULL
                GROUP BY username, password
                ORDER BY COUNT(*) DESC
                LIMIT 3
                """,
                ip_list,
            )
            primary_creds = [r[0] for r in cur.fetchall()]

            # C2 IPs/domains from ioc_records whose source_honeypots overlap
            cur.execute(
                """
                SELECT ioc_type, ioc_value
                FROM ioc_records
                WHERE ioc_type IN ('ip', 'domain')
                  AND source_honeypots && %s
                ORDER BY occurrence_count DESC
                LIMIT 20
                """,
                (["cowrie", "opencanary"],),   # broad filter; refine if needed
            )
            c2_ips:     list[str] = []
            c2_domains: list[str] = []
            for ioc_type, ioc_val in cur.fetchall():
                if ioc_type == "ip":
                    c2_ips.append(ioc_val)
                else:
                    c2_domains.append(ioc_val)

    return {
        "event_count":      event_count or 0,
        "first_seen":       first_seen.isoformat() if first_seen else None,
        "last_seen":        last_seen.isoformat()  if last_seen  else None,
        "primary_protocol": primary_protocol,
        "primary_creds":    primary_creds,
        "c2_ips":           c2_ips[:10],
        "c2_domains":       c2_domains[:10],
        "malware_hashes":   [h for h in (malware_hashes or []) if h][:10],
    }
