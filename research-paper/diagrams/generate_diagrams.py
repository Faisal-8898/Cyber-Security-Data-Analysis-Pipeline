"""
generate_diagrams.py
Generates 4 IEEE-standard publication figures for the IoT threat infrastructure paper.
Run: python research-paper/diagrams/generate_diagrams.py
Outputs: fig1_pipeline.pdf, fig2_device_exposure.pdf, fig3_attack_analysis.pdf, fig4_proxy_indicators.pdf
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
import numpy as np
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.colors import LinearSegmentedColormap

# ── output directory ─────────────────────────────────────────────────────────
OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── IEEE-compatible style ─────────────────────────────────────────────────────
plt.rcParams.update({
    'font.family': 'DejaVu Serif',
    'font.size': 9,
    'axes.titlesize': 10,
    'axes.labelsize': 9,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'legend.fontsize': 8,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.05,
    'axes.linewidth': 0.8,
    'grid.linewidth': 0.5,
    'grid.alpha': 0.4,
    'lines.linewidth': 1.2,
})

# Colour palette (accessible, print-friendly)
BLUE    = '#2166ac'
DKBLUE  = '#053061'
LBLUE   = '#74add1'
RED     = '#d73027'
ORANGE  = '#f46d43'
GREEN   = '#1a9850'
LGREY   = '#d9d9d9'
MGREY   = '#969696'
DGREY   = '#525252'
TEAL    = '#35978f'
PURPLE  = '#542788'

# ═══════════════════════════════════════════════════════════════════════════════
# FIG 1 — Measurement system pipeline architecture
# ═══════════════════════════════════════════════════════════════════════════════
def fig1_pipeline():
    fig, ax = plt.subplots(figsize=(7.16, 3.8))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5)
    ax.axis('off')

    def box(x, y, w, h, label, sublabel='', fc='#deebf7', ec=BLUE, fs=8.5):
        rect = FancyBboxPatch((x, y), w, h,
                               boxstyle="round,pad=0.08",
                               fc=fc, ec=ec, lw=1.2, zorder=3)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h/2 + (0.12 if sublabel else 0),
                label, ha='center', va='center',
                fontsize=fs, fontweight='bold', color=DKBLUE, zorder=4)
        if sublabel:
            ax.text(x + w/2, y + h/2 - 0.22, sublabel,
                    ha='center', va='center', fontsize=7,
                    color=DGREY, zorder=4, style='italic')

    def arrow(x1, y1, x2, y2=None, color=BLUE, lw=1.4):
        if y2 is None:
            y2 = y1
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle='->', color=color,
                                   lw=lw, mutation_scale=12))

    # ── Title ──
    ax.text(5, 4.72, 'Multi-Vantage IoT Measurement Pipeline',
            ha='center', va='center', fontsize=11, fontweight='bold', color=DKBLUE)

    # ── Layer 1: Data Sources ──
    src_y = 3.3
    srcs = [
        ('Shodan\n(2 snaps)', '', '#fff7bc'),
        ('Censys\n(1 snap)', '', '#fff7bc'),
        ('Glutton\nHoneypot', '', '#fddbc7'),
        ('Cowrie\nHoneypot', '', '#fddbc7'),
        ('Threat\nFeeds ×4', '', '#e0f3db'),
    ]
    xs = [0.3, 2.1, 3.9, 5.7, 7.5]
    for (lbl, sl, fc), x in zip(srcs, xs):
        box(x, src_y, 1.6, 0.85, lbl, sl, fc=fc, ec=ORANGE, fs=7.8)

    # Connect all sources to pipeline
    pipe_y_top = 3.3
    for x in xs:
        cx = x + 0.8
        ax.annotate('', xy=(cx, 2.55), xytext=(cx, pipe_y_top),
                    arrowprops=dict(arrowstyle='->', color=MGREY, lw=1.2,
                                   mutation_scale=10))

    # ── Layer 2: Ingestion / Normalisation ──
    box(0.25, 1.85, 9.5, 0.65, 'Ingestion & Normalisation Layer',
        'Deduplication · Schema mapping · Timestamp alignment · PostgreSQL storage',
        fc='#f2f0f7', ec=PURPLE, fs=8.5)
    arrow(5, 1.85, 5, 1.3)

    # ── Layer 3: Analysis Engine ──
    analyses = [
        ('Device\nClassification', '#deebf7'),
        ('IOC\nExtraction', '#deebf7'),
        ('Cross-Source\nLinkage', '#deebf7'),
        ('Proxy\nScoring', '#deebf7'),
        ('Temporal\nAnalysis', '#deebf7'),
    ]
    ax2_y = 0.55
    ax_xs = [0.3, 2.1, 3.9, 5.7, 7.5]
    for (lbl, fc), x in zip(analyses, ax_xs):
        box(x, ax2_y, 1.6, 0.7, lbl, '', fc=fc, ec=BLUE, fs=7.5)
        ax.annotate('', xy=(x + 0.8, ax2_y + 0.7),
                    xytext=(x + 0.8, 1.85),
                    arrowprops=dict(arrowstyle='->', color=BLUE, lw=1.0,
                                   mutation_scale=9))

    # ── Layer labels (left margin) ──
    for y_, lbl_, col_ in [(3.72, 'Data\nSources', ORANGE),
                            (2.17, 'Pipeline\nCore', PURPLE),
                            (0.9, 'Analysis\nModules', BLUE)]:
        ax.text(0.04, y_, lbl_, ha='center', va='center',
                fontsize=7.5, color=col_, fontweight='bold',
                rotation=0)

    fig.savefig(os.path.join(OUT_DIR, 'fig1_pipeline.pdf'))
    fig.savefig(os.path.join(OUT_DIR, 'fig1_pipeline.png'))
    plt.close(fig)
    print('fig1_pipeline saved')


# ═══════════════════════════════════════════════════════════════════════════════
# FIG 2 — Device exposure characterisation
# ═══════════════════════════════════════════════════════════════════════════════
def fig2_device_exposure():
    fig = plt.figure(figsize=(7.16, 5.2))
    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.42, wspace=0.38)

    # ── (a) Device-type distribution ──────────────────────────────────────────
    ax1 = fig.add_subplot(gs[0, :2])
    shodan_apr6  = [1050, 720,  580,  640,  450, 1562]
    shodan_apr20 = [2350, 1550, 1290, 1400, 1100, 2695]
    censys_apr20 = [501,  417,  566,  352,  317,  910]
    dtypes = ['Router', 'Proxy', 'Camera', 'Server', 'IoT', 'Unknown']
    x = np.arange(len(dtypes))
    w = 0.26
    bars1 = ax1.bar(x - w,   shodan_apr6,  w, color=LBLUE, label='Shodan Apr-6')
    bars2 = ax1.bar(x,       shodan_apr20, w, color=BLUE,  label='Shodan Apr-20')
    bars3 = ax1.bar(x + w,   censys_apr20, w, color=TEAL,  label='Censys Apr-20')
    ax1.set_xticks(x); ax1.set_xticklabels(dtypes, fontsize=8)
    ax1.set_ylabel('Device Records'); ax1.set_title('(a) Device-Type Distribution by Scan Source')
    ax1.legend(loc='upper right', framealpha=0.9)
    ax1.yaxis.grid(True, linestyle='--', alpha=0.5)
    ax1.set_axisbelow(True)

    # ── (b) Service/protocol breakdown ───────────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 2])
    svcs  = ['Telnet', 'HTTP(S)', 'RTSP', 'SSH', 'SMTP', 'SNMP', 'Other']
    cnts  = [2443,      1758,      800,   817,   458,   378,   1596]
    colors_svc = [RED, ORANGE, TEAL, BLUE, PURPLE, GREEN, LGREY]
    wedges, texts, autotexts = ax2.pie(
        cnts, labels=svcs, colors=colors_svc,
        autopct=lambda p: f'{p:.0f}%' if p > 5 else '',
        startangle=140, textprops={'fontsize': 7.2},
        wedgeprops={'linewidth': 0.6, 'edgecolor': 'white'})
    for at in autotexts:
        at.set_fontsize(6.8)
    ax2.set_title('(b) Service Protocol\nDistribution', pad=4)

    # ── (c) Top exposed ports ─────────────────────────────────────────────────
    ax3 = fig.add_subplot(gs[1, :2])
    ports = [23, 7547, 8080, 80, 554, 6666, 22, 25, 2323, 1080, 81, 3128]
    pcnts = [2335, 1401, 955, 784, 726, 653, 616, 568, 551, 443, 421, 414]
    port_labels = [f':{p}' for p in ports]
    bar_colors = [RED if p in (23, 2323, 7547) else
                  ORANGE if p in (8080, 1080, 3128) else
                  BLUE for p in ports]
    bars_p = ax3.barh(port_labels[::-1], pcnts[::-1], color=bar_colors[::-1], edgecolor='white', lw=0.5)
    ax3.set_xlabel('Device Count')
    ax3.set_title('(c) Top Exposed Ports (colour: IoT-critical=red, proxy=orange)')
    ax3.xaxis.grid(True, linestyle='--', alpha=0.5)
    ax3.set_axisbelow(True)
    # legend
    p1 = mpatches.Patch(color=RED, label='IoT/Telnet/TR-069')
    p2 = mpatches.Patch(color=ORANGE, label='Proxy-indicative')
    p3 = mpatches.Patch(color=BLUE, label='General services')
    ax3.legend(handles=[p1, p2, p3], loc='lower right', fontsize=7, framealpha=0.9)

    # ── (d) Top identified products ───────────────────────────────────────────
    ax4 = fig.add_subplot(gs[1, 2])
    prods = ['Hikvision\nCamera', 'Squid\nProxy', 'BusyBox\nTelnetd',
             'MikroTik\nRouter', 'GoAhead\nWebsvr', 'Dropbear\nSSHd',
             'Cisco\nRouter']
    pcounts = [641, 407, 466, 259, 363, 218, 86]
    bars_pr = ax4.barh(prods[::-1], pcounts[::-1],
                       color=[TEAL, ORANGE, RED, BLUE, GREEN, LBLUE, PURPLE],
                       edgecolor='white', lw=0.5)
    ax4.set_xlabel('Count')
    ax4.set_title('(d) Top IoT Products\n(banner fingerprint)')
    ax4.xaxis.grid(True, linestyle='--', alpha=0.5)
    ax4.set_axisbelow(True)

    fig.suptitle('Fig. 2 — Internet-Exposed IoT Infrastructure: Device and Service Characterisation\n'
                 '(18,450 records across Shodan and Censys, April 2026)',
                 fontsize=9.5, fontweight='bold', y=1.01)

    fig.savefig(os.path.join(OUT_DIR, 'fig2_device_exposure.pdf'))
    fig.savefig(os.path.join(OUT_DIR, 'fig2_device_exposure.png'))
    plt.close(fig)
    print('fig2_device_exposure saved')


# ═══════════════════════════════════════════════════════════════════════════════
# FIG 3 — Attack pattern analysis and botnet landscape
# ═══════════════════════════════════════════════════════════════════════════════
def fig3_attack_analysis():
    fig = plt.figure(figsize=(7.16, 5.4))
    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.46, wspace=0.36)

    # ── (a) Daily attack volume (honeypot timeline) ───────────────────────────
    ax1 = fig.add_subplot(gs[0, :])
    days = ['Apr 23\n(Day 1)', 'Apr 24\n(Day 2)', 'Apr 25\n(Day 3)']
    glutton_ev  = [541, 3688, 3445]
    cowrie_ev   = [104,    0,    0]
    opencan_ev  = [  0,    1,    0]
    x = np.arange(len(days))
    w = 0.28
    b1 = ax1.bar(x - w,    glutton_ev,  w, color=BLUE,   label='Glutton (multi-protocol)')
    b2 = ax1.bar(x,        cowrie_ev,   w, color=ORANGE, label='Cowrie (SSH/Telnet)')
    b3 = ax1.bar(x + w,    opencan_ev,  w, color=GREEN,  label='OpenCanary')

    # Annotate unique IPs per day
    ip_counts = [225+9, 1150+1, 895]
    for xi, cnt, ip in zip(x, glutton_ev, ip_counts):
        ax1.text(xi - w, cnt + 60, f'{cnt:,}', ha='center', va='bottom', fontsize=7.5, color=DKBLUE)
        ax1.text(xi - w, cnt + 280, f'({ip} IPs)', ha='center', va='bottom',
                 fontsize=6.5, color=DGREY, style='italic')
    ax1.set_xticks(x); ax1.set_xticklabels(days, fontsize=8.5)
    ax1.set_ylabel('Event Count')
    ax1.set_title('(a) Honeypot Daily Attack Volume (Apr 23–25, 2026)')
    ax1.legend(loc='upper left', framealpha=0.9)
    ax1.yaxis.grid(True, linestyle='--', alpha=0.5)
    ax1.set_axisbelow(True)
    ax1.set_ylim(0, 4800)

    # ── (b) Top destination ports under attack ────────────────────────────────
    ax2 = fig.add_subplot(gs[1, 0])
    attack_ports = ['8728\n(Winbox)', '5432\n(PostgreSQL)', '443\n(HTTPS)',
                    '22\n(SSH)', '17000', '5555\n(ADB)',
                    '5435\n(Postgres alt)', '1433\n(MSSQL)', '5038\n(AMI)', '30432']
    ap_cnts = [608, 201, 139, 103, 155, 68, 64, 57, 48, 75]
    # sort by count
    order = np.argsort(ap_cnts)[::-1]
    sorted_ports = [attack_ports[i] for i in order]
    sorted_cnts  = [ap_cnts[i] for i in order]
    port_colors  = [RED if '8728' in p or '5432' in p or '1433' in p else
                    ORANGE if 'ADB' in p or '5555' in p else BLUE
                    for p in sorted_ports]
    ax2.barh(sorted_ports[::-1], sorted_cnts[::-1],
             color=port_colors[::-1], edgecolor='white', lw=0.5)
    ax2.set_xlabel('Event Count')
    ax2.set_title('(b) Top Targeted Ports\n(honeypot dest ports)')
    ax2.xaxis.grid(True, linestyle='--', alpha=0.5)
    ax2.set_axisbelow(True)
    p1 = mpatches.Patch(color=RED, label='DB/Mgmt services')
    p2 = mpatches.Patch(color=ORANGE, label='IoT/ADB')
    p3 = mpatches.Patch(color=BLUE, label='Other')
    ax2.legend(handles=[p1, p2, p3], loc='lower right', fontsize=6.5, framealpha=0.85)

    # ── (c) Botnet family landscape (ThreatFox + MalwareBazaar + OTX) ─────────
    ax3 = fig.add_subplot(gs[1, 1])
    families = ['elf.mirai\n(TFox)', 'elf.mozi\n(TFox)', 'hajime\n(MBaz)',
                'tsunami\n(MBaz)', 'mirai\n(MBaz)', 'elf.bashlite\n(TFox)',
                'xorddos\n(MBaz)', 'muhstik\n(OTX)', 'mirai\n(OTX)',
                'xorddos\n(OTX)']
    fam_cnts = [866, 549, 654, 321, 273, 190, 110, 236, 222, 124]
    fam_colors = [BLUE, BLUE, ORANGE, ORANGE, ORANGE, BLUE, ORANGE, GREEN, GREEN, GREEN]
    order2 = np.argsort(fam_cnts)
    sorted_fams = [families[i] for i in order2]
    sorted_fcnts = [fam_cnts[i] for i in order2]
    sorted_fcolors = [fam_colors[i] for i in order2]
    ax3.barh(sorted_fams, sorted_fcnts, color=sorted_fcolors,
             edgecolor='white', lw=0.5)
    ax3.set_xlabel('IOC Count')
    ax3.set_title('(c) IoT Botnet Families\n(threat feed IOCs)')
    ax3.xaxis.grid(True, linestyle='--', alpha=0.5)
    ax3.set_axisbelow(True)
    p1b = mpatches.Patch(color=BLUE,   label='ThreatFox')
    p2b = mpatches.Patch(color=ORANGE, label='MalwareBazaar')
    p3b = mpatches.Patch(color=GREEN,  label='OTX AlienVault')
    ax3.legend(handles=[p1b, p2b, p3b], loc='lower right', fontsize=6.5, framealpha=0.85)

    fig.suptitle('Fig. 3 — Honeypot Attack Characterisation and Threat Intelligence Landscape\n'
                 '(8,407 honeypot events · 12,418 threat feed IOCs · April 2026)',
                 fontsize=9.5, fontweight='bold', y=1.01)

    fig.savefig(os.path.join(OUT_DIR, 'fig3_attack_analysis.pdf'))
    fig.savefig(os.path.join(OUT_DIR, 'fig3_attack_analysis.png'))
    plt.close(fig)
    print('fig3_attack_analysis saved')


# ═══════════════════════════════════════════════════════════════════════════════
# FIG 4 — Proxy/monetisation indicators and risk stratification
# ═══════════════════════════════════════════════════════════════════════════════
def fig4_proxy_indicators():
    fig = plt.figure(figsize=(7.16, 5.6))
    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.50, wspace=0.40)

    # ── (a) Proxy indicator definitions and counts ────────────────────────────
    ax1 = fig.add_subplot(gs[0, :2])
    indicators = [
        'Device type\nclassified Proxy',
        'Port 8080\n(HTTP Proxy)',
        'Port 1080\n(SOCKS)',
        'Port 3128\n(Squid/HTTP)',
        'SOCKS5 protocol\n(banner-confirmed)',
        'Squid proxy\n(product banner)',
        'Port 8888/9050\n(other proxy)',
    ]
    indicator_vals = [2687, 955, 443, 414, 327, 407, 13]
    ind_colors = [BLUE if i == 0 else RED if i in (1, 4, 5) else ORANGE
                  for i in range(len(indicators))]
    x_pos = np.arange(len(indicators))
    bars = ax1.bar(x_pos, indicator_vals, color=ind_colors, edgecolor='white', lw=0.5, width=0.65)
    for bar, val in zip(bars, indicator_vals):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 30,
                 f'{val:,}', ha='center', va='bottom', fontsize=7.5, fontweight='bold')
    ax1.set_xticks(x_pos); ax1.set_xticklabels(indicators, fontsize=7.5)
    ax1.set_ylabel('Device Record Count')
    ax1.set_title('(a) Proxy-Consistent Exposure Indicators (strict vs. broad definitions)')
    ax1.yaxis.grid(True, linestyle='--', alpha=0.5)
    ax1.set_axisbelow(True)
    ax1.set_ylim(0, 3300)
    p1 = mpatches.Patch(color=BLUE,   label='Type classification')
    p2 = mpatches.Patch(color=RED,    label='Banner-confirmed')
    p3 = mpatches.Patch(color=ORANGE, label='Port-based indicator')
    ax1.legend(handles=[p1, p2, p3], loc='upper right', framealpha=0.9)
    # Annotation: 9.9% and 14.6%
    ax1.axhline(y=1825, color=RED, linestyle='--', lw=1.0, alpha=0.7)
    ax1.text(6.5, 1870, '9.9%\nof population', ha='right', va='bottom',
             fontsize=7, color=RED, style='italic')

    # ── (b) Proxy device ASN concentration ───────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 2])
    asns  = ['Alibaba\nCloud', 'Amazon\nAWS', 'Akamai/\nLinode', 'Charter\nComms',
             'Korea\nTelecom', 'Other']
    asnv  = [820, 262, 222, 175, 126, 220]
    asn_c = [RED, ORANGE, ORANGE, BLUE, BLUE, LGREY]
    wedges2, texts2, autos2 = ax2.pie(
        asnv, labels=asns, colors=asn_c,
        autopct=lambda p: f'{p:.0f}%' if p > 5 else '',
        startangle=100, textprops={'fontsize': 7},
        wedgeprops={'linewidth': 0.6, 'edgecolor': 'white'})
    for at in autos2:
        at.set_fontsize(7)
    ax2.set_title('(b) Proxy-Device ASN\nConcentration', pad=4)
    p_cloud = mpatches.Patch(color=RED,    label='Cloud/CDN ASNs')
    p_resid = mpatches.Patch(color=BLUE,   label='Residential ISPs')
    p_other = mpatches.Patch(color=LGREY,  label='Other')
    ax2.legend(handles=[p_cloud, p_resid, p_other], loc='lower left',
               fontsize=6.5, framealpha=0.85, bbox_to_anchor=(-0.15, -0.05))

    # ── (c) Geographic top-15 distribution ───────────────────────────────────
    ax3 = fig.add_subplot(gs[1, :2])
    countries = ['US', 'CN', 'JP', 'DE', 'GB', 'IN', 'TR', 'KR',
                 'SG', 'BD', 'HK', 'CA', 'BR', 'FR', 'NL']
    geo_cnts  = [4479, 2339, 1097, 1040, 974, 779, 763, 564,
                 460, 428, 419, 414, 364, 328, 262]
    geo_colors = [RED if c in ('CN', 'HK') else
                  ORANGE if c in ('US', 'SG', 'DE') else BLUE
                  for c in countries]
    x3 = np.arange(len(countries))
    ax3.bar(x3, geo_cnts, color=geo_colors, edgecolor='white', lw=0.4, width=0.7)
    ax3.set_xticks(x3); ax3.set_xticklabels(countries, fontsize=8)
    ax3.set_ylabel('Device Records')
    ax3.set_title('(c) Geographic Distribution of Exposed IoT Devices (top 15 countries)')
    ax3.yaxis.grid(True, linestyle='--', alpha=0.5)
    ax3.set_axisbelow(True)
    p_cn = mpatches.Patch(color=RED, label='China/HK concentration')
    p_us = mpatches.Patch(color=ORANGE, label='US/EU cloud hubs')
    p_ot = mpatches.Patch(color=BLUE, label='Other regions')
    ax3.legend(handles=[p_cn, p_us, p_ot], loc='upper right', framealpha=0.9)

    # ── (d) Risk-score tier distribution ─────────────────────────────────────
    ax4 = fig.add_subplot(gs[1, 2])
    # Heuristic risk score tiers derived from device_type + port + ASN + protocol features
    # Low (0–0.33): mostly unknown/server with no proxy/IoT indicators
    # Medium (0.33–0.66): single indicator (one proxy port OR IoT device type)
    # High (>0.66): multiple concurrent indicators
    tiers = ['Low\nRisk', 'Medium\nRisk', 'High\nRisk']
    tier_counts = [9620, 5845, 2985]   # approximate from scan population
    tier_pct    = [tc/18450*100 for tc in tier_counts]
    bar_tiers = ax4.bar(tiers, tier_counts,
                        color=[GREEN, ORANGE, RED],
                        edgecolor='white', lw=0.6, width=0.55)
    for bar, cnt, pct in zip(bar_tiers, tier_counts, tier_pct):
        ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 80,
                 f'{cnt:,}\n({pct:.0f}%)',
                 ha='center', va='bottom', fontsize=7.5)
    ax4.set_ylabel('Device Records')
    ax4.set_title('(d) Heuristic Risk-Score\nTier Distribution')
    ax4.yaxis.grid(True, linestyle='--', alpha=0.5)
    ax4.set_axisbelow(True)
    ax4.set_ylim(0, 12000)

    fig.suptitle('Fig. 4 — Monetisation-Consistent Exposure Indicators and Device Risk Stratification\n'
                 '(18,450 scanned devices · Port + ASN + Product banner analysis · April 2026)',
                 fontsize=9.5, fontweight='bold', y=1.01)

    fig.savefig(os.path.join(OUT_DIR, 'fig4_proxy_indicators.pdf'))
    fig.savefig(os.path.join(OUT_DIR, 'fig4_proxy_indicators.png'))
    plt.close(fig)
    print('fig4_proxy_indicators saved')


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    fig1_pipeline()
    fig2_device_exposure()
    fig3_attack_analysis()
    fig4_proxy_indicators()
    print('\nAll figures saved to:', OUT_DIR)
