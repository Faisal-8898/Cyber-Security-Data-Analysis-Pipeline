.venv/bin/python3 scripts/investigate_data.py

============================================================
  1. HONEYPOT EVENTS — Overview
============================================================
Honeypot         Events   Unique IPs        First         Last
glutton            8302         2014   2026-04-23   2026-04-25
cowrie              104            9   2026-04-23   2026-04-23
opencanary            1            1   2026-04-24   2026-04-24

Total events:      8,407
Collection window: 2026-04-23 → 2026-04-25 (2 days)

============================================================
  2. ATTACK PATTERNS — Event Types
============================================================
  connection                       8303
  session.connect                    21
  session.closed                     21
  client.kex                         18
  client.version                     18
  login.failed                       15
  client.fingerprint                  7
  session.params                      1
  command.input                       1
  log.closed                          1
  login.success                       1

============================================================
  2b. TOP DEST PORTS (Honeypot)
============================================================
  Port 8728        608 hits
  Port 5432        201 hits
  Port 17000       155 hits
  Port 443         139 hits
  Port 22          103 hits
  Port 30432        75 hits
  Port 5555         68 hits
  Port 5435         64 hits
  Port 1433         57 hits
  Port 5038         48 hits

============================================================
  2c. TOP ATTACKER IPs (by hit count)
============================================================
  85.11.167.11            475 hits
  176.120.22.73           451 hits
  45.205.1.5              312 hits
  45.205.1.110            261 hits
  152.53.81.25            198 hits
  92.63.197.22            148 hits
  160.119.76.54           144 hits
  93.123.72.166           126 hits
  80.66.83.43             117 hits
  46.151.178.13           109 hits
  16.58.56.214             57 hits
  95.214.52.233            52 hits
  3.130.168.2              44 hits
  18.218.118.203           44 hits
  212.132.127.66           42 hits

============================================================
  2d. CREDENTIALS (total unique pairs)
============================================================
  Unique credential pairs: 10
  casino               / casino                x1
  root                 /                       x1
  root                 / casino                x1
  casino               / root                  x1
  bet                  / bet                   x1
  admin                / admin                 x1
  amusnet              / amusnet               x1
  testuser             / testuser              x1
  ada                  / 111111                x1
  AdminGPON            / ALC#FGU               x1

============================================================
  3. IOC RECORDS — Extracted from Honeypots
============================================================
  ip                          2021
  sha256                         1

  Total unique IOCs: 2,022
  IOC time range:    2026-04-23  →  2026-04-25

============================================================
  3b. DOWNLOAD URLs (C2/Loader indicators)
============================================================

============================================================
  3c. MALWARE HASHES
============================================================
  Total hashes: 1
  [sha256] 876deb10d4cf5b5c092011cec255ceaeaef66174cc3b5964b8eb53b60d9cab81  ['cowrie']

============================================================
  3d. COMMAND TEMPLATES (behavioral IoC)
============================================================
  Total command templates: 0

============================================================
  4. THREAT FEED IOCs — External Intelligence
============================================================
Source                   IOCs   Families Snapshot
  threatfox                5013         63 2026-04-25
  urlhaus                  4235         57 2026-04-25
  otx                      1665          5 2026-04-25
  malwarebazaar            1505         10 2026-04-25

  Total feed IOCs: 12,418

============================================================
  4b. TOP MALWARE FAMILIES (ThreatFox)
============================================================
  js.clearfake                     1685
  elf.mirai                         866
  elf.mozi                          549
  unknown                           379
  win.strelastealer                 375
  win.vidar                         341
  elf.bashlite                      190
  js.kongtuke                       103
  win.mirai                          78
  win.cobalt_strike                  46
  win.nanocore                       39
  win.valley_rat                     34
  unknown_loader                     33
  win.remcos                         29
  unknown_stealer                    29

============================================================
  4c. TOP MALWARE FAMILIES (MalwareBazaar)
============================================================
  hajime                            654
  tsunami                           321
  mirai                             273
  xorddos                           110
  mozi                               56
  moobot                             42
  okiru                              23
  dofloo                             17
  unknown                             5
  gafgyt                              4

============================================================
  4d. OTX — Pulse/Tag distribution
============================================================
  unknown                          1049
  muhstik                           236
  mirai                             222
  xorddos                           124
  satori                             34

============================================================
  4e. URLhaus — IOC type breakdown
============================================================
  url                    4081
  sha256                  154

============================================================
  5. DEVICE RECORDS — Shodan/Censys Internet Scans
============================================================
Source     Week             Records   Unique IPs
  shodan     2026-04-06         6,002        3,855
  censys     2026-04-20         2,063           60
  shodan     2026-04-20        10,385        9,510

  Total device records: 18,450

============================================================
  5b. DEVICE TYPE distribution
============================================================
  unknown                     5,167
  router                      3,901
  proxy                       2,687
  camera                      2,436
  server                      2,392
  iot                         1,867

============================================================
  5c. TOP SERVICES/PROTOCOLS
============================================================
  http-simple-new             3,671
  auto                        3,395
  telnet                      2,443
  rtsp-tcp                      800
  http                          758
  voldemort                     639
  MSSQL                         523
  ssh                           515
  smtp                          458
  snmp_v3                       378
  HIKVISION                     359
  IPP                           333
  socks5-proxy                  327
  https                         312
  SSH                           302

============================================================
  5d. TOP PORTS EXPOSED
============================================================
  Port 23           2,335
  Port 7547         1,401
  Port 8080           955
  Port 80             784
  Port 554            726
  Port 6666           653
  Port 22             616
  Port 25             568
  Port 2323           551
  Port 1080           443
  Port 81             421
  Port 3128           414
  Port 7000           319
  Port 161            287
  Port 443            236

============================================================
  5e. GEOGRAPHIC distribution (top 15 countries)
============================================================
  US    4,479
  CN    2,339
  JP    1,097
  DE    1,040
  GB      974
  IN      779
  TR      763
  KR      564
  SG      460
  BD      428
  HK      419
  CA      414
  BR      364
  FR      328
  NL      262

============================================================
  5f. TOP ASNs/ORGS (attack infrastructure concentration)
============================================================
  ALIBABA-CN-NET Alibaba US Technology Co., Ltd.      1,967
  Aliyun Computing Co., LTD                             664
  AMAZON-02 - Amazon.com, Inc.                          652
  ALIBABA-CN-NET Hangzhou Alibaba Advertising Co.,Lt    567
  AKAMAI-LINODE-AP Akamai Connected Cloud               554
  Charter Communications Inc                            437
  Linode                                                372
  Aliyun Computing Co.LTD                               360
  Korea Telecom                                         314
  Charter Communications LLC                            274

============================================================
  5g. PROXY INDICATORS (ports 1080/3128/8080/8888/9050)
============================================================
  Port 8080        955 (potential proxy)
  Port 1080        443 (potential proxy)
  Port 3128        414 (potential proxy)
  Port 8888          7 (potential proxy)
  Port 8118          3 (potential proxy)
  Port 3129          2 (potential proxy)
  Port 9050          1 (potential proxy)

  Total potential proxy endpoints: 1,825

============================================================
  5h. IoT-SPECIFIC DEVICE PORTS (telnet/23, TR-069/7547, MQTT/1883)
============================================================
  Port 23        2,335
  Port 7547      1,401
  Port 2323        551
  Port 5683         16
  Port 1883         14
  Port 8883         14
  Port 37777        11

============================================================
  5i. CPE / PRODUCT fingerprints (top IoT products)
============================================================
  Hikvision IP Camera                                   641
  Squid http proxy                                      407
  OpenSSH                                               395
  Busybox telnetd                                       260
  MikroTik                                              259
  Dropbear sshd                                         218
  BusyBox telnetd                                       206
  Docker Registry HTTP API                              189
  GoAhead Embedded Web Server                           187
  nginx                                                 185
  GoAhead-Webs httpd                                    176
  Apache httpd                                          139
  Postfix smtpd                                         105
  uhttpd Web Server                                      90
  Cisco router telnetd                                   86

============================================================
  6. CROSS-SOURCE LINKAGE — Honeypot IPs vs Feed IOCs
============================================================
  Honeypot attacker IPs found in ThreatFox: 0
  Honeypot IPs matched in feeds:

  Shodan/Censys device IPs found in threat feeds:
    threatfox                1 matches

  IoT botnet families in ThreatFox feed:
    elf.mirai                        866
    elf.mozi                         549
    elf.bashlite                     190
    win.mirai                         78

============================================================
  7. IP ACTIVITY DAILY — Longitudinal Churn Data
============================================================
Day            Honeypot           Events   Unique IPs
  2026-04-23     cowrie                104            9
  2026-04-23     glutton               541          225
  2026-04-24     glutton             3,688        1,150
  2026-04-24     opencanary              1            1
  2026-04-25     glutton             3,445          895

  Unique IPs tracked across 3 days: 1,918
  IPs seen on multiple days (persistence): 317

============================================================
  8. PIPELINE RUNS — Collection Activity
============================================================
  poll_censys                      10 runs  last: 2026-04-25
  poll_shodan                       8 runs  last: 2026-04-25
  ingest_cowrie                     4 runs  last: 2026-04-25
  ingest_opencanary                 3 runs  last: 2026-04-25
  ingest_glutton                    2 runs  last: 2026-04-25
  test_task_end                     2 runs  last: 2026-04-11
  test_task_fail                    2 runs  last: 2026-04-11
  test_task                         2 runs  last: 2026-04-11
  test_store                        2 runs  last: 2026-04-11

============================================================
  SUMMARY — What We Can Claim
============================================================

DATA WE HAVE (confirmed):
  - Honeypot events:      8,407  (3 days, 3 honeypots: Glutton/Cowrie/OpenCanary)
  - Unique attacker IPs:  2,014+ from honeypots
  - Extracted IOCs:       ~1,920 (IPs, URLs, hashes, commands)
  - Feed IOCs:            12,720 (ThreatFox/URLhaus/MalwareBazaar/OTX)
  - Device records:       18,450 (Shodan: 16,387 | Censys: 2,063)
  - Unique scanned IPs:   13,425+ across 2 snapshot weeks
  - Collection window:    ~3 days honeypot / 2 Shodan snap weeks (Apr 6 + Apr 20)


[Investigation complete]