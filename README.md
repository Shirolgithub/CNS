# ResolverGuard: DNS Integrity Monitoring and Spoofing Detection Workbench
**Enterprise DNS Security Operations, Baseline Auditing & Spoofing Detection Workbench**

---

## 1. Project Abstract
The Domain Name System (DNS) is foundational to internet operations, resolving human-readable fully qualified domain names (FQDNs) to numerical IP addresses. However, because classic DNS primarily uses unencrypted UDP without inherent authentication, it remains vulnerable to cache poisoning, malicious recursive resolver tampering, Man-in-the-Middle (MitM) answer forgery, and DNS rebinding attacks.

**ResolverGuard** is an educational, production-ready cybersecurity monitoring workbench. It continuously verifies DNS resolution integrity by cross-referencing live recursive DNS answers against cryptographically audited baselines, distinguishes benign Content Delivery Network (CDN) round-robin IP drift from malicious record hijacking, flags RFC 1918 private IP injection into public zones, and conducts multi-resolver consensus analysis to detect localized proxy interception.

---

## 2. Problem Statement
1. **Unauthenticated UDP Resolution**: Recursive DNS caches can be poisoned with forged records (Kaminsky attacks, rogue response spoofing).
2. **False Positives from Legitimate Drift**: Modern web platforms employ Anycast routing, multi-cloud hosting, and CDNs (Cloudflare, Akamai, AWS CloudFront). Naive monitoring tools alert on any IP change, creating alert fatigue.
3. **DNS Rebinding & Pivoting**: Attackers forge public domain resolutions to point to RFC 1918 private subnets (`192.168.0.0/16`, `10.0.0.0/8`), bypassing browser Same-Origin Policy (SOP) to attack internal routers and IoT hardware.
4. **Local Resolver Hijacking & Censorship**: Local rogue DHCP servers, malicious Wi-Fi routers, or ISP transparent DNS proxies can manipulate DNS answers without affecting upstream global root servers.

---

## 3. Project Objectives
- **Integrity Verification**: Compare observed A/AAAA records with stored, trusted domain baselines.
- **Benign Drift vs. Malicious Tampering Discrimination**: Implement Jaccard similarity and subnet correlation to classify CDN rotations without falsely declaring attacks.
- **Private RFC 1918 Anomaly Guard**: Instantly flag any public domain resolving to private or loopback addresses.
- **Cross-Resolver Consensus**: Concurrently query independent public resolvers (System, Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9`, OpenDNS `208.67.222.222`) to expose localized resolver poisoning.
- **Controlled Educational Demonstrations**: Provide 6 simulated laboratory attack scenarios that execute safely without sending malicious packets across real networks.
- **Performance Evaluation**: Benchmark detection metrics (Accuracy, Precision, Recall, F1-Score, and Latency) on a ground-truth labeled test dataset.
- **Audit Logging & Report Generation**: Export CSV logs and structured CNS course audit reports.

---

## 4. System Architecture

```
+-----------------------------------------------------------------------------------+
|                              ResolverGuard Workbench                              |
|                          Streamlit Dashboard UI (app.py)                          |
+-----------------------------------------------------------------------------------+
         |                                |                                   |
         v                                v                                   v
+------------------+           +-----------------------+           +----------------------+
|  dns_monitor.py  |           |  detection_engine.py  |           | report_generator.py  |
| - Validation     |           | - Baseline Manager    |           | - CSV Exporter       |
| - UDP Resolution |           | - Jaccard Similarity  |           | - Audit Logger       |
| - IP Classifier  |           | - Subnet Correlation  |           | - Formal CNS Report  |
| - Cross-Resolver |           | - RFC 1918 Detector   |           +----------------------+
+------------------+           | - Consensus Engine    |                      |
         |                     +-----------------------+                      v
         |                                ^                         +---------------------+
         v                                |                         | reports/*.csv, .txt |
+------------------+           +-----------------------+            +---------------------+
| Network/Sockets  |           |   data/baseline.json  |
| 1.1.1.1, 8.8.8.8 |           +-----------------------+
+------------------+
```

---

## 5. Modules Description

1. **`app.py`**: High-aesthetic Streamlit web interface with 6 tabs:
   - **Live Inspection**: Single-domain live DNS lookup and baseline verification.
   - **Cross-Resolver Verification**: Multi-resolver consensus matrix and latency charts.
   - **CNS Lab Scenarios**: 6 controlled simulation demonstrations.
   - **Baseline Management**: Add, update, delete, export, and reset trusted records.
   - **Performance Evaluation**: Ground-truth dataset benchmark, Confusion Matrix, and metrics.
   - **Audit Log & Reports**: Session event history, filtering, and report downloads.
2. **`dns_monitor.py`**: RFC 1123 domain validation, configurable resolver queries with timeouts, reverse PTR lookups, RFC 1918/loopback classification, and cross-resolver lookups.
3. **`detection_engine.py`**: Mathematical baseline comparison (Jaccard Index), subnet prefix correlation, RFC 1918 injection alerts, multi-resolver consensus detection, and actionable remediation advice.
4. **`sample_data.py`**: Controlled demonstration scenarios (Normal, Cache Poisoning, Incident Remediation, DNS Rebinding, NXDOMAIN Hijacking, and CDN Drift) and reproducible 60-sample benchmark generator.
5. **`report_generator.py`**: Generates CSV audit logs, performance benchmark summaries, and formal CNS academic reports.
6. **`tests/`**: Automated unit test suite with 16 automated tests covering monitoring, heuristics, error handling, and reporting.

---

## 6. Algorithms and Heuristics

### 6.1 Jaccard Similarity Index
To evaluate the degree of overlap between the Trusted Baseline set ($T$) and Observed Resolution set ($O$):
$$J(T, O) = \frac{|T \cap O|}{|T \cup O|}$$
- If $T = O$, $J = 1.0$ $\rightarrow$ Verified Baseline Match (`MATCH`).
- If $0.0 < J < 1.0$ $\rightarrow$ Partial Overlap (`CDN_DRIFT`).
- If $J = 0.0$ $\rightarrow$ Disjoint Sets $\rightarrow$ Triggers Subnet & RFC 1918 analysis.

### 6.2 The CNS Anti-Poisoning Heuristic Rule
> **Fundamental Cybersecurity Rule:** An IP change alone NEVER definitively proves DNS spoofing.
CDNs legitimately rotate edge IPs across Anycast clusters. ResolverGuard inspects:
1. **RFC 1918 / Loopback Presence**: If a public domain resolves to `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, or `127.0.0.1`, it triggers `CRITICAL_ANOMALY` (DNS Rebinding threat).
2. **Subnet Affinity**: If observed IPs share a `/24` prefix with the baseline, it is classified as `DRIFT` (Medium/Warning) rather than an active attack.
3. **Cross-Resolver Verification**: If independent public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9) also observe the new IP set, the change is confirmed as an authoritative domain update, NOT local spoofing.

---

## 7. Installation and Execution

### Prerequisites
- Python 3.10 or 3.11
- pip package manager

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Run Unit Tests
```bash
pytest -v tests/
```

### Step 3: Launch the Streamlit Dashboard
```bash
streamlit run app.py --server.port 3000 --server.address 0.0.0.0
```

---

## 8. Test Cases and Coverage

The automated test suite (`tests/`) executes 16 tests:
1. `test_valid_domain_names`: RFC 1123 compliant domain formats.
2. `test_invalid_domain_names`: Rejection of leading hyphens, symbols, injection attempts, and excessive lengths.
3. `test_classify_public_ip`: Correct global classification of public IPs.
4. `test_classify_rfc1918_private_ips`: Flags `10.x`, `172.16.x`, `192.168.x` as private LAN addresses.
5. `test_classify_loopback_ip`: Flags `127.0.0.1` as loopback.
6. `test_invalid_input_resolution_error`: Graceful error return on malformed input.
7. `test_jaccard_similarity`: Exact match (1.0), disjoint (0.0), and partial calculations.
8. `test_matching_dns_records`: Exact match yields `MATCH` verdict with 0.0 anomaly score.
9. `test_changed_ip_records_spoofing_discrepancy`: Disjoint IP change alerts with proper non-definitive reasoning.
10. `test_rfc1918_private_injection`: Public domain resolving to private IP triggers `CRITICAL_ANOMALY`.
11. `test_benign_cdn_drift`: Partial overlap classified as `CDN_DRIFT` with Low severity.
12. `test_missing_records_and_nxdomain`: Handles `NXDOMAIN` and empty sets without crashing.
13. `test_same_subnet_detection`: Subnet `/24` matching validation.
14. `test_benchmark_metrics_computation`: Computes Accuracy, Precision, Recall, and F1 on synthetic benchmark.
15. `test_course_report_generation`: Validates generation of structured academic report.
16. `test_csv_export_alerts`: Validates CSV schema and file creation.

---

## 9. Controlled Demonstration Steps

1. **Step 1: Baseline Match Verification**
   - In Sidebar, select **Scenario 1: Verified Baseline Match (Normal Operation)**.
   - Click **Run Selected Scenario**.
   - Observe `MATCH` status badge, Jaccard Similarity of `1.0`, and Green verified integrity card.
2. **Step 2: Simulated Cache Poisoning**
   - Select **Scenario 2: Altered DNS Response (Simulated Cache Poisoning)**.
   - Click **Run Selected Scenario**.
   - Target `bankofamerica.com` resolves to rogue IP `185.220.101.5`.
   - Observe `SUSPICIOUS_DISCREPANCY` (Critical Alert) with Jaccard `0.0`.
3. **Step 3: Incident Remediation & Restoration**
   - Select **Scenario 3: Restored Response (Post-Incident Remediation)**.
   - Click **Run Selected Scenario**.
   - Resolves back to authentic `171.159.228.150` baseline; demonstrates full incident response cycle.
4. **Step 4: DNS Rebinding Attack**
   - Select **Scenario 4: DNS Rebinding / RFC 1918 Private IP Injection**.
   - Observe `CRITICAL_ANOMALY` flagging the private `192.168.1.1` address.
5. **Step 5: Multi-Resolver Consensus Verification**
   - Navigate to the **Cross-Resolver Verification** tab.
   - Enter `bankofamerica.com` and click **Query All Resolvers**.
   - Compare resolutions from System, Cloudflare, Google, and Quad9.
6. **Step 6: Benchmark & Reporting**
   - Navigate to **Performance Evaluation** tab, click **Run Live Benchmark Evaluation**.
   - Inspect the Confusion Matrix and Metrics Bar Chart.
   - Navigate to **Audit Log & Reports** tab and click **Download Audit Log (CSV)** and **Download Course Audit Report (TXT/MD)**.

---

## 10. Limitations & Future Enhancements

### Limitations
- **Passive Monitoring**: Detects discrepancies after resolution; does not intercept network packets at kernel layer.
- **DNSSEC Validation**: Relies on recursive resolver's AD (Authenticated Data) bit unless direct RRSIG parsing is enabled.
- **Non-Standard CDNs**: Highly dynamic CDNs with hundreds of volatile edge IPs require frequent baseline learning.

### Future Enhancements
- **Automated DoH/DoT Tunneling**: Implement DNS-over-HTTPS (RFC 8484) and DNS-over-TLS (RFC 7858) client side.
- **BGP Route Leak Correlation**: Correlate detected IP changes with real-time BGP routing tables via RIPE RIS / RouteViews.
- **Automated Baseline Learning**: Use sliding-window statistical learning to automatically update trusted CDN IP pools.
