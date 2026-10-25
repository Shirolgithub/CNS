"""
ResolverGuard: DNS Integrity Monitoring and Spoofing Detection Workbench
sample_data.py - Safe, Reproducible Educational Scenarios & Benchmark Dataset Generator.
"""

import random
import time
from typing import Any, Dict, List, Optional, Tuple

from detection_engine import analyze_dns_integrity

# Demonstration scenarios for hands-on CNS laboratory sessions
DEMO_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "scenario_1_normal": {
        "id": "scenario_1_normal",
        "title": "Scenario 1: Verified Baseline Match (Normal Operation)",
        "domain": "bankofamerica.com",
        "description": "The recursive resolver returns IP addresses that perfectly match the registered enterprise baseline.",
        "category": "Normal Traffic",
        "simulated_resolver": "System Default (Recursive)",
        "status": "SUCCESS",
        "observed_ips": ["171.159.228.150", "171.161.148.150"],
        "response_time_ms": 24.5,
        "security_concept": "Baseline integrity verified. No DNS cache poisoning or unauthorized manipulation detected."
    },
    "scenario_2_altered": {
        "id": "scenario_2_altered",
        "title": "Scenario 2: Altered DNS Response (Simulated Cache Poisoning)",
        "domain": "bankofamerica.com",
        "description": "An attacker poisoned the recursive resolver's cache, redirecting traffic to an offshore rogue server.",
        "category": "DNS Spoofing / Hijacking",
        "simulated_resolver": "Compromised Edge Resolver",
        "status": "SUCCESS",
        "observed_ips": ["185.220.101.5"],  # Disjoint malicious rogue IP
        "response_time_ms": 18.2,
        "security_concept": "Complete IP mismatch without subnet correlation indicates high-risk record tampering or malicious redirection."
    },
    "scenario_3_restored": {
        "id": "scenario_3_restored",
        "title": "Scenario 3: Restored Response (Post-Incident Remediation)",
        "domain": "bankofamerica.com",
        "description": "Network administrators purged the corrupted DNS cache and applied DNSSEC validation, restoring authentic records.",
        "category": "Incident Remediation",
        "simulated_resolver": "Hardened Recursive Resolver",
        "status": "SUCCESS",
        "observed_ips": ["171.159.228.150", "171.161.148.150"],
        "response_time_ms": 26.1,
        "security_concept": "Baseline re-established. Illustrates the full lifecycle: Normal -> Compromised -> Remediated."
    },
    "scenario_4_rebinding": {
        "id": "scenario_4_rebinding",
        "title": "Scenario 4: DNS Rebinding / RFC 1918 Private IP Injection",
        "domain": "portal.internal-secure.com",
        "description": "A public domain record is manipulated to resolve to a private internal IPv4 address (192.168.1.1).",
        "category": "DNS Rebinding",
        "simulated_resolver": "Untrusted Upstream DNS",
        "status": "SUCCESS",
        "observed_ips": ["192.168.1.1"],
        "response_time_ms": 15.0,
        "security_concept": "Attackers exploit DNS to bypass browser Same-Origin Policy (SOP) and pivot into local private LAN routers."
    },
    "scenario_5_nxdomain_drop": {
        "id": "scenario_5_nxdomain_drop",
        "title": "Scenario 5: Resolution Denial / NXDOMAIN Tampering",
        "domain": "quad9.net",
        "description": "A man-in-the-middle or rogue resolver injects forged NXDOMAIN answers to disrupt secure communications.",
        "category": "Denial of Service (DoS)",
        "simulated_resolver": "Tampered Transit Proxy",
        "status": "NXDOMAIN",
        "observed_ips": [],
        "response_time_ms": 11.4,
        "security_concept": "Forged NXDOMAIN responses cause client-side denial of service and force fallback to insecure channels."
    },
    "scenario_6_cdn_drift": {
        "id": "scenario_6_cdn_drift",
        "title": "Scenario 6: Legitimate CDN Anycast Drift (Benign Change)",
        "domain": "github.com",
        "description": "GitHub rotates frontend Anycast edge nodes across Fastly/Akamai clusters. Baseline partially overlaps.",
        "category": "Benign Infrastructure Change",
        "simulated_resolver": "Cloudflare (1.1.1.1)",
        "status": "SUCCESS",
        "observed_ips": ["140.82.112.3", "140.82.114.4"],  # 1 shared, 1 rotated
        "response_time_ms": 19.8,
        "security_concept": "Crucial CNS principle: Never conclude spoofing from IP changes alone. CDNs legitimately rotate edge IPs."
    }
}


def generate_evaluation_dataset(n_samples: int = 60, seed: int = 42) -> List[Dict[str, Any]]:
    """
    Synthesizes a reproducible, ground-truth labeled benchmark dataset for
    rigorous evaluation of detection accuracy, precision, recall, and F1.
    """
    rng = random.Random(seed)
    dataset: List[Dict[str, Any]] = []

    # Distribution:
    # 20 Normal (ground_truth: Not a Threat, label=0)
    # 15 Spoofed / Disjoint (ground_truth: Threat, label=1)
    # 10 RFC 1918 Private Injections (ground_truth: Threat, label=1)
    # 10 CDN Legitimate Drift (ground_truth: Not a Threat, label=0)
    # 5 NXDOMAIN / Drop attacks (ground_truth: Threat, label=1)

    # 1. Normal Cases
    for i in range(20):
        domain = f"corp-service-{i+1}.example.org"
        base_ip = f"198.51.100.{10 + i}"
        dataset.append({
            "id": f"bench_{len(dataset)+1}",
            "domain": domain,
            "baseline_ips": [base_ip],
            "observed_ips": [base_ip],
            "status": "SUCCESS",
            "is_threat": False,
            "category": "Normal Traffic",
            "description": "Observed IP matches registered baseline."
        })

    # 2. Spoofed / Disjoint High-Risk Anomalies
    for i in range(15):
        domain = f"financial-gateway-{i+1}.securebank.net"
        base_ip = f"203.0.113.{20 + i}"
        rogue_ip = f"185.220.{100 + i}.{5 + i}"
        dataset.append({
            "id": f"bench_{len(dataset)+1}",
            "domain": domain,
            "baseline_ips": [base_ip],
            "observed_ips": [rogue_ip],
            "status": "SUCCESS",
            "is_threat": True,
            "category": "DNS Spoofing",
            "description": "Complete IP divergence to rogue Autonomous System."
        })

    # 3. DNS Rebinding / Private RFC 1918 Injection
    for i in range(10):
        domain = f"cloud-api-{i+1}.techcorp.io"
        base_ip = f"192.0.2.{40 + i}"
        private_ip = f"192.168.{i}.1" if i % 2 == 0 else f"10.0.{i}.10"
        dataset.append({
            "id": f"bench_{len(dataset)+1}",
            "domain": domain,
            "baseline_ips": [base_ip],
            "observed_ips": [private_ip],
            "status": "SUCCESS",
            "is_threat": True,
            "category": "DNS Rebinding (RFC 1918)",
            "description": "Public domain resolved to private intranet RFC 1918 IP."
        })

    # 4. Benign CDN Record Drift
    for i in range(10):
        domain = f"edge-cdn-{i+1}.globalmedia.com"
        shared_ip = f"151.101.{i*2}.133"
        old_ip = f"151.101.{i*2+1}.133"
        new_ip = f"151.101.{i*2+2}.133"
        dataset.append({
            "id": f"bench_{len(dataset)+1}",
            "domain": domain,
            "baseline_ips": [shared_ip, old_ip],
            "observed_ips": [shared_ip, new_ip],
            "status": "SUCCESS",
            "is_threat": False,
            "category": "Benign CDN Drift",
            "description": "Legitimate round-robin CDN edge node rollover."
        })

    # 5. NXDOMAIN / Drop Attacks
    for i in range(5):
        domain = f"vital-auth-{i+1}.gov.mil"
        base_ip = f"198.18.0.{15 + i}"
        dataset.append({
            "id": f"bench_{len(dataset)+1}",
            "domain": domain,
            "baseline_ips": [base_ip],
            "observed_ips": [],
            "status": "NXDOMAIN",
            "is_threat": True,
            "category": "NXDOMAIN Blackhole",
            "description": "Target domain actively dropped or blackholed."
        })

    rng.shuffle(dataset)
    return dataset[:n_samples]


def run_benchmark_evaluation(dataset: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Executes detection engine against the ground-truth labeled benchmark dataset.
    Measures processing time (latency in ms) for each check.
    Calculates Confusion Matrix, Accuracy, Precision, Recall, and F1-Score.
    """
    test_cases = dataset or generate_evaluation_dataset()
    tp, fp, tn, fn = 0, 0, 0, 0
    latencies_ms: List[float] = []
    evaluation_rows: List[Dict[str, Any]] = []

    for item in test_cases:
        t_start = time.perf_counter()
        analysis = analyze_dns_integrity(
            domain=item["domain"],
            observed_ips=item["observed_ips"],
            trusted_ips=item["baseline_ips"],
            resolution_status=item["status"],
            resolver_name="Benchmark Resolver"
        )
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        latencies_ms.append(elapsed_ms)

        # Engine decision rule: Threat detected if severity in (HIGH, CRITICAL)
        predicted_threat = analysis["severity"] in ("HIGH", "CRITICAL")
        actual_threat = item["is_threat"]

        if predicted_threat and actual_threat:
            classification = "True Positive (TP)"
            tp += 1
        elif predicted_threat and not actual_threat:
            classification = "False Positive (FP)"
            fp += 1
        elif not predicted_threat and not actual_threat:
            classification = "True Negative (TN)"
            tn += 1
        else:
            classification = "False Negative (FN)"
            fn += 1

        evaluation_rows.append({
            "Test ID": item["id"],
            "Domain": item["domain"],
            "Category": item["category"],
            "Status": item["status"],
            "Actual Threat": actual_threat,
            "Predicted Threat": predicted_threat,
            "Engine Verdict": analysis["verdict"],
            "Severity": analysis["severity"],
            "Anomaly Score": analysis["anomaly_score"],
            "Classification": classification,
            "Processing Time (ms)": round(elapsed_ms, 3)
        })

    total = len(test_cases)
    accuracy = round((tp + tn) / total, 4) if total > 0 else 0.0
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1_score = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    avg_latency = round(sum(latencies_ms) / len(latencies_ms), 3) if latencies_ms else 0.0

    return {
        "summary": {
            "total_samples": total,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "avg_latency_ms": avg_latency,
            "min_latency_ms": round(min(latencies_ms), 3) if latencies_ms else 0.0,
            "max_latency_ms": round(max(latencies_ms), 3) if latencies_ms else 0.0
        },
        "rows": evaluation_rows
    }
