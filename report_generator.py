"""
ResolverGuard: DNS Integrity Monitoring and Spoofing Detection Workbench
report_generator.py - Security Audit Logging, CSV Export, and Course Report Generation.
"""

from datetime import datetime, timezone
import io
import json
import os
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd


REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


def ensure_reports_directory() -> str:
    """Creates the reports directory if it does not exist."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    return REPORTS_DIR


def export_alerts_to_csv(alerts: List[Dict[str, Any]], filename: Optional[str] = None) -> Tuple[str, str]:
    """
    Exports security alerts and integrity analysis records to CSV format.
    Returns (csv_string, file_path_if_saved).
    """
    ensure_reports_directory()
    if not alerts:
        # Create empty DataFrame with standard columns
        df = pd.DataFrame(columns=[
            "Timestamp", "Domain", "Resolver", "Verdict", "Severity",
            "Jaccard Similarity", "Baseline IPs", "Observed IPs",
            "Added IPs", "Removed IPs", "Anomaly Score", "Reason", "Recommended Action"
        ])
    else:
        rows = []
        for a in alerts:
            rows.append({
                "Timestamp": a.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "Domain": a.get("domain", ""),
                "Resolver": a.get("resolver", "System Default"),
                "Verdict": a.get("verdict", ""),
                "Severity": a.get("severity", ""),
                "Jaccard Similarity": a.get("jaccard_similarity", 0.0),
                "Baseline IPs": "; ".join(a.get("baseline_ips", [])),
                "Observed IPs": "; ".join(a.get("observed_ips", [])),
                "Added IPs": "; ".join(a.get("added_ips", [])),
                "Removed IPs": "; ".join(a.get("removed_ips", [])),
                "Anomaly Score": a.get("anomaly_score", 0.0),
                "Reason": a.get("reason", ""),
                "Recommended Action": a.get("recommended_action", "")
            })
        df = pd.DataFrame(rows)

    csv_data = df.to_csv(index=False)

    target_filename = filename or f"resolverguard_audit_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    file_path = os.path.join(REPORTS_DIR, target_filename)

    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(csv_data)
    except Exception:
        pass

    return csv_data, file_path


def export_benchmark_to_csv(benchmark_data: Dict[str, Any], filename: Optional[str] = None) -> Tuple[str, str]:
    """Exports benchmark evaluation results to CSV."""
    ensure_reports_directory()
    rows = benchmark_data.get("rows", [])
    df = pd.DataFrame(rows)
    csv_data = df.to_csv(index=False)

    target_filename = filename or f"resolverguard_benchmark_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    file_path = os.path.join(REPORTS_DIR, target_filename)

    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(csv_data)
    except Exception:
        pass

    return csv_data, file_path


def generate_cns_course_report(
    alerts: List[Dict[str, Any]],
    benchmark_summary: Optional[Dict[str, Any]] = None,
    active_resolver: str = "System Default",
    total_baseline_domains: int = 0
) -> str:
    """
    Generates a structured DNS Security Operations Center (SOC) Investigation Report.
    Adheres to rigorous industry standards with Executive Summary, Methodology, Findings, and Evaluation.
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Count statistics
    total_events = len(alerts)
    critical_count = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    high_count = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium_count = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
    low_count = sum(1 for a in alerts if a.get("severity") == "LOW")
    info_count = sum(1 for a in alerts if a.get("severity") == "INFO")

    normal_matches = sum(1 for a in alerts if a.get("verdict") == "MATCH")
    cdn_drifts = sum(1 for a in alerts if a.get("verdict") == "CDN_DRIFT")
    anomalies = critical_count + high_count

    report_lines = [
        "=" * 80,
        "RESOLVERGUARD: DNS INTEGRITY MONITORING & SPOOFING DETECTION WORKBENCH",
        "DNS Security Operations Center (SOC) Integrity Investigation Audit Report",
        "=" * 80,
        f"Generated At: {now_str}",
        f"Active Resolver Monitored: {active_resolver}",
        f"Monitored Baseline Domains: {total_baseline_domains}",
        f"Total Inspection Events: {total_events}",
        "-" * 80,
        "",
        "1. EXECUTIVE SUMMARY & ABSTRACT",
        "--------------------------------------------------------------------------------",
        "The Domain Name System (DNS) operates primarily over unencrypted UDP, rendering it",
        "susceptible to Kaminsky-style cache poisoning, rogue resolver redirection, and DNS",
        "rebinding attacks. ResolverGuard provides an automated integrity verification layer",
        "that cross-references observed recursive DNS resolution sets against cryptographically",
        "audited baseline mappings. In accordance with CNS detection principles, the engine",
        "distinguishes legitimate Content Delivery Network (CDN) round-robin drift from",
        "high-confidence malicious record tampering, preventing false positives while alerting",
        "on critical threats such as private RFC 1918 address injection into public records.",
        "",
        "2. AUDIT SUMMARY METRICS",
        "--------------------------------------------------------------------------------",
        f"  - Verified Baseline Matches (Safe):  {normal_matches}",
        f"  - Benign Record Drifts (CDN/TTL):    {cdn_drifts}",
        f"  - High/Critical Security Alerts:     {anomalies}",
        f"    * Critical Severity:               {critical_count}",
        f"    * High Severity:                   {high_count}",
        f"    * Medium Severity:                 {medium_count}",
        f"    * Low Severity:                    {low_count}",
        f"    * Informational (Unmonitored):     {info_count}",
        "",
        "3. DETAILED EVENT AUDIT TRAIL",
        "--------------------------------------------------------------------------------",
    ]

    if not alerts:
        report_lines.append("  No inspection events recorded in the current session.")
    else:
        for idx, a in enumerate(alerts, 1):
            report_lines.extend([
                f"[{idx}] Domain: {a.get('domain', 'N/A')}",
                f"    Timestamp:         {a.get('timestamp', 'N/A')}",
                f"    Verdict:           {a.get('verdict', 'N/A')}",
                f"    Severity:          {a.get('severity', 'N/A')}",
                f"    Jaccard Index:     {a.get('jaccard_similarity', 0.0)}",
                f"    Baseline IP(s):    {a.get('baseline_ips', [])}",
                f"    Observed IP(s):    {a.get('observed_ips', [])}",
                f"    Anomaly Score:     {a.get('anomaly_score', 0.0)}",
                f"    Reasoning:         {a.get('reason', '')}",
                f"    Action:            {a.get('recommended_action', '')}",
                ""
            ])

    if benchmark_summary:
        report_lines.extend([
            "4. PERFORMANCE EVALUATION & BENCHMARK METRICS",
            "--------------------------------------------------------------------------------",
            f"  - Total Benchmark Samples:     {benchmark_summary.get('total_samples', 0)}",
            f"  - Classification Accuracy:     {benchmark_summary.get('accuracy', 0.0) * 100:.2f}%",
            f"  - Precision:                   {benchmark_summary.get('precision', 0.0) * 100:.2f}%",
            f"  - Recall (Sensitivity):        {benchmark_summary.get('recall', 0.0) * 100:.2f}%",
            f"  - F1-Score:                    {benchmark_summary.get('f1_score', 0.0):.4f}",
            f"  - Confusion Matrix:            TP={benchmark_summary.get('true_positives', 0)}, "
            f"FP={benchmark_summary.get('false_positives', 0)}, "
            f"TN={benchmark_summary.get('true_negatives', 0)}, "
            f"FN={benchmark_summary.get('false_negatives', 0)}",
            f"  - Average Processing Latency:  {benchmark_summary.get('avg_latency_ms', 0.0)} ms per check",
            f"  - Min / Max Latency:           {benchmark_summary.get('min_latency_ms', 0.0)} ms / {benchmark_summary.get('max_latency_ms', 0.0)} ms",
            ""
        ])

    report_lines.extend([
        "5. SECURITY RECOMMENDATIONS & INCIDENT HANDLING",
        "--------------------------------------------------------------------------------",
        "1. DNSSEC Enforcement: Implement cryptographic validation of RRSIG and DS records",
        "   to establish an unbroken chain of trust from root nameservers.",
        "2. Multi-Resolver Consensus: Cross-query public anycast resolvers (Quad9, Cloudflare)",
        "   to detect localized ISP proxy manipulation or rogue gateway DHCP tampering.",
        "3. RFC 1918 Filtering: Configure recursive resolvers to discard A/AAAA responses",
        "   pointing to 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 for public domain zones.",
        "4. Transport Layer Hardening: Migrate stub resolvers to DNS-over-HTTPS (DoH) or",
        "   DNS-over-TLS (DoT) to prevent on-path eavesdropping and tampering.",
        "",
        "=" * 80,
        "END OF CNS AUDIT REPORT - RESOLVERGUARD WORKBENCH",
        "=" * 80
    ])

    return "\n".join(report_lines)
