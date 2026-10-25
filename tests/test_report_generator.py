import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from report_generator import (
    export_alerts_to_csv,
    export_benchmark_to_csv,
    generate_cns_course_report,
    REPORTS_DIR
)
from sample_data import run_benchmark_evaluation, DEMO_SCENARIOS


class TestReportGenerator(unittest.TestCase):

    def test_csv_export_alerts(self):
        sample_alerts = [
            {
                "timestamp": "2026-10-25T08:00:00Z",
                "domain": "bankofamerica.com",
                "resolver": "System Default",
                "verdict": "SUSPICIOUS_DISCREPANCY",
                "severity": "CRITICAL",
                "jaccard_similarity": 0.0,
                "baseline_ips": ["171.159.228.150"],
                "observed_ips": ["185.220.101.5"],
                "added_ips": ["185.220.101.5"],
                "removed_ips": ["171.159.228.150"],
                "anomaly_score": 0.90,
                "reason": "Test reason",
                "recommended_action": "Flush cache"
            }
        ]
        csv_str, filepath = export_alerts_to_csv(sample_alerts, filename="test_alert_report.csv")
        self.assertTrue(len(csv_str) > 0)
        self.assertIn("bankofamerica.com", csv_str)
        self.assertIn("185.220.101.5", csv_str)
        self.assertTrue(os.path.exists(filepath))

    def test_benchmark_metrics_computation(self):
        benchmark_res = run_benchmark_evaluation()
        summary = benchmark_res["summary"]
        self.assertGreater(summary["total_samples"], 0)
        self.assertGreaterEqual(summary["accuracy"], 0.85)
        self.assertGreaterEqual(summary["precision"], 0.85)
        self.assertGreaterEqual(summary["recall"], 0.85)
        self.assertGreaterEqual(summary["f1_score"], 0.85)
        self.assertGreater(summary["avg_latency_ms"], 0.0)

    def test_course_report_generation(self):
        alerts = [
            {
                "domain": "example.com",
                "verdict": "MATCH",
                "severity": "INFO",
                "jaccard_similarity": 1.0,
                "baseline_ips": ["93.184.215.14"],
                "observed_ips": ["93.184.215.14"],
                "anomaly_score": 0.0,
                "reason": "Match verified",
                "recommended_action": "None"
            }
        ]
        benchmark = {
            "total_samples": 60,
            "accuracy": 0.9667,
            "precision": 1.0,
            "recall": 0.9333,
            "f1_score": 0.9655,
            "true_positives": 28,
            "false_positives": 0,
            "true_negatives": 30,
            "false_negatives": 2,
            "avg_latency_ms": 0.12,
            "min_latency_ms": 0.05,
            "max_latency_ms": 0.80
        }
        report = generate_cns_course_report(
            alerts=alerts,
            benchmark_summary=benchmark,
            active_resolver="Google DNS (8.8.8.8)",
            total_baseline_domains=8
        )
        self.assertIn("RESOLVERGUARD", report)
        self.assertIn("EXECUTIVE SUMMARY", report)
        self.assertIn("PERFORMANCE EVALUATION", report)
        self.assertIn("0.9655", report)


if __name__ == "__main__":
    unittest.main()
