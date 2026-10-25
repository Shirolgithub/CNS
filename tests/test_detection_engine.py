import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detection_engine import (
    calculate_jaccard_similarity,
    analyze_dns_integrity,
    are_ips_in_same_subnet
)


class TestDetectionEngine(unittest.TestCase):

    def test_jaccard_similarity(self):
        # Exact match
        self.assertEqual(calculate_jaccard_similarity({"1.1.1.1"}, {"1.1.1.1"}), 1.0)
        # Disjoint
        self.assertEqual(calculate_jaccard_similarity({"1.1.1.1"}, {"2.2.2.2"}), 0.0)
        # Partial overlap (1 shared out of 3 total -> 1/3 ~ 0.3333)
        self.assertAlmostEqual(calculate_jaccard_similarity({"1.1.1.1", "1.1.1.2"}, {"1.1.1.1", "1.1.1.3"}), 0.3333, places=3)
        # Empty sets
        self.assertEqual(calculate_jaccard_similarity(set(), set()), 1.0)

    def test_matching_dns_records(self):
        result = analyze_dns_integrity(
            domain="example.com",
            observed_ips=["93.184.215.14"],
            trusted_ips=["93.184.215.14"],
            resolution_status="SUCCESS"
        )
        self.assertEqual(result["verdict"], "MATCH")
        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(result["jaccard_similarity"], 1.0)
        self.assertEqual(result["anomaly_score"], 0.0)
        self.assertEqual(len(result["added_ips"]), 0)
        self.assertEqual(len(result["removed_ips"]), 0)

    def test_changed_ip_records_spoofing_discrepancy(self):
        result = analyze_dns_integrity(
            domain="bankofamerica.com",
            observed_ips=["185.220.101.5"],
            trusted_ips=["171.159.228.150", "171.161.148.150"],
            resolution_status="SUCCESS"
        )
        self.assertEqual(result["verdict"], "SUSPICIOUS_DISCREPANCY")
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["jaccard_similarity"], 0.0)
        self.assertGreaterEqual(result["anomaly_score"], 0.8)
        # Verify requirement: Never claim that an IP change alone proves DNS spoofing
        self.assertIn("alone does not definitively prove spoofing", result["reason"])

    def test_rfc1918_private_injection(self):
        result = analyze_dns_integrity(
            domain="portal.enterprise.com",
            observed_ips=["192.168.1.1"],
            trusted_ips=["198.51.100.5"],
            resolution_status="SUCCESS"
        )
        self.assertEqual(result["verdict"], "CRITICAL_ANOMALY")
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertTrue(result["has_private_ip"])
        self.assertGreater(result["anomaly_score"], 0.9)
        self.assertIn("DNS Rebinding", result["reason"])

    def test_benign_cdn_drift(self):
        result = analyze_dns_integrity(
            domain="github.com",
            observed_ips=["140.82.112.3", "140.82.114.4"],
            trusted_ips=["140.82.112.3", "140.82.112.4"],
            resolution_status="SUCCESS"
        )
        self.assertEqual(result["verdict"], "CDN_DRIFT")
        self.assertEqual(result["severity"], "LOW")
        self.assertGreater(result["jaccard_similarity"], 0.0)
        self.assertLess(result["jaccard_similarity"], 1.0)

    def test_missing_records_and_nxdomain(self):
        result = analyze_dns_integrity(
            domain="dropped-domain.com",
            observed_ips=[],
            trusted_ips=["198.51.100.1"],
            resolution_status="NXDOMAIN"
        )
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIn("Resolution Failure (NXDOMAIN)", result["reason"])

    def test_same_subnet_detection(self):
        self.assertTrue(are_ips_in_same_subnet("192.168.1.10", "192.168.1.99", prefix_len=24))
        self.assertFalse(are_ips_in_same_subnet("192.168.1.10", "192.168.2.10", prefix_len=24))


if __name__ == "__main__":
    unittest.main()
