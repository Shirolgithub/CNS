import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dns_monitor import (
    validate_domain_name,
    classify_ip_address,
    resolve_domain,
    PUBLIC_RESOLVERS
)


class TestDNSMonitor(unittest.TestCase):

    def test_valid_domain_names(self):
        valid_domains = [
            "example.com",
            "sub.domain.example.org",
            "dns.google",
            "one.one.one.one",
            "my-company123.co.uk"
        ]
        for d in valid_domains:
            is_valid, cleaned = validate_domain_name(d)
            self.assertTrue(is_valid, f"Expected {d} to be valid, got: {cleaned}")
            self.assertEqual(cleaned, d.lower())

    def test_invalid_domain_names(self):
        invalid_domains = [
            "",
            "   ",
            "-leading-hyphen.com",
            "trailing-hyphen-.com",
            "domain..double-dot.com",
            "has space.com",
            "inject;rm -rf.com",
            "a" * 255 + ".com"
        ]
        for d in invalid_domains:
            is_valid, msg = validate_domain_name(d)
            self.assertFalse(is_valid, f"Expected {d} to be invalid, but passed: {msg}")

    def test_classify_public_ip(self):
        res = classify_ip_address("93.184.215.14")
        self.assertFalse(res["is_private"])
        self.assertFalse(res["is_loopback"])
        self.assertTrue(res["is_global"])
        self.assertFalse(res["is_suspicious_for_public_domain"])

    def test_classify_rfc1918_private_ips(self):
        private_ips = ["192.168.1.1", "10.0.0.50", "172.16.5.10"]
        for ip in private_ips:
            res = classify_ip_address(ip)
            self.assertTrue(res["is_private"], f"Expected {ip} to be private")
            self.assertTrue(res["is_suspicious_for_public_domain"])

    def test_classify_loopback_ip(self):
        res = classify_ip_address("127.0.0.1")
        self.assertTrue(res["is_loopback"])
        self.assertTrue(res["is_suspicious_for_public_domain"])

    def test_invalid_input_resolution_error(self):
        res = resolve_domain("invalid;bad domain!")
        self.assertEqual(res["status"], "ERROR")
        self.assertIn("Validation Error", res["error_message"])


if __name__ == "__main__":
    unittest.main()
