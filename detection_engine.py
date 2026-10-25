"""
ResolverGuard: DNS Integrity Monitoring and Spoofing Detection Workbench
detection_engine.py - Integrity Verification, Discrepancy Analysis, and Spoofing Heuristics.
"""

from datetime import datetime, timezone
import ipaddress
import json
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from dns_monitor import classify_ip_address


DEFAULT_BASELINE_FILE = os.path.join(os.path.dirname(__file__), "data", "trusted_baseline.json")


class BaselineManager:
    """Manages trusted domain-to-IP mappings with persistence."""

    def __init__(self, filepath: str = DEFAULT_BASELINE_FILE):
        self.filepath = filepath
        self.baseline: Dict[str, Dict[str, Any]] = {}
        self.load()

    def load(self) -> Dict[str, Dict[str, Any]]:
        """Loads baseline from JSON file or initializes defaults."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.baseline = json.load(f)
                    return self.baseline
            except Exception:
                self.baseline = {}
        else:
            self.baseline = {}
        return self.baseline

    def save(self) -> bool:
        """Persists current baseline dictionary to disk."""
        try:
            os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self.baseline, f, indent=2)
            return True
        except Exception:
            return False

    def get_trusted_ips(self, domain: str) -> Optional[List[str]]:
        """Returns trusted IPs for domain or None if unmonitored."""
        clean = domain.strip().lower()
        if clean in self.baseline:
            return sorted(self.baseline[clean].get("trusted_ips", []))
        return None

    def set_trusted_record(
        self,
        domain: str,
        trusted_ips: List[str],
        organization: str = "User Configured",
        notes: str = ""
    ) -> None:
        """Adds or updates a domain baseline entry."""
        clean = domain.strip().lower()
        self.baseline[clean] = {
            "trusted_ips": sorted(list(set(trusted_ips))),
            "organization": organization,
            "notes": notes,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        self.save()

    def remove_record(self, domain: str) -> bool:
        """Removes a domain from the baseline."""
        clean = domain.strip().lower()
        if clean in self.baseline:
            del self.baseline[clean]
            self.save()
            return True
        return False

    def list_all(self) -> Dict[str, Dict[str, Any]]:
        """Returns all baseline records."""
        return self.baseline


def calculate_jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Computes Jaccard Similarity index between two sets."""
    if not set_a and not set_b:
        return 1.0
    union = set_a.union(set_b)
    if not union:
        return 0.0
    intersection = set_a.intersection(set_b)
    return round(len(intersection) / len(union), 4)


def are_ips_in_same_subnet(ip1: str, ip2: str, prefix_len: int = 24) -> bool:
    """Checks if two IPv4 addresses belong to the same network prefix."""
    try:
        net1 = ipaddress.ip_network(f"{ip1}/{prefix_len}", strict=False)
        net2 = ipaddress.ip_network(f"{ip2}/{prefix_len}", strict=False)
        return net1 == net2
    except ValueError:
        return False


def analyze_dns_integrity(
    domain: str,
    observed_ips: List[str],
    trusted_ips: Optional[List[str]],
    resolution_status: str = "SUCCESS",
    resolver_name: str = "System Default",
    error_message: Optional[str] = None
) -> Dict[str, Any]:
    """
    Core CNS Detection Engine. Compares observed resolution against baseline.

    Adheres strictly to RFC guidelines & Computer and Network Security principles:
    - Never asserts that an IP difference alone proves spoofing.
    - Evaluates subnets, RFC 1918 private injection, CDN drift, and availability failures.
    - Produces an anomaly score (0.0 to 1.0) and actionable recommendations.
    """
    clean_domain = domain.strip().lower()
    timestamp = datetime.now(timezone.utc).isoformat()

    obs_set = set(observed_ips)
    trust_set = set(trusted_ips or [])

    # Inspect observed IPs for RFC 1918 or loopback injection
    ip_classifications = [classify_ip_address(ip) for ip in observed_ips]
    has_private_ip = any(c.get("is_rfc1918", False) for c in ip_classifications)
    has_loopback = any(c.get("is_loopback", False) for c in ip_classifications)
    suspicious_types = [c["ip"] for c in ip_classifications if c.get("is_suspicious_for_public_domain", False)]

    # Case 1: Resolution Failure (NXDOMAIN, TIMEOUT, ERROR)
    if resolution_status != "SUCCESS":
        status_reasons = {
            "NXDOMAIN": "Authoritative or recursive resolver reported domain does not exist.",
            "TIMEOUT": "Resolver query timed out. Network latency, packet drop, or UDP firewall block.",
            "NO_ANSWER": "Resolver returned query success but no A/AAAA records were available.",
            "ERROR": f"Resolver returned operational error: {error_message or 'Unknown failure'}."
        }
        return {
            "domain": clean_domain,
            "resolver": resolver_name,
            "timestamp": timestamp,
            "verdict": "ERROR",
            "severity": "HIGH" if trust_set else "MEDIUM",
            "jaccard_similarity": 0.0,
            "baseline_ips": sorted(list(trust_set)),
            "observed_ips": [],
            "added_ips": [],
            "removed_ips": sorted(list(trust_set)),
            "has_private_ip": False,
            "anomaly_score": 0.65 if trust_set else 0.40,
            "reason": (
                f"Resolution Failure ({resolution_status}). {status_reasons.get(resolution_status, 'DNS query failed')}. "
                "Note: A resolution failure could indicate blackholing, network disruption, or domain expiry, "
                "not necessarily malicious tampering."
            ),
            "recommended_action": (
                "Verify authoritative nameservers with `dig +trace`, check local firewall UDP 53 rules, "
                "and verify domain registration status."
            )
        }

    # Case 2: No Baseline Exists (Unmonitored / New Domain)
    if trusted_ips is None:
        severity = "HIGH" if suspicious_types else "INFO"
        verdict = "SUSPICIOUS" if suspicious_types else "UNMONITORED"
        anomaly_score = 0.85 if suspicious_types else 0.10
        reason = (
            f"Observed {len(observed_ips)} IP(s) for '{clean_domain}', but no trusted baseline is established. "
        )
        if suspicious_types:
            reason += (
                f"ALERT: Public domain resolved to private/loopback/reserved IP address: {suspicious_types}. "
                "This is a strong indicator of DNS Rebinding or internal network poisoning."
            )
        else:
            reason += "Add this domain to the baseline workbench to begin automated integrity tracking."

        return {
            "domain": clean_domain,
            "resolver": resolver_name,
            "timestamp": timestamp,
            "verdict": verdict,
            "severity": severity,
            "jaccard_similarity": 1.0 if not observed_ips else 0.0,
            "baseline_ips": [],
            "observed_ips": sorted(observed_ips),
            "added_ips": sorted(observed_ips),
            "removed_ips": [],
            "has_private_ip": has_private_ip or has_loopback,
            "anomaly_score": anomaly_score,
            "reason": reason,
            "recommended_action": (
                "Review observed IPs with WHOIS/ASN verification and click 'Add to Baseline' if legitimate."
            )
        }

    # Case 3: Baseline exists - Calculate Set Differences & Similarity
    jaccard = calculate_jaccard_similarity(trust_set, obs_set)
    added_ips = sorted(list(obs_set - trust_set))
    removed_ips = sorted(list(trust_set - obs_set))

    # Scenario 3A: Perfect Baseline Match
    if obs_set == trust_set:
        return {
            "domain": clean_domain,
            "resolver": resolver_name,
            "timestamp": timestamp,
            "verdict": "MATCH",
            "severity": "INFO",
            "jaccard_similarity": 1.0,
            "baseline_ips": sorted(list(trust_set)),
            "observed_ips": sorted(list(obs_set)),
            "added_ips": [],
            "removed_ips": [],
            "has_private_ip": has_private_ip,
            "anomaly_score": 0.0,
            "reason": "Observed IP records match the verified baseline exactly. DNS integrity verified.",
            "recommended_action": "No action needed. Periodic monitoring scheduled."
        }

    # Scenario 3B: Critical Threat - Private RFC 1918 / Loopback Injection
    # A public domain should NEVER resolve to 192.168.x.x, 10.x.x.x, or 127.0.0.1 unless internal
    if (has_private_ip or has_loopback) and not any(classify_ip_address(ip).get("is_rfc1918", False) for ip in trust_set):
        return {
            "domain": clean_domain,
            "resolver": resolver_name,
            "timestamp": timestamp,
            "verdict": "CRITICAL_ANOMALY",
            "severity": "CRITICAL",
            "jaccard_similarity": jaccard,
            "baseline_ips": sorted(list(trust_set)),
            "observed_ips": sorted(list(obs_set)),
            "added_ips": added_ips,
            "removed_ips": removed_ips,
            "has_private_ip": True,
            "anomaly_score": 0.98,
            "reason": (
                f"High-Risk Security Anomaly: Public domain '{clean_domain}' resolved to private/loopback address {suspicious_types}. "
                "This is a high-confidence signature of DNS Rebinding, internal cache poisoning, or hostile router hijacking. "
                "Important: While indicative of foul play, verify whether split-horizon DNS or local hosts file redirection is configured."
            ),
            "recommended_action": (
                "Isolate client immediately. Check /etc/hosts, router DNS proxy settings, DHCP server lease, "
                "and flush local DNS resolver cache (sudo systemd-resolve --flush-caches / ipconfig /flushdns)."
            )
        }

    # Scenario 3C: Complete IP Mismatch (Disjoint sets, Jaccard = 0.0)
    if jaccard == 0.0:
        # Check if they share the same /24 subnet
        same_subnet = False
        if observed_ips and trusted_ips:
            same_subnet = are_ips_in_same_subnet(observed_ips[0], trusted_ips[0], prefix_len=24)

        if same_subnet:
            severity = "MEDIUM"
            verdict = "DRIFT"
            anomaly_score = 0.45
            reason = (
                f"Record Discrepancy: All observed IPs differ from baseline, but share the same subnet prefix (/24). "
                "Common cause: Internal load-balancer IP rotation or ISP edge re-allocation. "
                "Caution: IP changes alone do not prove DNS spoofing; cross-resolver comparison is advised."
            )
            rec_action = "Compare with external resolvers (1.1.1.1, 8.8.8.8) to verify if authoritative nameservers updated records."
        else:
            severity = "CRITICAL"
            verdict = "SUSPICIOUS_DISCREPANCY"
            anomaly_score = 0.90
            reason = (
                f"Record Discrepancy: Observed IPs {observed_ips} do not overlap with baseline {trusted_ips}. "
                "This could indicate DNS cache poisoning, rogue BGP hijack, or an unannounced infrastructure migration. "
                "Important: IP change alone does not definitively prove spoofing without cryptographic proof (DNSSEC validation failure) "
                "or authoritative nameserver divergence."
            )
            rec_action = (
                "Run Cross-Resolver Verification tab to confirm if other resolvers observe the same change. "
                "Inspect ASN ownership via WHOIS and validate DNSSEC RRSIG records."
            )

        return {
            "domain": clean_domain,
            "resolver": resolver_name,
            "timestamp": timestamp,
            "verdict": verdict,
            "severity": severity,
            "jaccard_similarity": jaccard,
            "baseline_ips": sorted(list(trust_set)),
            "observed_ips": sorted(list(obs_set)),
            "added_ips": added_ips,
            "removed_ips": removed_ips,
            "has_private_ip": False,
            "anomaly_score": anomaly_score,
            "reason": reason,
            "recommended_action": rec_action
        }

    # Scenario 3D: Partial Drift (Partial overlap, 0 < Jaccard < 1.0)
    # Common for Content Delivery Networks (Akamai, Cloudflare, Fastly, AWS CloudFront)
    severity = "LOW"
    verdict = "CDN_DRIFT"
    anomaly_score = round(0.35 * (1.0 - jaccard), 3)
    reason = (
        f"Partial IP Variation (Jaccard Index: {jaccard}). Observed {len(added_ips)} new IP(s) and {len(removed_ips)} omitted IP(s). "
        "Common cause: Legitimate CDN round-robin rotation, Anycast routing updates, or multi-homed server changes. "
        "Cybersecurity Rule: This is classified as benign record drift rather than an attack, since established baseline IPs remain partially present."
    )
    rec_action = "Review if the newly added IPs belong to the same Autonomous System (ASN). If legitimate, update the baseline."

    return {
        "domain": clean_domain,
        "resolver": resolver_name,
        "timestamp": timestamp,
        "verdict": verdict,
        "severity": severity,
        "jaccard_similarity": jaccard,
        "baseline_ips": sorted(list(trust_set)),
        "observed_ips": sorted(list(obs_set)),
        "added_ips": added_ips,
        "removed_ips": removed_ips,
        "has_private_ip": False,
        "anomaly_score": anomaly_score,
        "reason": reason,
        "recommended_action": rec_action
    }


def analyze_cross_resolver_consensus(
    domain: str,
    multi_results: Dict[str, Dict[str, Any]],
    baseline_ips: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Evaluates agreement across independent recursive resolvers.
    Detects local resolver poisoning, transparent ISP interception, and censorship.
    """
    resolver_ips_map: Dict[str, Set[str]] = {}
    valid_resolvers: List[str] = []

    for res_name, res_data in multi_results.items():
        if res_data.get("status") == "SUCCESS":
            ips = set(res_data.get("ips", []))
            resolver_ips_map[res_name] = ips
            valid_resolvers.append(res_name)

    if not valid_resolvers:
        return {
            "domain": domain,
            "consensus": "UNAVAILABLE",
            "agreement_rate": 0.0,
            "details": "All resolvers failed or timed out.",
            "is_tampered": False
        }

    # Check pairwise equality
    first_name = valid_resolvers[0]
    first_ips = resolver_ips_map[first_name]
    discrepant_resolvers: List[str] = []

    for name in valid_resolvers[1:]:
        current_ips = resolver_ips_map[name]
        # Check intersection
        if not first_ips.intersection(current_ips):
            discrepant_resolvers.append(name)

    agreement_rate = round(1.0 - (len(discrepant_resolvers) / max(1, len(valid_resolvers))), 2)

    is_tampered = len(discrepant_resolvers) > 0
    if is_tampered:
        summary = (
            f"Cross-Resolver Conflict Detected! Resolvers disagree on IP mapping for '{domain}'. "
            f"Discrepancies found with: {discrepant_resolvers}. "
            "Evidence points to localized resolver tampering, ISP DNS redirection, or GEO-DNS divergence."
        )
    else:
        summary = f"Consensus Confirmed: All {len(valid_resolvers)} responding resolvers returned matching or overlapping IP pools."

    return {
        "domain": domain,
        "consensus": "CONFLICT" if is_tampered else "CONSENSUS",
        "agreement_rate": agreement_rate,
        "details": summary,
        "discrepant_resolvers": discrepant_resolvers,
        "is_tampered": is_tampered
    }
