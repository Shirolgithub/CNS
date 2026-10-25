"""
ResolverGuard: DNS Integrity Monitoring and Spoofing Detection Workbench
dns_monitor.py - Core DNS Resolution, Validation, and Network Monitoring Engine.
"""

from datetime import datetime, timezone
import ipaddress
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

# Standard public DNS resolvers for cross-verification
PUBLIC_RESOLVERS: Dict[str, str] = {
    "System Default": "",
    "Cloudflare (1.1.1.1)": "1.1.1.1",
    "Google DNS (8.8.8.8)": "8.8.8.8",
    "Quad9 (9.9.9.9)": "9.9.9.9",
    "OpenDNS (208.67.222.222)": "208.67.222.222",
}

# RFC 1123 Hostname Regex
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def validate_domain_name(domain: str) -> Tuple[bool, str]:
    """
    Validates user-provided domain string against RFC 1123 requirements.
    Prevents shell injection, control characters, and malformed inputs.
    """
    if not domain or not isinstance(domain, str):
        return False, "Domain name cannot be empty."

    cleaned = domain.strip().lower()
    if cleaned.endswith("."):
        cleaned = cleaned[:-1]

    if len(cleaned) < 3 or len(cleaned) > 253:
        return False, f"Domain length ({len(cleaned)}) must be between 3 and 253 characters."

    if not DOMAIN_REGEX.match(cleaned):
        return False, "Invalid characters or formatting in domain name (RFC 1123 violation)."

    # Must contain at least one dot or be localhost/internal
    labels = cleaned.split(".")
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False, "Individual domain labels must be between 1 and 63 characters."
        if label.startswith("-") or label.endswith("-"):
            return False, "Domain labels cannot start or end with a hyphen."

    return True, cleaned


RFC_1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10")
]


def classify_ip_address(ip_str: str) -> Dict[str, Any]:
    """
    Inspects an IP address string to determine its network classification.
    Flags RFC 1918 (Private LAN), RFC 5735 (Loopback), Multicast, and Reserved IPs.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        is_rfc1918 = any(ip_obj in net for net in RFC_1918_NETWORKS)
        return {
            "ip": ip_str,
            "version": ip_obj.version,
            "is_private": ip_obj.is_private,
            "is_rfc1918": is_rfc1918,
            "is_loopback": ip_obj.is_loopback,
            "is_multicast": ip_obj.is_multicast,
            "is_reserved": ip_obj.is_reserved,
            "is_global": ip_obj.is_global,
            "is_suspicious_for_public_domain": is_rfc1918 or ip_obj.is_loopback
        }
    except ValueError:
        return {
            "ip": ip_str,
            "version": None,
            "is_private": False,
            "is_rfc1918": False,
            "is_loopback": False,
            "is_multicast": False,
            "is_reserved": False,
            "is_global": False,
            "is_suspicious_for_public_domain": True,
            "error": "Malformed IP address"
        }


def get_reverse_dns(ip_str: str, timeout: float = 1.5) -> Optional[str]:
    """Performs reverse DNS (PTR) lookup with a strict timeout."""
    try:
        # socket.setdefaulttimeout affects gethostbyaddr
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            return hostname
        finally:
            socket.setdefaulttimeout(old_timeout)
    except Exception:
        return None


def resolve_domain(
    domain: str,
    resolver_ip: Optional[str] = None,
    timeout: float = 3.0,
    record_type: str = "A"
) -> Dict[str, Any]:
    """
    Resolves DNS records for a given domain using dnspython with a fallback
    to standard library socket.

    Returns a structured dictionary with:
    - domain, resolver, status (SUCCESS, NXDOMAIN, TIMEOUT, ERROR)
    - ips (sorted list)
    - response_time_ms
    - canonical_name (if CNAME encountered)
    - timestamp
    - error_message (if any)
    """
    is_valid, sanitized_or_err = validate_domain_name(domain)
    if not is_valid:
        return {
            "domain": domain,
            "resolver": resolver_ip or "System Default",
            "status": "ERROR",
            "ips": [],
            "response_time_ms": 0.0,
            "canonical_name": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error_message": f"Validation Error: {sanitized_or_err}"
        }

    target_domain = sanitized_or_err
    start_time = time.perf_counter()
    resolver_label = resolver_ip if resolver_ip else "System Default"

    try:
        res = dns.resolver.Resolver()
        res.lifetime = timeout
        res.timeout = timeout

        if resolver_ip and resolver_ip.strip():
            res.nameservers = [resolver_ip.strip()]

        # Perform query
        answers = res.resolve(target_domain, record_type)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        observed_ips: List[str] = []
        cname_target: Optional[str] = None

        if hasattr(answers, "canonical_name"):
            cname_str = str(answers.canonical_name).rstrip(".")
            if cname_str != target_domain:
                cname_target = cname_str

        for rdata in answers:
            if record_type in ("A", "AAAA"):
                ip_val = rdata.to_text().strip()
                if ip_val not in observed_ips:
                    observed_ips.append(ip_val)
            else:
                observed_ips.append(rdata.to_text().strip())

        observed_ips.sort()

        return {
            "domain": target_domain,
            "resolver": resolver_label,
            "status": "SUCCESS",
            "ips": observed_ips,
            "response_time_ms": elapsed_ms,
            "canonical_name": cname_target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error_message": None
        }

    except dns.resolver.NXDOMAIN:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "domain": target_domain,
            "resolver": resolver_label,
            "status": "NXDOMAIN",
            "ips": [],
            "response_time_ms": elapsed_ms,
            "canonical_name": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error_message": f"Non-Existent Domain (NXDOMAIN): '{target_domain}' does not exist."
        }

    except dns.resolver.Timeout:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "domain": target_domain,
            "resolver": resolver_label,
            "status": "TIMEOUT",
            "ips": [],
            "response_time_ms": elapsed_ms,
            "canonical_name": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error_message": f"Resolution timed out after {timeout}s using {resolver_label}."
        }

    except dns.resolver.NoAnswer:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "domain": target_domain,
            "resolver": resolver_label,
            "status": "NO_ANSWER",
            "ips": [],
            "response_time_ms": elapsed_ms,
            "canonical_name": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error_message": f"No {record_type} records found for '{target_domain}'."
        }

    except Exception as exc:
        # Fallback to system socket if custom resolver was not requested
        if not resolver_ip:
            try:
                addr_info = socket.getaddrinfo(target_domain, 80, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
                ips = sorted(list({item[4][0] for item in addr_info}))
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
                return {
                    "domain": target_domain,
                    "resolver": "System Socket Fallback",
                    "status": "SUCCESS",
                    "ips": ips,
                    "response_time_ms": elapsed_ms,
                    "canonical_name": None,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "error_message": None
                }
            except Exception as sock_err:
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
                return {
                    "domain": target_domain,
                    "resolver": resolver_label,
                    "status": "ERROR",
                    "ips": [],
                    "response_time_ms": elapsed_ms,
                    "canonical_name": None,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "error_message": f"DNS Resolution Error: {str(sock_err)}"
                }

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "domain": target_domain,
            "resolver": resolver_label,
            "status": "ERROR",
            "ips": [],
            "response_time_ms": elapsed_ms,
            "canonical_name": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error_message": f"DNS Resolution Error: {str(exc)}"
        }


def cross_resolver_lookup(
    domain: str,
    resolvers: Optional[Dict[str, str]] = None,
    timeout: float = 2.5
) -> Dict[str, Dict[str, Any]]:
    """
    Queries multiple independent resolvers to verify consensus and detect
    local resolver poisoning, transparent proxying, or censorship.
    """
    active_resolvers = resolvers or PUBLIC_RESOLVERS
    results: Dict[str, Dict[str, Any]] = {}

    for name, ip_addr in active_resolvers.items():
        results[name] = resolve_domain(
            domain=domain,
            resolver_ip=ip_addr if ip_addr else None,
            timeout=timeout,
            record_type="A"
        )

    return results
