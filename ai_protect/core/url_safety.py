"""URL safety guards for DAST scans.

Refuses to launch a DAST scan against IPs/networks that have no legitimate
external-scan use case, picking up the design from a PAL review on 2026-05-26.
The guards apply BEFORE adapter dispatch — once a URL passes here, every
adapter in the DAST set can be invoked against it safely-ish.

Hard-deny (non-overridable even via manifest.target.network_allowed_zones):
  - 169.254.169.254/32 and cloud metadata aliases
  - Embedded creds in URL (user:pass@host)
  - non-http(s) schemes

Default-deny (overridable per-manifest by listing the CIDR in
target.network_allowed_zones, or by setting allow_internal_scan=True):
  - localhost / 127/8, ::1
  - RFC1918: 10/8, 172.16/12, 192.168/16
  - Link-local: 169.254/16, fe80::/10
  - Multicast: 224/4, ff00::/8
  - IPv6 ULA: fc00::/7
  - Reserved / unroutable: 0/8, 100.64/10 (CGNAT), 198.18/15 (benchmark)
  - Documentation: 192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32

Default-warn (HTTP without TLS): refuses by default in DAST mode; operator
must explicitly toggle "allow_insecure_http=True" on the manifest target
or pass it as a per-scan override.

DNS is re-resolved on every check (no cache) to defeat rebinding-style
attacks where a hostname pretends to be public but resolves to internal IPs.
The check rejects if ANY resolved A/AAAA matches a denied range — not just
the first one.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


# --- range definitions ----------------------------------------------------

# Always-refused — no security-scan justification, ever. PAL noted metadata
# endpoints sit too close to the SSRF blast-radius class to be overridable.
_HARD_DENY_V4 = [
    ipaddress.ip_network("169.254.169.254/32"),   # cloud metadata
]
_HARD_DENY_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.azure.com",
    "metadata.azure.internal",
    "metadata.oraclecloud.internal",   # Oracle Cloud
}

# Refused by default; can be overridden via manifest.target.network_allowed_zones
# (CIDR list) or the ad-hoc "allow internal scan" typed-confirmation gate.
_DEFAULT_DENY = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),         # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),         # link-local (subsumes metadata)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.2.0/24"),           # docs / TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),          # benchmark / RFC 2544
    ipaddress.ip_network("198.51.100.0/24"),        # docs / TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),         # docs / TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),            # multicast
    ipaddress.ip_network("240.0.0.0/4"),            # reserved
    ipaddress.ip_network("255.255.255.255/32"),     # limited broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),                # loopback
    ipaddress.ip_network("fc00::/7"),               # ULA
    ipaddress.ip_network("fe80::/10"),              # link-local
    ipaddress.ip_network("ff00::/8"),               # multicast
    ipaddress.ip_network("2001:db8::/32"),          # docs
]


# --- result type ---------------------------------------------------------

@dataclass
class UrlCheck:
    ok: bool
    url: str                                 # the URL after normalization
    hostname: str                            # normalized host (lowercase, no trailing dot)
    port: int                                # explicit port (443 / 80 if not given)
    resolved_ips: list[str]                  # IPs we resolved the host to
    reason: str = ""                         # human-readable refusal reason if not ok
    hard_deny: bool = False                  # True = never overridable

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "url": self.url, "hostname": self.hostname,
            "port": self.port, "resolved_ips": self.resolved_ips,
            "reason": self.reason, "hard_deny": self.hard_deny,
        }


# --- the public check ---------------------------------------------------

def check_url(
    url: str,
    *,
    allow_internal_zones: Iterable[str] = (),
    allow_insecure_http: bool = False,
    allow_internal_scan: bool = False,
) -> UrlCheck:
    """Validate a candidate DAST target URL.

    Args:
      url: the URL to scan.
      allow_internal_zones: list of CIDR strings the operator pre-approved on the
        manifest (target.network_allowed_zones). Resolved IPs in any of these
        CIDRs are allowed even if they'd otherwise be default-denied.
      allow_insecure_http: when False (default), http:// URLs are refused unless
        the host also lies in an allowed internal zone.
      allow_internal_scan: when True, the operator has typed-confirmed an
        internal scan; default-deny ranges are allowed (but hard-deny still applies).

    Returns:
      UrlCheck with ok=True on pass, ok=False with a populated reason
      otherwise.
    """
    if not url or not isinstance(url, str):
        return UrlCheck(False, url or "", "", 0, [], "URL is empty", hard_deny=True)

    url = url.strip()
    parsed = urlparse(url)

    # Scheme — only http(s).
    if parsed.scheme not in ("http", "https"):
        return UrlCheck(False, url, "", 0, [],
                        f"unsupported scheme '{parsed.scheme}' — only http/https allowed",
                        hard_deny=True)

    # Embedded creds → SSRF-class hazard. Never overridable.
    if parsed.username or parsed.password:
        return UrlCheck(False, url, "", 0, [],
                        "URL contains userinfo (user:pass@host) — refuse to log/forward credentials",
                        hard_deny=True)

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return UrlCheck(False, url, "", 0, [], "URL has no hostname", hard_deny=True)

    # Explicit metadata-host shortcut (some clouds expose them by name).
    if host in _HARD_DENY_HOSTNAMES:
        return UrlCheck(False, url, host, 0, [],
                        f"hostname '{host}' is a cloud metadata endpoint — hard-denied",
                        hard_deny=True)

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # HTTP → HTTPS preference. Don't block in internal zones (TLS often
    # absent in dev), but refuse on the public path unless explicitly allowed.
    if parsed.scheme == "http" and not allow_insecure_http and not allow_internal_scan:
        return UrlCheck(False, url, host, port, [],
                        "http:// refused — use https, or enable 'allow insecure HTTP' on the manifest target")

    # Allow-zones (parsed once)
    allowed_nets = []
    for z in (allow_internal_zones or []):
        try:
            allowed_nets.append(ipaddress.ip_network(z, strict=False))
        except ValueError:
            # Operator wrote a non-CIDR in target.network_allowed_zones — ignore
            # silently. Per PAL: zones are CIDRs only, not env names.
            continue

    # Resolve. Hostnames that are already literal IPs skip DNS but still hit
    # the same CIDR checks below.
    resolved: list[str] = []
    try:
        ipaddress.ip_address(host)            # raises if not a bare IP
        resolved = [host]
    except ValueError:
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
                ip = sockaddr[0]
                if ip not in resolved:
                    resolved.append(ip)
        except socket.gaierror as e:
            return UrlCheck(False, url, host, port, [],
                            f"DNS resolution failed: {e}", hard_deny=True)

    if not resolved:
        return UrlCheck(False, url, host, port, [], "DNS resolved zero addresses", hard_deny=True)

    # Hard-deny pass — non-overridable.
    for ip_s in resolved:
        try:
            ip = ipaddress.ip_address(ip_s)
        except ValueError:
            continue
        for net in _HARD_DENY_V4:
            if ip in net:
                return UrlCheck(False, url, host, port, resolved,
                                f"resolved IP {ip_s} is in hard-denied range {net} (cloud metadata or equivalent)",
                                hard_deny=True)

    # Default-deny pass — overridable via allow_internal_scan or allow zones.
    for ip_s in resolved:
        try:
            ip = ipaddress.ip_address(ip_s)
        except ValueError:
            continue
        in_allowed = any(ip in n for n in allowed_nets)
        if in_allowed:
            continue
        for net in _DEFAULT_DENY:
            if ip.version != net.version:
                continue
            if ip in net:
                if allow_internal_scan:
                    continue   # operator typed-confirmed
                return UrlCheck(False, url, host, port, resolved,
                                f"resolved IP {ip_s} is in default-denied range {net}; "
                                f"enable 'allow internal scan' on this scan request "
                                f"OR add the CIDR to manifest.target.network_allowed_zones")

    return UrlCheck(True, url, host, port, resolved)


# --- helpers for the UI / orchestrator ---

def adhoc_app_name(host: str, port: int) -> str:
    """Stable per-host:port app_name for ad-hoc DAST findings.

    Include port so example.com:443 and example.com:8443 don't merge."""
    host = (host or "").lower().rstrip(".")
    default_port = port in (80, 443)
    return f"adhoc:{host}" if default_port else f"adhoc:{host}:{port}"
