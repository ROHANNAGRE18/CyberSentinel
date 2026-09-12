"""
SSRF Protection and URL Validation Layer
=========================================
This module is the security gate that every URL passes through BEFORE
any outbound network request is made by the scanner.

Validation pipeline (in order):
  1. Basic format check  – scheme, length, parsability
  2. Scheme allowlist    – only http:// and https://
  3. Hostname extraction – reject empty, IP literals that are private
  4. DNS resolution      – resolve to IP(s), reject private/reserved addresses
  5. Redirect guard      – same IP-blocklist check applied after each redirect

Blocked address categories:
  - Loopback             127.0.0.0/8,  ::1
  - Private              10.0.0.0/8,   172.16.0.0/12,  192.168.0.0/16
  - Link-local           169.254.0.0/16  (includes AWS/GCP/Azure metadata)
  - Unique local (IPv6)  fc00::/7
  - Any-address          0.0.0.0,  ::
  - Cloud metadata IPs   169.254.169.254 (AWS/GCP/Azure),  fd00:ec2::254 (AWS IPv6)
  - NAT64 (64:ff9b::/96) only when the embedded IPv4 is itself in a blocked range

Usage:
  from app.core.security import validate_url, is_safe_ip

  # Raises SSRFError (subclass of HTTPException 400) on any violation
  validated_url = await validate_url("https://example.com")

  # Used by the httpx redirect hook to re-check resolved IPs after redirects
  is_safe_ip("1.2.3.4")  # returns True / False
"""

import ipaddress
import logging
import socket
from typing import Optional
from urllib.parse import urlparse

import dns.resolver
import dns.exception
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

#: Maximum URL length accepted (characters)
MAX_URL_LENGTH = 2048

#: Schemes the scanner is allowed to request
ALLOWED_SCHEMES = {"http", "https"}

#: Explicit cloud metadata IP addresses to always block
CLOUD_METADATA_IPS = {
    "169.254.169.254",   # AWS / GCP / Azure instance metadata (IPv4)
    "fd00:ec2::254",     # AWS instance metadata (IPv6)
    "metadata.google.internal",  # GCP metadata hostname
}

#: Private / reserved IPv4 networks – RFC-1918, loopback, link-local, etc.
_BLOCKED_IPV4_NETWORKS = [
    ipaddress.IPv4Network("0.0.0.0/8"),        # "This" network
    ipaddress.IPv4Network("10.0.0.0/8"),        # RFC-1918 private
    ipaddress.IPv4Network("100.64.0.0/10"),     # Shared address space (RFC-6598)
    ipaddress.IPv4Network("127.0.0.0/8"),       # Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),    # Link-local / cloud metadata
    ipaddress.IPv4Network("172.16.0.0/12"),     # RFC-1918 private
    ipaddress.IPv4Network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.IPv4Network("192.0.2.0/24"),      # TEST-NET-1 (documentation)
    ipaddress.IPv4Network("192.168.0.0/16"),    # RFC-1918 private
    ipaddress.IPv4Network("198.18.0.0/15"),     # Network benchmarking
    ipaddress.IPv4Network("198.51.100.0/24"),   # TEST-NET-2 (documentation)
    ipaddress.IPv4Network("203.0.113.0/24"),    # TEST-NET-3 (documentation)
    ipaddress.IPv4Network("224.0.0.0/4"),       # Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),       # Reserved
    ipaddress.IPv4Network("255.255.255.255/32"),# Broadcast
]

#: Private / reserved IPv6 networks
_BLOCKED_IPV6_NETWORKS = [
    ipaddress.IPv6Network("::1/128"),           # Loopback
    ipaddress.IPv6Network("::/128"),            # Unspecified
    ipaddress.IPv6Network("::ffff:0:0/96"),     # IPv4-mapped (catches 127.x via IPv6)
    # 64:ff9b::/96 (NAT64 Well-Known Prefix, RFC 6052) is NOT in this list.
    # NAT64 addresses embed a real public IPv4 in the last 32 bits; we extract
    # and validate that IPv4 separately in is_safe_ip() below.
    ipaddress.IPv6Network("fc00::/7"),          # Unique local (RFC-4193)
    ipaddress.IPv6Network("fe80::/10"),         # Link-local
    ipaddress.IPv6Network("ff00::/8"),          # Multicast
    ipaddress.IPv6Network("100::/64"),          # Discard prefix
]

#: NAT64 Well-Known Prefix (RFC 6052). Addresses in this /96 embed a
#: public-or-private IPv4 address in the low 32 bits. We must not block
#: the entire prefix — only those whose embedded IPv4 is itself blocked.
_NAT64_WKP = ipaddress.IPv6Network("64:ff9b::/96")


# ── Custom exceptions ─────────────────────────────────────────────────────────

class SSRFError(HTTPException):
    """Raised when a URL or resolved IP violates SSRF protection rules."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
        logger.warning("SSRF protection triggered: %s", detail)


class URLValidationError(HTTPException):
    """Raised when a URL fails basic format/scheme validation."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
        logger.warning("URL validation failed: %s", detail)


# ── IP safety check ───────────────────────────────────────────────────────────

def is_safe_ip(ip_str: str) -> bool:
    """
    Return True if the IP address is safe for outbound scanning.
    Return False if it falls into any private, reserved, or metadata range.

    This function is also called by the httpx redirect hook so that
    redirects to internal addresses are caught mid-flight.
    """
    # Explicit cloud metadata hostnames / IPs (string match before parsing)
    if ip_str.strip().lower() in {ip.lower() for ip in CLOUD_METADATA_IPS}:
        return False

    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        # Not a valid IP address at all – reject it
        logger.debug("is_safe_ip: could not parse '%s' as an IP address", ip_str)
        return False

    if isinstance(addr, ipaddress.IPv4Address):
        for network in _BLOCKED_IPV4_NETWORKS:
            if addr in network:
                return False
    else:
        # IPv6
        for network in _BLOCKED_IPV6_NETWORKS:
            if addr in network:
                return False

        # NAT64 Well-Known Prefix (64:ff9b::/96, RFC 6052):
        # The last 32 bits encode a real IPv4 address. Extract it and run the
        # same IPv4 blocklist check — this blocks NAT64 addresses that would
        # reach private/loopback/link-local IPv4 targets while allowing those
        # that translate to genuine public IPv4 addresses (e.g. github.com).
        if addr in _NAT64_WKP:
            embedded_ipv4 = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
            for network in _BLOCKED_IPV4_NETWORKS:
                if embedded_ipv4 in network:
                    logger.debug(
                        "is_safe_ip: NAT64 address %s embeds blocked IPv4 %s",
                        addr, embedded_ipv4,
                    )
                    return False

    return True


# ── DNS resolution ────────────────────────────────────────────────────────────

async def resolve_hostname(hostname: str) -> list[str]:
    """
    Resolve a hostname to its IP addresses using dnspython.

    Returns a list of IP address strings.
    Raises SSRFError if the hostname cannot be resolved or resolves to
    zero addresses.

    Note: We use a synchronous dns.resolver call inside an async context.
    This is acceptable because DNS resolution is fast and the stdlib socket
    resolver is available as a fallback.  For high-concurrency production
    use, swap to aiodns.
    """
    resolved_ips: list[str] = []

    # Try A records (IPv4)
    try:
        answers = dns.resolver.resolve(hostname, "A", lifetime=5.0)
        resolved_ips.extend(str(rdata) for rdata in answers)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except dns.exception.DNSException as exc:
        logger.debug("DNS A lookup failed for %s: %s", hostname, exc)

    # Try AAAA records (IPv6)
    try:
        answers = dns.resolver.resolve(hostname, "AAAA", lifetime=5.0)
        resolved_ips.extend(str(rdata) for rdata in answers)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except dns.exception.DNSException as exc:
        logger.debug("DNS AAAA lookup failed for %s: %s", hostname, exc)

    # Fall back to stdlib getaddrinfo if dnspython returns nothing
    if not resolved_ips:
        try:
            infos = socket.getaddrinfo(hostname, None)
            resolved_ips = [info[4][0] for info in infos]
        except socket.gaierror as exc:
            raise SSRFError(
                f"Could not resolve hostname '{hostname}': {exc}"
            ) from exc

    if not resolved_ips:
        raise SSRFError(f"Hostname '{hostname}' resolved to no IP addresses.")

    return resolved_ips


# ── SSRF IP guard ─────────────────────────────────────────────────────────────

def assert_safe_ips(hostname: str, resolved_ips: list[str]) -> None:
    """
    Assert that ALL resolved IPs for a hostname are safe.

    We check every IP, not just the first, to prevent DNS re-binding attacks
    where an attacker rotates between a public IP and an internal one.

    Raises SSRFError if any IP is in a blocked range.
    """
    for ip in resolved_ips:
        if not is_safe_ip(ip):
            raise SSRFError(
                f"Hostname '{hostname}' resolves to a blocked IP address ({ip}). "
                "Scanning private, loopback, link-local, or cloud metadata "
                "addresses is not permitted."
            )


# ── Main validation entry point ───────────────────────────────────────────────

async def validate_url(raw_url: str) -> str:
    """
    Full validation pipeline for a user-supplied URL.

    Steps:
      1. Strip whitespace
      2. Length check
      3. URL parsing & scheme check
      4. Hostname extraction
      5. Block raw IP literals that are private/reserved
      6. DNS resolution
      7. SSRF IP guard against all resolved IPs

    Returns the normalised URL string on success.
    Raises URLValidationError or SSRFError on any failure.
    """
    # ── Step 1: Strip ─────────────────────────────────────────────────────────
    url = raw_url.strip()

    if not url:
        raise URLValidationError("URL must not be empty.")

    # ── Step 2: Length ────────────────────────────────────────────────────────
    if len(url) > MAX_URL_LENGTH:
        raise URLValidationError(
            f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters."
        )

    # ── Step 3: Scheme ────────────────────────────────────────────────────────
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise URLValidationError(f"URL could not be parsed: {exc}") from exc

    scheme = parsed.scheme.lower()

    if scheme not in ALLOWED_SCHEMES:
        raise URLValidationError(
            f"URL scheme '{scheme}' is not allowed. "
            f"Only {', '.join(sorted(ALLOWED_SCHEMES))} URLs are accepted."
        )

    # ── Step 4: Hostname ──────────────────────────────────────────────────────
    hostname: Optional[str] = parsed.hostname  # lowercased, brackets stripped for IPv6

    if not hostname:
        raise URLValidationError("URL must contain a valid hostname.")

    # Reject userinfo (user:pass@host) in the URL — not needed and a risk vector
    if parsed.username or parsed.password:
        raise URLValidationError(
            "URLs with embedded credentials (user:password@host) are not accepted."
        )

    # ── Step 5: Block raw IP literals ─────────────────────────────────────────
    # If the user typed an IP address directly (e.g. http://192.168.1.1/),
    # we catch it here without even doing a DNS lookup.
    try:
        ip_literal = ipaddress.ip_address(hostname)
        if not is_safe_ip(str(ip_literal)):
            raise SSRFError(
                f"The IP address '{hostname}' is in a blocked range. "
                "Scanning private, loopback, or link-local addresses is not permitted."
            )
        # If it IS a public IP literal, skip DNS resolution (nothing to resolve)
        logger.info("URL validation passed for IP literal: %s", url)
        return url
    except ValueError:
        # hostname is a domain name, not an IP literal — continue to DNS step
        pass

    # Block known cloud metadata hostnames explicitly
    if hostname.lower() in {h.lower() for h in CLOUD_METADATA_IPS}:
        raise SSRFError(
            f"Hostname '{hostname}' is a cloud metadata endpoint and is blocked."
        )

    # ── Step 6: DNS resolution ────────────────────────────────────────────────
    resolved_ips = await resolve_hostname(hostname)
    logger.debug("Resolved %s → %s", hostname, resolved_ips)

    # ── Step 7: SSRF IP guard ─────────────────────────────────────────────────
    assert_safe_ips(hostname, resolved_ips)

    logger.info("URL validation passed: %s (resolved: %s)", url, resolved_ips)
    return url


# ── Redirect guard (used by httpx event hook) ─────────────────────────────────

def build_redirect_guard():
    """
    Returns an httpx-compatible event hook function that validates
    redirect destinations before following them.

    Usage in scanner:
        import httpx
        from app.core.security import build_redirect_guard

        async with httpx.AsyncClient(
            event_hooks={"response": [build_redirect_guard()]}
        ) as client:
            ...

    The hook raises SSRFError (HTTPException 400) if a redirect would lead
    to a private/internal IP, stopping the request chain immediately.
    """
    async def _redirect_guard(response) -> None:
        """
        Called by httpx after every response, including redirects.
        If the response is a redirect, resolve the Location header's
        hostname and validate it before httpx follows the redirect.
        """
        if response.status_code not in (301, 302, 303, 307, 308):
            return  # Not a redirect — nothing to check

        location = response.headers.get("location", "")
        if not location:
            return

        try:
            parsed = urlparse(location)
            redirect_host = parsed.hostname
        except Exception:
            raise SSRFError(
                f"Redirect to malformed Location header blocked: '{location}'"
            )

        if not redirect_host:
            raise SSRFError(
                f"Redirect to URL with no hostname blocked: '{location}'"
            )

        # Block if the redirect target is a raw private IP
        try:
            ip_literal = ipaddress.ip_address(redirect_host)
            if not is_safe_ip(str(ip_literal)):
                raise SSRFError(
                    f"Redirect to private IP '{redirect_host}' blocked."
                )
            return  # Public IP literal — safe
        except ValueError:
            pass  # Not an IP literal, fall through to DNS check

        # Resolve the redirect hostname and validate all resulting IPs
        try:
            resolved = await resolve_hostname(redirect_host)
            assert_safe_ips(redirect_host, resolved)
        except SSRFError:
            raise
        except Exception as exc:
            raise SSRFError(
                f"Redirect to '{redirect_host}' could not be validated: {exc}"
            ) from exc

    return _redirect_guard
