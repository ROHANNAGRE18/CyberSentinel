"""
DNS Analyzer — Phase 2E
========================

Performs passive, read-only DNS lookups against the target hostname.
All queries use dnspython with a 5-second per-query timeout.
DNS queries are non-intrusive — equivalent to what any browser or
email server performs routinely.

Record types checked
─────────────────────
  dns_a_records      – IPv4 address records (required for HTTP/HTTPS)
  dns_aaaa_records   – IPv6 address records (informational)
  dns_ns_records     – Authoritative name servers (informational)
  dns_mx_records     – Mail exchange records (informational only — not a
                       website vulnerability if absent)
  dns_spf_record     – SPF TXT record (email security, informational only)
  dns_dmarc_record   – DMARC TXT record (email security, informational only)

Scoring / severity intent
──────────────────────────
  dns_a_records      – FAIL if no A records found (site won't resolve)
  dns_aaaa_records   – INFO always (no pass/fail — IPv6 is optional)
  dns_ns_records     – INFO always (reporting only)
  dns_mx_records     – INFO always (not a website requirement)
  dns_spf_record     – INFO always (email security, per design requirement)
  dns_dmarc_record   – INFO always (email security, per design requirement)

None of the DNS results directly affect the site security score (that is
handled by the scoring engine in a future phase). SPF/DMARC are explicitly
informational as requested by the project design.

Concurrency
────────────
  DNS lookups are synchronous (dnspython's default resolver). We wrap
  each query in asyncio.to_thread to prevent blocking the event loop,
  then gather all six queries in parallel.
"""

import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

import dns.exception
import dns.resolver

from app.services.analyzer.base import (
    CheckBundle,
    CheckResult,
    CheckStatus,
    Priority,
    Recommendation,
    Severity,
)

logger = logging.getLogger(__name__)

# Per-query DNS timeout in seconds
_DNS_TIMEOUT = 5.0


# ── Low-level DNS query helper ────────────────────────────────────────────────

def _query(hostname: str, record_type: str) -> list[str]:
    """
    Synchronous DNS query. Returns a list of string representations of
    each record in the answer section. Returns an empty list if the
    record type does not exist (NXDOMAIN / NoAnswer). Raises only on
    unexpected errors.

    Designed to be called via asyncio.to_thread.
    """
    try:
        answers = dns.resolver.resolve(hostname, record_type, lifetime=_DNS_TIMEOUT)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        raise TimeoutError(f"DNS query for {record_type} timed out")
    except dns.exception.DNSException as exc:
        raise OSError(f"DNS error for {record_type}: {exc}") from exc


# ── Individual record checks ──────────────────────────────────────────────────

def _check_a_records(records: list[str]) -> tuple[CheckResult, Optional[Recommendation]]:
    """
    A records — required for the site to resolve over IPv4.
    FAIL if none found; PASS otherwise.
    """
    if not records:
        return (
            CheckResult(
                check_name="dns_a_records",
                status=CheckStatus.FAIL,
                title="DNS A Records: Not Found",
                detail=(
                    "No A (IPv4 address) records were found for this hostname. "
                    "The domain cannot be reached over IPv4, which will prevent "
                    "most browsers from loading the site."
                ),
                severity=Severity.HIGH,
            ),
            Recommendation(
                check_name="dns_a_records",
                priority=Priority.HIGH,
                title="Add A records to your DNS configuration",
                description=(
                    "Create at least one A record pointing to your server's "
                    "public IPv4 address. Without A records, browsers cannot "
                    "resolve the domain to an IP address."
                ),
                reference_url="https://www.cloudflare.com/learning/dns/dns-records/dns-a-record/",
            ),
        )

    display = ", ".join(records[:10])
    if len(records) > 10:
        display += f" … (+{len(records) - 10} more)"

    return (
        CheckResult(
            check_name="dns_a_records",
            status=CheckStatus.PASS,
            title=f"DNS A Records: {len(records)} Record(s) Found",
            detail=f"IPv4 address(es): {display}",
            severity=Severity.INFO,
        ),
        None,
    )


def _check_aaaa_records(records: list[str]) -> CheckResult:
    """
    AAAA records — IPv6 addresses. Always informational.
    Not having AAAA records is not a security issue.
    """
    if not records:
        return CheckResult(
            check_name="dns_aaaa_records",
            status=CheckStatus.INFO,
            title="DNS AAAA Records: None Found",
            detail=(
                "No AAAA (IPv6 address) records were found. "
                "IPv6 is optional — most sites are reachable over IPv4 only."
            ),
            severity=Severity.INFO,
        )

    display = ", ".join(records[:5])
    if len(records) > 5:
        display += f" … (+{len(records) - 5} more)"

    return CheckResult(
        check_name="dns_aaaa_records",
        status=CheckStatus.INFO,
        title=f"DNS AAAA Records: {len(records)} Record(s) Found",
        detail=f"IPv6 address(es): {display}",
        severity=Severity.INFO,
    )


def _check_ns_records(records: list[str]) -> CheckResult:
    """
    NS records — authoritative name servers. Always informational.
    """
    if not records:
        return CheckResult(
            check_name="dns_ns_records",
            status=CheckStatus.INFO,
            title="DNS NS Records: None Found",
            detail=(
                "No NS (Name Server) records were found. "
                "This may indicate a lookup error or a non-standard DNS setup."
            ),
            severity=Severity.INFO,
        )

    display = ", ".join(r.rstrip(".") for r in records[:10])
    return CheckResult(
        check_name="dns_ns_records",
        status=CheckStatus.INFO,
        title=f"DNS NS Records: {len(records)} Name Server(s)",
        detail=f"Authoritative name server(s): {display}",
        severity=Severity.INFO,
    )


def _check_mx_records(records: list[str]) -> CheckResult:
    """
    MX records — mail exchange. Always informational.
    Absence is normal for websites that don't send/receive email directly.
    """
    if not records:
        return CheckResult(
            check_name="dns_mx_records",
            status=CheckStatus.INFO,
            title="DNS MX Records: None Found",
            detail=(
                "No MX (Mail Exchange) records were found. "
                "This is normal for websites that do not handle email directly. "
                "Not a website security issue."
            ),
            severity=Severity.INFO,
        )

    # Strip priority prefix (e.g. "10 mail.example.com.") for display
    hosts = []
    for r in records[:10]:
        parts = r.split(None, 1)
        hosts.append(parts[1].rstrip(".") if len(parts) == 2 else r.rstrip("."))

    display = ", ".join(hosts)
    return CheckResult(
        check_name="dns_mx_records",
        status=CheckStatus.INFO,
        title=f"DNS MX Records: {len(records)} Mail Server(s) Found",
        detail=f"Mail server(s): {display}",
        severity=Severity.INFO,
    )


def _check_spf_record(txt_records: list[str]) -> CheckResult:
    """
    SPF record — email sender policy. Always informational.
    Detected by searching TXT records for 'v=spf1'.
    """
    spf_records = [r for r in txt_records if "v=spf1" in r.lower()]

    if not spf_records:
        return CheckResult(
            check_name="dns_spf_record",
            status=CheckStatus.INFO,
            title="SPF Record: Not Found",
            detail=(
                "No SPF (Sender Policy Framework) TXT record was found. "
                "SPF specifies which mail servers are authorised to send email "
                "on behalf of this domain. Absence is informational for a website "
                "security check — it affects email deliverability and anti-spoofing, "
                "not the website itself."
            ),
            severity=Severity.INFO,
        )

    # Strip surrounding quotes that dnspython includes in TXT record strings
    value = spf_records[0].strip('"')
    return CheckResult(
        check_name="dns_spf_record",
        status=CheckStatus.INFO,
        title="SPF Record Found",
        detail=f"SPF policy: {value[:300]}",
        severity=Severity.INFO,
    )


def _check_dmarc_record(dmarc_records: list[str]) -> CheckResult:
    """
    DMARC record — email authentication policy. Always informational.
    Queried from _dmarc.<hostname> TXT records.
    """
    if not dmarc_records:
        return CheckResult(
            check_name="dns_dmarc_record",
            status=CheckStatus.INFO,
            title="DMARC Record: Not Found",
            detail=(
                "No DMARC (Domain-based Message Authentication, Reporting and "
                "Conformance) record was found at _dmarc.<domain>. "
                "DMARC builds on SPF and DKIM to protect against email spoofing. "
                "Absence is informational for a website security check."
            ),
            severity=Severity.INFO,
        )

    value = dmarc_records[0].strip('"')
    return CheckResult(
        check_name="dns_dmarc_record",
        status=CheckStatus.INFO,
        title="DMARC Record Found",
        detail=f"DMARC policy: {value[:300]}",
        severity=Severity.INFO,
    )


# ── Error result factory ──────────────────────────────────────────────────────

def _error_bundle(hostname: str, detail: str) -> CheckBundle:
    """
    Return a CheckBundle with 6 INFO results when the DNS lookups
    cannot run (e.g. network issue, invalid hostname).
    """
    check_names = [
        ("dns_a_records",   "DNS A Records"),
        ("dns_aaaa_records","DNS AAAA Records"),
        ("dns_ns_records",  "DNS NS Records"),
        ("dns_mx_records",  "DNS MX Records"),
        ("dns_spf_record",  "SPF Record"),
        ("dns_dmarc_record","DMARC Record"),
    ]
    return CheckBundle(
        results=[
            CheckResult(
                check_name=name,
                status=CheckStatus.INFO,
                title=f"{label}: Check Could Not Run",
                detail=detail,
                severity=Severity.INFO,
            )
            for name, label in check_names
        ],
        recommendations=[],
    )


# ── Public entry point ────────────────────────────────────────────────────────

async def run_dns_checks(url: str) -> CheckBundle:
    """
    Run all DNS checks for the hostname extracted from the given URL.

    All six record-type queries run concurrently via asyncio.gather
    (each wrapped in asyncio.to_thread since dnspython is synchronous).

    Never raises — all exceptions produce INFO results so the scan
    continues even if DNS is unreachable.
    """
    parsed   = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return _error_bundle("unknown", "Could not extract hostname from URL.")

    # Strip 'www.' to query the apex domain for MX/SPF/DMARC, but keep the
    # original hostname for A/AAAA/NS so we match what the browser resolves.
    apex = hostname.lstrip("www.") if hostname.startswith("www.") else hostname
    dmarc_host = f"_dmarc.{apex}"

    logger.debug("dns_checker: querying records for %s (apex: %s)", hostname, apex)

    # ── Run all queries concurrently ──────────────────────────────────────────
    try:
        (
            a_records,
            aaaa_records,
            ns_records,
            mx_records,
            txt_records,
            dmarc_records,
        ) = await asyncio.gather(
            asyncio.to_thread(_query, hostname, "A"),
            asyncio.to_thread(_query, hostname, "AAAA"),
            asyncio.to_thread(_query, apex,     "NS"),
            asyncio.to_thread(_query, apex,     "MX"),
            asyncio.to_thread(_query, apex,     "TXT"),
            asyncio.to_thread(_query, dmarc_host, "TXT"),
        )
    except TimeoutError as exc:
        logger.info("dns_checker: timeout for %s: %s", hostname, exc)
        return _error_bundle(hostname, f"DNS query timed out: {exc}")
    except OSError as exc:
        logger.info("dns_checker: os error for %s: %s", hostname, exc)
        return _error_bundle(hostname, f"DNS lookup failed: {exc}")
    except Exception as exc:
        logger.warning("dns_checker: unexpected error for %s: %s", hostname, exc)
        return _error_bundle(hostname, f"Unexpected error during DNS check: {exc}")

    # ── Build results ─────────────────────────────────────────────────────────
    results:         list[CheckResult]   = []
    recommendations: list[Recommendation] = []

    a_result, a_rec = _check_a_records(a_records)
    results.append(a_result)
    if a_rec:
        recommendations.append(a_rec)

    results.append(_check_aaaa_records(aaaa_records))
    results.append(_check_ns_records(ns_records))
    results.append(_check_mx_records(mx_records))
    results.append(_check_spf_record(txt_records))
    results.append(_check_dmarc_record(dmarc_records))

    logger.info(
        "dns_checker: completed for %s — A:%d AAAA:%d NS:%d MX:%d TXT:%d DMARC:%d",
        hostname,
        len(a_records), len(aaaa_records), len(ns_records),
        len(mx_records), len(txt_records),  len(dmarc_records),
    )
    return CheckBundle(results=results, recommendations=recommendations)
