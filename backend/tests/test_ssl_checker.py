"""
Tests for the SSL/TLS Certificate Analyzer (Phase 2C).

Unit tests mock all socket/SSL I/O with unittest.mock so no network
connections are made and tests run fully offline.

Integration tests (marked @pytest.mark.network) open a real TLS connection
to example.com and require internet access.

Run offline tests only:
  pytest tests/test_ssl_checker.py -v -m "not network"

Run all including live network:
  pytest tests/test_ssl_checker.py -v
"""

import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.analyzer.base import CheckStatus, Priority, Severity
from app.services.analyzer.ssl_checker import (
    EXPIRY_CRITICAL_DAYS,
    EXPIRY_HIGH_DAYS,
    EXPIRY_MEDIUM_DAYS,
    _check_expiry,
    _check_issuer,
    _check_subject,
    _check_validity,
    _extract_cn,
    _extract_org,
    _extract_sans,
    _parse_cert_date,
    run_ssl_checks,
)


# ── Helper: build a minimal fake cert dict ────────────────────────────────────

def _make_cert(
    days_until_expiry: int = 90,
    issuer_cn: str = "R3",
    issuer_org: str = "Let's Encrypt",
    subject_cn: str = "example.com",
    sans: list[str] | None = None,
) -> dict:
    """
    Build a fake cert dict matching the structure returned by
    ssl.SSLSocket.getpeercert().
    """
    now      = datetime.now(timezone.utc)
    not_before = now - timedelta(days=30)
    not_after  = now + timedelta(days=days_until_expiry)

    cert = {
        "notBefore": not_before.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter":  not_after.strftime("%b %d %H:%M:%S %Y GMT"),
        "issuer": (
            (("organizationName", issuer_org),),
            (("commonName", issuer_cn),),
        ),
        "subject": (
            (("commonName", subject_cn),),
        ),
        "subjectAltName": tuple(
            ("DNS", name) for name in (sans if sans is not None else [subject_cn])
        ),
    }
    return cert


# ════════════════════════════════════════════════════════════════════════════
# _parse_cert_date
# ════════════════════════════════════════════════════════════════════════════

class TestParseCertDate:

    def test_parses_standard_format(self):
        dt = _parse_cert_date("Jan  1 00:00:00 2025 GMT")
        assert dt is not None
        assert dt.year == 2025
        assert dt.month == 1
        assert dt.tzinfo is not None

    def test_parses_double_digit_day(self):
        dt = _parse_cert_date("Dec 31 23:59:59 2025 GMT")
        assert dt is not None
        assert dt.day == 31
        assert dt.month == 12

    def test_returns_none_on_invalid(self):
        assert _parse_cert_date("not-a-date") is None
        assert _parse_cert_date("") is None
        assert _parse_cert_date(None) is None  # type: ignore[arg-type]

    def test_result_is_utc(self):
        dt = _parse_cert_date("Jun 15 12:00:00 2026 GMT")
        assert dt.tzinfo == timezone.utc


# ════════════════════════════════════════════════════════════════════════════
# _extract_cn / _extract_org / _extract_sans
# ════════════════════════════════════════════════════════════════════════════

class TestExtractHelpers:

    def test_extract_cn_from_issuer(self):
        issuer = (
            (("organizationName", "ACME CA"),),
            (("commonName", "ACME Root"),),
        )
        assert _extract_cn(issuer) == "ACME Root"

    def test_extract_cn_returns_none_when_absent(self):
        issuer = ((("organizationName", "ACME CA"),),)
        assert _extract_cn(issuer) is None

    def test_extract_org(self):
        issuer = ((("organizationName", "Let's Encrypt"),),)
        assert _extract_org(issuer) == "Let's Encrypt"

    def test_extract_org_returns_none_when_absent(self):
        issuer = ((("commonName", "R3"),),)
        assert _extract_org(issuer) is None

    def test_extract_sans(self):
        cert = {
            "subjectAltName": (
                ("DNS", "example.com"),
                ("DNS", "www.example.com"),
                ("IP Address", "93.184.216.34"),  # non-DNS entries ignored
            )
        }
        sans = _extract_sans(cert)
        assert sans == ["example.com", "www.example.com"]

    def test_extract_sans_empty_when_no_san(self):
        assert _extract_sans({}) == []


# ════════════════════════════════════════════════════════════════════════════
# _check_validity
# ════════════════════════════════════════════════════════════════════════════

class TestCheckValidity:

    def test_always_pass_if_cert_returned(self):
        cert = _make_cert()
        result, rec = _check_validity(cert)
        assert result.status == CheckStatus.PASS
        assert result.check_name == "ssl_certificate_valid"
        assert rec is None

    def test_detail_contains_valid_from(self):
        cert = _make_cert()
        result, _ = _check_validity(cert)
        assert "Valid from" in result.detail


# ════════════════════════════════════════════════════════════════════════════
# _check_expiry
# ════════════════════════════════════════════════════════════════════════════

class TestCheckExpiry:

    def test_pass_when_60_days_remaining(self):
        cert = _make_cert(days_until_expiry=60)
        result, rec = _check_expiry(cert)
        assert result.status == CheckStatus.PASS
        assert rec is None
        assert "60" in result.title

    def test_pass_when_365_days_remaining(self):
        cert = _make_cert(days_until_expiry=365)
        result, rec = _check_expiry(cert)
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_warn_medium_at_45_days(self):
        cert = _make_cert(days_until_expiry=45)
        result, rec = _check_expiry(cert)
        assert result.status == CheckStatus.WARN
        assert result.severity == Severity.MEDIUM
        assert rec is not None
        assert rec.priority == Priority.MEDIUM

    def test_warn_high_at_20_days(self):
        cert = _make_cert(days_until_expiry=20)
        result, rec = _check_expiry(cert)
        assert result.status == CheckStatus.WARN
        assert result.severity == Severity.HIGH
        assert rec.priority == Priority.HIGH

    def test_fail_critical_at_7_days(self):
        cert = _make_cert(days_until_expiry=7)
        result, rec = _check_expiry(cert)
        assert result.status == CheckStatus.FAIL
        assert result.severity == Severity.CRITICAL
        assert rec.priority == Priority.CRITICAL

    def test_fail_critical_when_expired(self):
        cert = _make_cert(days_until_expiry=-5)
        result, rec = _check_expiry(cert)
        assert result.status == CheckStatus.FAIL
        assert result.severity == Severity.CRITICAL
        assert "expired" in result.title.lower() or "Expired" in result.title
        assert rec is not None

    def test_warn_when_not_after_unparseable(self):
        cert = {"notBefore": "Jan  1 00:00:00 2020 GMT", "notAfter": "invalid"}
        result, rec = _check_expiry(cert)
        assert result.status == CheckStatus.WARN
        assert rec is not None

    def test_expiry_boundary_exactly_60_days(self):
        cert = _make_cert(days_until_expiry=60)
        result, _ = _check_expiry(cert)
        assert result.status == CheckStatus.PASS

    def test_expiry_boundary_59_days_is_warn(self):
        cert = _make_cert(days_until_expiry=59)
        result, _ = _check_expiry(cert)
        assert result.status == CheckStatus.WARN

    def test_expiry_boundary_30_days_is_warn(self):
        cert = _make_cert(days_until_expiry=30)
        result, _ = _check_expiry(cert)
        assert result.status == CheckStatus.WARN

    def test_expiry_boundary_0_days_is_fail(self):
        # 0 days left means expiry is today — still critical
        cert = _make_cert(days_until_expiry=0)
        result, _ = _check_expiry(cert)
        assert result.status == CheckStatus.FAIL


# ════════════════════════════════════════════════════════════════════════════
# _check_issuer
# ════════════════════════════════════════════════════════════════════════════

class TestCheckIssuer:

    def test_pass_with_trusted_ca(self):
        cert = _make_cert(issuer_cn="R3", issuer_org="Let's Encrypt",
                          subject_cn="example.com")
        result, rec = _check_issuer(cert)
        assert result.status == CheckStatus.PASS
        assert rec is None
        assert "Let's Encrypt" in result.detail

    def test_warn_self_signed(self):
        # Self-signed: issuer CN == subject CN
        cert = _make_cert(issuer_cn="example.com", issuer_org="Self",
                          subject_cn="example.com")
        result, rec = _check_issuer(cert)
        assert result.status == CheckStatus.WARN
        assert result.severity == Severity.HIGH
        assert rec is not None
        assert rec.priority == Priority.HIGH

    def test_pass_when_issuer_different_from_subject(self):
        cert = _make_cert(issuer_cn="DigiCert Root", issuer_org="DigiCert Inc",
                          subject_cn="example.com")
        result, rec = _check_issuer(cert)
        assert result.status == CheckStatus.PASS
        assert rec is None


# ════════════════════════════════════════════════════════════════════════════
# _check_subject
# ════════════════════════════════════════════════════════════════════════════

class TestCheckSubject:

    def test_pass_with_cn_and_sans(self):
        cert = _make_cert(subject_cn="example.com",
                          sans=["example.com", "www.example.com"])
        result, rec = _check_subject(cert, "example.com")
        assert result.status == CheckStatus.PASS
        assert rec is None
        assert "example.com" in result.detail

    def test_pass_with_many_sans_truncates(self):
        sans = [f"sub{i}.example.com" for i in range(10)]
        cert = _make_cert(subject_cn="example.com", sans=sans)
        result, rec = _check_subject(cert, "example.com")
        assert result.status == CheckStatus.PASS
        assert "+" in result.detail  # truncation indicator

    def test_check_name_correct(self):
        cert = _make_cert()
        result, _ = _check_subject(cert, "example.com")
        assert result.check_name == "ssl_certificate_subject"


# ════════════════════════════════════════════════════════════════════════════
# run_ssl_checks (bundle)
# ════════════════════════════════════════════════════════════════════════════

class TestRunSslChecks:

    @pytest.mark.asyncio
    async def test_returns_four_results_on_success(self):
        cert = _make_cert()
        with patch("app.services.analyzer.ssl_checker.asyncio.to_thread",
                   new=AsyncMock(return_value=cert)):
            bundle = await run_ssl_checks("https://example.com")

        assert len(bundle.results) == 4
        names = {r.check_name for r in bundle.results}
        assert "ssl_certificate_valid"   in names
        assert "ssl_certificate_expiry"  in names
        assert "ssl_certificate_issuer"  in names
        assert "ssl_certificate_subject" in names

    @pytest.mark.asyncio
    async def test_no_recommendations_for_healthy_cert(self):
        cert = _make_cert(days_until_expiry=90)
        with patch("app.services.analyzer.ssl_checker.asyncio.to_thread",
                   new=AsyncMock(return_value=cert)):
            bundle = await run_ssl_checks("https://example.com")

        assert bundle.recommendations == []

    @pytest.mark.asyncio
    async def test_recommendation_for_expiring_cert(self):
        cert = _make_cert(days_until_expiry=10)
        with patch("app.services.analyzer.ssl_checker.asyncio.to_thread",
                   new=AsyncMock(return_value=cert)):
            bundle = await run_ssl_checks("https://example.com")

        rec_names = {r.check_name for r in bundle.recommendations}
        assert "ssl_certificate_expiry" in rec_names

    @pytest.mark.asyncio
    async def test_cert_verification_error_returns_four_results(self):
        exc = ssl.SSLCertVerificationError(1, "CERTIFICATE_VERIFY_FAILED")
        with patch("app.services.analyzer.ssl_checker.asyncio.to_thread",
                   new=AsyncMock(side_effect=exc)):
            bundle = await run_ssl_checks("https://example.com")

        assert len(bundle.results) == 4
        validity = next(r for r in bundle.results
                        if r.check_name == "ssl_certificate_valid")
        assert validity.status == CheckStatus.FAIL
        assert validity.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_cert_verification_error_has_recommendation(self):
        exc = ssl.SSLCertVerificationError(1, "CERTIFICATE_VERIFY_FAILED")
        with patch("app.services.analyzer.ssl_checker.asyncio.to_thread",
                   new=AsyncMock(side_effect=exc)):
            bundle = await run_ssl_checks("https://example.com")

        assert len(bundle.recommendations) == 1
        assert bundle.recommendations[0].priority == Priority.CRITICAL

    @pytest.mark.asyncio
    async def test_ssl_error_returns_fail_results(self):
        exc = ssl.SSLError("WRONG_VERSION_NUMBER")
        with patch("app.services.analyzer.ssl_checker.asyncio.to_thread",
                   new=AsyncMock(side_effect=exc)):
            bundle = await run_ssl_checks("https://example.com")

        assert len(bundle.results) == 4
        validity = next(r for r in bundle.results
                        if r.check_name == "ssl_certificate_valid")
        assert validity.status == CheckStatus.FAIL

    @pytest.mark.asyncio
    async def test_connection_refused_returns_info_not_fail(self):
        with patch("app.services.analyzer.ssl_checker.asyncio.to_thread",
                   new=AsyncMock(side_effect=ConnectionRefusedError("refused"))):
            bundle = await run_ssl_checks("https://example.com")

        assert len(bundle.results) == 4
        validity = next(r for r in bundle.results
                        if r.check_name == "ssl_certificate_valid")
        # Connection refused is not a cert validation failure — INFO
        assert validity.status == CheckStatus.INFO
        assert bundle.recommendations == []

    @pytest.mark.asyncio
    async def test_timeout_returns_info(self):
        with patch("app.services.analyzer.ssl_checker.asyncio.to_thread",
                   new=AsyncMock(side_effect=TimeoutError("timed out"))):
            bundle = await run_ssl_checks("https://example.com")

        assert len(bundle.results) == 4
        validity = next(r for r in bundle.results
                        if r.check_name == "ssl_certificate_valid")
        assert validity.status == CheckStatus.INFO

    @pytest.mark.asyncio
    async def test_bad_url_returns_four_info_results(self):
        """URL with no hostname should not crash — returns 4 info results."""
        bundle = await run_ssl_checks("https:///no-hostname")
        assert len(bundle.results) == 4

    @pytest.mark.asyncio
    async def test_http_url_still_checks_port_443(self):
        """Even if url is http://, ssl_checker targets port 443."""
        cert = _make_cert()
        captured = {}

        async def fake_to_thread(fn, *args, **kwargs):
            captured["args"] = args
            return cert

        with patch("app.services.analyzer.ssl_checker.asyncio.to_thread",
                   side_effect=fake_to_thread):
            await run_ssl_checks("http://example.com")

        # Second positional arg to _fetch_cert_info is the port
        assert captured["args"][1] == 443

    @pytest.mark.asyncio
    async def test_self_signed_cert_has_recommendation(self):
        cert = _make_cert(issuer_cn="example.com", issuer_org="Self",
                          subject_cn="example.com")
        with patch("app.services.analyzer.ssl_checker.asyncio.to_thread",
                   new=AsyncMock(return_value=cert)):
            bundle = await run_ssl_checks("https://example.com")

        rec_names = {r.check_name for r in bundle.recommendations}
        assert "ssl_certificate_issuer" in rec_names

    @pytest.mark.asyncio
    async def test_all_results_have_valid_status_values(self):
        cert = _make_cert()
        with patch("app.services.analyzer.ssl_checker.asyncio.to_thread",
                   new=AsyncMock(return_value=cert)):
            bundle = await run_ssl_checks("https://example.com")

        valid = {CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL, CheckStatus.INFO}
        for r in bundle.results:
            assert r.status in valid


# ════════════════════════════════════════════════════════════════════════════
# Integration tests (live network — requires internet access)
# ════════════════════════════════════════════════════════════════════════════

class TestSslCheckerIntegration:

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_example_com_returns_four_results(self):
        bundle = await run_ssl_checks("https://example.com")
        assert len(bundle.results) == 4

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_example_com_certificate_is_valid(self):
        bundle = await run_ssl_checks("https://example.com")
        validity = next(r for r in bundle.results
                        if r.check_name == "ssl_certificate_valid")
        assert validity.status == CheckStatus.PASS

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_example_com_expiry_pass_or_warn(self):
        """example.com cert should not be expired."""
        bundle = await run_ssl_checks("https://example.com")
        expiry = next(r for r in bundle.results
                      if r.check_name == "ssl_certificate_expiry")
        assert expiry.status in (CheckStatus.PASS, CheckStatus.WARN)

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_example_com_check_names_correct(self):
        bundle = await run_ssl_checks("https://example.com")
        names = {r.check_name for r in bundle.results}
        assert names == {
            "ssl_certificate_valid",
            "ssl_certificate_expiry",
            "ssl_certificate_issuer",
            "ssl_certificate_subject",
        }

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_example_com_issuer_is_trusted(self):
        bundle = await run_ssl_checks("https://example.com")
        issuer = next(r for r in bundle.results
                      if r.check_name == "ssl_certificate_issuer")
        assert issuer.status == CheckStatus.PASS
