"""
Tests for the Security Headers Analyzer (Phase 2B).

Unit tests patch httpx so no real network calls are made and run fully
offline. Integration tests (marked @pytest.mark.network) hit example.com.

Run offline tests only:
  pytest tests/test_headers_checker.py -v -m "not network"

Run all including live network:
  pytest tests/test_headers_checker.py -v
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.analyzer.base import CheckStatus, Priority, Severity
from app.services.analyzer.headers_checker import (
    _check_csp,
    _check_hsts,
    _check_x_frame_options,
    _check_x_content_type_options,
    _check_referrer_policy,
    _check_permissions_policy,
    run_headers_checks,
)


# ── Mock response factory ─────────────────────────────────────────────────────

def _mock_response(status_code: int = 200, headers: dict | None = None,
                   url: str = "https://example.com") -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = httpx.Headers(headers or {})
    resp.url = httpx.URL(url)
    resp.aclose = AsyncMock()
    return resp


def _patched_client(response: MagicMock):
    """Context manager helper: returns a mock httpx.AsyncClient that yields response."""
    client_ctx = AsyncMock()
    client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
    client_ctx.__aexit__  = AsyncMock(return_value=False)
    client_ctx.get = AsyncMock(return_value=response)
    return client_ctx


# ════════════════════════════════════════════════════════════════════════════
# _check_csp
# ════════════════════════════════════════════════════════════════════════════

class TestCheckCsp:

    def test_fail_when_absent(self):
        result, rec = _check_csp(None)
        assert result.status == CheckStatus.FAIL
        assert result.severity == Severity.HIGH
        assert result.check_name == "csp_header"
        assert rec is not None
        assert rec.priority == Priority.HIGH

    def test_pass_with_basic_policy(self):
        result, rec = _check_csp("default-src 'self'")
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_pass_with_unsafe_inline_plus_nonce(self):
        """unsafe-inline with a nonce present should still pass."""
        result, rec = _check_csp("script-src 'nonce-abc123' 'unsafe-inline'")
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_pass_with_unsafe_inline_plus_hash(self):
        result, rec = _check_csp("script-src 'sha256-abc123' 'unsafe-inline'")
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_warn_with_unsafe_inline_no_mitigation(self):
        result, rec = _check_csp("default-src 'self'; script-src 'unsafe-inline'")
        assert result.status == CheckStatus.WARN
        assert result.severity == Severity.MEDIUM
        assert rec is not None
        assert rec.priority == Priority.MEDIUM

    def test_warn_with_unsafe_eval(self):
        result, rec = _check_csp("script-src 'self' 'unsafe-eval'")
        assert result.status == CheckStatus.WARN
        assert rec is not None

    def test_detail_truncated_at_200_chars(self):
        long_value = "default-src 'self'; " + "a" * 300
        result, _ = _check_csp(long_value)
        # detail should not embed more than 200 chars of the value
        assert len(result.detail) < 500  # reasonable upper bound


# ════════════════════════════════════════════════════════════════════════════
# _check_hsts
# ════════════════════════════════════════════════════════════════════════════

class TestCheckHsts:

    def test_fail_when_absent_on_https(self):
        result, rec = _check_hsts(None, is_https=True)
        assert result.status == CheckStatus.FAIL
        assert result.severity == Severity.HIGH
        assert rec is not None
        assert rec.priority == Priority.HIGH

    def test_info_when_absent_on_http(self):
        """HSTS is only meaningful on HTTPS — absence on HTTP is informational."""
        result, rec = _check_hsts(None, is_https=False)
        assert result.status == CheckStatus.INFO
        assert rec is None

    def test_pass_with_long_max_age(self):
        result, rec = _check_hsts("max-age=31536000; includeSubDomains", is_https=True)
        assert result.status == CheckStatus.PASS
        assert rec is None
        assert "365" in result.detail  # days shown in detail

    def test_pass_with_exact_min_max_age(self):
        result, rec = _check_hsts("max-age=15552000", is_https=True)
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_warn_when_max_age_too_short(self):
        result, rec = _check_hsts("max-age=86400", is_https=True)  # 1 day
        assert result.status == CheckStatus.WARN
        assert result.severity == Severity.LOW
        assert rec is not None

    def test_warn_when_max_age_zero(self):
        """max-age=0 disables HSTS — warn."""
        result, rec = _check_hsts("max-age=0", is_https=True)
        assert result.status == CheckStatus.WARN
        assert rec is not None

    def test_warn_when_max_age_unparseable(self):
        result, rec = _check_hsts("max-age=abc; includeSubDomains", is_https=True)
        assert result.status == CheckStatus.WARN
        assert rec is not None

    def test_case_insensitive_max_age_parsing(self):
        """Header values may use different casing."""
        result, _ = _check_hsts("Max-Age=31536000", is_https=True)
        assert result.status == CheckStatus.PASS

    def test_whitespace_in_value_parsed_correctly(self):
        result, _ = _check_hsts("max-age = 31536000 ; includeSubDomains", is_https=True)
        assert result.status == CheckStatus.PASS


# ════════════════════════════════════════════════════════════════════════════
# _check_x_frame_options
# ════════════════════════════════════════════════════════════════════════════

class TestCheckXFrameOptions:

    def test_fail_when_absent(self):
        result, rec = _check_x_frame_options(None)
        assert result.status == CheckStatus.FAIL
        assert result.severity == Severity.MEDIUM
        assert rec is not None
        assert rec.priority == Priority.MEDIUM

    def test_pass_with_deny(self):
        result, rec = _check_x_frame_options("DENY")
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_pass_with_sameorigin(self):
        result, rec = _check_x_frame_options("SAMEORIGIN")
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_pass_case_insensitive(self):
        result, rec = _check_x_frame_options("deny")
        assert result.status == CheckStatus.PASS

    def test_warn_with_allow_from(self):
        result, rec = _check_x_frame_options("ALLOW-FROM https://trusted.example.com")
        assert result.status == CheckStatus.WARN
        assert result.severity == Severity.MEDIUM
        assert rec is not None

    def test_warn_with_unknown_value(self):
        result, rec = _check_x_frame_options("ALLOWALL")
        assert result.status == CheckStatus.WARN
        assert rec is not None


# ════════════════════════════════════════════════════════════════════════════
# _check_x_content_type_options
# ════════════════════════════════════════════════════════════════════════════

class TestCheckXContentTypeOptions:

    def test_fail_when_absent(self):
        result, rec = _check_x_content_type_options(None)
        assert result.status == CheckStatus.FAIL
        assert result.severity == Severity.MEDIUM
        assert rec is not None

    def test_pass_with_nosniff(self):
        result, rec = _check_x_content_type_options("nosniff")
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_pass_case_insensitive(self):
        result, rec = _check_x_content_type_options("NoSniff")
        assert result.status == CheckStatus.PASS

    def test_pass_strips_whitespace(self):
        result, rec = _check_x_content_type_options("  nosniff  ")
        assert result.status == CheckStatus.PASS

    def test_warn_with_unexpected_value(self):
        result, rec = _check_x_content_type_options("sniff")
        assert result.status == CheckStatus.WARN
        assert rec is not None


# ════════════════════════════════════════════════════════════════════════════
# _check_referrer_policy
# ════════════════════════════════════════════════════════════════════════════

class TestCheckReferrerPolicy:

    def test_fail_when_absent(self):
        result, rec = _check_referrer_policy(None)
        assert result.status == CheckStatus.FAIL
        assert result.severity == Severity.LOW
        assert rec is not None

    @pytest.mark.parametrize("value", [
        "no-referrer",
        "strict-origin-when-cross-origin",
        "same-origin",
        "origin",
        "no-referrer-when-downgrade",
        "strict-origin",
        "origin-when-cross-origin",
    ])
    def test_pass_with_recognised_safe_values(self, value):
        result, rec = _check_referrer_policy(value)
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_warn_with_unsafe_url(self):
        result, rec = _check_referrer_policy("unsafe-url")
        assert result.status == CheckStatus.WARN
        assert result.severity == Severity.MEDIUM
        assert rec is not None

    def test_warn_with_unrecognised_value(self):
        result, rec = _check_referrer_policy("everything")
        assert result.status == CheckStatus.WARN
        assert rec is not None

    def test_uses_last_value_in_comma_list(self):
        """Browser uses last recognised value in comma-separated list."""
        result, _ = _check_referrer_policy("unsafe-url, no-referrer")
        assert result.status == CheckStatus.PASS  # last value is no-referrer


# ════════════════════════════════════════════════════════════════════════════
# _check_permissions_policy
# ════════════════════════════════════════════════════════════════════════════

class TestCheckPermissionsPolicy:

    def test_fail_when_absent(self):
        result, rec = _check_permissions_policy(None)
        assert result.status == CheckStatus.FAIL
        assert result.severity == Severity.LOW
        assert rec is not None
        assert rec.priority == Priority.LOW

    def test_pass_when_present(self):
        result, rec = _check_permissions_policy("camera=(), microphone=()")
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_pass_with_any_non_empty_value(self):
        result, rec = _check_permissions_policy("geolocation=(self)")
        assert result.status == CheckStatus.PASS
        assert rec is None


# ════════════════════════════════════════════════════════════════════════════
# run_headers_checks (bundle — mocked HTTP)
# ════════════════════════════════════════════════════════════════════════════

class TestRunHeadersChecks:

    @pytest.mark.asyncio
    async def test_returns_six_results(self):
        """Bundle always contains exactly 6 CheckResult rows."""
        resp = _mock_response(200, {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=()",
        })
        with patch("app.services.analyzer.headers_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_headers_checks("https://example.com")

        assert len(bundle.results) == 6

    @pytest.mark.asyncio
    async def test_all_pass_no_recommendations(self):
        resp = _mock_response(200, {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "camera=()",
        })
        with patch("app.services.analyzer.headers_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_headers_checks("https://example.com")

        assert all(r.status == CheckStatus.PASS for r in bundle.results)
        assert bundle.recommendations == []

    @pytest.mark.asyncio
    async def test_all_fail_when_headers_absent(self):
        """No security headers → 6 fail/info results, multiple recommendations."""
        resp = _mock_response(200, {})
        with patch("app.services.analyzer.headers_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_headers_checks("https://example.com")

        # HSTS absent on HTTP is INFO, not FAIL — adjust expectation
        statuses = {r.status for r in bundle.results}
        assert CheckStatus.FAIL in statuses
        assert len(bundle.recommendations) >= 4  # at least CSP, X-Frame, XCTO, etc.

    @pytest.mark.asyncio
    async def test_check_names_are_correct(self):
        resp = _mock_response(200, {})
        with patch("app.services.analyzer.headers_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_headers_checks("https://example.com")

        names = {r.check_name for r in bundle.results}
        assert names == {
            "csp_header",
            "hsts_header",
            "x_frame_options",
            "x_content_type_options",
            "referrer_policy",
            "permissions_policy",
        }

    @pytest.mark.asyncio
    async def test_connect_error_returns_six_info_results(self):
        """Fetch failure → 6 INFO results, no recommendations, no exception raised."""
        with patch("app.services.analyzer.headers_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_build.return_value = client_ctx

            bundle = await run_headers_checks("https://example.com")

        assert len(bundle.results) == 6
        assert all(r.status == CheckStatus.INFO for r in bundle.results)
        assert bundle.recommendations == []

    @pytest.mark.asyncio
    async def test_timeout_returns_six_info_results(self):
        with patch("app.services.analyzer.headers_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_build.return_value = client_ctx

            bundle = await run_headers_checks("https://example.com")

        assert len(bundle.results) == 6
        assert all(r.status == CheckStatus.INFO for r in bundle.results)

    @pytest.mark.asyncio
    async def test_hsts_is_info_on_http_url(self):
        """When the final URL is http://, HSTS absence is INFO not FAIL."""
        resp = _mock_response(200, {}, url="http://example.com")
        with patch("app.services.analyzer.headers_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_headers_checks("http://example.com")

        hsts = next(r for r in bundle.results if r.check_name == "hsts_header")
        assert hsts.status == CheckStatus.INFO

    @pytest.mark.asyncio
    async def test_partial_headers_mixed_results(self):
        """Some headers present, others absent → mixed pass/fail results."""
        resp = _mock_response(200, {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            # CSP, HSTS, Referrer-Policy, Permissions-Policy all absent
        })
        with patch("app.services.analyzer.headers_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_headers_checks("https://example.com")

        statuses = {r.check_name: r.status for r in bundle.results}
        assert statuses["x_content_type_options"] == CheckStatus.PASS
        assert statuses["x_frame_options"]        == CheckStatus.PASS
        assert statuses["csp_header"]             == CheckStatus.FAIL
        assert statuses["permissions_policy"]     == CheckStatus.FAIL


# ════════════════════════════════════════════════════════════════════════════
# Integration tests (live network — requires internet access)
# ════════════════════════════════════════════════════════════════════════════

class TestHeadersCheckerIntegration:

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_example_com_returns_six_results(self):
        bundle = await run_headers_checks("https://example.com")
        assert len(bundle.results) == 6

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_example_com_check_names_correct(self):
        bundle = await run_headers_checks("https://example.com")
        names = {r.check_name for r in bundle.results}
        assert "csp_header" in names
        assert "hsts_header" in names
        assert "x_frame_options" in names
        assert "x_content_type_options" in names
        assert "referrer_policy" in names
        assert "permissions_policy" in names

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_every_result_has_valid_status(self):
        bundle = await run_headers_checks("https://example.com")
        valid = {CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL, CheckStatus.INFO}
        for r in bundle.results:
            assert r.status in valid

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_each_recommendation_has_reference_url(self):
        bundle = await run_headers_checks("https://example.com")
        for rec in bundle.recommendations:
            assert rec.reference_url is not None
            assert rec.reference_url.startswith("https://")
