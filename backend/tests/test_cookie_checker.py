"""
Tests for the Cookie Security Analyzer (Phase 2D).

All unit tests mock httpx so no real network calls are made.
Integration tests (marked @pytest.mark.network) make live requests
and require internet access.

Run offline tests only:
  pytest tests/test_cookie_checker.py -v -m "not network"

Run all including live network:
  pytest tests/test_cookie_checker.py -v
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.analyzer.base import CheckStatus, Priority, Severity
from app.services.analyzer.cookie_checker import (
    ParsedCookie,
    _build_overview,
    _evaluate_httponly_flag,
    _evaluate_samesite_attr,
    _evaluate_secure_flag,
    collect_cookies,
    parse_set_cookie,
    run_cookie_checks,
)


# ── Mock response helpers ─────────────────────────────────────────────────────

def _make_response(
    set_cookie_headers: list[str],
    url: str = "https://example.com",
    status_code: int = 200,
) -> MagicMock:
    """Build a minimal mock httpx.Response with the given Set-Cookie values."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.url = httpx.URL(url)
    resp.aclose = AsyncMock()

    # httpx.Headers.get_list returns a list of all values for a header name
    headers = MagicMock(spec=httpx.Headers)
    headers.get_list = MagicMock(
        side_effect=lambda name: set_cookie_headers if name == "set-cookie" else []
    )
    resp.headers = headers
    return resp


def _patched_client(response: MagicMock):
    client_ctx = AsyncMock()
    client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
    client_ctx.__aexit__  = AsyncMock(return_value=False)
    client_ctx.get = AsyncMock(return_value=response)
    return client_ctx


# ════════════════════════════════════════════════════════════════════════════
# parse_set_cookie
# ════════════════════════════════════════════════════════════════════════════

class TestParseSetCookie:

    def test_fully_secure_cookie(self):
        c = parse_set_cookie("session=abc; Secure; HttpOnly; SameSite=Strict; Path=/")
        assert c.name == "session"
        assert c.has_secure   is True
        assert c.has_httponly is True
        assert c.samesite == "Strict"

    def test_lax_samesite(self):
        c = parse_set_cookie("pref=1; SameSite=Lax; Path=/")
        assert c.samesite == "Lax"
        assert c.has_secure is False

    def test_samesite_none(self):
        c = parse_set_cookie("tracker=x; SameSite=None; Secure")
        assert c.samesite == "None"
        assert c.has_secure is True

    def test_samesite_none_without_secure(self):
        c = parse_set_cookie("tracker=x; SameSite=None")
        assert c.samesite == "None"
        assert c.has_secure is False

    def test_missing_all_attributes(self):
        c = parse_set_cookie("id=xyz; Path=/")
        assert c.has_secure   is False
        assert c.has_httponly is False
        assert c.samesite     is None

    def test_case_insensitive_flags(self):
        c = parse_set_cookie("x=1; secure; httponly; samesite=Strict")
        assert c.has_secure   is True
        assert c.has_httponly is True
        assert c.samesite == "Strict"

    def test_empty_cookie_name(self):
        # Edge case: malformed cookie
        c = parse_set_cookie("; Secure")
        assert c.has_secure is True

    def test_cookie_name_extracted_correctly(self):
        c = parse_set_cookie("my_token=xyz123; Secure; HttpOnly")
        assert c.name == "my_token"

    def test_analytics_hint_detected(self):
        c = parse_set_cookie("_ga=GA1.2; Path=/; Expires=Fri, 01 Jan 2027 00:00:00 GMT")
        assert c.is_analytics_hint is True

    def test_non_analytics_cookie(self):
        c = parse_set_cookie("session_token=abc; Secure; HttpOnly")
        assert c.is_analytics_hint is False


# ════════════════════════════════════════════════════════════════════════════
# collect_cookies
# ════════════════════════════════════════════════════════════════════════════

class TestCollectCookies:

    def test_extracts_multiple_set_cookie_headers(self):
        resp = _make_response([
            "session=abc; Secure; HttpOnly; SameSite=Strict",
            "_ga=xyz; Path=/",
        ])
        cookies = collect_cookies(resp)
        assert len(cookies) == 2
        assert cookies[0].name == "session"
        assert cookies[1].name == "_ga"

    def test_empty_when_no_cookies(self):
        resp = _make_response([])
        cookies = collect_cookies(resp)
        assert cookies == []

    def test_skips_blank_values(self):
        resp = _make_response(["", "  ", "x=1; Secure"])
        cookies = collect_cookies(resp)
        assert len(cookies) == 1
        assert cookies[0].name == "x"


# ════════════════════════════════════════════════════════════════════════════
# _evaluate_secure_flag
# ════════════════════════════════════════════════════════════════════════════

class TestEvaluateSecureFlag:

    def test_pass_all_have_secure_over_https(self):
        cookies = [
            ParsedCookie("a", has_secure=True),
            ParsedCookie("b", has_secure=True),
        ]
        result, rec = _evaluate_secure_flag(cookies, is_https=True)
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_fail_missing_secure_over_https(self):
        cookies = [
            ParsedCookie("session", has_secure=True),
            ParsedCookie("pref", has_secure=False),
        ]
        result, rec = _evaluate_secure_flag(cookies, is_https=True)
        assert result.status == CheckStatus.FAIL
        assert result.severity == Severity.HIGH
        assert rec is not None
        assert rec.priority == Priority.HIGH
        assert "'pref'" in result.detail

    def test_info_over_http_regardless(self):
        """Secure flag is meaningless on HTTP — skip the check."""
        cookies = [ParsedCookie("session", has_secure=False)]
        result, rec = _evaluate_secure_flag(cookies, is_https=False)
        assert result.status == CheckStatus.INFO
        assert rec is None

    def test_analytics_note_added_when_applicable(self):
        cookies = [ParsedCookie("_ga", has_secure=False)]
        result, rec = _evaluate_secure_flag(cookies, is_https=True)
        assert result.status == CheckStatus.FAIL
        assert "analytics" in result.detail.lower()


# ════════════════════════════════════════════════════════════════════════════
# _evaluate_httponly_flag
# ════════════════════════════════════════════════════════════════════════════

class TestEvaluateHttpOnlyFlag:

    def test_pass_all_have_httponly(self):
        cookies = [
            ParsedCookie("a", has_httponly=True),
            ParsedCookie("b", has_httponly=True),
        ]
        result, rec = _evaluate_httponly_flag(cookies)
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_warn_missing_httponly_on_sensitive_cookie(self):
        cookies = [ParsedCookie("session_token", has_httponly=False)]
        result, rec = _evaluate_httponly_flag(cookies)
        assert result.status == CheckStatus.WARN
        assert result.severity == Severity.MEDIUM
        assert rec.priority == Priority.MEDIUM

    def test_warn_lower_severity_for_analytics_only(self):
        """All missing-HttpOnly cookies are analytics → LOW severity."""
        cookies = [ParsedCookie("_ga", has_httponly=False)]
        result, rec = _evaluate_httponly_flag(cookies)
        assert result.status == CheckStatus.WARN
        assert result.severity == Severity.LOW
        assert rec.priority == Priority.LOW

    def test_detail_contains_cookie_name(self):
        cookies = [ParsedCookie("my_session", has_httponly=False)]
        result, _ = _evaluate_httponly_flag(cookies)
        assert "'my_session'" in result.detail

    def test_check_name_correct(self):
        cookies = [ParsedCookie("x", has_httponly=False)]
        result, _ = _evaluate_httponly_flag(cookies)
        assert result.check_name == "cookie_httponly_flag"


# ════════════════════════════════════════════════════════════════════════════
# _evaluate_samesite_attr
# ════════════════════════════════════════════════════════════════════════════

class TestEvaluateSamesiteAttr:

    def test_pass_all_strict_or_lax(self):
        cookies = [
            ParsedCookie("a", samesite="Strict"),
            ParsedCookie("b", samesite="Lax"),
        ]
        result, rec = _evaluate_samesite_attr(cookies)
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_fail_samesite_none_without_secure(self):
        cookies = [ParsedCookie("embed", samesite="None", has_secure=False)]
        result, rec = _evaluate_samesite_attr(cookies)
        assert result.status == CheckStatus.FAIL
        assert result.severity == Severity.HIGH
        assert rec.priority == Priority.HIGH

    def test_pass_samesite_none_with_secure(self):
        """SameSite=None + Secure is valid (cross-site embeds)."""
        cookies = [ParsedCookie("embed", samesite="None", has_secure=True)]
        result, rec = _evaluate_samesite_attr(cookies)
        assert result.status == CheckStatus.PASS
        assert rec is None

    def test_warn_missing_samesite(self):
        cookies = [ParsedCookie("pref", samesite=None)]
        result, rec = _evaluate_samesite_attr(cookies)
        assert result.status == CheckStatus.WARN
        assert result.severity == Severity.LOW
        assert rec is not None

    def test_fail_takes_precedence_over_missing(self):
        """If any cookie has SameSite=None without Secure, result is FAIL."""
        cookies = [
            ParsedCookie("a", samesite="Lax"),
            ParsedCookie("b", samesite="None", has_secure=False),
            ParsedCookie("c", samesite=None),
        ]
        result, _ = _evaluate_samesite_attr(cookies)
        assert result.status == CheckStatus.FAIL

    def test_check_name_correct(self):
        cookies = [ParsedCookie("x", samesite=None)]
        result, _ = _evaluate_samesite_attr(cookies)
        assert result.check_name == "cookie_samesite_attr"


# ════════════════════════════════════════════════════════════════════════════
# _build_overview
# ════════════════════════════════════════════════════════════════════════════

class TestBuildOverview:

    def test_info_when_no_cookies(self):
        result = _build_overview([], issue_count=0)
        assert result.status == CheckStatus.INFO
        assert result.check_name == "cookie_overview"
        assert "No Cookies" in result.title

    def test_pass_when_no_issues(self):
        cookies = [ParsedCookie("session")]
        result = _build_overview(cookies, issue_count=0)
        assert result.status == CheckStatus.PASS

    def test_warn_when_issues_exist(self):
        cookies = [ParsedCookie("session")]
        result = _build_overview(cookies, issue_count=2)
        assert result.status == CheckStatus.WARN
        assert "2" in result.title


# ════════════════════════════════════════════════════════════════════════════
# run_cookie_checks (integration with mock HTTP)
# ════════════════════════════════════════════════════════════════════════════

class TestRunCookieChecks:

    @pytest.mark.asyncio
    async def test_no_cookies_returns_one_info_result(self):
        resp = _make_response([])
        with patch("app.services.analyzer.cookie_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_cookie_checks("https://example.com")

        assert len(bundle.results) == 1
        assert bundle.results[0].status == CheckStatus.INFO
        assert bundle.results[0].check_name == "cookie_overview"
        assert bundle.recommendations == []

    @pytest.mark.asyncio
    async def test_secure_cookies_return_four_results(self):
        resp = _make_response([
            "session=abc; Secure; HttpOnly; SameSite=Strict; Path=/",
        ])
        with patch("app.services.analyzer.cookie_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_cookie_checks("https://example.com")

        assert len(bundle.results) == 4  # overview + 3 attribute checks
        names = {r.check_name for r in bundle.results}
        assert "cookie_overview"     in names
        assert "cookie_secure_flag"  in names
        assert "cookie_httponly_flag" in names
        assert "cookie_samesite_attr" in names

    @pytest.mark.asyncio
    async def test_all_secure_no_recommendations(self):
        resp = _make_response([
            "session=abc; Secure; HttpOnly; SameSite=Strict",
            "pref=1; Secure; HttpOnly; SameSite=Lax",
        ])
        with patch("app.services.analyzer.cookie_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_cookie_checks("https://example.com")

        assert bundle.recommendations == []
        overview = next(r for r in bundle.results if r.check_name == "cookie_overview")
        assert overview.status == CheckStatus.PASS

    @pytest.mark.asyncio
    async def test_missing_secure_creates_recommendation(self):
        resp = _make_response([
            "session=abc; HttpOnly; SameSite=Strict",  # missing Secure
        ])
        with patch("app.services.analyzer.cookie_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_cookie_checks("https://example.com")

        rec_names = {r.check_name for r in bundle.recommendations}
        assert "cookie_secure_flag" in rec_names

    @pytest.mark.asyncio
    async def test_missing_httponly_creates_recommendation(self):
        resp = _make_response([
            "session=abc; Secure; SameSite=Strict",  # missing HttpOnly
        ])
        with patch("app.services.analyzer.cookie_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_cookie_checks("https://example.com")

        rec_names = {r.check_name for r in bundle.recommendations}
        assert "cookie_httponly_flag" in rec_names

    @pytest.mark.asyncio
    async def test_samesite_none_without_secure_is_fail(self):
        resp = _make_response([
            "embed=x; SameSite=None",  # SameSite=None without Secure — invalid
        ])
        with patch("app.services.analyzer.cookie_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_cookie_checks("https://example.com")

        samesite = next(r for r in bundle.results if r.check_name == "cookie_samesite_attr")
        assert samesite.status == CheckStatus.FAIL

    @pytest.mark.asyncio
    async def test_connect_error_returns_one_info_result(self):
        with patch("app.services.analyzer.cookie_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_build.return_value = client_ctx

            bundle = await run_cookie_checks("https://example.com")

        assert len(bundle.results) == 1
        assert bundle.results[0].status == CheckStatus.INFO
        assert bundle.recommendations == []

    @pytest.mark.asyncio
    async def test_timeout_returns_one_info_result(self):
        with patch("app.services.analyzer.cookie_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_build.return_value = client_ctx

            bundle = await run_cookie_checks("https://example.com")

        assert len(bundle.results) == 1
        assert bundle.results[0].status == CheckStatus.INFO

    @pytest.mark.asyncio
    async def test_secure_flag_skipped_on_http_url(self):
        """When the final URL is http://, Secure flag check returns INFO."""
        resp = _make_response(
            ["session=abc; HttpOnly; SameSite=Strict"],
            url="http://example.com",
        )
        with patch("app.services.analyzer.cookie_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_cookie_checks("http://example.com")

        secure = next(r for r in bundle.results if r.check_name == "cookie_secure_flag")
        assert secure.status == CheckStatus.INFO

    @pytest.mark.asyncio
    async def test_multiple_cookies_all_flagged(self):
        """Three insecure cookies → three recommendations."""
        resp = _make_response([
            "a=1",  # missing everything
            "b=2",  # missing everything
        ])
        with patch("app.services.analyzer.cookie_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_cookie_checks("https://example.com")

        assert len(bundle.recommendations) == 3  # secure + httponly + samesite

    @pytest.mark.asyncio
    async def test_check_names_in_results(self):
        resp = _make_response(["session=abc; Secure; HttpOnly; SameSite=Lax"])
        with patch("app.services.analyzer.cookie_checker._build_client",
                   return_value=_patched_client(resp)):
            bundle = await run_cookie_checks("https://example.com")

        names = {r.check_name for r in bundle.results}
        assert names == {
            "cookie_overview",
            "cookie_secure_flag",
            "cookie_httponly_flag",
            "cookie_samesite_attr",
        }


# ════════════════════════════════════════════════════════════════════════════
# Integration tests (live network — requires internet access)
# ════════════════════════════════════════════════════════════════════════════

class TestCookieCheckerIntegration:

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_example_com_returns_results(self):
        """example.com may or may not set cookies — either is valid."""
        bundle = await run_cookie_checks("https://example.com")
        assert len(bundle.results) >= 1

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_check_names_always_present(self):
        bundle = await run_cookie_checks("https://example.com")
        names = {r.check_name for r in bundle.results}
        # cookie_overview is always present
        assert "cookie_overview" in names

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_all_results_have_valid_status(self):
        bundle = await run_cookie_checks("https://example.com")
        valid = {CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL, CheckStatus.INFO}
        for r in bundle.results:
            assert r.status in valid

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_recommendations_have_reference_urls(self):
        bundle = await run_cookie_checks("https://example.com")
        for rec in bundle.recommendations:
            assert rec.reference_url is not None
            assert rec.reference_url.startswith("https://")
