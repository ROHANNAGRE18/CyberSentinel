"""
Tests for the HTTPS availability and HTTP→HTTPS redirect checks.

Unit tests use unittest.mock to patch httpx so no real network calls
are made. They run fully offline and are always included in the default
test suite.

Integration tests (marked @pytest.mark.network) make live HTTP requests
and require internet access. Skip them in CI with: -m "not network"

Run all offline tests:
  pytest tests/test_https_checker.py -v -m "not network"

Run everything including live network tests:
  pytest tests/test_https_checker.py -v
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.analyzer.base import CheckStatus, Severity, Priority
from app.services.analyzer.https_checker import (
    _force_scheme,
    check_https_available,
    check_http_redirects_to_https,
    run_https_checks,
)


# ── Helper: build a minimal mock httpx.Response ───────────────────────────────

def _mock_response(status_code: int, headers: dict | None = None) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = httpx.Headers(headers or {})
    return resp


# ── _force_scheme ─────────────────────────────────────────────────────────────

class TestForceScheme:

    def test_https_to_http(self):
        assert _force_scheme("https://example.com/path", "http") == "http://example.com/path"

    def test_http_to_https(self):
        assert _force_scheme("http://example.com", "https") == "https://example.com"

    def test_preserves_path_and_query(self):
        url = "http://example.com/path?q=1#frag"
        result = _force_scheme(url, "https")
        assert result.startswith("https://")
        assert "/path" in result

    def test_already_correct_scheme(self):
        assert _force_scheme("https://example.com", "https") == "https://example.com"


# ── check_https_available ─────────────────────────────────────────────────────

class TestCheckHttpsAvailable:

    @pytest.mark.asyncio
    async def test_pass_on_200(self):
        """HTTPS returns 200 → pass result."""
        mock_resp = _mock_response(200)

        with patch(
            "app.services.analyzer.https_checker._build_client"
        ) as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.head = AsyncMock(return_value=mock_resp)
            mock_build.return_value = client_ctx

            result, recs = await check_https_available("https://example.com")

        assert result.status   == CheckStatus.PASS
        assert result.check_name == "https_available"
        assert "200" in result.detail
        assert recs == []

    @pytest.mark.asyncio
    async def test_pass_on_301(self):
        """HTTPS returns 301 (redirected to canonical URL) → still a pass."""
        mock_resp = _mock_response(301, {"location": "https://www.example.com/"})

        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.head = AsyncMock(return_value=mock_resp)
            mock_build.return_value = client_ctx

            result, recs = await check_https_available("https://example.com")

        assert result.status == CheckStatus.PASS
        assert recs == []

    @pytest.mark.asyncio
    async def test_head_405_falls_back_to_get(self):
        """HEAD returns 405 → checker retries with GET and returns pass."""
        head_resp = _mock_response(405)
        get_resp  = _mock_response(200)

        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.head = AsyncMock(return_value=head_resp)
            client_ctx.get  = AsyncMock(return_value=get_resp)
            mock_build.return_value = client_ctx

            result, recs = await check_https_available("https://example.com")

        assert result.status == CheckStatus.PASS
        client_ctx.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_fail_on_connect_error(self):
        """Connection refused → fail with CRITICAL severity and a recommendation."""
        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.head = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            mock_build.return_value = client_ctx

            result, recs = await check_https_available("https://example.com")

        assert result.status   == CheckStatus.FAIL
        assert result.severity == Severity.CRITICAL
        assert len(recs) == 1
        assert recs[0].priority == Priority.CRITICAL
        assert recs[0].check_name == "https_available"

    @pytest.mark.asyncio
    async def test_fail_on_timeout(self):
        """Connection timeout → fail with HIGH severity."""
        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.head = AsyncMock(
                side_effect=httpx.TimeoutException("timed out")
            )
            mock_build.return_value = client_ctx

            result, recs = await check_https_available("https://example.com")

        assert result.status   == CheckStatus.FAIL
        assert result.severity == Severity.HIGH
        assert len(recs) == 1

    @pytest.mark.asyncio
    async def test_fail_on_ssl_error(self):
        """SSL handshake error (simulated via ConnectError) → fail result."""
        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.head = AsyncMock(
                side_effect=httpx.ConnectError("certificate verify failed")
            )
            mock_build.return_value = client_ctx

            result, recs = await check_https_available("https://example.com")

        assert result.status   == CheckStatus.FAIL
        assert result.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_uses_https_url_when_given_http(self):
        """Even if user passes http://, the check always tests https://."""
        mock_resp = _mock_response(200)
        captured_url = []

        async def fake_head(url, **kwargs):
            captured_url.append(url)
            return mock_resp

        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.head = fake_head
            mock_build.return_value = client_ctx

            await check_https_available("http://example.com")

        assert captured_url[0].startswith("https://")


# ── check_http_redirects_to_https ─────────────────────────────────────────────

class TestCheckHttpRedirectsToHttps:

    @pytest.mark.asyncio
    async def test_pass_on_301_to_https(self):
        """HTTP 301 to https:// location → pass."""
        mock_resp = _mock_response(301, {"location": "https://example.com/"})

        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.get = AsyncMock(return_value=mock_resp)
            mock_build.return_value = client_ctx

            result, recs = await check_http_redirects_to_https("http://example.com")

        assert result.status == CheckStatus.PASS
        assert recs == []
        assert "301" in result.detail

    @pytest.mark.asyncio
    async def test_pass_on_302_to_https(self):
        """HTTP 302 to https:// location → also a pass."""
        mock_resp = _mock_response(302, {"location": "https://example.com/"})

        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.get = AsyncMock(return_value=mock_resp)
            mock_build.return_value = client_ctx

            result, recs = await check_http_redirects_to_https("http://example.com")

        assert result.status == CheckStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_on_200_no_redirect(self):
        """HTTP 200 with no redirect → fail with HIGH severity."""
        mock_resp = _mock_response(200)

        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.get = AsyncMock(return_value=mock_resp)
            mock_build.return_value = client_ctx

            result, recs = await check_http_redirects_to_https("https://example.com")

        assert result.status   == CheckStatus.FAIL
        assert result.severity == Severity.HIGH
        assert len(recs) == 1
        assert recs[0].priority == Priority.HIGH

    @pytest.mark.asyncio
    async def test_warn_on_redirect_to_non_https(self):
        """HTTP 301 to another http:// URL → warn."""
        mock_resp = _mock_response(301, {"location": "http://www.example.com/"})

        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.get = AsyncMock(return_value=mock_resp)
            mock_build.return_value = client_ctx

            result, recs = await check_http_redirects_to_https("http://example.com")

        assert result.status   == CheckStatus.WARN
        assert result.severity == Severity.MEDIUM
        assert len(recs) == 1

    @pytest.mark.asyncio
    async def test_info_on_connect_error(self):
        """Port 80 not reachable → info (not a security failure on its own)."""
        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.get = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            mock_build.return_value = client_ctx

            result, recs = await check_http_redirects_to_https("https://example.com")

        assert result.status == CheckStatus.INFO
        # No recommendation for this case
        assert recs == []

    @pytest.mark.asyncio
    async def test_warn_on_timeout(self):
        """HTTP connection times out → warn (inconclusive)."""
        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.get = AsyncMock(
                side_effect=httpx.TimeoutException("timed out")
            )
            mock_build.return_value = client_ctx

            result, recs = await check_http_redirects_to_https("http://example.com")

        assert result.status == CheckStatus.WARN

    @pytest.mark.asyncio
    async def test_always_tests_http_url(self):
        """Even when given an https:// URL, the check targets http://."""
        mock_resp = _mock_response(301, {"location": "https://example.com/"})
        captured_url = []

        async def fake_get(url, **kwargs):
            captured_url.append(url)
            return mock_resp

        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.get = fake_get
            mock_build.return_value = client_ctx

            await check_http_redirects_to_https("https://example.com")

        assert captured_url[0].startswith("http://")
        assert not captured_url[0].startswith("https://")


# ── run_https_checks (bundle) ─────────────────────────────────────────────────

class TestRunHttpsChecks:

    @pytest.mark.asyncio
    async def test_returns_two_results(self):
        """Bundle always contains exactly 2 CheckResult rows."""
        mock_resp_https   = _mock_response(200)
        mock_resp_http    = _mock_response(301, {"location": "https://example.com/"})
        call_count = [0]

        def make_client(follow_redirects):
            call_count[0] += 1
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            if follow_redirects:
                client_ctx.head = AsyncMock(return_value=mock_resp_https)
            else:
                client_ctx.get = AsyncMock(return_value=mock_resp_http)
            return client_ctx

        with patch("app.services.analyzer.https_checker._build_client", side_effect=make_client):
            bundle = await run_https_checks("https://example.com")

        assert len(bundle.results) == 2
        check_names = {r.check_name for r in bundle.results}
        assert "https_available" in check_names
        assert "http_redirects_to_https" in check_names

    @pytest.mark.asyncio
    async def test_no_recommendations_on_all_pass(self):
        """Both checks pass → no recommendations."""
        mock_resp_https = _mock_response(200)
        mock_resp_http  = _mock_response(301, {"location": "https://example.com/"})

        def make_client(follow_redirects):
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            if follow_redirects:
                client_ctx.head = AsyncMock(return_value=mock_resp_https)
            else:
                client_ctx.get = AsyncMock(return_value=mock_resp_http)
            return client_ctx

        with patch("app.services.analyzer.https_checker._build_client", side_effect=make_client):
            bundle = await run_https_checks("https://example.com")

        assert bundle.recommendations == []

    @pytest.mark.asyncio
    async def test_recommendations_on_fail(self):
        """HTTPS unavailable + no HTTP redirect → 2 recommendations."""
        with patch("app.services.analyzer.https_checker._build_client") as mock_build:
            client_ctx = AsyncMock()
            client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
            client_ctx.__aexit__  = AsyncMock(return_value=False)
            client_ctx.head = AsyncMock(side_effect=httpx.ConnectError("refused"))
            client_ctx.get  = AsyncMock(return_value=_mock_response(200))
            mock_build.return_value = client_ctx

            bundle = await run_https_checks("http://example.com")

        rec_names = {r.check_name for r in bundle.recommendations}
        assert "https_available" in rec_names
        assert "http_redirects_to_https" in rec_names


# ── Integration tests (live network) ─────────────────────────────────────────

class TestHttpsCheckerIntegration:
    """
    These tests make real HTTP requests. Requires internet access.
    Skip in offline environments: pytest -m "not network"
    """

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_example_com_https_available(self):
        """example.com has valid HTTPS — should pass."""
        result, recs = await check_https_available("https://example.com")
        assert result.status == CheckStatus.PASS
        assert recs == []

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_example_com_redirects_to_https(self):
        """example.com HTTP behaviour varies — pass, info, or fail are all valid."""
        result, _ = await check_http_redirects_to_https("https://example.com")
        # example.com may redirect http→https (pass), have port 80 closed (info),
        # or serve HTTP directly (fail). Any of these is a valid live result.
        assert result.status in (CheckStatus.PASS, CheckStatus.INFO, CheckStatus.FAIL)

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_run_https_checks_bundle_for_example_com(self):
        """Full bundle for example.com produces 2 results."""
        bundle = await run_https_checks("https://example.com")
        assert len(bundle.results) == 2
        check_names = {r.check_name for r in bundle.results}
        assert "https_available" in check_names
        assert "http_redirects_to_https" in check_names
