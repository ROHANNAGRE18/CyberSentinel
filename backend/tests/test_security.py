"""
Unit tests for SSRF protection and URL validation (app/core/security.py).

Run with:  pytest tests/test_security.py -v
"""

import pytest

from app.core.security import (
    SSRFError,
    URLValidationError,
    is_safe_ip,
    assert_safe_ips,
    validate_url,
)


# ── is_safe_ip ────────────────────────────────────────────────────────────────

class TestIsSafeIp:

    # ── Safe (public) IPs ────────────────────────────────────────────────────
    @pytest.mark.parametrize("ip", [
        "8.8.8.8",           # Google DNS
        "1.1.1.1",           # Cloudflare
        "93.184.216.34",     # example.com
        "2606:2800:220:1:248:1893:25c8:1946",  # example.com IPv6
    ])
    def test_public_ips_are_safe(self, ip):
        assert is_safe_ip(ip) is True

    # ── Loopback ─────────────────────────────────────────────────────────────
    @pytest.mark.parametrize("ip", [
        "127.0.0.1",
        "127.0.0.2",
        "127.255.255.255",
        "::1",
    ])
    def test_loopback_blocked(self, ip):
        assert is_safe_ip(ip) is False

    # ── Private IPv4 ─────────────────────────────────────────────────────────
    @pytest.mark.parametrize("ip", [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
    ])
    def test_private_ipv4_blocked(self, ip):
        assert is_safe_ip(ip) is False

    # ── Link-local / cloud metadata ───────────────────────────────────────────
    @pytest.mark.parametrize("ip", [
        "169.254.0.1",
        "169.254.169.254",   # AWS/GCP/Azure metadata
        "169.254.255.255",
    ])
    def test_link_local_blocked(self, ip):
        assert is_safe_ip(ip) is False

    # ── IPv6 private ─────────────────────────────────────────────────────────
    @pytest.mark.parametrize("ip", [
        "fc00::1",
        "fd00::1",
        "fe80::1",           # link-local
    ])
    def test_private_ipv6_blocked(self, ip):
        assert is_safe_ip(ip) is False

    # ── Cloud metadata explicit list ─────────────────────────────────────────
    def test_aws_metadata_ip_blocked(self):
        assert is_safe_ip("169.254.169.254") is False

    def test_aws_ipv6_metadata_blocked(self):
        assert is_safe_ip("fd00:ec2::254") is False

    # ── Edge cases ────────────────────────────────────────────────────────────
    def test_invalid_ip_returns_false(self):
        assert is_safe_ip("not-an-ip") is False

    def test_empty_string_returns_false(self):
        assert is_safe_ip("") is False


# ── assert_safe_ips ───────────────────────────────────────────────────────────

class TestAssertSafeIps:

    def test_all_safe_ips_passes(self):
        # Should not raise
        assert_safe_ips("example.com", ["93.184.216.34", "8.8.8.8"])

    def test_one_private_ip_raises(self):
        with pytest.raises(SSRFError):
            assert_safe_ips("evil.com", ["93.184.216.34", "192.168.1.1"])

    def test_all_private_raises(self):
        with pytest.raises(SSRFError):
            assert_safe_ips("internal", ["10.0.0.1", "172.16.5.5"])


# ── validate_url ──────────────────────────────────────────────────────────────

class TestValidateUrl:

    # ── Format errors ─────────────────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_empty_url_raises(self):
        with pytest.raises(URLValidationError):
            await validate_url("")

    @pytest.mark.asyncio
    async def test_whitespace_only_raises(self):
        with pytest.raises(URLValidationError):
            await validate_url("   ")

    @pytest.mark.asyncio
    async def test_url_too_long_raises(self):
        long_url = "https://example.com/" + "a" * 2048
        with pytest.raises(URLValidationError):
            await validate_url(long_url)

    # ── Scheme validation ─────────────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_ftp_scheme_blocked(self):
        with pytest.raises(URLValidationError):
            await validate_url("ftp://example.com")

    @pytest.mark.asyncio
    async def test_file_scheme_blocked(self):
        with pytest.raises(URLValidationError):
            await validate_url("file:///etc/passwd")

    @pytest.mark.asyncio
    async def test_no_scheme_blocked(self):
        with pytest.raises(URLValidationError):
            await validate_url("example.com")

    # ── Embedded credentials ──────────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_url_with_credentials_blocked(self):
        with pytest.raises(URLValidationError):
            await validate_url("https://user:pass@example.com")

    # ── Private IP literals ───────────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_loopback_ip_literal_blocked(self):
        with pytest.raises(SSRFError):
            await validate_url("http://127.0.0.1/")

    @pytest.mark.asyncio
    async def test_private_ip_literal_blocked(self):
        with pytest.raises(SSRFError):
            await validate_url("http://192.168.1.1/admin")

    @pytest.mark.asyncio
    async def test_metadata_ip_literal_blocked(self):
        with pytest.raises(SSRFError):
            await validate_url("http://169.254.169.254/latest/meta-data/")

    @pytest.mark.asyncio
    async def test_internal_ip_10_blocked(self):
        with pytest.raises(SSRFError):
            await validate_url("https://10.0.0.1/")

    # ── Missing hostname ──────────────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_no_hostname_raises(self):
        with pytest.raises(URLValidationError):
            await validate_url("https:///path")

    # ── Valid public URL (integration — requires network) ─────────────────────
    # Marked with a custom marker; skip in offline CI environments.
    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_valid_public_url_passes(self):
        result = await validate_url("https://example.com")
        assert result == "https://example.com"

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_url_whitespace_stripped(self):
        result = await validate_url("  https://example.com  ")
        assert result == "https://example.com"
