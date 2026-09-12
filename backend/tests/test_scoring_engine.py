"""
Tests for the security scoring engine (Phase 2F).

All tests are pure unit tests — no network, no database, no mocking needed.
The scoring engine operates entirely on in-memory CheckResult objects.

Run:
  pytest tests/test_scoring_engine.py -v
"""

import pytest

from app.services.analyzer.base import CheckResult, CheckStatus, Severity
from app.services.analyzer.scoring_engine import (
    Deduction,
    ScoreResult,
    _FAIL_DEDUCTIONS,
    _WARN_DEDUCTIONS,
    _risk_level,
    calculate_score,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _r(check_name: str, status: CheckStatus, severity: Severity) -> CheckResult:
    """Shorthand for building a CheckResult."""
    return CheckResult(
        check_name=check_name,
        status=status,
        title=f"Test: {check_name}",
        severity=severity,
    )


def _pass(check_name: str) -> CheckResult:
    return _r(check_name, CheckStatus.PASS, Severity.INFO)


def _info(check_name: str) -> CheckResult:
    return _r(check_name, CheckStatus.INFO, Severity.INFO)


def _fail(check_name: str, severity: Severity = Severity.HIGH) -> CheckResult:
    return _r(check_name, CheckStatus.FAIL, severity)


def _warn(check_name: str, severity: Severity = Severity.MEDIUM) -> CheckResult:
    return _r(check_name, CheckStatus.WARN, severity)


# ════════════════════════════════════════════════════════════════════════════
# _risk_level
# ════════════════════════════════════════════════════════════════════════════

class TestRiskLevel:

    def test_100_is_excellent(self):
        assert _risk_level(100) == "Excellent"

    def test_90_is_excellent(self):
        assert _risk_level(90) == "Excellent"

    def test_89_is_good(self):
        assert _risk_level(89) == "Good"

    def test_70_is_good(self):
        assert _risk_level(70) == "Good"

    def test_69_is_fair(self):
        assert _risk_level(69) == "Fair"

    def test_40_is_fair(self):
        assert _risk_level(40) == "Fair"

    def test_39_is_poor(self):
        assert _risk_level(39) == "Poor"

    def test_0_is_poor(self):
        assert _risk_level(0) == "Poor"


# ════════════════════════════════════════════════════════════════════════════
# Baseline: empty or all-PASS/INFO results
# ════════════════════════════════════════════════════════════════════════════

class TestBaselineScore:

    def test_empty_results_returns_100(self):
        result = calculate_score([])
        assert result.score == 100
        assert result.risk_level == "Excellent"
        assert result.deductions == []

    def test_all_pass_returns_100(self):
        results = [
            _pass("https_available"),
            _pass("http_redirects_to_https"),
            _pass("ssl_certificate_valid"),
            _pass("csp_header"),
        ]
        assert calculate_score(results).score == 100

    def test_all_info_returns_100(self):
        results = [
            _info("dns_a_records"),
            _info("dns_aaaa_records"),
            _info("cookie_overview"),
            _info("hsts_header"),
        ]
        assert calculate_score(results).score == 100

    def test_mixed_pass_and_info_returns_100(self):
        results = [_pass("https_available"), _info("dns_spf_record")]
        assert calculate_score(results).score == 100


# ════════════════════════════════════════════════════════════════════════════
# FAIL deductions
# ════════════════════════════════════════════════════════════════════════════

class TestFailDeductions:

    def test_fail_critical_deducts_25(self):
        result = calculate_score([_fail("https_available", Severity.CRITICAL)])
        assert result.score == 75
        assert len(result.deductions) == 1
        assert result.deductions[0].points == 25

    def test_fail_high_deducts_15(self):
        result = calculate_score([_fail("https_available", Severity.HIGH)])
        assert result.score == 85

    def test_fail_medium_deducts_10(self):
        result = calculate_score([_fail("csp_header", Severity.MEDIUM)])
        assert result.score == 90

    def test_fail_low_deducts_5(self):
        result = calculate_score([_fail("referrer_policy", Severity.LOW)])
        assert result.score == 95

    def test_fail_info_severity_deducts_0(self):
        """FAIL with INFO severity — unusual but never penalised."""
        result = calculate_score([_fail("some_check", Severity.INFO)])
        assert result.score == 100
        assert result.deductions == []

    def test_multiple_fails_accumulate(self):
        results = [
            _fail("https_available",        Severity.CRITICAL),  # −25
            _fail("ssl_certificate_expiry", Severity.HIGH),      # −15
            _fail("csp_header",             Severity.MEDIUM),    # −10
        ]
        result = calculate_score(results)
        assert result.score == 100 - 25 - 15 - 10
        assert len(result.deductions) == 3


# ════════════════════════════════════════════════════════════════════════════
# WARN deductions
# ════════════════════════════════════════════════════════════════════════════

class TestWarnDeductions:

    def test_warn_critical_deducts_12(self):
        result = calculate_score([_warn("https_available", Severity.CRITICAL)])
        assert result.score == 88

    def test_warn_high_deducts_7(self):
        result = calculate_score([_warn("hsts_header", Severity.HIGH)])
        assert result.score == 93

    def test_warn_medium_deducts_5(self):
        result = calculate_score([_warn("csp_header", Severity.MEDIUM)])
        assert result.score == 95

    def test_warn_low_deducts_2(self):
        result = calculate_score([_warn("referrer_policy", Severity.LOW)])
        assert result.score == 98

    def test_warn_info_severity_deducts_0(self):
        result = calculate_score([_warn("some_check", Severity.INFO)])
        assert result.score == 100

    def test_warn_is_less_than_fail_same_severity(self):
        fail_r = calculate_score([_fail("x", Severity.HIGH)])
        warn_r = calculate_score([_warn("x", Severity.HIGH)])
        assert warn_r.score > fail_r.score


# ════════════════════════════════════════════════════════════════════════════
# DNS always scores 0
# ════════════════════════════════════════════════════════════════════════════

class TestDnsExclusion:

    def test_dns_fail_does_not_deduct(self):
        result = calculate_score([_fail("dns_a_records", Severity.HIGH)])
        assert result.score == 100
        assert result.deductions == []

    def test_dns_warn_does_not_deduct(self):
        result = calculate_score([_warn("dns_ns_records", Severity.MEDIUM)])
        assert result.score == 100

    def test_all_dns_checks_excluded(self):
        dns_checks = [
            _info("dns_a_records"),
            _info("dns_aaaa_records"),
            _info("dns_ns_records"),
            _info("dns_mx_records"),
            _info("dns_spf_record"),
            _info("dns_dmarc_record"),
            # Even if they were FAIL (shouldn't happen in practice)
            _fail("dns_a_records",    Severity.HIGH),
            _fail("dns_spf_record",   Severity.MEDIUM),
            _fail("dns_dmarc_record", Severity.LOW),
        ]
        result = calculate_score(dns_checks)
        assert result.score == 100
        assert result.deductions == []


# ════════════════════════════════════════════════════════════════════════════
# cookie_overview excluded
# ════════════════════════════════════════════════════════════════════════════

class TestCookieOverviewExclusion:

    def test_cookie_overview_warn_does_not_deduct(self):
        result = calculate_score([_warn("cookie_overview", Severity.MEDIUM)])
        assert result.score == 100

    def test_cookie_overview_fail_does_not_deduct(self):
        result = calculate_score([_fail("cookie_overview", Severity.HIGH)])
        assert result.score == 100

    def test_cookie_attribute_checks_do_deduct(self):
        """The attribute-level cookie checks should still penalise."""
        results = [
            _fail("cookie_secure_flag",   Severity.HIGH),    # −15
            _warn("cookie_httponly_flag",  Severity.MEDIUM),  # −5
            _warn("cookie_samesite_attr",  Severity.LOW),     # −2
            _warn("cookie_overview",       Severity.LOW),     # −0 (excluded)
        ]
        result = calculate_score(results)
        assert result.score == 100 - 15 - 5 - 2


# ════════════════════════════════════════════════════════════════════════════
# Duplicate prevention
# ════════════════════════════════════════════════════════════════════════════

class TestDuplicatePrevention:

    def test_same_check_name_penalised_once(self):
        """Two results with the same check_name — only the first is scored."""
        results = [
            _fail("ssl_certificate_expiry", Severity.CRITICAL),  # −25
            _fail("ssl_certificate_expiry", Severity.HIGH),      # ignored (duplicate)
        ]
        result = calculate_score(results)
        assert result.score == 75
        assert len(result.deductions) == 1

    def test_different_check_names_both_penalised(self):
        results = [
            _fail("https_available",   Severity.CRITICAL),  # −25
            _fail("csp_header",        Severity.HIGH),       # −15
        ]
        result = calculate_score(results)
        assert result.score == 60
        assert len(result.deductions) == 2

    def test_pass_then_fail_same_name_still_penalised(self):
        """PASS is skipped (not added to seen_check_names), so FAIL after is scored."""
        results = [
            _pass("csp_header"),
            _fail("csp_header", Severity.HIGH),  # should still deduct
        ]
        result = calculate_score(results)
        assert result.score == 85


# ════════════════════════════════════════════════════════════════════════════
# Score clamping
# ════════════════════════════════════════════════════════════════════════════

class TestScoreClamping:

    def test_score_cannot_go_below_0(self):
        """Many critical failures — score must clamp at 0, not go negative."""
        results = [
            _fail(f"check_{i}", Severity.CRITICAL)
            for i in range(20)  # 20 × 25 = 500 points deducted
        ]
        result = calculate_score(results)
        assert result.score == 0

    def test_score_cannot_exceed_100(self):
        """No results — score stays at 100."""
        result = calculate_score([])
        assert result.score == 100

    def test_score_exactly_at_0_is_poor(self):
        results = [_fail(f"c{i}", Severity.CRITICAL) for i in range(20)]
        result = calculate_score(results)
        assert result.risk_level == "Poor"


# ════════════════════════════════════════════════════════════════════════════
# Deduction metadata
# ════════════════════════════════════════════════════════════════════════════

class TestDeductionMetadata:

    def test_deduction_records_check_name(self):
        result = calculate_score([_fail("https_available", Severity.HIGH)])
        assert result.deductions[0].check_name == "https_available"

    def test_deduction_records_status(self):
        result = calculate_score([_warn("csp_header", Severity.MEDIUM)])
        assert result.deductions[0].status == "warn"

    def test_deduction_records_severity(self):
        result = calculate_score([_fail("hsts_header", Severity.CRITICAL)])
        assert result.deductions[0].severity == "critical"

    def test_deduction_records_points(self):
        result = calculate_score([_fail("hsts_header", Severity.CRITICAL)])
        assert result.deductions[0].points == 25

    def test_deductions_list_sorted_by_insertion_order(self):
        """Deductions appear in the same order as results were evaluated."""
        results = [
            _fail("a_check", Severity.HIGH),
            _fail("b_check", Severity.MEDIUM),
        ]
        result = calculate_score(results)
        assert result.deductions[0].check_name == "a_check"
        assert result.deductions[1].check_name == "b_check"


# ════════════════════════════════════════════════════════════════════════════
# Realistic end-to-end scenario
# ════════════════════════════════════════════════════════════════════════════

class TestRealisticScenarios:

    def test_well_configured_site(self):
        """Site with all checks passing — score 100."""
        results = [
            _pass("https_available"),
            _pass("http_redirects_to_https"),
            _pass("ssl_certificate_valid"),
            _pass("ssl_certificate_expiry"),
            _pass("ssl_certificate_issuer"),
            _pass("ssl_certificate_subject"),
            _pass("csp_header"),
            _pass("hsts_header"),
            _pass("x_frame_options"),
            _pass("x_content_type_options"),
            _pass("referrer_policy"),
            _pass("permissions_policy"),
            _pass("cookie_secure_flag"),
            _pass("cookie_httponly_flag"),
            _pass("cookie_samesite_attr"),
            _info("cookie_overview"),
            _info("dns_a_records"),
            _info("dns_aaaa_records"),
            _info("dns_ns_records"),
            _info("dns_mx_records"),
            _info("dns_spf_record"),
            _info("dns_dmarc_record"),
        ]
        result = calculate_score(results)
        assert result.score == 100
        assert result.risk_level == "Excellent"
        assert result.deductions == []

    def test_typical_misconfigured_site(self):
        """Missing CSP, no X-Frame-Options, HSTS max-age too short, no Permissions-Policy."""
        results = [
            _pass("https_available"),
            _pass("http_redirects_to_https"),
            _pass("ssl_certificate_valid"),
            _pass("ssl_certificate_expiry"),
            _pass("ssl_certificate_issuer"),
            _pass("ssl_certificate_subject"),
            _fail("csp_header",            Severity.HIGH),    # −15
            _warn("hsts_header",           Severity.LOW),     # −2
            _pass("x_frame_options"),
            _pass("x_content_type_options"),
            _fail("referrer_policy",       Severity.LOW),     # −5
            _fail("permissions_policy",    Severity.LOW),     # −5
            _info("cookie_overview"),
            _pass("cookie_secure_flag"),
            _pass("cookie_httponly_flag"),
            _warn("cookie_samesite_attr",  Severity.LOW),     # −2
            _info("dns_a_records"),
            _info("dns_aaaa_records"),
            _info("dns_ns_records"),
            _info("dns_mx_records"),
            _info("dns_spf_record"),
            _info("dns_dmarc_record"),
        ]
        expected = 100 - 15 - 2 - 5 - 5 - 2
        result = calculate_score(results)
        assert result.score == expected
        assert result.risk_level == "Good"  # 71

    def test_severely_misconfigured_site(self):
        """No HTTPS, expired cert, missing most headers."""
        results = [
            _fail("https_available",          Severity.CRITICAL),  # −25
            _fail("http_redirects_to_https",  Severity.HIGH),      # −15
            _fail("ssl_certificate_valid",    Severity.CRITICAL),  # −25
            _fail("ssl_certificate_expiry",   Severity.CRITICAL),  # −25 (dup of valid? no — different name)
            _fail("csp_header",               Severity.HIGH),      # −15
            _fail("hsts_header",              Severity.HIGH),      # −15 (wait — HIGH fail = 15)
            _fail("x_frame_options",          Severity.MEDIUM),    # −10
            _fail("x_content_type_options",   Severity.MEDIUM),    # −10
            _fail("referrer_policy",          Severity.LOW),       # −5
            _fail("permissions_policy",       Severity.LOW),       # −5
        ]
        # 25+15+25+25+15+15+10+10+5+5 = 150 → clamped to 0
        result = calculate_score(results)
        assert result.score == 0
        assert result.risk_level == "Poor"

    def test_score_result_is_score_result_type(self):
        result = calculate_score([])
        assert isinstance(result, ScoreResult)
        assert isinstance(result.score, int)
        assert isinstance(result.risk_level, str)
        assert isinstance(result.deductions, list)
