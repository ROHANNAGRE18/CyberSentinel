"""
Security Scoring Engine — Phase 2F
=====================================

Converts the flat list of CheckResult objects produced by all Phase 2A–2E
analyzer modules into a single integer score (0–100) plus a risk level label.

Scoring model
──────────────
  Start:   100 points
  Deduct:  points per FAIL or WARN finding based on severity
  PASS:    no deduction
  INFO:    no deduction (always zero, by design requirement)
  DNS INFO: always zero, regardless of check_name prefix

Deduction table (maximum per check_name, applied once)
────────────────────────────────────────────────────────
  FAIL + critical severity  → −25 pts
  FAIL + high severity      → −15 pts
  FAIL + medium severity    → −10 pts
  FAIL + low severity       →  −5 pts
  WARN + any severity       → half the FAIL deduction for that severity level
    WARN + critical         → −12 pts
    WARN + high             →  −7 pts
    WARN + medium           →  −5 pts
    WARN + low              →  −2 pts

Duplicate penalty prevention
──────────────────────────────
  Each check_name is penalised at most once. If a check can produce
  multiple results with the same check_name (e.g. ssl_certificate_expiry
  can be FAIL-critical or WARN-high depending on days remaining), only
  the first occurrence in the results list is scored.

  cookie_overview is a summary result — it is explicitly excluded from
  scoring because the individual attribute checks (cookie_secure_flag etc.)
  already capture the substance.

Excluded from scoring (always 0 deduction)
────────────────────────────────────────────
  - Any check_name starting with "dns_"  (all DNS checks are informational)
  - check_name == "cookie_overview"      (duplicate of attribute checks)
  - status == INFO or status == PASS

Score clamping
───────────────
  Score is clamped to [0, 100] after all deductions.

Risk level labels
──────────────────
  90–100  Excellent
  70–89   Good
  40–69   Fair
   0–39   Poor

Return value
─────────────
  ScoreResult dataclass:
    score       int       0–100
    risk_level  str       "Excellent" | "Good" | "Fair" | "Poor"
    deductions  list      each deduction applied (for transparency/debugging)
"""

from dataclasses import dataclass, field
from typing import List

from app.services.analyzer.base import CheckResult, CheckStatus, Severity


# ── Deduction tables ──────────────────────────────────────────────────────────

# Maximum deduction for a FAIL result at each severity level
_FAIL_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH:     15,
    Severity.MEDIUM:   10,
    Severity.LOW:       5,
    Severity.INFO:      0,  # FAIL+INFO is unusual but never penalised
}

# WARN deductions are roughly half of FAIL for the same severity
_WARN_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 12,
    Severity.HIGH:      7,
    Severity.MEDIUM:    5,
    Severity.LOW:       2,
    Severity.INFO:      0,
}

# check_names that are never scored regardless of their status
_EXCLUDED_CHECK_NAMES: frozenset[str] = frozenset({
    "cookie_overview",   # summary card — attribute checks already score it
})


# ── Return type ───────────────────────────────────────────────────────────────

@dataclass
class Deduction:
    """Records one penalty applied during scoring (for transparency)."""
    check_name: str
    status:     str
    severity:   str
    points:     int


@dataclass
class ScoreResult:
    """The complete output of the scoring engine."""
    score:      int                   # 0–100
    risk_level: str                   # "Excellent" | "Good" | "Fair" | "Poor"
    deductions: List[Deduction] = field(default_factory=list)


# ── Core scoring function ─────────────────────────────────────────────────────

def calculate_score(results: list[CheckResult]) -> ScoreResult:
    """
    Calculate the security score from a flat list of CheckResult objects.

    Parameters
    ----------
    results : list[CheckResult]
        All CheckResult instances produced by every Phase 2A–2E checker,
        collected from their CheckBundle.results lists.

    Returns
    -------
    ScoreResult
        score, risk_level, and the list of deductions applied.
    """
    score      = 100
    deductions: list[Deduction] = []
    seen_check_names: set[str] = set()

    for result in results:
        cn = result.check_name

        # ── Exclusions ────────────────────────────────────────────────────────
        # 1. INFO and PASS never penalise
        if result.status in (CheckStatus.PASS, CheckStatus.INFO):
            continue

        # 2. DNS checks are always informational — never score
        if cn.startswith("dns_"):
            continue

        # 3. Explicitly excluded check_names
        if cn in _EXCLUDED_CHECK_NAMES:
            continue

        # 4. Duplicate prevention: each check_name penalised at most once
        if cn in seen_check_names:
            continue
        seen_check_names.add(cn)

        # ── Deduction amount ──────────────────────────────────────────────────
        severity = result.severity

        if result.status == CheckStatus.FAIL:
            points = _FAIL_DEDUCTIONS.get(severity, 0)
        elif result.status == CheckStatus.WARN:
            points = _WARN_DEDUCTIONS.get(severity, 0)
        else:
            points = 0

        if points == 0:
            continue

        score -= points
        deductions.append(Deduction(
            check_name=cn,
            status=result.status.value,
            severity=severity.value,
            points=points,
        ))

    # ── Clamp ─────────────────────────────────────────────────────────────────
    score = max(0, min(100, score))

    return ScoreResult(
        score=score,
        risk_level=_risk_level(score),
        deductions=deductions,
    )


def _risk_level(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 70:
        return "Good"
    if score >= 40:
        return "Fair"
    return "Poor"
