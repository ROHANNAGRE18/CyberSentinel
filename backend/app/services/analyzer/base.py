"""
Base classes for all CyberSentinel analyzer modules.

Every checker module returns a list of CheckResult dataclass instances.
The scanner orchestrator collects these and persists them as CheckResult
ORM rows plus Recommendation ORM rows.

Design principles:
  - Each checker is a standalone async class with a single public method: run()
  - Checkers never raise — they catch their own exceptions and return a
    fail/info result so one broken check never kills the entire scan
  - Checkers receive the validated URL and a shared httpx.AsyncClient
    (built with SSRF redirect guard) so connection settings are uniform
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Result types (mirror ORM enums exactly) ───────────────────────────────────

class CheckStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


# ── Result dataclasses ────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    """
    Represents the outcome of a single security check.

    Maps 1-to-1 with the CheckResult ORM model in app/models/scan.py.
    """
    check_name: str
    status:     CheckStatus
    title:      str
    detail:     Optional[str] = None
    severity:   Severity      = Severity.INFO


@dataclass
class Recommendation:
    """
    A remediation recommendation generated when a check is warn or fail.

    Maps 1-to-1 with the Recommendation ORM model in app/models/scan.py.
    """
    check_name:    str
    priority:      Priority
    title:         str
    description:   str
    reference_url: Optional[str] = None


@dataclass
class CheckBundle:
    """
    The complete output of one checker module:
      - one or more CheckResult rows
      - zero or more Recommendation rows (only for warn/fail results)
    """
    results:         list[CheckResult]   = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)
