"""
Scanner orchestrator.

Responsibilities:
  1. Transition the Scan row through pending → running → completed/failed
  2. Run all active checker modules concurrently via asyncio.gather
  3. Persist CheckResult and Recommendation rows to the database
  4. Calculate and store the overall security score (scoring engine: Phase 2C+)

Phase 2E status:
  - HTTPS availability check    ✓ implemented (Phase 2A)
  - HTTP→HTTPS redirect check   ✓ implemented (Phase 2A)
  - Security headers check      ✓ implemented (Phase 2B)
  - SSL/TLS certificate check   ✓ implemented (Phase 2C)
  - Cookie security check       ✓ implemented (Phase 2D)
  - DNS check                   ✓ implemented (Phase 2E)
  - Scoring engine              ✓ implemented (Phase 2F)
"""

import asyncio
import logging
import time

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import (
    CheckResult as CheckResultORM,
    Recommendation as RecommendationORM,
    Scan,
    ScanStatus,
)
from app.services.analyzer.base import CheckBundle
from app.services.analyzer.https_checker import run_https_checks
from app.services.analyzer.headers_checker import run_headers_checks
from app.services.analyzer.ssl_checker import run_ssl_checks
from app.services.analyzer.cookie_checker import run_cookie_checks
from app.services.analyzer.dns_checker import run_dns_checks
from app.services.analyzer.scoring_engine import calculate_score

logger = logging.getLogger(__name__)


# ── Persistence helper ────────────────────────────────────────────────────────

async def _persist_bundle(scan_id: str, bundle: CheckBundle, db: AsyncSession) -> None:
    """
    Write all CheckResult and Recommendation rows from a CheckBundle to the DB.
    Called after each checker completes so results are visible incrementally.
    """
    for result in bundle.results:
        db.add(CheckResultORM(
            scan_id    = scan_id,
            check_name = result.check_name,
            status     = result.status.value,
            title      = result.title,
            detail     = result.detail,
            severity   = result.severity.value,
        ))

    for rec in bundle.recommendations:
        db.add(RecommendationORM(
            scan_id       = scan_id,
            check_name    = rec.check_name,
            priority      = rec.priority.value,
            title         = rec.title,
            description   = rec.description,
            reference_url = rec.reference_url,
        ))

    await db.commit()


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_scan(scan_id: str, url: str, db: AsyncSession) -> None:
    """
    Background task entry point.

    Fetches the Scan row, transitions it to 'running', runs all active
    checker modules concurrently, persists results, then marks the scan
    'completed' or 'failed'.

    Called via FastAPI BackgroundTasks (see api/v1/scans.py) so the HTTP
    response is returned to the client before scanning begins.
    """
    start_time = time.monotonic()

    scan: Scan | None = await db.get(Scan, scan_id)
    if scan is None:
        logger.error("run_scan: scan %s not found", scan_id)
        return

    # ── pending → running ─────────────────────────────────────────────────────
    scan.status = ScanStatus.RUNNING
    await db.commit()
    logger.info("Scan %s started for %s", scan_id, url)

    try:
        # ── Run all active checkers concurrently ──────────────────────────────
        # asyncio.gather runs them in parallel; each checker is independently
        # exception-safe and returns a CheckBundle even on internal error.
        https_bundle, headers_bundle, ssl_bundle, cookie_bundle, dns_bundle = await asyncio.gather(
            run_https_checks(url),
            run_headers_checks(url),
            run_ssl_checks(url),
            run_cookie_checks(url),
            run_dns_checks(url),
        )

        # ── Persist all results ───────────────────────────────────────────────
        await _persist_bundle(scan_id, https_bundle, db)
        await _persist_bundle(scan_id, headers_bundle, db)
        await _persist_bundle(scan_id, ssl_bundle, db)
        await _persist_bundle(scan_id, cookie_bundle, db)
        await _persist_bundle(scan_id, dns_bundle, db)

        # ── Re-fetch scan after commits inside _persist_bundle ────────────────
        await db.refresh(scan)

        duration     = time.monotonic() - start_time
        total_checks = (
            len(https_bundle.results)
            + len(headers_bundle.results)
            + len(ssl_bundle.results)
            + len(cookie_bundle.results)
            + len(dns_bundle.results)
        )
        total_recs = (
            len(https_bundle.recommendations)
            + len(headers_bundle.recommendations)
            + len(ssl_bundle.recommendations)
            + len(cookie_bundle.recommendations)
            + len(dns_bundle.recommendations)
        )

        # ── Score ──────────────────────────────────────────────────────────────
        all_results = (
            https_bundle.results
            + headers_bundle.results
            + ssl_bundle.results
            + cookie_bundle.results
            + dns_bundle.results
        )
        score_result = calculate_score(all_results)

        # ── running → completed ───────────────────────────────────────────────
        scan.status        = ScanStatus.COMPLETED
        scan.score         = score_result.score
        scan.scan_duration = round(duration, 3)
        await db.commit()

        logger.info(
            "Scan %s completed in %.2fs — score=%d (%s), %d checks, %d recommendations",
            scan_id, duration, score_result.score, score_result.risk_level,
            total_checks, total_recs,
        )

    except Exception as exc:
        duration = time.monotonic() - start_time
        # Re-fetch in case session state was altered before the exception
        scan = await db.get(Scan, scan_id)
        if scan:
            scan.status        = ScanStatus.FAILED
            scan.error_message = str(exc)
            scan.scan_duration = round(duration, 3)
            await db.commit()
        logger.exception("Scan %s failed: %s", scan_id, exc)
