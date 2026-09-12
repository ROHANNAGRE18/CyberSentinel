"""
Scan endpoints.

POST   /api/v1/scans              – submit a new scan
GET    /api/v1/scans/{scan_id}    – get full results for one scan
GET    /api/v1/scans              – paginated scan history list

Design notes:
- POST returns 202 Accepted immediately; the actual scan runs as a
  FastAPI BackgroundTask so the HTTP response is never blocked by I/O.
- Scan results are accessible to anyone who knows the scan_id (UUID).
  User authentication / private history is deferred to a future phase.
- Rate limiting is applied per client IP via slowapi.
"""

import logging
from typing import Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.rate_limiter import limiter, scan_rate_limit
from app.core.security import validate_url
from app.db.database import get_db
from app.models.scan import Scan, ScanStatus, CheckResult, Recommendation
from app.schemas.scan import (
    ScanCreateResponse,
    ScanDetailResponse,
    ScanListResponse,
    ScanRequest,
    ScanSummary,
    CheckResultSchema,
    RecommendationSchema,
)
from app.services.scanner import run_scan

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Scans"])


# ── Helper ────────────────────────────────────────────────────────────────────

def _scan_to_detail(scan: Scan) -> ScanDetailResponse:
    """Convert a Scan ORM object (with relationships loaded) to the response schema."""
    return ScanDetailResponse(
        scan_id=scan.id,
        url=scan.url,
        status=scan.status,
        score=scan.score,
        created_at=scan.created_at,
        scan_duration=scan.scan_duration,
        error_message=scan.error_message,
        checks=[
            CheckResultSchema(
                check_name=c.check_name,
                status=c.status,
                title=c.title,
                detail=c.detail,
                severity=c.severity,
            )
            for c in (scan.check_results or [])
        ],
        recommendations=[
            RecommendationSchema(
                check_name=r.check_name,
                priority=r.priority,
                title=r.title,
                description=r.description,
                reference_url=r.reference_url,
            )
            for r in (scan.recommendations or [])
        ],
    )


# ── POST /scans ───────────────────────────────────────────────────────────────

@router.post(
    "/scans",
    response_model=ScanCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a new scan",
    description=(
        "Validates the URL, creates a scan record, and queues the scan as a "
        "background task. Returns immediately with the scan_id. "
        "Poll GET /api/v1/scans/{scan_id} to check progress and retrieve results."
    ),
)
@limiter.limit(scan_rate_limit)
async def create_scan(
    request: Request,                           # required by slowapi
    response: Response,                         # required by slowapi for header injection
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> ScanCreateResponse:
    """
    1. Validate URL format (Pydantic) + SSRF guard (security.py)
    2. Persist a Scan row with status=pending
    3. Enqueue run_scan as a background task
    4. Return 202 with scan_id
    """
    # ── SSRF + URL validation ─────────────────────────────────────────────────
    validated_url = await validate_url(body.url)

    # ── Persist scan record ───────────────────────────────────────────────────
    scan = Scan(url=validated_url, status=ScanStatus.PENDING)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    logger.info("Scan %s created for %s", scan.id, validated_url)

    # ── Enqueue background task ───────────────────────────────────────────────
    # We pass a new session into the background task because the request-scoped
    # session above will be closed by the time the background task runs.
    from app.db.database import AsyncSessionLocal

    async def _run_with_new_session():
        async with AsyncSessionLocal() as bg_db:
            try:
                await run_scan(scan.id, validated_url, bg_db)
                await bg_db.commit()
            except Exception:
                await bg_db.rollback()
                raise

    background_tasks.add_task(_run_with_new_session)

    return ScanCreateResponse(
        scan_id=scan.id,
        status=scan.status,
        message=(
            f"Scan started. Poll GET /api/v1/scans/{scan.id} for results."
        ),
    )


# ── GET /scans/{scan_id} ──────────────────────────────────────────────────────

@router.get(
    "/scans/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get scan results",
    description=(
        "Returns the full results of a scan by its ID. "
        "While the scan is still running, checks and recommendations will be "
        "empty lists and score will be null. "
        "Poll this endpoint until status is 'completed' or 'failed'."
    ),
)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> ScanDetailResponse:
    """Fetch a scan and all its related check results and recommendations."""
    result = await db.execute(
        select(Scan)
        .options(
            selectinload(Scan.check_results),
            selectinload(Scan.recommendations),
        )
        .where(Scan.id == scan_id)
    )
    scan: Optional[Scan] = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )

    return _scan_to_detail(scan)


# ── GET /scans ────────────────────────────────────────────────────────────────

@router.get(
    "/scans",
    response_model=ScanListResponse,
    summary="List scan history",
    description=(
        "Returns a paginated list of all past scans, most recent first. "
        "Use page and limit for pagination. "
        "Note: full check results are not included — use GET /scans/{scan_id} "
        "for the complete report."
    ),
)
async def list_scans(
    page: int  = Query(default=1,  ge=1,  description="Page number (1-indexed)"),
    limit: int = Query(default=20, ge=1, le=100, description="Results per page (max 100)"),
    sort: Literal["created_at", "score"] = Query(
        default="created_at",
        description="Field to sort by",
    ),
    order: Literal["asc", "desc"] = Query(
        default="desc",
        description="Sort direction",
    ),
    db: AsyncSession = Depends(get_db),
) -> ScanListResponse:
    """Paginated scan history. Returns lightweight summary rows."""

    # ── Total count ───────────────────────────────────────────────────────────
    count_result = await db.execute(select(func.count()).select_from(Scan))
    total: int = count_result.scalar_one()

    # ── Sort column ───────────────────────────────────────────────────────────
    sort_col = Scan.created_at if sort == "created_at" else Scan.score
    sort_expr = sort_col.desc() if order == "desc" else sort_col.asc()

    # ── Paginated query ───────────────────────────────────────────────────────
    offset = (page - 1) * limit
    rows_result = await db.execute(
        select(Scan).order_by(sort_expr).offset(offset).limit(limit)
    )
    scans = rows_result.scalars().all()

    return ScanListResponse(
        total=total,
        page=page,
        limit=limit,
        scans=[
            ScanSummary(
                scan_id=s.id,
                url=s.url,
                status=s.status,
                score=s.score,
                created_at=s.created_at,
            )
            for s in scans
        ],
    )
