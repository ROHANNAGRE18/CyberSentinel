"""
Health check endpoint.

GET /api/v1/health

Returns basic liveness information. Used by monitoring tools, load
balancers, and the frontend to confirm the API is reachable.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.database import get_db

router = APIRouter(tags=["Health"])
settings = get_settings()


@router.get(
    "/health",
    summary="API health check",
    response_description="API and database liveness status",
)
async def health_check(db: AsyncSession = Depends(get_db)):
    """
    Returns HTTP 200 when the API is running.

    Also probes the database connection so a downstream failure is
    surfaced here rather than on the first scan request.
    """
    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"error: {exc}"

    return {
        "status": "healthy",
        "version": settings.app_version,
        "database": db_status,
    }
