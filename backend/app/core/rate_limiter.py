"""
Rate limiting for CyberSentinel API endpoints.

Uses slowapi (a Starlette/FastAPI wrapper around limits).
The limiter instance is attached to app.state in main.py and
the RateLimitExceeded handler is registered there too.

Default limit: 10 scan requests per minute per client IP.
The limit string is configurable via RATE_LIMIT_SCANS_PER_MINUTE in .env.
"""

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.core.config import get_settings

settings = get_settings()

# ── Limiter singleton ─────────────────────────────────────────────────────────
# key_func=get_remote_address extracts the client IP from the request.
# In production behind a reverse proxy, ensure X-Forwarded-For is trusted.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],          # no global default; limits are per-route
    headers_enabled=True,       # adds X-RateLimit-* headers to responses
)


# ── Convenience helpers ───────────────────────────────────────────────────────

def scan_rate_limit() -> str:
    """
    Return the rate-limit string for scan endpoints, e.g. '10/minute'.
    Reads from settings so it stays in sync with .env.
    """
    return f"{settings.rate_limit_scans_per_minute}/minute"


# ── Exception handler ─────────────────────────────────────────────────────────

async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """
    Return a clean JSON 429 response instead of slowapi's default plain-text one.
    Registered on the FastAPI app in main.py.
    """
    return JSONResponse(
        status_code=429,
        content={
            "detail": (
                f"Rate limit exceeded: {exc.detail}. "
                f"You may submit up to {settings.rate_limit_scans_per_minute} "
                "scan requests per minute."
            )
        },
        headers={"Retry-After": "60"},
    )
