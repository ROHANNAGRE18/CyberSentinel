"""
CyberSentinel – FastAPI application entry point.

Responsibilities:
- Create the FastAPI app instance with metadata
- Configure CORS middleware
- Register API routers
- Run database initialisation on startup
- Expose a root redirect for convenience
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.rate_limiter import limiter, rate_limit_exceeded_handler
from app.api.v1.router import api_router
from app.db.init_db import init_db
from slowapi.errors import RateLimitExceeded

settings = get_settings()


# ── Lifespan (startup / shutdown) ────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise database tables on startup."""
    await init_db()
    yield
    # Nothing to clean up for SQLite; add teardown here for future resources.


# ── App factory ──────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "CyberSentinel performs passive, non-intrusive security checks "
            "against websites you own or are authorised to test."
        ),
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # ── Rate limiter ─────────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

    # ── CORS ─────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Accept"],
    )

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(api_router, prefix="/api/v1")

    # ── Root ─────────────────────────────────────────────────────────────────
    @app.get("/", include_in_schema=False)
    async def root():
        return JSONResponse(
            content={
                "name": settings.app_name,
                "version": settings.app_version,
                "docs": "/api/docs",
                "health": "/api/v1/health",
            }
        )

    return app


app = create_app()
