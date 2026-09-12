"""
Aggregates all v1 API routers into a single router
that gets mounted at /api/v1 in main.py.
"""

from fastapi import APIRouter

from app.api.v1 import health, scans

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(scans.router)
