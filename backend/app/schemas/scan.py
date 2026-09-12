"""
Pydantic v2 request and response schemas for scan-related API endpoints.

Separation of concerns:
  ScanRequest        – what the client sends to POST /scans
  ScanCreateResponse – what POST /scans returns immediately (scan_id + status)
  CheckResultSchema  – one security check result in a full report
  RecommendationSchema – one remediation recommendation in a full report
  ScanDetailResponse – full scan report returned by GET /scans/{scan_id}
  ScanSummary        – lightweight row used in the history list
  ScanListResponse   – paginated list of ScanSummary rows
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


# ── Request ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Body accepted by POST /api/v1/scans."""

    url: str = Field(
        ...,
        min_length=7,           # shortest valid: "http://x"
        max_length=2048,
        examples=["https://example.com"],
        description="The URL of the website to scan. Must be publicly reachable.",
    )

    @field_validator("url")
    @classmethod
    def url_must_have_scheme(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError(
                "URL must start with http:// or https://"
            )
        return v


# ── Sub-schemas ───────────────────────────────────────────────────────────────

class CheckResultSchema(BaseModel):
    """One security check result within a full scan report."""

    check_name: str = Field(..., examples=["ssl_certificate"])
    status: str     = Field(..., examples=["pass"], description="pass | warn | fail | info")
    title: str      = Field(..., examples=["SSL Certificate Valid"])
    detail: Optional[str] = Field(None, examples=["Certificate expires in 87 days."])
    severity: str   = Field(..., examples=["info"], description="critical | high | medium | low | info")

    model_config = {"from_attributes": True}


class RecommendationSchema(BaseModel):
    """One remediation recommendation within a full scan report."""

    check_name: str    = Field(..., examples=["csp_header"])
    priority: str      = Field(..., examples=["high"], description="critical | high | medium | low")
    title: str         = Field(..., examples=["Add Content-Security-Policy Header"])
    description: str   = Field(..., examples=["A CSP header was not detected..."])
    reference_url: Optional[str] = Field(None, examples=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"])

    model_config = {"from_attributes": True}


# ── Responses ─────────────────────────────────────────────────────────────────

class ScanCreateResponse(BaseModel):
    """Returned immediately after POST /api/v1/scans (202 Accepted)."""

    scan_id: str  = Field(..., description="UUID of the newly created scan job")
    status: str   = Field(..., examples=["running"])
    message: str  = Field(..., examples=["Scan started. Poll GET /api/v1/scans/{scan_id} for results."])


class ScanDetailResponse(BaseModel):
    """
    Full scan report returned by GET /api/v1/scans/{scan_id}.

    While the scan is still running, checks and recommendations will be
    empty lists and score will be null.
    """

    scan_id: str
    url: str
    status: str
    score: Optional[int]          = Field(None, ge=0, le=100)
    created_at: datetime
    scan_duration: Optional[float] = Field(None, description="Total scan time in seconds")
    error_message: Optional[str]  = None
    checks: List[CheckResultSchema]          = Field(default_factory=list)
    recommendations: List[RecommendationSchema] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    """Lightweight scan row used in the history list."""

    scan_id: str
    url: str
    status: str
    score: Optional[int] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    """Paginated list of past scans returned by GET /api/v1/scans."""

    total: int   = Field(..., description="Total number of scans in the database")
    page: int    = Field(..., ge=1)
    limit: int   = Field(..., ge=1, le=100)
    scans: List[ScanSummary] = Field(default_factory=list)
