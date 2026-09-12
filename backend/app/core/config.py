"""
Application configuration loaded from environment variables via pydantic-settings.
All settings have safe defaults; override via the .env file.
"""

from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Application ──────────────────────────────────────────────────────────
    app_name: str = "CyberSentinel"
    app_version: str = "1.0.0"
    debug: bool = False

    # ── Server ───────────────────────────────────────────────────────────────
    host: str = "127.0.0.1"
    port: int = 8000

    # ── CORS ─────────────────────────────────────────────────────────────────
    # Stored as a comma-separated string in .env, parsed into a list below.
    allowed_origins: str = "http://localhost:3000"

    @property
    def allowed_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./cybersentinel.db"

    # ── Rate limiting ─────────────────────────────────────────────────────────
    rate_limit_scans_per_minute: int = 10

    # ── Scanner timeouts (seconds) ────────────────────────────────────────────
    connect_timeout: float = 10.0
    read_timeout: float = 15.0
    total_scan_timeout: float = 60.0

    # ── Response size cap ─────────────────────────────────────────────────────
    # Default: 5 MB
    max_response_bytes: int = 5_242_880

    # ── Redirect policy ───────────────────────────────────────────────────────
    max_redirects: int = 5

    @field_validator("rate_limit_scans_per_minute", "connect_timeout", "read_timeout", mode="before")
    @classmethod
    def must_be_positive(cls, v: int | float) -> int | float:
        if float(v) <= 0:
            raise ValueError("Value must be positive")
        return v


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton Settings instance."""
    return Settings()
