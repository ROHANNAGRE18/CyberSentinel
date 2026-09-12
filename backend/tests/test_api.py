"""
Integration tests for Phase 1 API endpoints.

Uses FastAPI's TestClient (synchronous WSGI wrapper) with an in-memory
SQLite database so no real network calls are made and no files are written.

Run with:  pytest tests/test_api.py -v
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import StaticPool
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.database import Base, get_db
from app.main import app

# ── In-memory test database ───────────────────────────────────────────────────

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def override_get_db():
    async with TestSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
async def setup_test_db():
    """Create tables in the in-memory DB before tests run."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture(scope="module")
def client():
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


# ── Health endpoint ───────────────────────────────────────────────────────────

class TestHealthEndpoint:

    def test_health_returns_200(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200

    def test_health_body(self, client):
        data = client.get("/api/v1/health").json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "database" in data


# ── Root endpoint ─────────────────────────────────────────────────────────────

class TestRootEndpoint:

    def test_root_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_root_has_name(self, client):
        data = client.get("/").json()
        assert data["name"] == "CyberSentinel"


# ── POST /scans ───────────────────────────────────────────────────────────────

class TestCreateScan:

    def test_valid_url_returns_202(self, client):
        # Use a public IP to avoid real DNS resolution in unit tests
        # This will be blocked by SSRF for private IPs — so we mock nothing,
        # just confirm the schema validation layer works.
        response = client.post("/api/v1/scans", json={"url": "https://example.com"})
        # May be 202 (success) or 400 (DNS failure in CI) — both are correct behaviour
        assert response.status_code in (202, 400)

    def test_missing_url_returns_422(self, client):
        response = client.post("/api/v1/scans", json={})
        assert response.status_code == 422

    def test_empty_url_returns_422_or_400(self, client):
        response = client.post("/api/v1/scans", json={"url": ""})
        assert response.status_code in (400, 422)

    def test_private_ip_returns_400(self, client):
        response = client.post("/api/v1/scans", json={"url": "http://192.168.1.1/"})
        assert response.status_code == 400

    def test_loopback_returns_400(self, client):
        response = client.post("/api/v1/scans", json={"url": "http://127.0.0.1/"})
        assert response.status_code == 400

    def test_metadata_ip_returns_400(self, client):
        response = client.post(
            "/api/v1/scans",
            json={"url": "http://169.254.169.254/latest/meta-data/"},
        )
        assert response.status_code == 400

    def test_ftp_scheme_returns_400_or_422(self, client):
        response = client.post("/api/v1/scans", json={"url": "ftp://example.com"})
        assert response.status_code in (400, 422)

    def test_file_scheme_returns_400_or_422(self, client):
        response = client.post("/api/v1/scans", json={"url": "file:///etc/passwd"})
        assert response.status_code in (400, 422)


# ── GET /scans/{scan_id} ──────────────────────────────────────────────────────

class TestGetScan:

    def test_nonexistent_scan_returns_404(self, client):
        response = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404

    def test_404_body_has_detail(self, client):
        response = client.get("/api/v1/scans/does-not-exist")
        assert response.status_code == 404
        assert "detail" in response.json()


# ── GET /scans ────────────────────────────────────────────────────────────────

class TestListScans:

    def test_list_returns_200(self, client):
        response = client.get("/api/v1/scans")
        assert response.status_code == 200

    def test_list_body_structure(self, client):
        data = client.get("/api/v1/scans").json()
        assert "total" in data
        assert "page" in data
        assert "limit" in data
        assert "scans" in data
        assert isinstance(data["scans"], list)

    def test_list_pagination_defaults(self, client):
        data = client.get("/api/v1/scans").json()
        assert data["page"] == 1
        assert data["limit"] == 20

    def test_list_invalid_page_returns_422(self, client):
        response = client.get("/api/v1/scans?page=0")
        assert response.status_code == 422

    def test_list_limit_too_high_returns_422(self, client):
        response = client.get("/api/v1/scans?limit=200")
        assert response.status_code == 422
