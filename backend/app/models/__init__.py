# Re-export models so Alembic's env.py can import Base and discover all tables.
from app.models.scan import Scan, CheckResult, Recommendation  # noqa: F401
