"""
Pytest configuration for CyberSentinel backend tests.
"""

import pytest


def pytest_configure(config):
    """Register custom markers to avoid warnings."""
    config.addinivalue_line(
        "markers",
        "network: mark test as requiring live network access (deselect with -m 'not network')",
    )


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"
