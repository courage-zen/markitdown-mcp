"""
pytest configuration and shared fixtures for MarkItDown MCP server tests.
"""

import shutil
import tempfile

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory that's cleaned up after the test.

    The directory is created under the system temp location, which is on
    the server's safe-directory list.
    """
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line("markers", "unit: Unit tests - fast, isolated")
    config.addinivalue_line("markers", "integration: Integration tests - component interaction")
    config.addinivalue_line("markers", "security: Security tests - vulnerability testing")
    config.addinivalue_line("markers", "slow: Tests that take more than 10 seconds")
