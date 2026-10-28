"""
pytest configuration and shared fixtures for MarkItDown MCP server tests.
"""

import base64
import json
import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory that's cleaned up after the test.

    The directory is created under the system temp location, which is on the
    server's safe-directory list.
    """
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def sample_text_file(temp_dir):
    """Create a sample text file for testing."""
    file_path = Path(temp_dir) / "sample.txt"
    content = "Hello, World!\nThis is a test file.\nWith multiple lines."
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


@pytest.fixture
def sample_json_file(temp_dir):
    """Create a sample JSON file for testing."""
    file_path = Path(temp_dir) / "sample.json"
    content = {
        "name": "Test Document",
        "type": "test",
        "data": [1, 2, 3, 4, 5],
        "metadata": {"created": "2024-01-01", "author": "Test Suite"},
    }
    file_path.write_text(json.dumps(content, indent=2), encoding="utf-8")
    return str(file_path)


@pytest.fixture
def sample_csv_file(temp_dir):
    """Create a sample CSV file for testing."""
    file_path = Path(temp_dir) / "sample.csv"
    content = """Name,Age,City,Country
John Doe,25,New York,USA
Jane Smith,30,London,UK
Bob Johnson,35,Toronto,Canada
Alice Brown,28,Sydney,Australia"""
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


@pytest.fixture
def sample_html_file(temp_dir):
    """Create a sample HTML file for testing."""
    file_path = Path(temp_dir) / "sample.html"
    content = """<!DOCTYPE html>
<html>
<head>
    <title>Test Document</title>
</head>
<body>
    <h1>Main Heading</h1>
    <p>This is a paragraph with <strong>bold text</strong> and <em>italic text</em>.</p>
    <ul>
        <li>List item 1</li>
        <li>List item 2</li>
        <li>List item 3</li>
    </ul>
</body>
</html>"""
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


@pytest.fixture
def empty_file(temp_dir):
    """Create an empty file for testing edge cases."""
    file_path = Path(temp_dir) / "empty.txt"
    file_path.touch()
    return str(file_path)


@pytest.fixture
def large_text_file(temp_dir):
    """Create a large text file for performance testing."""
    file_path = Path(temp_dir) / "large.txt"
    # Create 1MB of text content
    content = "This is a line of text for testing large file handling.\n" * 50000
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


@pytest.fixture
def unicode_filename_file(temp_dir):
    """Create a file with unicode characters in the name."""
    file_path = Path(temp_dir) / "测试文件_🚀_test.txt"
    content = "Unicode filename test content"
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


@pytest.fixture
def malicious_path_attempts():
    """Provide common malicious path patterns for security testing."""
    return [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/shadow",
        "C:\\Windows\\System32\\config\\SAM",
        "../../../../../../etc/hosts",
        "\\\\server\\share\\file.txt",
        "/dev/null",
        "/proc/version",
        "file:///etc/passwd",
        "\\x2e\\x2e/\\x2e\\x2e/etc/passwd",
    ]


@pytest.fixture
def sample_base64_content():
    """Provide sample content encoded as base64."""
    content = "This is test content for base64 encoding tests.\nSecond line of content."
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    return {"original": content, "encoded": encoded, "filename": "test.txt"}


def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line("markers", "unit: Unit tests - fast, isolated")
    config.addinivalue_line("markers", "integration: Integration tests - component interaction")
    config.addinivalue_line("markers", "security: Security tests - vulnerability testing")
    config.addinivalue_line("markers", "slow: Tests that take more than 10 seconds")
