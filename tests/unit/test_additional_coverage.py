"""
Additional coverage for the security helpers in markitdown_mcp.security.
"""

import base64
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from markitdown_mcp.security import (
    SecurityError,
    extract_text_from_binary,
    safe_convert_with_limits,
    sanitize_unicode_text,
    validate_base64,
    validate_file_content_security,
    validate_json_security,
    validate_xml_security,
    with_timeout,
)


def _temp_file(content, suffix: str, mode: str = "w") -> str:
    """Create a temp file with the given content; caller unlinks it."""
    with tempfile.NamedTemporaryFile(mode=mode, suffix=suffix, delete=False) as f:
        f.write(content)
        return f.name


class TestAdditionalCoverage:
    """Test additional code paths to improve coverage."""

    def test_xml_security_validation_dangerous_entities(self):
        """Test XML security validation catches dangerous entities."""
        dangerous_xml = '''<?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>'''

        temp_path = _temp_file(dangerous_xml, ".xml")

        try:
            with pytest.raises(SecurityError, match="dangerous XML entities"):
                validate_xml_security(temp_path)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_xml_security_validation_too_many_entities(self):
        """Test XML security validation catches too many entities."""
        entities = "".join(f"<!ENTITY ent{i} 'value{i}'>" for i in range(15))
        dangerous_xml = f'''<?xml version="1.0"?>
        <!DOCTYPE foo [{entities}]>
        <root>test</root>'''

        temp_path = _temp_file(dangerous_xml, ".xml")

        try:
            with pytest.raises(SecurityError, match="too many XML entities"):
                validate_xml_security(temp_path)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_xml_security_validation_safe_content(self):
        """Test XML security validation with safe content."""
        safe_xml = '''<?xml version="1.0"?>
        <root><child>Safe content</child></root>'''

        temp_path = _temp_file(safe_xml, ".xml")

        try:
            # Should return sanitized content path
            result = validate_xml_security(temp_path)
            assert Path(result).exists()
            if result != temp_path:
                Path(result).unlink(missing_ok=True)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_json_security_validation_large_file(self):
        """Test JSON security validation catches large files."""
        large_data = {"key": "x" * (11 * 1024 * 1024)}
        temp_path = _temp_file(json.dumps(large_data), ".json")

        try:
            with pytest.raises(SecurityError, match="JSON file too large"):
                validate_json_security(temp_path)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_json_security_validation_deep_nesting(self):
        """Test JSON security validation catches deep nesting."""
        nested: dict = {}
        current = nested
        for _ in range(35):
            current["level"] = {}
            current = current["level"]
        current["value"] = "deep"

        temp_path = _temp_file(json.dumps(nested), ".json")

        try:
            with pytest.raises(SecurityError, match="recursion depth limit"):
                validate_json_security(temp_path)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_json_security_validation_invalid_json(self):
        """Test JSON security validation with invalid JSON."""
        temp_path = _temp_file("invalid json {", ".json")

        try:
            # Should return original path for invalid JSON
            result = validate_json_security(temp_path)
            assert result == temp_path
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_extract_text_from_binary_utf8(self):
        """Test text extraction from UTF-8 binary data."""
        result = extract_text_from_binary("Hello, world!".encode("utf-8"), "test.txt")
        assert result == "Hello, world!"

    def test_extract_text_from_binary_latin1_fallback(self):
        """Test text extraction with Latin-1 fallback."""
        result = extract_text_from_binary("Cafe resume".encode("latin-1"), "test.txt")
        assert "Cafe" in result

    def test_extract_text_from_binary_ascii_fallback(self):
        """Test text extraction with ASCII fallback."""
        result = extract_text_from_binary(b"Hello\x00\x01World\x02!", "test.bin")
        assert "Hello" in result
        assert "World" in result
        assert "!" in result

    def test_extract_text_from_binary_no_content(self):
        """Test text extraction with no readable content."""
        result = extract_text_from_binary(b"\x00\x01\x02\x03\x04\x05", "test.bin")
        assert result is None

    def test_sanitize_unicode_text_control_chars(self):
        """Test Unicode text sanitization removes dangerous characters."""
        result = sanitize_unicode_text("Hello\x00World‮")
        assert "\x00" not in result
        assert "Hello" in result
        assert "World" in result

    def test_sanitize_unicode_text_preserve_whitespace(self):
        """Test Unicode text sanitization preserves valid whitespace."""
        test_text = "Hello\n\t World\r\n"
        assert sanitize_unicode_text(test_text) == test_text

    def test_timeout_decorator_success(self):
        """Test timeout decorator with successful operation."""

        @with_timeout(timeout_seconds=1)
        def quick_operation():
            return "success"

        assert quick_operation() == "success"

    def test_timeout_decorator_exception(self):
        """Test timeout decorator when function raises exception."""

        @with_timeout(timeout_seconds=1)
        def failing_operation():
            raise ValueError("Test error")

        with pytest.raises(ValueError, match="Test error"):
            failing_operation()

    def test_timeout_decorator_no_timeout(self):
        """Test timeout decorator with default timeout."""

        @with_timeout()
        def operation():
            return "no timeout"

        assert operation() == "no timeout"

    def test_validate_base64_valid(self):
        """Test base64 validation with valid data."""
        test_data = "Hello, world!"
        encoded = base64.b64encode(test_data.encode()).decode()
        result = validate_base64(encoded)
        assert result.decode() == test_data

    def test_validate_base64_invalid(self):
        """Test base64 validation with invalid data."""
        with pytest.raises(SecurityError):
            validate_base64("invalid_base64!")

    def test_validate_base64_too_large(self):
        """Test base64 validation with data too large."""
        large_data = "x" * (11 * 1024 * 1024)
        encoded = base64.b64encode(large_data.encode()).decode()

        with pytest.raises(SecurityError):
            validate_base64(encoded, max_size=1024)

    def test_safe_convert_with_limits_success(self):
        """Test safe conversion with limits succeeds."""
        temp_path = _temp_file(b"Test content", ".txt", mode="wb")

        try:
            with patch("markitdown_mcp.security.Path.stat") as _mock_stat:
                _mock_stat.return_value.st_size = 10
                mock_instance = Mock()
                mock_result = Mock()
                mock_result.text_content = "Test content"
                mock_instance.convert.return_value = mock_result

                result = safe_convert_with_limits(mock_instance, temp_path)
                assert result.text_content == "Test content"
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_validate_file_content_security_xml(self):
        """Test file content security validation for XML files."""
        dangerous_xml = '''<?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>'''

        temp_path = _temp_file(dangerous_xml, ".xml")

        try:
            with pytest.raises(SecurityError):
                validate_file_content_security(temp_path)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_validate_file_content_security_json(self):
        """Test file content security validation for JSON files."""
        temp_path = _temp_file(json.dumps({"test": "data"}), ".json")

        try:
            assert validate_file_content_security(temp_path) == temp_path
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_validate_file_content_security_csv(self):
        """Test file content security validation for CSV files."""
        temp_path = _temp_file("name,value\ntest,123\n", ".csv")

        try:
            assert validate_file_content_security(temp_path) == temp_path
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_validate_file_content_security_other(self):
        """Test file content security validation for other file types."""
        temp_path = _temp_file("Plain text content", ".txt")

        try:
            assert validate_file_content_security(temp_path) == temp_path
        finally:
            Path(temp_path).unlink(missing_ok=True)
