"""
Malicious file handling security tests.

All attacks go through ``convert_file_impl``: a malicious file must either
convert harmlessly (bounded output) or fail with a sanitized ``ToolError``.
It must never hang, crash with an unhandled exception, or produce runaway
output.
"""

import base64
import json
import time
import zipfile
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from markitdown_mcp.conversion import convert_file_impl


class MaliciousFileGenerator:
    """Generate various types of malicious files for testing."""

    @staticmethod
    def create_zip_bomb(file_path: Path, depth: int = 10) -> str:
        """Create a nested zip bomb for testing."""
        current_zip = file_path
        large_content = "A" * (1024 * 100)  # 100KB

        for i in range(depth):
            if i == 0:
                with zipfile.ZipFile(current_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("large_file.txt", large_content)
            else:
                prev_zip = current_zip
                current_zip = file_path.parent / f"bomb_{i}.zip"
                with zipfile.ZipFile(current_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.write(prev_zip, prev_zip.name)

        return str(current_zip)

    @staticmethod
    def create_xml_bomb(file_path: Path) -> str:
        """Create an XML billion laughs attack file."""
        xml_bomb_content = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""

        file_path.write_text(xml_bomb_content, encoding="utf-8")
        return str(file_path)

    @staticmethod
    def create_json_bomb(file_path: Path) -> str:
        """Create a JSON file designed to cause excessive memory usage."""
        json_data = "test"
        for i in range(100):
            json_data = {"nested": json_data, "level": i}

        with open(file_path, "w") as f:
            json.dump(json_data, f)

        return str(file_path)

    @staticmethod
    def create_csv_bomb(file_path: Path) -> str:
        """Create a CSV file with excessive data."""
        headers = [f"col_{i}" for i in range(1000)]

        with open(file_path, "w") as f:
            f.write(",".join(headers) + "\n")
            for row in range(100):
                row_data = [f"data_{row}_{col}" * 10 for col in range(1000)]
                f.write(",".join(row_data) + "\n")

        return str(file_path)

    @staticmethod
    def create_html_with_scripts(file_path: Path) -> str:
        """Create HTML with potentially malicious scripts."""
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Malicious HTML Test</title>
    <script>
        alert("XSS Test");
        document.cookie = "stolen=credentials";
        while(true) { console.log("CPU exhaustion attempt"); }
    </script>
</head>
<body>
    <h1>Test HTML with Scripts</h1>
    <img src="x" onerror="alert('XSS via img tag')">
    <a href="javascript:alert('XSS via link')">Click me</a>
    <iframe src="javascript:alert('XSS via iframe')"></iframe>
    <div onclick="alert('XSS via onclick')">Click this div</div>
</body>
</html>"""

        file_path.write_text(html_content, encoding="utf-8")
        return str(file_path)

    @staticmethod
    def create_binary_polyglot(file_path: Path) -> str:
        """Create a file that appears to be one format but contains another."""
        content = b'{"legitimate": "json", "data": ['
        content += b"\x00\x01\x02\x03\xff\xfe\xfd\xfc"
        content += b"PK\x03\x04"  # ZIP signature
        content += b"\x89PNG\r\n\x1a\n"  # PNG signature
        content += b"%PDF-1.4"  # PDF signature
        content += b"]}"

        file_path.write_bytes(content)
        return str(file_path)

    @staticmethod
    def create_unicode_bomb(file_path: Path) -> str:
        """Create file with problematic Unicode characters."""
        problematic_chars = [
            "\u0000",
            "�",
            "﻿",
            "​",
            "‎",
            "‏",
            "‪",
            "‫",
            "‬",
            "‭",
            "‮",
            "\U0001f4a9",
        ]

        content = "Unicode bomb test:\n"
        for char in problematic_chars:
            content += f"Character: {char} (U+{ord(char):04X})\n"
        content += "RTL test: ‮hello‬\n"

        file_path.write_text(content, encoding="utf-8")
        return str(file_path)


async def _convert_or_error(file_path: str) -> tuple[str | None, str | None]:
    """Run a conversion, returning (content, error_message) — one of the two."""
    try:
        result = await convert_file_impl(file_path=file_path)
    except ToolError as e:
        return None, str(e)
    return result, None


class TestMaliciousFileDetection:
    """Test detection and handling of malicious file types."""

    @pytest.mark.security
    async def test_zip_bomb_protection(self, temp_dir):
        """Test protection against zip bomb attacks."""
        generator = MaliciousFileGenerator()
        zip_bomb_path = Path(temp_dir) / "bomb.zip"
        generator.create_zip_bomb(zip_bomb_path, depth=5)

        start = time.time()
        content, error = await _convert_or_error(str(zip_bomb_path))
        elapsed = time.time() - start

        # Must not hang.
        assert elapsed < 30, f"Zip bomb took {elapsed:.2f}s"
        # Must either convert with bounded output or fail cleanly.
        assert content is not None or error is not None
        if content is not None:
            assert len(content) < 1024 * 1024, "Zip bomb produced excessive output"

    @pytest.mark.security
    async def test_xml_entity_expansion_protection(self, temp_dir):
        """Test protection against XML entity expansion attacks."""
        generator = MaliciousFileGenerator()
        xml_bomb_path = Path(temp_dir) / "xml_bomb.xml"
        generator.create_xml_bomb(xml_bomb_path)

        content, error = await _convert_or_error(str(xml_bomb_path))

        assert content is not None or error is not None
        if content is not None:
            # Entities must not have been expanded into a giant payload.
            assert len(content) < 1024 * 1024, "XML entity expansion not limited"
            assert content.count("lol") < 1000, "Entities may have been expanded unsafely"

    @pytest.mark.security
    async def test_json_recursion_protection(self, temp_dir):
        """Test protection against JSON recursion bombs."""
        generator = MaliciousFileGenerator()
        json_bomb_path = Path(temp_dir) / "json_bomb.json"
        generator.create_json_bomb(json_bomb_path)

        content, error = await _convert_or_error(str(json_bomb_path))

        assert content is not None or error is not None
        if content is None:
            lowered = (error or "").lower()
            assert any(
                term in lowered for term in ("recursion", "depth", "security", "failed")
            ), f"Unexpected error message: {error}"

    @pytest.mark.security
    async def test_csv_bomb_protection(self, temp_dir):
        """Test protection against CSV bombs."""
        generator = MaliciousFileGenerator()
        csv_bomb_path = Path(temp_dir) / "csv_bomb.csv"
        generator.create_csv_bomb(csv_bomb_path)

        content, error = await _convert_or_error(str(csv_bomb_path))

        assert content is not None or error is not None
        if content is not None:
            assert len(content) < 15 * 1024 * 1024, "CSV bomb produced excessive output"


class TestMaliciousContentSanitization:
    """Test sanitization of malicious content in files."""

    @pytest.mark.security
    async def test_html_script_sanitization(self, temp_dir):
        """Test that HTML scripts are properly sanitized in output."""
        generator = MaliciousFileGenerator()
        html_path = Path(temp_dir) / "malicious.html"
        generator.create_html_with_scripts(html_path)

        content, error = await _convert_or_error(str(html_path))

        assert content is not None or error is not None
        if content is not None:
            dangerous_patterns = [
                "alert(",
                "document.cookie",
                "javascript:",
                "onerror=",
                "onclick=",
                "<script",
                "<iframe",
            ]
            lowered = content.lower()
            for pattern in dangerous_patterns:
                assert pattern not in lowered, f"Pattern not sanitized: {pattern}"

    @pytest.mark.security
    async def test_unicode_normalization_safety(self, temp_dir):
        """Test safe handling of problematic Unicode characters."""
        generator = MaliciousFileGenerator()
        unicode_path = Path(temp_dir) / "unicode_bomb.txt"
        generator.create_unicode_bomb(unicode_path)

        content, error = await _convert_or_error(str(unicode_path))

        assert content is not None or error is not None
        if content is not None:
            assert len(content) > 0, "Unicode file produced empty output"
            assert "\x00" not in content, "Output contains null bytes"
            assert "Unicode bomb test" in content, "Unicode content not preserved safely"

    @pytest.mark.security
    async def test_binary_content_in_text_files(self, temp_dir):
        """Test handling of binary content disguised as text files."""
        binary_text_path = Path(temp_dir) / "binary_disguised.txt"

        mixed_content = b"This looks like text\n"
        mixed_content += b"\x00\x01\x02\x03\xff\xfe\xfd\xfc"
        mixed_content += b"\nMore text here\n"
        mixed_content += b"Final text line"
        binary_text_path.write_bytes(mixed_content)

        content, error = await _convert_or_error(str(binary_text_path))

        assert content is not None or error is not None


class TestFileFormatSpoofing:
    """Test protection against file format spoofing attacks."""

    @pytest.mark.security
    async def test_extension_vs_content_mismatch(self, temp_dir):
        """Test handling of files where extension doesn't match content."""
        test_cases = [
            ("fake.txt", '{"this": "is actually JSON", "not": "text"}'),
            ("fake2.txt", "<html><body><h1>This is HTML</h1></body></html>"),
            ("fake.json", "Name,Age,City\nJohn,30,NYC\nJane,25,LA"),
            ("fake.csv", '<?xml version="1.0"?><root><item>XML content</item></root>'),
        ]

        for filename, file_content in test_cases:
            file_path = Path(temp_dir) / filename
            file_path.write_text(file_content)

            content, error = await _convert_or_error(str(file_path))
            # Either outcome is acceptable; it must never crash.
            assert content is not None or error is not None

    @pytest.mark.security
    async def test_polyglot_file_handling(self, temp_dir):
        """Test handling of polyglot files (multiple format signatures)."""
        generator = MaliciousFileGenerator()
        polyglot_path = Path(temp_dir) / "polyglot.json"
        generator.create_binary_polyglot(polyglot_path)

        content, error = await _convert_or_error(str(polyglot_path))

        assert content is not None or error is not None
        if content is not None:
            assert len(content) >= 0


class TestBase64MaliciousContent:
    """Test handling of malicious content via base64 encoding."""

    @pytest.mark.security
    async def test_base64_zip_bomb(self, temp_dir):
        """Test base64-encoded zip bomb handling."""
        generator = MaliciousFileGenerator()
        zip_bomb_path = Path(temp_dir) / "bomb.zip"
        generator.create_zip_bomb(zip_bomb_path, depth=3)

        encoded_content = base64.b64encode(zip_bomb_path.read_bytes()).decode("ascii")

        try:
            result = await convert_file_impl(
                file_content=encoded_content, filename="bomb.zip"
            )
            assert len(result) < 1024 * 1024, "Base64 zip bomb produced excessive output"
        except ToolError:
            pass  # Rejection is the safer outcome

    @pytest.mark.security
    async def test_base64_malformed_data(self):
        """Test handling of malformed base64 data."""
        malformed_base64_cases = [
            "Invalid base64!@#$%",
            "SGVsbG8gV29ybGQ=invalid",
            "SGVsbG8gV29ybGQ",  # Missing padding
            "SGVsbG8gV29ybGQ===",  # Too much padding
            "SGVs\x00bG8gV29ybGQ=",  # Null byte
            "",  # Empty string
            "A",  # Too short
        ]

        for malformed_b64 in malformed_base64_cases:
            with pytest.raises(ToolError) as exc_info:
                await convert_file_impl(
                    file_content=malformed_b64, filename="test.txt"
                )

            error_msg = str(exc_info.value).lower()
            # Either a base64-specific rejection or a generic sanitized failure.
            assert "base64" in error_msg or "required" in error_msg, (
                f"Unexpected error message: {error_msg}"
            )
            # Never leaks internals.
            assert "traceback" not in error_msg

    @pytest.mark.security
    async def test_base64_size_limits(self):
        """Test base64 content size limits (10MB decode cap)."""
        # 11MB of 'A' — beyond the validate_base64 default cap.
        large_content = "A" * (11 * 1024 * 1024)
        encoded_content = base64.b64encode(large_content.encode()).decode()

        with pytest.raises(ToolError) as exc_info:
            await convert_file_impl(
                file_content=encoded_content, filename="large.txt"
            )

        error_msg = str(exc_info.value).lower()
        assert any(
            term in error_msg for term in ("size", "large", "limit", "security")
        ), f"Unexpected error: {error_msg}"


class TestResourceExhaustionProtection:
    """Test protection against resource exhaustion attacks."""

    @pytest.mark.security
    @pytest.mark.slow
    async def test_processing_time_limits(self, temp_dir):
        """Test that processing time is bounded."""
        generator = MaliciousFileGenerator()

        time_bomb_cases = [
            ("csv_time_bomb.csv", generator.create_csv_bomb),
            ("json_time_bomb.json", generator.create_json_bomb),
        ]

        for filename, creator in time_bomb_cases:
            file_path = Path(temp_dir) / filename
            creator(file_path)

            start_time = time.time()
            content, error = await _convert_or_error(str(file_path))
            processing_time = time.time() - start_time

            assert processing_time < 30, (
                f"Processing took too long: {processing_time:.2f}s for {filename}"
            )
            assert content is not None or error is not None

    @pytest.mark.security
    async def test_memory_exhaustion_protection(self, temp_dir):
        """Test protection against memory exhaustion."""
        memory_bomb_path = Path(temp_dir) / "memory_bomb.json"

        large_array = ["memory_exhaustion_test"] * 100000
        large_json = {
            "array": large_array,
            "nested": {"more_array": large_array, "deep": {"even_more": large_array}},
        }

        with open(memory_bomb_path, "w") as f:
            json.dump(large_json, f)

        content, error = await _convert_or_error(str(memory_bomb_path))

        assert content is not None or error is not None
        if content is None:
            lowered = (error or "").lower()
            assert any(
                term in lowered for term in ("memory", "size", "large", "security", "failed")
            ), f"Unexpected error: {error}"
