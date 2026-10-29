"""
Malicious file handling security tests.

All attacks go through ``convert_file_impl``: a malicious file must either
convert harmlessly (bounded output) or fail with a sanitized ``ToolError``.
It must never hang, crash with an unhandled exception, or produce runaway
output.
"""

import json
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from moto import mock_aws

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


@contextmanager
def _s3_backend(monkeypatch):
    """Enter moto's S3 backend with a configured server env and one bucket."""
    monkeypatch.setenv("S3_BUCKET", "multica-uploads")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testkey")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testsecret")
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("S3_REGION", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    with mock_aws():
        import boto3

        client = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id="testkey",
            aws_secret_access_key="testsecret",
        )
        client.create_bucket(Bucket="multica-uploads")
        yield client


def _upload(client, local_path: Path, key: str) -> str:
    """Upload a local file into the mock bucket; return the key used."""
    client.put_object(Bucket="multica-uploads", Key=key, Body=local_path.read_bytes())
    return key


async def _convert_or_error(file_path: str, monkeypatch) -> tuple[str | None, str | None]:
    """Run a conversion of the given local file via its S3 key.

    Uploads the file to the mock bucket and calls convert_file_impl with
    s3_key — mirroring how a caller reaches the conversion layer now that
    local-path input is gone.
    """
    key = f"workspaces/test/{Path(file_path).name}"
    with _s3_backend(monkeypatch) as client:
        _upload(client, Path(file_path), key)
        try:
            result = await convert_file_impl(s3_key=key)
        except ToolError as e:
            return None, str(e)
        return result, None


class TestMaliciousFileDetection:
    """Test detection and handling of malicious file types."""

    @pytest.mark.security
    async def test_zip_bomb_protection(self, monkeypatch, temp_dir):
        """Test protection against zip bomb attacks."""
        generator = MaliciousFileGenerator()
        zip_bomb_path = Path(temp_dir) / "bomb.zip"
        generator.create_zip_bomb(zip_bomb_path, depth=5)

        start = time.time()
        content, error = await _convert_or_error(str(zip_bomb_path), monkeypatch)
        elapsed = time.time() - start

        # Must not hang.
        assert elapsed < 30, f"Zip bomb took {elapsed:.2f}s"
        # Must either convert with bounded output or fail cleanly.
        assert content is not None or error is not None
        if content is not None:
            assert len(content) < 1024 * 1024, "Zip bomb produced excessive output"

    @pytest.mark.security
    async def test_xml_entity_expansion_protection(self, monkeypatch, temp_dir):
        """Test protection against XML entity expansion attacks."""
        generator = MaliciousFileGenerator()
        xml_bomb_path = Path(temp_dir) / "xml_bomb.xml"
        generator.create_xml_bomb(xml_bomb_path)

        content, error = await _convert_or_error(str(xml_bomb_path), monkeypatch)

        assert content is not None or error is not None
        if content is not None:
            # Entities must not have been expanded into a giant payload.
            assert len(content) < 1024 * 1024, "XML entity expansion not limited"
            assert content.count("lol") < 1000, "Entities may have been expanded unsafely"

    @pytest.mark.security
    async def test_json_recursion_protection(self, monkeypatch, temp_dir):
        """Test protection against JSON recursion bombs."""
        generator = MaliciousFileGenerator()
        json_bomb_path = Path(temp_dir) / "json_bomb.json"
        generator.create_json_bomb(json_bomb_path)

        content, error = await _convert_or_error(str(json_bomb_path), monkeypatch)

        assert content is not None or error is not None
        if content is None:
            lowered = (error or "").lower()
            assert any(
                term in lowered for term in ("recursion", "depth", "security", "failed")
            ), f"Unexpected error message: {error}"

    @pytest.mark.security
    async def test_csv_bomb_protection(self, monkeypatch, temp_dir):
        """Test protection against CSV bombs."""
        generator = MaliciousFileGenerator()
        csv_bomb_path = Path(temp_dir) / "csv_bomb.csv"
        generator.create_csv_bomb(csv_bomb_path)

        content, error = await _convert_or_error(str(csv_bomb_path), monkeypatch)

        assert content is not None or error is not None
        if content is not None:
            assert len(content) < 15 * 1024 * 1024, "CSV bomb produced excessive output"


class TestMaliciousContentSanitization:
    """Test sanitization of malicious content in files."""

    @pytest.mark.security
    async def test_html_script_sanitization(self, monkeypatch, temp_dir):
        """Test that HTML scripts are properly sanitized in output."""
        generator = MaliciousFileGenerator()
        html_path = Path(temp_dir) / "malicious.html"
        generator.create_html_with_scripts(html_path)

        content, error = await _convert_or_error(str(html_path), monkeypatch)

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
    async def test_unicode_normalization_safety(self, monkeypatch, temp_dir):
        """Test safe handling of problematic Unicode characters."""
        generator = MaliciousFileGenerator()
        unicode_path = Path(temp_dir) / "unicode_bomb.txt"
        generator.create_unicode_bomb(unicode_path)

        content, error = await _convert_or_error(str(unicode_path), monkeypatch)

        assert content is not None or error is not None
        if content is not None:
            assert len(content) > 0, "Unicode file produced empty output"
            assert "\x00" not in content, "Output contains null bytes"
            assert "Unicode bomb test" in content, "Unicode content not preserved safely"

    @pytest.mark.security
    async def test_binary_content_in_text_files(self, monkeypatch, temp_dir):
        """Test handling of binary content disguised as text files."""
        binary_text_path = Path(temp_dir) / "binary_disguised.txt"

        mixed_content = b"This looks like text\n"
        mixed_content += b"\x00\x01\x02\x03\xff\xfe\xfd\xfc"
        mixed_content += b"\nMore text here\n"
        mixed_content += b"Final text line"
        binary_text_path.write_bytes(mixed_content)

        content, error = await _convert_or_error(str(binary_text_path), monkeypatch)

        assert content is not None or error is not None


class TestFileFormatSpoofing:
    """Test protection against file format spoofing attacks."""

    @pytest.mark.security
    async def test_extension_vs_content_mismatch(self, monkeypatch, temp_dir):
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

            content, error = await _convert_or_error(str(file_path), monkeypatch)
            # Either outcome is acceptable; it must never crash.
            assert content is not None or error is not None

    @pytest.mark.security
    async def test_polyglot_file_handling(self, monkeypatch, temp_dir):
        """Test handling of polyglot files (multiple format signatures)."""
        generator = MaliciousFileGenerator()
        polyglot_path = Path(temp_dir) / "polyglot.json"
        generator.create_binary_polyglot(polyglot_path)

        content, error = await _convert_or_error(str(polyglot_path), monkeypatch)

        assert content is not None or error is not None
        if content is not None:
            assert len(content) >= 0



class TestResourceExhaustionProtection:
    """Test protection against resource exhaustion attacks."""

    @pytest.mark.security
    @pytest.mark.slow
    async def test_processing_time_limits(self, monkeypatch, temp_dir):
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
            content, error = await _convert_or_error(str(file_path), monkeypatch)
            processing_time = time.time() - start_time

            assert processing_time < 30, (
                f"Processing took too long: {processing_time:.2f}s for {filename}"
            )
            assert content is not None or error is not None

    @pytest.mark.security
    async def test_memory_exhaustion_protection(self, monkeypatch, temp_dir):
        """Test protection against memory exhaustion."""
        memory_bomb_path = Path(temp_dir) / "memory_bomb.json"

        large_array = ["memory_exhaustion_test"] * 100000
        large_json = {
            "array": large_array,
            "nested": {"more_array": large_array, "deep": {"even_more": large_array}},
        }

        with open(memory_bomb_path, "w") as f:
            json.dump(large_json, f)

        content, error = await _convert_or_error(str(memory_bomb_path), monkeypatch)

        assert content is not None or error is not None
        if content is None:
            lowered = (error or "").lower()
            assert any(
                term in lowered for term in ("memory", "size", "large", "security", "failed")
            ), f"Unexpected error: {error}"
