"""
Unit tests for the convert_file MCP tool.
"""

import base64
import zipfile
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from markitdown_mcp.conversion import convert_file_impl
from markitdown_mcp.security import (
    get_safe_working_directories,
    validate_file_content_security,
)
from tests.helpers.file_utils import (
    create_minimal_docx,
    create_minimal_xlsx,
    create_test_file,
)


def _tool_error(exc_info: pytest.ExceptionInfo) -> str:
    """Return the sanitized error message from a ToolError."""
    return str(exc_info.value)


class TestConvertFileBasicFunctionality:
    """Test basic convert_file tool functionality."""

    @pytest.mark.unit
    async def test_convert_text_file_by_path(self, sample_text_file):
        """Test converting a text file using file path."""
        result = await convert_file_impl(file_path=sample_text_file)

        assert "Successfully converted" in result
        assert "sample.txt" in result
        assert "This is a test file" in result
        assert "multiple lines" in result

    @pytest.mark.unit
    async def test_convert_json_file_by_path(self, sample_json_file):
        """Test converting a JSON file using file path."""
        result = await convert_file_impl(file_path=sample_json_file)

        assert "Successfully converted" in result
        assert "sample.json" in result
        assert "test" in result.lower()

    @pytest.mark.unit
    async def test_convert_csv_file_by_path(self, sample_csv_file):
        """Test converting a CSV file using file path."""
        result = await convert_file_impl(file_path=sample_csv_file)

        assert "Successfully converted" in result
        assert "sample.csv" in result
        assert "Name,Age,City" in result or "John Doe" in result

    @pytest.mark.unit
    async def test_convert_html_file_by_path(self, sample_html_file):
        """Test converting an HTML file using file path."""
        result = await convert_file_impl(file_path=sample_html_file)

        assert "Successfully converted" in result
        assert "Main Heading" in result

    @pytest.mark.unit
    def test_ooxml_files_are_not_routed_through_xml_sanitizer(self, temp_dir):
        """DOCX/XLSX files are ZIP containers even though their MIME type contains xml."""
        docx_path = create_minimal_docx(temp_dir)
        xlsx_path = create_minimal_xlsx(temp_dir)

        for file_path in [docx_path, xlsx_path]:
            assert zipfile.is_zipfile(file_path)
            validated_path = validate_file_content_security(file_path)
            assert validated_path == file_path
            assert zipfile.is_zipfile(validated_path)

    @pytest.mark.unit
    def test_markitdown_safe_dirs_env_adds_absolute_existing_directories(
        self, monkeypatch, temp_dir
    ):
        """MARKITDOWN_SAFE_DIRS extends the operator-controlled safe directory list."""
        import os

        extra_dir = Path(temp_dir) / "extra-safe-dir"
        extra_dir.mkdir()
        missing_dir = Path(temp_dir) / "missing"
        monkeypatch.setenv(
            "MARKITDOWN_SAFE_DIRS",
            os.pathsep.join([str(extra_dir), str(missing_dir), "relative-dir"]),
        )

        safe_dirs = get_safe_working_directories()

        assert str(extra_dir.resolve()) in safe_dirs
        assert str(missing_dir.resolve()) not in safe_dirs
        assert "relative-dir" not in safe_dirs


class TestConvertFileBase64Content:
    """Test convert_file tool with base64 encoded content."""

    @pytest.mark.unit
    async def test_convert_base64_text_content(self, sample_base64_content):
        """Test converting text content via base64 encoding."""
        result = await convert_file_impl(
            file_content=sample_base64_content["encoded"],
            filename=sample_base64_content["filename"],
        )

        assert "Successfully converted" in result
        assert sample_base64_content["filename"] in result
        assert sample_base64_content["original"] in result

    @pytest.mark.unit
    async def test_convert_base64_json_content(self):
        """Test converting JSON content via base64."""
        json_content = '{"message": "Hello from base64", "type": "test"}'
        encoded_content = base64.b64encode(json_content.encode()).decode()

        result = await convert_file_impl(
            file_content=encoded_content, filename="test.json"
        )

        assert "Successfully converted" in result
        assert "Hello from base64" in result

    @pytest.mark.unit
    async def test_convert_large_base64_content(self):
        """Test converting large content via base64."""
        # 100KB of text content
        large_content = "Large content line.\n" * 5000
        encoded_content = base64.b64encode(large_content.encode()).decode()

        result = await convert_file_impl(
            file_content=encoded_content, filename="large.txt"
        )

        assert "Successfully converted" in result
        assert "Large content line" in result


class TestConvertFileErrorCases:
    """Test error handling in convert_file tool."""

    @pytest.mark.unit
    async def test_nonexistent_file_error(self):
        """Test error when file doesn't exist."""
        with pytest.raises(ToolError) as exc_info:
            await convert_file_impl(file_path="nonexistent_file.txt")

        error_msg = _tool_error(exc_info).lower()
        assert "not found" in error_msg or "security violation" in error_msg

    @pytest.mark.unit
    async def test_missing_arguments_error(self):
        """Test error when required arguments are missing."""
        with pytest.raises(ToolError) as exc_info:
            await convert_file_impl()

        assert "required" in _tool_error(exc_info).lower()

    @pytest.mark.unit
    async def test_invalid_base64_error(self):
        """Test error with invalid base64 content."""
        with pytest.raises(ToolError) as exc_info:
            await convert_file_impl(
                file_content="!!invalid-base64!!",  # This will definitely fail
                filename="test.txt",
            )

        assert "base64" in _tool_error(exc_info).lower()

    @pytest.mark.unit
    async def test_missing_filename_for_base64(self):
        """Test error when filename is missing for base64 content."""
        content = base64.b64encode(b"test content").decode()

        with pytest.raises(ToolError) as exc_info:
            await convert_file_impl(file_content=content)  # Missing filename

        assert "required" in _tool_error(exc_info).lower()


class TestConvertFileEdgeCases:
    """Test edge cases for convert_file tool."""

    @pytest.mark.unit
    async def test_empty_file_conversion(self, empty_file):
        """Test converting an empty file."""
        result = await convert_file_impl(file_path=empty_file)

        assert "Successfully converted" in result

    @pytest.mark.unit
    async def test_unicode_filename_handling(self, unicode_filename_file):
        """Test handling files with unicode characters in filename."""
        result = await convert_file_impl(file_path=unicode_filename_file)

        assert "Successfully converted" in result
        assert "Unicode filename test content" in result

    @pytest.mark.unit
    async def test_unicode_content_handling(self, temp_dir):
        """Test handling files with unicode content."""
        unicode_content = "Unicode test: 你好世界 🌍 émojis and accénts"
        unicode_file = create_test_file(unicode_content, "unicode_content.txt", temp_dir)

        result = await convert_file_impl(file_path=unicode_file)

        assert "Successfully converted" in result
        assert "你好世界" in result
        assert "émojis" in result

    @pytest.mark.unit
    async def test_binary_file_handling(self, temp_dir):
        """Test handling of binary files."""
        binary_content = bytes(range(256))  # 0-255 byte values
        binary_file = Path(temp_dir) / "binary.bin"
        binary_file.write_bytes(binary_content)

        # Should either succeed or fail with a sanitized ToolError
        try:
            result = await convert_file_impl(file_path=str(binary_file))
            assert "Successfully converted" in result
        except ToolError:
            pass


class TestConvertFileFormats:
    """Test convert_file with various file formats."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        ("file_extension"),
        [".txt", ".json", ".csv", ".html", ".xml", ".md"],
    )
    async def test_supported_text_formats(self, temp_dir, file_extension):
        """Test conversion of various supported text formats."""
        content_map = {
            ".txt": "Plain text content",
            ".json": '{"key": "value", "number": 42}',
            ".csv": "Name,Age\nAlice,30\nBob,25",
            ".html": "<html><body><h1>Title</h1><p>Content</p></body></html>",
            ".xml": '<?xml version="1.0"?><root><item>value</item></root>',
            ".md": "# Markdown Title\n\nSome **bold** text.",
        }

        content = content_map[file_extension]
        test_file = create_test_file(content, f"test{file_extension}", temp_dir)

        result = await convert_file_impl(file_path=test_file)

        # Should succeed for all supported formats
        assert "Successfully converted" in result


class TestConvertFileSecurityAspects:
    """Test security aspects of convert_file tool."""

    @pytest.mark.unit
    @pytest.mark.security
    async def test_path_traversal_prevention(self, malicious_path_attempts):
        """Test that path traversal attacks are prevented."""
        for malicious_path in malicious_path_attempts:
            with pytest.raises(ToolError):
                await convert_file_impl(file_path=malicious_path)

    @pytest.mark.unit
    @pytest.mark.security
    async def test_error_messages_are_sanitized(self, temp_dir):
        """Error messages must not leak tracebacks or exception internals."""
        # A file with an unsupported/corrupt structure for the converter
        bad_file = Path(temp_dir) / "bad.docx"
        bad_file.write_bytes(b"this is not a real docx")

        try:
            await convert_file_impl(file_path=str(bad_file))
        except ToolError as e:
            error_msg = str(e).lower()
            assert "traceback" not in error_msg
            assert "exception" not in error_msg
            # Path must not leak the full local directory structure
            assert temp_dir not in str(e)


class TestConvertFileViaMCPClient:
    """Test convert_file through the full MCP tool-call path."""

    @pytest.mark.unit
    async def test_tool_call_returns_text_content(self, sample_text_file):
        """Calling convert_file via MCP returns the markdown text."""
        from mcp.client import Client

        from markitdown_mcp import mcp

        async with Client(mcp) as client:
            result = await client.call_tool(
                "convert_file", {"file_path": sample_text_file}
            )

        assert result.is_error is not True
        text = result.content[0].text
        assert "Successfully converted" in text
        assert "This is a test file" in text

    @pytest.mark.unit
    async def test_tool_error_becomes_is_error_response(self):
        """A ToolError surfaces as isError=true with a sanitized message."""
        from mcp.client import Client

        from markitdown_mcp import mcp

        async with Client(mcp) as client:
            result = await client.call_tool(
                "convert_file", {"file_path": "nonexistent_file.txt"}
            )

        assert result.is_error is True
        error_text = result.content[0].text
        assert "not found" in error_text.lower()
