"""
Unit tests for the convert_file MCP tool.

convert_file accepts exactly one input source — an S3 object key. These tests
drive the tool with moto's S3 backend and assert the s3-only contract:
valid keys convert, invalid keys are rejected before any download, and
legacy inputs (file_path / file_content) are refused with guidance.
"""

import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from moto import mock_aws

from markitdown_mcp.conversion import convert_file_impl
from markitdown_mcp.security import validate_file_content_security
from tests.helpers.file_utils import create_minimal_docx, create_minimal_xlsx


@contextmanager
def aws_backend():
    """Enter moto's mock backend.

    moto's own ``mock_aws`` decorator wraps the test function in a plain
    sync wrapper, which hides the coroutine function from pytest-asyncio's
    collection ("async def functions are not natively supported"). The
    context-manager form keeps the async test function intact.
    """
    with mock_aws():
        yield


def _env(monkeypatch, **overrides: str) -> None:
    """Set a complete S3 env block, applying overrides on top."""
    base = {
        "S3_BUCKET": "multica-uploads",
        "AWS_ACCESS_KEY_ID": "testkey",
        "AWS_SECRET_ACCESS_KEY": "testsecret",
        "AWS_ENDPOINT_URL": "",
        "S3_REGION": "us-east-1",
    }
    base.update(overrides)
    # Remove keys explicitly set to "" so overrides can blank a value.
    for name, value in base.items():
        if value == "":
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def _make_bucket(region: str = "us-east-1", bucket: str = "multica-uploads"):
    """Create the bucket inside the current moto backend and return a client.

    Credentials are passed explicitly: the env vars the config reads are what
    _env() set, and with mock_aws active boto3's own env-resolution can pick
    the mock's placeholder key instead — which moto then rejects as unknown.
    """
    import os

    import boto3

    client = boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    )
    client.create_bucket(Bucket=bucket)
    return client


def _tool_error(exc_info: pytest.ExceptionInfo) -> str:
    """Return the sanitized error message from a ToolError."""
    return str(exc_info.value)


class TestConvertFileBasicFunctionality:
    """convert_file converts objects fetched from S3 by key."""

    @pytest.mark.unit
    async def test_convert_text_object(self, monkeypatch):
        _env(monkeypatch)
        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/sample.txt",
                Body=b"Hello, World!\nThis is a test file.\nWith multiple lines.",
            )

            result = await convert_file_impl(s3_key="workspaces/ws-1/sample.txt")

        assert "Successfully converted" in result
        assert "sample.txt" in result
        assert "This is a test file" in result
        assert "multiple lines" in result

    @pytest.mark.unit
    async def test_convert_json_object(self, monkeypatch):
        _env(monkeypatch)
        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/sample.json",
                Body=b'{"name": "Test Document", "data": [1, 2, 3]}',
            )

            result = await convert_file_impl(s3_key="workspaces/ws-1/sample.json")

        assert "Successfully converted" in result
        assert "sample.json" in result
        assert "test" in result.lower()

    @pytest.mark.unit
    async def test_convert_csv_object(self, monkeypatch):
        _env(monkeypatch)
        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/sample.csv",
                Body=b"Name,Age,City\nJohn Doe,25,NYC\nJane Smith,30,London",
            )

            result = await convert_file_impl(s3_key="workspaces/ws-1/sample.csv")

        assert "Successfully converted" in result
        assert "sample.csv" in result
        assert "John Doe" in result

    @pytest.mark.unit
    async def test_convert_html_object(self, monkeypatch):
        _env(monkeypatch)
        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/sample.html",
                Body=b"<html><body><h1>Main Heading</h1><p>Content</p></body></html>",
            )

            result = await convert_file_impl(s3_key="workspaces/ws-1/sample.html")

        assert "Successfully converted" in result
        assert "Main Heading" in result

    @pytest.mark.unit
    async def test_filename_overrides_display_name(self, monkeypatch):
        _env(monkeypatch)
        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/01a184fc-2434-7856-9461-7703c5da35a1.xlsx",
                Body=b"placeholder",
            )

            result = await convert_file_impl(
                s3_key="workspaces/ws-1/01a184fc-2434-7856-9461-7703c5da35a1.xlsx",
                filename="2026年江苏电信盲评表.xlsx",
            )

        assert "Successfully converted" in result
        assert "2026年江苏电信盲评表.xlsx" in result
        assert "01a184fc" not in result

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

class TestConvertFileLegacyInputsRejected:
    """The removed inputs (file_path / file_content) are refused.

    The enforcement boundary for client calls is the tool schema (see
    TestConvertFileViaMCPClient.test_legacy_file_path_over_mcp_is_rejected);
    at the Python level the strict signature simply does not accept the
    legacy kwargs.
    """

    @pytest.mark.unit
    async def test_file_path_is_rejected(self, monkeypatch, temp_dir):
        _env(monkeypatch)
        local = Path(temp_dir) / "sample.txt"
        local.write_text("local file content")

        with pytest.raises(TypeError, match="file_path"):
            await convert_file_impl(file_path=str(local))

    @pytest.mark.unit
    async def test_file_content_is_rejected(self, monkeypatch):
        import base64

        _env(monkeypatch)
        with pytest.raises(TypeError, match="file_content"):
            await convert_file_impl(
                file_content=base64.b64encode(b"hello").decode(), filename="hello.txt"
            )

    @pytest.mark.unit
    async def test_no_input_is_rejected(self, monkeypatch):
        _env(monkeypatch)
        with pytest.raises(TypeError, match="s3_key"):
            await convert_file_impl()


class TestConvertFileErrorCases:
    """Error handling in convert_file tool."""

    @pytest.mark.unit
    async def test_missing_object_error(self, monkeypatch):
        """A key that does not exist fails with a sanitized message."""
        _env(monkeypatch)
        with aws_backend():
            _make_bucket()

            with pytest.raises(ToolError) as exc_info:
                await convert_file_impl(s3_key="workspaces/ws-1/nonexistent.txt")

        message = _tool_error(exc_info).lower()
        assert "not found" in message or "not accessible" in message
        # No bucket or endpoint details leak.
        assert "multica-uploads" not in message

    @pytest.mark.unit
    async def test_empty_key_error(self, monkeypatch):
        _env(monkeypatch)
        with pytest.raises(ToolError) as exc_info:
            await convert_file_impl(s3_key="   ")

        assert "security violation" in _tool_error(exc_info).lower()

    @pytest.mark.unit
    async def test_dangerous_extension_rejected(self, monkeypatch):
        _env(monkeypatch)
        with pytest.raises(ToolError, match="(?i)security violation"):
            await convert_file_impl(s3_key="workspaces/ws-1/payload.exe")

    @pytest.mark.unit
    async def test_unconfigured_s3_reports_not_configured(self, monkeypatch):
        _env(
            monkeypatch,
            S3_BUCKET="",
            AWS_ACCESS_KEY_ID="",
            AWS_SECRET_ACCESS_KEY="",
        )
        with pytest.raises(ToolError, match="(?i)not configured"):
            await convert_file_impl(s3_key="workspaces/ws-1/report.txt")


class TestConvertFileEdgeCases:
    """Edge cases for convert_file tool."""

    @pytest.mark.unit
    async def test_empty_object_conversion(self, monkeypatch):
        """Converting a zero-byte object."""
        _env(monkeypatch)
        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads", Key="workspaces/ws-1/empty.txt", Body=b""
            )

            result = await convert_file_impl(s3_key="workspaces/ws-1/empty.txt")

        assert "Successfully converted" in result

    @pytest.mark.unit
    async def test_unicode_filename_display(self, monkeypatch):
        """A filename with unicode characters shows up in the success message."""
        _env(monkeypatch)
        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/attachment-1.txt",
                Body="Unicode test: 你好世界 🌍 émojis and accénts".encode(),
            )

            result = await convert_file_impl(
                s3_key="workspaces/ws-1/attachment-1.txt",
                filename="测试文件_🚀_test.txt",
            )

        assert "Successfully converted" in result
        assert "测试文件" in result
        assert "你好世界" in result

    @pytest.mark.unit
    async def test_unicode_object_content(self, monkeypatch):
        _env(monkeypatch)
        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/unicode.txt",
                Body="Unicode test: 你好世界 🌍 émojis and accénts".encode(),
            )

            result = await convert_file_impl(s3_key="workspaces/ws-1/unicode.txt")

        assert "Successfully converted" in result
        assert "你好世界" in result
        assert "émojis" in result


class TestConvertFileFormats:
    """Test convert_file with various object formats."""

    @pytest.mark.unit
    @pytest.mark.parametrize("file_extension", [".txt", ".json", ".csv", ".html", ".xml", ".md"])
    async def test_supported_text_formats(self, monkeypatch, file_extension):
        """Test conversion of various supported formats stored in S3."""
        content_map = {
            ".txt": "Plain text content",
            ".json": '{"key": "value", "number": 42}',
            ".csv": "Name,Age\nAlice,30\nBob,25",
            ".html": "<html><body><h1>Title</h1><p>Content</p></body></html>",
            ".xml": '<?xml version="1.0"?><root><item>value</item></root>',
            ".md": "# Markdown Title\n\nSome **bold** text.",
        }

        _env(monkeypatch)
        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key=f"workspaces/ws-1/test{file_extension}",
                Body=content_map[file_extension].encode(),
            )

            result = await convert_file_impl(s3_key=f"workspaces/ws-1/test{file_extension}")

        # Should succeed for all supported formats
        assert "Successfully converted" in result


class TestConvertFileSecurityAspects:
    """Security aspects of convert_file tool."""

    @pytest.mark.unit
    @pytest.mark.security
    async def test_key_traversal_rejected(self, monkeypatch):
        """Keys with traversal segments are rejected before any download."""
        _env(monkeypatch)
        for malicious_key in [
            "workspaces/../etc/passwd",
            "workspaces/ws/../../secret.txt",
            "..\\..\\windows\\system32\\config\\sam",
        ]:
            with pytest.raises(ToolError, match="(?i)security violation"):
                await convert_file_impl(s3_key=malicious_key)

    @pytest.mark.unit
    @pytest.mark.security
    async def test_prefix_allowlist_enforced(self, monkeypatch):
        _env(monkeypatch, S3_KEY_PREFIXES="workspaces/allowed")
        with pytest.raises(ToolError, match="(?i)security violation"):
            await convert_file_impl(s3_key="users/42/report.txt")

    @pytest.mark.unit
    @pytest.mark.security
    async def test_error_messages_are_sanitized(self, monkeypatch):
        """Error messages must not leak tracebacks or S3 internals."""
        _env(monkeypatch)
        with aws_backend():
            _make_bucket()
            # A corrupt docx: conversion fails after download.
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/bad.docx",
                Body=b"this is not a real docx",
            )

            try:
                await convert_file_impl(s3_key="workspaces/ws-1/bad.docx")
            except ToolError as e:
                error_msg = str(e).lower()
                assert "traceback" not in error_msg
                assert "exception" not in error_msg
                assert "multica-uploads" not in error_msg


class TestConvertFileViaMCPClient:
    """Test convert_file through the full MCP tool-call path."""

    @pytest.mark.unit
    async def test_tool_call_returns_text_content(self, monkeypatch):
        """Calling convert_file via MCP returns the markdown text."""
        from mcp.client import Client

        from markitdown_mcp import mcp

        _env(monkeypatch)
        with aws_backend():
            _make_bucket()
            import boto3
            import os

            client = boto3.client(
                "s3",
                region_name="us-east-1",
                aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
            )
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/sample.txt",
                Body=b"This is a test file.",
            )

            async with Client(mcp) as mcp_client:
                result = await mcp_client.call_tool(
                    "convert_file", {"s3_key": "workspaces/ws-1/sample.txt"}
                )

        assert result.is_error is not True
        text = result.content[0].text
        assert "Successfully converted" in text
        assert "This is a test file" in text

    @pytest.mark.unit
    async def test_legacy_file_path_over_mcp_is_rejected(self, monkeypatch):
        """file_path calls over MCP fail with guidance, not a crash."""
        from mcp.client import Client

        from markitdown_mcp import mcp

        _env(monkeypatch)
        async with Client(mcp) as mcp_client:
            result = await mcp_client.call_tool(
                "convert_file", {"file_path": "/etc/passwd"}
            )

        assert result.is_error is True
        error_text = result.content[0].text
        assert "s3_key" in error_text.lower()
