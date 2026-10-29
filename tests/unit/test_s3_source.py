"""
Unit tests for the S3 object source (config + fetch) used by convert_file.
"""

import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest
from moto import mock_aws

from markitdown_mcp.s3source import S3SourceConfig, fetch_s3_object_to_tempfile


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

def _env(monkeypatch, **overrides: str) -> None:
    """Set a complete S3 env block, applying overrides on top."""
    base = {
        "S3_BUCKET": "multica-uploads",
        "AWS_ACCESS_KEY_ID": "testkey",
        "AWS_SECRET_ACCESS_KEY": "testsecret",
        "AWS_ENDPOINT_URL": "http://127.0.0.1:9000",
        "S3_REGION": "us-east-1",
    }
    base.update(overrides)
    # Remove keys explicitly set to "" so overrides can blank a value.
    for name, value in base.items():
        if value == "":
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


class TestS3SourceConfigFromEnv:
    """Environment parsing for the S3 source."""

    @pytest.mark.unit
    def test_complete_config(self, monkeypatch):
        _env(monkeypatch)
        config = S3SourceConfig.from_env()
        assert config is not None
        assert config.bucket == "multica-uploads"
        assert config.endpoint_url == "http://127.0.0.1:9000"
        assert config.region == "us-east-1"
        assert config.use_path_style is True

    @pytest.mark.unit
    def test_missing_bucket_means_unconfigured(self, monkeypatch):
        _env(monkeypatch, S3_BUCKET="")
        assert S3SourceConfig.from_env() is None

    @pytest.mark.unit
    def test_missing_credentials_mean_unconfigured(self, monkeypatch):
        _env(monkeypatch, AWS_SECRET_ACCESS_KEY="")
        assert S3SourceConfig.from_env() is None

    @pytest.mark.unit
    def test_no_endpoint_means_virtual_hosted_style(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="")
        config = S3SourceConfig.from_env()
        assert config is not None
        assert config.use_path_style is False

    @pytest.mark.unit
    def test_use_path_style_override_true(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="", S3_USE_PATH_STYLE="true")
        config = S3SourceConfig.from_env()
        assert config is not None
        assert config.use_path_style is True

    @pytest.mark.unit
    def test_use_path_style_override_false(self, monkeypatch):
        _env(monkeypatch, S3_USE_PATH_STYLE="false")
        config = S3SourceConfig.from_env()
        assert config is not None
        assert config.use_path_style is False

    @pytest.mark.unit
    def test_region_falls_back_to_aws_region(self, monkeypatch):
        _env(monkeypatch, S3_REGION="")
        monkeypatch.setenv("AWS_REGION", "eu-central-1")
        config = S3SourceConfig.from_env()
        assert config is not None
        assert config.region == "eu-central-1"

    @pytest.mark.unit
    def test_region_defaults_to_us_east_1(self, monkeypatch):
        _env(monkeypatch, S3_REGION="")
        monkeypatch.delenv("AWS_REGION", raising=False)
        config = S3SourceConfig.from_env()
        assert config is not None
        assert config.region == "us-east-1"


class TestFetchS3ObjectToTempfile:
    """Downloading an object to a local temp file."""

    @pytest.mark.unit
    def test_downloads_object_content(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="")
        config = S3SourceConfig.from_env()
        assert config is not None

        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket=config.bucket,
                Key="workspaces/ws-1/report.txt",
                Body=b"Hello from S3!",
            )

            path = fetch_s3_object_to_tempfile(config, "workspaces/ws-1/report.txt")
            try:
                assert Path(path).read_bytes() == b"Hello from S3!"
                assert Path(path).suffix == ".txt"
            finally:
                Path(path).unlink(missing_ok=True)

    @pytest.mark.unit
    def test_missing_object_raises_generic_error(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="")
        config = S3SourceConfig.from_env()
        assert config is not None

        with aws_backend():
            _make_bucket()

            with pytest.raises(Exception) as exc_info:
                fetch_s3_object_to_tempfile(config, "workspaces/ws-1/missing.txt")

            message = str(exc_info.value)
            assert "security violation" in message.lower() or "not found" in message.lower()
            # The generic error must not leak the bucket or endpoint.
            assert config.bucket not in message
            assert "127.0.0.1" not in message

    @pytest.mark.unit
    def test_object_larger_than_limit_raises_and_cleans_up(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="")
        config = S3SourceConfig.from_env()
        assert config is not None

        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket=config.bucket,
                Key="workspaces/ws-1/big.txt",
                Body=b"x" * 1024,
            )

            with pytest.raises(Exception, match="(?i)security violation"):
                fetch_s3_object_to_tempfile(
                    config, "workspaces/ws-1/big.txt", max_bytes=100
                )

            # The partial temp file must not be left behind.
            leftovers = [
                p for p in Path(tempfile.gettempdir()).glob("s3-*") if p.stat().st_size
            ]
            assert leftovers == []

    @pytest.mark.unit
    def test_zero_deadline_raises_timeout(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="")
        config = S3SourceConfig.from_env()
        assert config is not None

        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket=config.bucket,
                Key="workspaces/ws-1/report.txt",
                Body=b"Hello from S3!",
            )

            with pytest.raises(Exception, match="(?i)timed out"):
                fetch_s3_object_to_tempfile(
                    config, "workspaces/ws-1/report.txt", timeout_seconds=0
                )


class TestConvertFileS3Branch:
    """convert_file_impl's s3_key input, exercised end to end with moto."""

    @pytest.mark.unit
    async def test_convert_s3_key_returns_markdown(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="")
        from markitdown_mcp.conversion import convert_file_impl

        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/report.txt",
                Body=b"Hello from S3 object!",
            )

            result = await convert_file_impl(s3_key="workspaces/ws-1/report.txt")

        assert "Successfully converted" in result
        assert "Hello from S3 object!" in result
        # The success message names the object, not a server-side temp path.
        assert "report.txt" in result
        assert "/tmp" not in result
        assert "s3-" not in result

    @pytest.mark.unit
    async def test_filename_overrides_display_name(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="")
        from markitdown_mcp.conversion import convert_file_impl

        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/report.txt",
                Body=b"Hello from S3 object!",
            )

            result = await convert_file_impl(
                s3_key="workspaces/ws-1/report.txt", filename="original-upload.txt"
            )

        assert "Successfully converted" in result
        assert "original-upload.txt" in result

    @pytest.mark.unit
    async def test_unconfigured_s3_reports_not_configured(self, monkeypatch):
        monkeypatch.delenv("S3_BUCKET", raising=False)
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
        from mcp.server.mcpserver.exceptions import ToolError

        from markitdown_mcp.conversion import convert_file_impl

        with pytest.raises(ToolError, match="(?i)not configured"):
            await convert_file_impl(s3_key="workspaces/ws-1/report.txt")

    @pytest.mark.unit
    async def test_dangerous_extension_rejected_before_download(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="")
        from mcp.server.mcpserver.exceptions import ToolError

        from markitdown_mcp.conversion import convert_file_impl

        with pytest.raises(ToolError, match="(?i)security violation"):
            await convert_file_impl(s3_key="workspaces/ws-1/payload.exe")

    @pytest.mark.unit
    async def test_prefix_allowlist_enforced(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="", S3_KEY_PREFIXES="workspaces/allowed")
        from mcp.server.mcpserver.exceptions import ToolError

        from markitdown_mcp.conversion import convert_file_impl

        # Outside the allowed prefix: rejected before any download attempt.
        with pytest.raises(ToolError, match="(?i)security violation"):
            await convert_file_impl(s3_key="users/42/report.txt")

    @pytest.mark.unit
    async def test_prefix_allowlist_admits_in_prefix_key(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="", S3_KEY_PREFIXES="workspaces/allowed")
        from markitdown_mcp.conversion import convert_file_impl

        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/allowed/report.txt",
                Body=b"Inside allowed prefix!",
            )

            result = await convert_file_impl(s3_key="workspaces/allowed/report.txt")
            assert "Inside allowed prefix!" in result

    @pytest.mark.unit
    async def test_missing_object_gives_sanitized_tool_error(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="")
        from mcp.server.mcpserver.exceptions import ToolError

        from markitdown_mcp.conversion import convert_file_impl

        with aws_backend():
            _make_bucket()

            with pytest.raises(ToolError) as exc_info:
                await convert_file_impl(s3_key="workspaces/ws-1/missing.txt")

            message = str(exc_info.value)
            assert "multica-uploads" not in message
            assert "127.0.0.1" not in message

class TestConvertFileS3OverMCP:
    """The s3_key input through the full MCP tool-call path."""

    @pytest.mark.unit
    async def test_tools_list_schema_contains_s3_key(self):
        from mcp.client import Client

        from markitdown_mcp import mcp

        async with Client(mcp) as client:
            tools_result = await client.list_tools()
        tools = tools_result.tools
        convert_file = next(t for t in tools if t.name == "convert_file")

        schema = convert_file.input_schema
        assert "s3_key" in schema["properties"]
        # s3_key is the one required input; filename is an optional nicety.
        assert schema["properties"]["s3_key"].get("type") == "string"
        assert schema.get("required") == ["s3_key"]

    @pytest.mark.unit
    async def test_tool_call_with_s3_key(self, monkeypatch):
        _env(monkeypatch, AWS_ENDPOINT_URL="")
        from mcp.client import Client

        from markitdown_mcp import mcp

        with aws_backend():
            client_bucket = _make_bucket()
            client_bucket.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/report.txt",
                Body=b"Hello over MCP!",
            )

            async with Client(mcp) as client:
                result = await client.call_tool(
                    "convert_file", {"s3_key": "workspaces/ws-1/report.txt"}
                )

            assert result.is_error is not True
            text = result.content[0].text
            assert "Successfully converted" in text
            assert "Hello over MCP!" in text
