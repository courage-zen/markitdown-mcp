"""
Protocol-level tests for the MCP server (in-memory client).

Each test opens and closes its own in-memory ``Client`` in a single task:
the client's anyio task group must be entered and exited from the same
task, which an async fixture cannot guarantee under pytest-asyncio.
"""

import pytest

from markitdown_mcp import mcp
from markitdown_mcp.conversion import FORMAT_CATEGORIES


class TestMCPServerTools:
    """The server exposes exactly the expected tool surface."""

    @pytest.mark.unit
    async def test_tools_list_contains_exactly_two_tools(self):
        """Only convert_file and list_supported_formats are exposed."""
        from mcp.client import Client

        async with Client(mcp) as client:
            result = await client.list_tools()

        tool_names = sorted(t.name for t in result.tools)
        assert tool_names == ["convert_file", "list_supported_formats"]

    @pytest.mark.unit
    async def test_convert_file_schema_shape(self):
        """convert_file keeps its parameter names for client compatibility."""
        from mcp.client import Client

        async with Client(mcp) as client:
            result = await client.list_tools()

        convert_tool = next(t for t in result.tools if t.name == "convert_file")
        props = convert_tool.input_schema["properties"]
        assert set(props.keys()) == {"s3_key", "filename"}
        # s3_key is the one required input; filename is an optional nicety.
        assert convert_tool.input_schema.get("required") == ["s3_key"]

    @pytest.mark.unit
    async def test_list_supported_formats_has_empty_schema(self):
        """list_supported_formats takes no parameters."""
        from mcp.client import Client

        async with Client(mcp) as client:
            result = await client.list_tools()

        formats_tool = next(t for t in result.tools if t.name == "list_supported_formats")
        props = formats_tool.input_schema.get("properties", {})
        assert props == {}

    @pytest.mark.unit
    async def test_tool_descriptions_present(self):
        """Both tools carry a description for client-side discovery."""
        from mcp.client import Client

        async with Client(mcp) as client:
            result = await client.list_tools()

        for tool in result.tools:
            assert tool.description
            assert len(tool.description) > 10

    @pytest.mark.unit
    async def test_convert_file_description_guides_s3_usage(self):
        """The description tells an agent how to build an s3_key — the only
        input. Without the derivation rule agents cannot use the tool."""
        from mcp.client import Client

        async with Client(mcp) as client:
            result = await client.list_tools()

        convert_tool = next(t for t in result.tools if t.name == "convert_file")
        desc = convert_tool.description or ""
        # Key derivation rule for multica-style attachments
        assert "workspaces/" in desc
        assert "MULTICA_WORKSPACE_ID" in desc
        # The removed inputs must not be advertised anymore.
        assert "file_path" not in desc
        assert "file_content" not in desc
        assert "base64" not in desc.lower()


class TestMCPProtocolHandshake:
    """Protocol basics negotiated by the in-memory client."""

    @pytest.mark.unit
    async def test_initialize_negotiates_protocol(self):
        """A completed handshake populates server info and protocol version."""
        from mcp.client import Client

        async with Client(mcp) as client:
            assert client.server_info.name == "markitdown-mcp"
            assert client.server_info.version == "3.0.0"
            assert client.protocol_version

    @pytest.mark.unit
    async def test_unknown_tool_returns_error_result(self):
        """Calling an unregistered tool yields an isError result, not a crash."""
        from mcp.client import Client

        async with Client(mcp) as client:
            result = await client.call_tool("convert_directory", {"input_directory": "/tmp"})

        assert result.is_error is True
        assert "unknown tool" in result.content[0].text.lower()

    @pytest.mark.unit
    async def test_convert_directory_tool_is_gone(self):
        """The convert_directory tool was removed in 2.1.0."""
        from mcp.client import Client

        async with Client(mcp) as client:
            result = await client.list_tools()

        assert "convert_directory" not in [t.name for t in result.tools]


class TestMCPToolCallSemantics:
    """tools/call result semantics over the in-memory transport."""

    @pytest.mark.unit
    async def test_call_error_carries_sanitized_text(self, monkeypatch):
        """A failing call returns isError=true, not a raised exception."""
        from mcp.client import Client

        from tests.unit.test_convert_file_tool import _env

        _env(monkeypatch)
        async with Client(mcp) as client:
            result = await client.call_tool(
                "convert_file", {"s3_key": "workspaces/ws/definitely-missing.txt"}
            )

        assert result.is_error is True
        assert result.content
        error_text = result.content[0].text
        assert "not found" in error_text.lower() or "not accessible" in error_text.lower()


class TestFormatCatalogConsistency:
    """The advertised format catalog stays internally consistent."""

    @pytest.mark.unit
    def test_format_categories_cover_supported_extensions(self):
        """Every category extension is in SUPPORTED_EXTENSIONS."""
        from markitdown_mcp.conversion import SUPPORTED_EXTENSIONS

        for extensions in FORMAT_CATEGORIES.values():
            for ext in extensions:
                assert ext in SUPPORTED_EXTENSIONS
