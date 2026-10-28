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
        assert set(props.keys()) == {"file_path", "file_content", "filename", "s3_key"}

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


class TestMCPProtocolHandshake:
    """Protocol basics negotiated by the in-memory client."""

    @pytest.mark.unit
    async def test_initialize_negotiates_protocol(self):
        """A completed handshake populates server info and protocol version."""
        from mcp.client import Client

        async with Client(mcp) as client:
            assert client.server_info.name == "markitdown-mcp"
            assert client.server_info.version == "2.2.0"
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
    async def test_call_result_carries_text_content(self, sample_text_file):
        """A successful call returns text content blocks."""
        from mcp.client import Client

        async with Client(mcp) as client:
            result = await client.call_tool("convert_file", {"file_path": sample_text_file})

        assert result.is_error is not True
        assert result.content
        assert hasattr(result.content[0], "text")

    @pytest.mark.unit
    async def test_call_error_carries_sanitized_text(self):
        """A failing call returns isError=true, not a raised exception."""
        from mcp.client import Client

        async with Client(mcp) as client:
            result = await client.call_tool(
                "convert_file", {"file_path": "definitely_missing_file.txt"}
            )

        assert result.is_error is True
        assert result.content
        error_text = result.content[0].text
        assert "not found" in error_text.lower()


class TestFormatCatalogConsistency:
    """The advertised format catalog stays internally consistent."""

    @pytest.mark.unit
    def test_format_categories_cover_supported_extensions(self):
        """Every category extension is in SUPPORTED_EXTENSIONS."""
        from markitdown_mcp.conversion import SUPPORTED_EXTENSIONS

        for extensions in FORMAT_CATEGORIES.values():
            for ext in extensions:
                assert ext in SUPPORTED_EXTENSIONS
