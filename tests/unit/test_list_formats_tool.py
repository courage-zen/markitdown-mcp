"""
Unit tests for the list_supported_formats MCP tool.
"""

import pytest

from markitdown_mcp.conversion import (
    FORMAT_CATEGORIES,
    SUPPORTED_EXTENSIONS,
    list_supported_formats_impl,
)


class TestListSupportedFormatsBasicFunctionality:
    """Test basic functionality of list_supported_formats tool."""

    @pytest.mark.unit
    async def test_list_formats_success(self):
        """Test successful format listing."""
        result = await list_supported_formats_impl()

        assert "Supported file formats" in result
        assert len(result) > 0

    @pytest.mark.unit
    async def test_list_formats_no_arguments_needed(self):
        """Test that list_supported_formats needs no arguments."""
        result = await list_supported_formats_impl()

        assert isinstance(result, str)
        assert "**" in result  # category headers use markdown bold


class TestListSupportedFormatsContent:
    """Test the content and structure of format listings."""

    @pytest.mark.unit
    async def test_format_categories_present(self):
        """Test that all expected format categories are present."""
        result = await list_supported_formats_impl()

        for category in FORMAT_CATEGORIES:
            assert f"**{category}:**" in result

    @pytest.mark.unit
    async def test_all_supported_extensions_listed(self):
        """Every extension in SUPPORTED_EXTENSIONS appears in the listing."""
        result = await list_supported_formats_impl()

        for ext in SUPPORTED_EXTENSIONS:
            assert ext in result, f"Extension {ext} missing from listing"

    @pytest.mark.unit
    async def test_common_formats_present(self):
        """Test that the most common formats are listed."""
        result = await list_supported_formats_impl()

        for ext in [".pdf", ".docx", ".pptx", ".xlsx", ".csv", ".json", ".html", ".txt", ".md"]:
            assert ext in result

    @pytest.mark.unit
    async def test_audio_formats_not_advertised(self):
        """Audio formats are not advertised (no ffmpeg in the container image)."""
        result = await list_supported_formats_impl()

        assert "Audio" not in result
        assert ".mp3" not in result
        assert ".wav" not in result

    @pytest.mark.unit
    async def test_category_structure(self):
        """Each category header is followed by its extension bullets."""
        result = await list_supported_formats_impl()

        for category, extensions in FORMAT_CATEGORIES.items():
            header_idx = result.find(f"**{category}:**")
            assert header_idx != -1
            section = result[header_idx : result.find("\n\n", header_idx)]
            for ext in extensions:
                assert f"- {ext}" in section


class TestListSupportedFormatsViaMCPClient:
    """Test list_supported_formats through the full MCP tool-call path."""

    @pytest.mark.unit
    async def test_tool_call_returns_listing(self):
        """Calling list_supported_formats via MCP returns the listing text."""
        from mcp.client import Client

        from markitdown_mcp import mcp

        async with Client(mcp) as client:
            result = await client.call_tool("list_supported_formats", {})

        assert result.is_error is not True
        text = result.content[0].text
        assert "Supported file formats" in text
        assert ".pdf" in text
