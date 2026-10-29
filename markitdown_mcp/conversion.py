#!/usr/bin/env python3
"""Tool implementations for the MarkItDown MCP server.

Each function implements one MCP tool and raises
:class:`mcp.server.mcpserver.exceptions.ToolError` with a sanitized message on
failure, so raw exception details never reach the client.
"""

import logging
from pathlib import Path

from markitdown import MarkItDown
from mcp.server.mcpserver.exceptions import ToolError

from markitdown_mcp.s3source import S3SourceConfig, fetch_s3_object_to_tempfile
from markitdown_mcp.security import (
    SecurityError,
    TimeoutError,
    safe_convert_with_limits,
    validate_s3_key,
)

logger = logging.getLogger("markitdown-mcp")

SUPPORTED_EXTENSIONS = {
    # Office documents
    ".pdf",
    ".docx",
    ".pptx",
    ".xlsx",
    ".xls",
    # Web and markup
    ".html",
    ".htm",
    # Data formats
    ".csv",
    ".json",
    ".xml",
    # Archives
    ".zip",
    # E-books
    ".epub",
    # Images (common formats)
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".tiff",
    ".tif",
    ".webp",
    # Text files
    ".txt",
    ".md",
    ".rst",
}

FORMAT_CATEGORIES: dict[str, list[str]] = {
    "Office Documents": [".pdf", ".docx", ".pptx", ".xlsx", ".xls"],
    "Web and Markup": [".html", ".htm"],
    "Data Formats": [".csv", ".json", ".xml"],
    "Archives": [".zip"],
    "E-books": [".epub"],
    "Images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp"],
    "Text Files": [".txt", ".md", ".rst"],
}

# Global converter instance; created once at first use
_markitdown: MarkItDown | None = None


def _get_converter() -> MarkItDown:
    """Lazily create the shared MarkItDown converter instance."""
    global _markitdown
    if _markitdown is None:
        _markitdown = MarkItDown()
    return _markitdown


def _sanitize_error_message(error: Exception) -> str:
    """Map a raw exception to a message safe to return to the client."""
    error_str = str(error).lower()
    if (
        "permission denied" in error_str
        or "access denied" in error_str
        or "no such file or directory" in error_str
    ):
        return "File not found or not accessible"
    if isinstance(error, (SecurityError, TimeoutError)):
        return str(error)
    if "timeout" in error_str:
        return "Operation timed out"
    if "not a directory" in error_str or any(
        word in error_str for word in ["security violation", "invalid path", "path traversal"]
    ):
        return "Invalid file path"
    return "File conversion failed"


async def convert_file_impl(s3_key: str, filename: str = "") -> str:
    """Convert a single S3 object to Markdown.

    Args:
        s3_key: S3 object key to fetch and convert
        filename: Optional display name (defaults to the key's basename)
    """
    try:
        config = S3SourceConfig.from_env()
        if config is None:
            raise ToolError(
                "S3 input is not configured on this server; ask the operator "
                "to set S3_BUCKET and credentials"
            )

        try:
            key = validate_s3_key(s3_key, config.allowed_key_prefixes(), bucket=config.bucket)
        except SecurityError as e:
            logger.warning("Security violation blocked: %s", e)
            raise ToolError(str(e)) from e

        display_name = filename.strip() or s3_key.rsplit("/", 1)[-1]

        temp_path = None
        try:
            temp_path = fetch_s3_object_to_tempfile(config, key)
            result = safe_convert_with_limits(_get_converter(), temp_path)
            return f"Successfully converted {display_name} to Markdown:\n\n{result.text_content}"
        except (TimeoutError, SecurityError) as e:
            raise ToolError(str(e)) from e
        except ToolError:
            raise
        except Exception as e:
            logger.exception("Error processing S3 object %s", key)
            raise ToolError(_sanitize_error_message(e)) from e
        finally:
            if temp_path:
                Path(temp_path).unlink(missing_ok=True)

    except ToolError:
        raise
    except Exception as e:
        logger.exception("Error in convert_file tool")
        raise ToolError(_sanitize_error_message(e)) from e


async def list_supported_formats_impl() -> str:
    """List all supported file formats."""
    format_list = []
    for category, extensions in FORMAT_CATEGORIES.items():
        format_list.append(f"**{category}:**")
        for ext in extensions:
            format_list.append(f"  - {ext}")
        format_list.append("")

    return "Supported file formats for MarkItDown conversion:\n\n" + "\n".join(format_list)
