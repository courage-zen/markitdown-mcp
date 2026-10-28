#!/usr/bin/env python3
"""Tool implementations for the MarkItDown MCP server.

Each function implements one MCP tool and raises
:class:`mcp.server.mcpserver.exceptions.ToolError` with a sanitized message on
failure, so raw exception details never reach the client.
"""

import logging
import tempfile
from pathlib import Path

from markitdown import MarkItDown
from mcp.server.mcpserver.exceptions import ToolError

from markitdown_mcp.security import (
    SecurityError,
    TimeoutError,
    get_safe_working_directories,
    safe_convert_with_limits,
    validate_and_sanitize_path,
    validate_base64,
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

# Global converter instance; safe_directories is computed once at import
_markitdown: MarkItDown | None = None
_safe_directories: list[str] | None = None


def _get_converter() -> MarkItDown:
    """Lazily create the shared MarkItDown converter instance."""
    global _markitdown
    if _markitdown is None:
        _markitdown = MarkItDown()
    return _markitdown


def _get_safe_directories() -> list[str]:
    """Lazily compute the allowed working directories."""
    global _safe_directories
    if _safe_directories is None:
        _safe_directories = get_safe_working_directories()
        logger.info("Safe directories: %s", _safe_directories)
    return _safe_directories


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


async def convert_file_impl(
    file_path: str = "",
    file_content: str = "",
    filename: str = "",
) -> str:
    """Convert a single file to Markdown.

    Args:
        file_path: Path to the file to convert
        file_content: Base64 encoded file content (alternative to file_path)
        filename: Original filename when using file_content
    """
    try:
        if file_path:
            basic_path = Path(file_path)
            if not basic_path.exists():
                raise ToolError(f"File not found: {file_path}")

            try:
                validated_path, _is_safe = validate_and_sanitize_path(
                    file_path, _get_safe_directories()
                )
            except SecurityError as e:
                logger.warning("Security violation blocked: %s", e)
                raise ToolError(str(e)) from e

            import os

            if not os.access(validated_path, os.R_OK):
                raise ToolError(f"File not readable: {file_path}")

            try:
                result = safe_convert_with_limits(_get_converter(), str(validated_path))
            except (TimeoutError, SecurityError) as e:
                raise ToolError(str(e)) from e

            return (
                f"Successfully converted {validated_path.name} to "
                f"Markdown:\n\n{result.text_content}"
            )

        if file_content is not None and file_content != "" and filename:
            # Convert from base64 encoded content
            try:
                decoded_content = validate_base64(file_content)

                # Create temporary file
                with tempfile.NamedTemporaryFile(
                    suffix=Path(filename).suffix, delete=False
                ) as temp_file:
                    temp_file.write(decoded_content)
                    temp_path = temp_file.name
                del decoded_content

                try:
                    result = safe_convert_with_limits(_get_converter(), temp_path)
                    return (
                        f"Successfully converted {filename} to Markdown:\n\n{result.text_content}"
                    )
                finally:
                    # Clean up temporary file
                    Path(temp_path).unlink(missing_ok=True)

            except SecurityError as e:
                raise ToolError(str(e)) from e
            except ToolError:
                raise
            except Exception as e:
                logger.exception("Error processing file content")
                raise ToolError(_sanitize_error_message(e)) from e

        raise ToolError("Either file_path or (file_content + filename) required")

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
