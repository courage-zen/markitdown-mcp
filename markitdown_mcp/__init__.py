"""MarkItDown MCP Server — document-to-Markdown conversion over Streamable HTTP.

This package provides a Model Context Protocol (MCP) server that converts
various file formats to Markdown using Microsoft's MarkItDown library, served
over stateless Streamable HTTP with optional Bearer-token authentication.

Supported formats include:
- Office documents (PDF, DOCX, PPTX, XLSX)
- Images with OCR (JPG, PNG, GIF, BMP, TIFF, WebP)
- Web/markup files (HTML, HTM)
- Data formats (CSV, JSON, XML)
- Archives (ZIP) and e-books (EPUB)
- Text files (TXT, MD, RST)
"""

__version__ = "2.1.0"

from .server import mcp

__all__ = ["mcp"]
