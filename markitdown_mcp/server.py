#!/usr/bin/env python3
"""MarkItDown MCP Server — converts documents to Markdown over Streamable HTTP.

Exposes two MCP tools (``convert_file``, ``list_supported_formats``) via the
official MCP Python SDK, served as a stateless Streamable HTTP endpoint with
optional Bearer-token authentication.
"""

import logging
import os

from dotenv import load_dotenv
from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from markitdown_mcp.conversion import convert_file_impl, list_supported_formats_impl

# Load .env once at server startup
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("markitdown-mcp")

mcp = MCPServer("markitdown-mcp", version="2.2.1")

_raw = os.getenv("MCP_AUTH_KEY", "")
AUTH_KEYS: set[str] = {k.strip() for k in _raw.split(",") if k.strip()}


class AuthKeyMiddleware:
    """ASGI middleware that validates a pre-shared key via Bearer token.

    If MCP_AUTH_KEY is configured, all requests must include:
        Authorization: Bearer <key>

    Multiple keys can be set with comma separation:
        MCP_AUTH_KEY=agent1-key,agent2-key,agent3-key

    The /health endpoint is exempt from authentication.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not AUTH_KEYS or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Exempt health check
        if scope.get("path") == "/health":
            await self.app(scope, receive, send)
            return

        auth_header = self._get_header(scope, "authorization") or ""
        key = _extract_bearer_token(auth_header)

        if key is None or key not in AUTH_KEYS:
            response = JSONResponse(
                {"error": "unauthorized", "message": "Invalid or missing authentication key"},
                status_code=401,
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)

    @staticmethod
    def _get_header(scope: Scope, name: str) -> str | None:
        """Extract a header value from ASGI scope without consuming the receive stream."""
        name_lower = name.lower()
        headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
        for key, value in headers:
            decoded: str = key.decode("latin-1").lower()
            if decoded == name_lower:
                result: str = value.decode("latin-1")
                return result
        return None


def _extract_bearer_token(header: str) -> str | None:
    """Extract the token from a Bearer authorization header."""
    if not header.lower().startswith("bearer "):
        return None
    token = header[7:].strip()
    return token or None


@mcp.tool(name="convert_file")
async def convert_file_tool(
    file_path: str = "",
    file_content: str = "",
    filename: str = "",
    s3_key: str = "",
) -> str:
    """Convert one document to Markdown. Supported: pdf, docx, pptx, xlsx,
    xls, csv, json, xml, html, epub, zip, txt, md, rst, images.

    Inputs are mutually alternative — pass exactly ONE of:
      1. file_path: path on the SERVER's filesystem (not your local
         machine). Use only for files already visible to the server.
      2. s3_key: object key in the configured S3/MinIO store. PREFERRED
         for platform-stored attachments. For multica attachments the key
         is "workspaces/$MULTICA_WORKSPACE_ID/<attachment-id><ext>", where
         <attachment-id> is the attachment's UUID and <ext> (including the
         dot) comes from the attachment's filename. Keys outside the
         configured prefixes are rejected. Optionally pass filename for a
         nicer display name / correct suffix.
      3. file_content: the raw bytes, base64-encoded (standard alphabet,
         single line, no data URI prefix). Max 10 MB decoded. Use for
         small files you already have in memory; pass filename too (its
         extension is required for format detection).

    Priority when several are given: file_path > s3_key > file_content.
    """
    return await convert_file_impl(
        file_path=file_path,
        file_content=file_content,
        filename=filename,
        s3_key=s3_key,
    )


@mcp.tool(name="list_supported_formats")
async def list_supported_formats_tool() -> str:
    """List all supported file formats for conversion."""
    return await list_supported_formats_impl()


@mcp.custom_route("/health", methods=["GET"])  # type: ignore[untyped-decorator]
async def health_check(request: Request) -> JSONResponse:  # noqa: ARG001
    """Health endpoint for k8s probes; exempt from authentication."""
    return JSONResponse({"status": "ok", "server": "markitdown-mcp"})


def build_app() -> ASGIApp:
    """Build the Starlette ASGI app (streamable HTTP + auth middleware)."""
    app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        host=os.getenv("MCP_HOST", "0.0.0.0"),
    )
    app.add_middleware(AuthKeyMiddleware)
    return app


def main() -> None:
    """Run the MCP server with uvicorn."""
    import uvicorn

    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "8000"))

    app = build_app()

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level=os.getenv("MCP_LOG_LEVEL", "info").lower(),
    )
    server = uvicorn.Server(config)
    import anyio

    anyio.run(server.serve)
