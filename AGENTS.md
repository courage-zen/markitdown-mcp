# AGENTS.md

Guidance for AI agents working on this repository. For usage of the running
server (as an MCP client), see `README.md`.

## What this repository is

An MCP server (`markitdown-mcp`) that converts documents to Markdown over
Streamable HTTP. It is built for k8s deployment: stateless, Bearer-token auth,
`/health` probes. The tool surface is exactly two tools — `convert_file` and
`list_supported_formats` — and their names and schemas are client-facing API:
changing them breaks every client. `convert_file` accepts three optional,
mutually alternative inputs (`file_path`, `s3_key`, `file_content`).

## Layout

| Path | Purpose |
|---|---|
| `markitdown_mcp/server.py` | MCPServer instance, tool registrations, `AuthKeyMiddleware`, `/health` route, uvicorn entry point |
| `markitdown_mcp/conversion.py` | Tool implementations (`convert_file_impl`, `list_supported_formats_impl`); raises `ToolError` with sanitized messages |
| `markitdown_mcp/security.py` | All safety guards: path validation, S3 key validation, content bombs, timeouts, size limits |
| `markitdown_mcp/s3source.py` | S3/MinIO object source for the `s3_key` input: env config, streamed download with size/deadline caps |
| `tests/unit/`, `tests/security/`, `tests/helpers/` | Test suite (pytest, pytest-asyncio; moto mocks S3) |
| `deploy/Dockerfile`, `deploy/k8s.yaml` | Container image and example k8s manifest |
| `.github/workflows/build.yml` | CI: ruff + mypy + pytest on push/PR |
| `.github/workflows/release.yml` | Tag-triggered release: docker images (amd64/arm64) + sdist/wheel + checksums |

## Validate before proposing a change

```sh
uv sync --frozen --dev
uv run ruff format --check . && uv run ruff check .
uv run mypy markitdown_mcp/
uv run pytest -q
```

All four must pass. CI runs the same chain.

## How to test the tools

Unit tests call the implementations directly
(`from markitdown_mcp.conversion import convert_file_impl`). Protocol-level tests
open an in-memory MCP client — note the constraint: each test must own the full
client lifecycle (`async with Client(mcp) as client:` inside the test body),
because the SDK's task group cannot be entered in one task and exited in another
(pytest-asyncio fixtures run setup/teardown in different tasks).

HTTP transport behavior (auth middleware, `/health`) is tested via Starlette's
TestClient in `tests/unit/test_server_http.py`.

## Rules

- Every change goes through a pull request; nothing is pushed straight to
  `main`. Conventional commit format (`feat:`, `fix:`, `docs:`, …).
- Do not rewrite history, force push, or delete branches.
- Do not commit secrets or tokens.
- Do not create or move tags, and do not run the release workflow, unless the
  maintainer explicitly asked for a release. A release is triggered by pushing a
  tag `v*` and must match the version in `pyproject.toml`.
- The server reads and writes files on the host it runs on. Do not add a code
  path that reads outside the paths the caller supplies or outside the
  safe-directory allowlist in `security.py`.
- New dependencies need a justification in the PR.
- The server is stateless by design. Do not introduce in-memory session state,
  client-session affinity, or SSE streams without checking with the maintainer.

## Release artifacts

The release workflow attaches to each GitHub Release:

- `markitdown-mcp-image-linux-amd64.tar.gz` and
  `markitdown-mcp-image-linux-arm64.tar.gz` — `docker load`-able images
- sdist and wheel built by `uv build`
- `checksums.txt` (sha256)

Consumers download the image tarball for their architecture, `docker load` it,
tag it for their registry, push, and deploy per `deploy/k8s.yaml`.
