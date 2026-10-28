# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-10-28

### Changed
- **Transport rewritten to Streamable HTTP** on the official MCP Python SDK (mcp 2.x):
  the hand-written JSON-RPC-over-stdio implementation is gone. The server is now a
  stateless HTTP endpoint (JSON responses, no session affinity) suitable for running
  behind a Kubernetes Service with multiple replicas.
  - Optional Bearer-token authentication (`MCP_AUTH_KEY`, comma-separated for multiple
    keys); all requests without a valid token get HTTP 401.
  - `GET /health` endpoint (auth-exempt) for liveness/readiness probes.
- **Server runs with uvicorn**; entry points are `markitdown-mcp` (console script) and
  `python -m markitdown_mcp`.
- **The `convert_directory` tool is removed.** The tool surface is now exactly
  `convert_file` and `list_supported_formats`.
- Packaging switched to `uv` + `hatchling`; dependencies trimmed to
  `mcp`, `markitdown[docx,pdf,pptx,xls,xlsx]`, `uvicorn` and `python-dotenv`
  (dropped: `python-magic`, `pdf2image` and the direct pypdf/pillow/pptx pins, all
  either unused or transitively provided).
- Audio formats are no longer advertised in `list_supported_formats`: the container
  image does not include ffmpeg, so listing `.mp3`/`.wav` would be misleading.

### Added
- **GitHub release pipeline**: pushing a tag `v*` builds Docker images for
  `linux/amd64` and `linux/arm64`, exports each as
  `markitdown-mcp-image-linux-<arch>.tar.gz`, and attaches them (plus sdist, wheel and
  `checksums.txt`) to the GitHub Release. CI runs ruff + mypy + pytest on every push
  and pull request.
- `deploy/Dockerfile` and `deploy/k8s.yaml` for building and deploying from the
  release artifacts.
- `MARKITDOWN_SAFE_DIRS` environment variable to extend the server's readable
  directories in deployments (comma/path-separator separated, absolute paths only).

### Security
- All conversion-path guards from the previous architecture are retained and now run
  on every request: path validation (traversal, symlink and system-directory blocklist,
  safe-directory allowlist), XML entity-bomb defense, JSON recursion limits, CSV bomb
  detection, base64 size cap (10 MB), conversion timeout and output-size limits, and
  Unicode sanitization. Tool errors are sanitized before they reach the client.

## [1.2.2] - 2026-06-10

### Fixed
- Resolve MCP protocol and file validation issues (#44)

### Performance
- Remove artificial path validation delay (#43)

## [1.2.1] - 2026-05-28

### Fixed
- Timeout handling for large file conversions
- Memory cleanup for temporary files

## [1.2.0] - 2026-05-15

### Added
- Base64 file content support in `convert_file`
- `convert_directory` tool for batch conversions
- Enhanced security validation for file paths and content
- Comprehensive test suite (unit, integration, security, performance)

## [1.1.0] - 2026-04-20

### Added
- `list_supported_formats` tool
- Documentation and usage examples

## [1.0.0] - 2026-03-15

### Added
- Initial release: `convert_file` tool over stdio JSON-RPC
