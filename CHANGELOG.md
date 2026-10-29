# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-10-29

### Changed
- **`convert_file` now takes exactly one input: `s3_key` (required).** The
  server fetches the object from its configured S3-compatible store and
  converts it. This deployment serves multica agents whose attachments all
  live in MinIO, so a single, unambiguous input beats three alternative ones.
  - The `file_path` (server-local path) input is removed. The server no
    longer reads the host filesystem on any tool path.
  - The `file_content` (base64) input is removed. In practice it never
    worked for real attachments: agents hit the client-side tool-input size
    limit (~254 KB of JSON) on any file worth converting, and wasted turns
    retrying truncated or unpadded base64.
  - `filename` remains optional, purely as a display name / nicer suffix.
  - Schema: `{"s3_key": string (required), "filename": string (optional)}`.
    **Breaking** for any caller passing `file_path` or `file_content` —
    those calls now fail with a message pointing at `s3_key`.
  - S3 configuration (`S3_BUCKET` + credentials) is now required for the
    server to convert anything; unconfigured servers answer "not configured".

### Security
- The server-filesystem attack surface is gone: `convert_file` cannot read
  local paths, so traversal/symlink/allowlist path checks no longer guard a
  reachable code path. S3-key validation (``..``-segments, dangerous
  extensions, prefix allowlist) runs before any download, and all conversion
  content guards are unchanged.

## [2.2.1] - 2026-10-29

### Fixed
- **`file_content` now accepts the base64 variants agents actually produce.**
  `validate_base64` passed the raw input to `b64decode(validate=True)`, which
  rejects trailing newlines (shell `base64` output always ends with one), MIME
  76-column folding, embedded whitespace, and the URL-safe alphabet — so a
  correctly-encoded file failed with "invalid base64 data". Whitespace is now
  stripped and the URL-safe alphabet normalized before the strict decode;
  garbage is still rejected and the 10 MB decoded cap is unchanged.
- **`convert_file`'s tool description now tells agents how to pass inputs.**
  Previously a 4-line docstring left agents to guess: they tried local paths
  for `file_path` (it is a server-side path) and never used `s3_key` because
  the key-derivation rule was undocumented. The description now states the
  mutually-alternative inputs, the `file_path` > `s3_key` > `file_content`
  priority, the multica key format
  `workspaces/$MULTICA_WORKSPACE_ID/<attachment-id><ext>`, and the base64
  requirements (standard alphabet, single line, filename with extension).

## [2.2.0] - 2026-10-28

### Added
- **`s3_key` input on `convert_file`**: the server fetches an object from S3-compatible
  storage (AWS S3 or a MinIO endpoint in the same cluster) and converts it, so clients
  that store documents in object storage (e.g. multica) can convert without base64-
  encoding the body. The parameter is optional and additive; `file_path` / `file_content`
  behave exactly as before. Priority order: `file_path` > `s3_key` > `file_content`.
  - New environment variables: `S3_BUCKET`, `AWS_ACCESS_KEY_ID`,
    `AWS_SECRET_ACCESS_KEY`, `AWS_ENDPOINT_URL`, `S3_REGION`, `S3_USE_PATH_STYLE` and
    `S3_KEY_PREFIXES` (names mirror the multica backend so both can share one secret).
    With S3 unset, `s3_key` calls fail with "not configured" and the other inputs keep
    working.
  - Downloads are streamed with a 100 MB cap, a 60 s deadline and connect/read
    timeouts; the fetched file passes through the same content guards and conversion
    limits as local files.
  - New `markitdown_mcp/s3source.py` module; boto3 is the one new dependency.

### Security
- `S3_KEY_PREFIXES` restricts which object keys callers may request, matched
  segment-aware ("workspaces/abc" admits itself and its descendants, not
  "workspaces/abc123/…"). Empty means no restriction — appropriate only when every
  caller holds a trusted `MCP_AUTH_KEY`, since any key holder can otherwise read any
  object in the configured bucket. S3 errors are sanitized before reaching the client
  (no bucket, endpoint or key details).

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
