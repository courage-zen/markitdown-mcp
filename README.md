# MarkItDown MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server that converts
documents to Markdown using Microsoft's [MarkItDown](https://pypi.org/project/markitdown/)
library, served over **Streamable HTTP** for container deployments.

Built for Kubernetes: stateless (any replica can serve any request), optional
Bearer-token authentication, and a `/health` endpoint for liveness/readiness probes.

## Tools

| Tool | Description |
|------|-------------|
| `convert_file` | Convert one document to Markdown from the configured S3/MinIO store (`s3_key`, required; `filename` optional for display) |
| `list_supported_formats` | List every supported file extension, grouped by category |

Only these two tools are exposed. Since 3.0.0 `s3_key` is the **only** input to
`convert_file`: the server fetches the object from its configured S3 store.
The former `file_path` (server-local path) and `file_content` (base64) inputs
were removed — see the changelog.

## Supported formats

- **Office documents**: `.pdf` `.docx` `.pptx` `.xlsx` `.xls`
- **Web and markup**: `.html` `.htm`
- **Data formats**: `.csv` `.json` `.xml`
- **Archives**: `.zip`
- **E-books**: `.epub`
- **Images**: `.jpg` `.jpeg` `.png` `.gif` `.bmp` `.tiff` `.tif` `.webp`
- **Text**: `.txt` `.md` `.rst`

Audio formats are intentionally not advertised: the container image ships without
ffmpeg, so transcription would not work there.

## Quick start

### From source

```bash
uv sync --dev
cp .env.example .env        # edit as needed
uv run markitdown-mcp       # or: uv run python -m markitdown_mcp
```

The server listens on `http://0.0.0.0:8000/mcp`.

### From a release image

Each [GitHub release](../../releases) attaches prebuilt images for `linux/amd64`
and `linux/arm64`:

```bash
gunzip -c markitdown-mcp-image-linux-amd64.tar.gz | docker load
docker tag markitdown-mcp:v2.1.0 registry.example.com/markitdown-mcp:v2.1.0
docker push registry.example.com/markitdown-mcp:v2.1.0
```

Or build it yourself:

```bash
docker build -t markitdown-mcp -f deploy/Dockerfile .
```

### Kubernetes

See [`deploy/k8s.yaml`](deploy/k8s.yaml) for an example Deployment + Service with
`/health` probes and `MCP_AUTH_KEY` sourced from a Secret.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_HOST` | `0.0.0.0` | Bind address |
| `MCP_PORT` | `8000` | Listen port |
| `MCP_LOG_LEVEL` | `info` | `debug` / `info` / `warning` / `error` |
| `MCP_AUTH_KEY` | *(empty)* | Bearer token(s); comma-separated for multiple. Empty disables auth — only safe on localhost |
| `MARKITDOWN_SAFE_DIRS` | *(empty)* | Extra readable directories (absolute, existing paths), path-separator separated |
| `S3_BUCKET` | *(empty)* | **Required** — bucket `convert_file` fetches objects from. With no bucket + credentials set, calls fail with "not configured" |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | *(empty)* | Credentials for the S3 input (shared names with the multica backend) |
| `AWS_ENDPOINT_URL` | *(empty)* | Custom S3 endpoint, e.g. `http://multica-minio.<ns>.svc.cluster.local:9000` for MinIO |
| `S3_REGION` | `us-east-1` | Region (falls back to `AWS_REGION`) |
| `S3_USE_PATH_STYLE` | *(auto)* | `true`/`false`; auto means path-style whenever `AWS_ENDPOINT_URL` is set |
| `S3_KEY_PREFIXES` | *(empty)* | Comma-separated key-prefix allowlist, matched segment-aware. Empty = no restriction (only safe when every caller is trusted) |

`convert_file` no longer reads server-local paths (removed in 3.0.0), so
`MARKITDOWN_SAFE_DIRS` no longer affects the tool surface; it remains for
operators running custom code against this package.

### Converting objects from S3 / MinIO (the only conversion path)

`convert_file` fetches every object from the configured S3-compatible store
itself — clients pass only a key, never file contents:

```json
{"s3_key": "workspaces/<workspace-id>/<attachment-id>.pdf", "filename": "report.pdf"}
```

Configuration is **required** for the server to convert anything: set
`S3_BUCKET` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
`AWS_ENDPOINT_URL` (pointing at the MinIO service). Without them every
`convert_file` call fails with "not configured".

For multica the key is derivable from the attachment metadata an agent already
has: `workspaces/$MULTICA_WORKSPACE_ID/<attachment-id><extension-from-filename>`.
Share the same secret the multica backend uses, and set `S3_KEY_PREFIXES` to
the workspace prefixes this deployment may read.

## HTTP API

All MCP traffic goes to `POST /mcp` (JSON request/response, stateless — no
session headers needed). With auth enabled, every request must carry
`Authorization: Bearer <key>`.

```bash
curl -s -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer $MCP_AUTH_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

`GET /health` is auth-exempt and returns `{"status":"ok"}` — use it for probes.

## Client configuration

### Claude Code

```json
{
  "mcpServers": {
    "markitdown": {
      "type": "http",
      "url": "http://localhost:8000/mcp",
      "headers": {
        "Authorization": "Bearer <your-key>"
      }
    }
  }
}
```

### Claude Desktop

```json
{
  "mcpServers": {
    "markitdown": {
      "url": "http://localhost:8000/mcp",
      "headers": {
        "Authorization": "Bearer <your-key>"
      }
    }
  }
}
```

## Development

```bash
uv sync --dev
uv run ruff format --check . && uv run ruff check .   # lint
uv run mypy markitdown_mcp/                            # types
uv run pytest -q                                       # tests
```

CI (`.github/workflows/build.yml`) runs the same chain on every push to `main`
and on every pull request.

### Releasing

Pushing a tag `v*` triggers `.github/workflows/release.yml`, which:

1. Runs the full test suite
2. Builds Docker images for `linux/amd64` and `linux/arm64` and smoke-tests the
   amd64 image end-to-end (auth, handshake, tool listing, a real conversion)
3. Verifies the tag matches `pyproject.toml` and builds the sdist/wheel
4. Publishes everything to a GitHub Release with a `checksums.txt`

## Security

- Bearer-token authentication on every endpoint except `/health`
- S3-key validation: ``..``-segment rejection, dangerous-extension blocklist,
  key-prefix allowlist — all checked before any download is attempted
- Content guards on every conversion: XML entity bombs, JSON recursion depth,
  CSV bombs, conversion timeout, output-size limit
- S3 downloads: 100 MB streamed download cap, 60 s download deadline, and
  sanitized errors (no bucket/endpoint/key details). Any `MCP_AUTH_KEY`
  holder can read objects under the allowed prefixes — scope them with
  `S3_KEY_PREFIXES` accordingly
- No server-filesystem reads and no inline uploads: the tool surface
  physically cannot reach either (removed in 3.0.0)
- Tool errors are sanitized before reaching the client — no stack traces, no
  server paths

## License

MIT — see [LICENSE](LICENSE).
