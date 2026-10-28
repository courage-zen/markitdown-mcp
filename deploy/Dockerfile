# markitdown-mcp container image.
# Built in CI for linux/amd64 and linux/arm64; also buildable locally:
#   docker build -t markitdown-mcp -f deploy/Dockerfile .
FROM python:3.12-slim

# uv for dependency installation from the lockfile (much faster than pip)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Install dependencies first so this layer caches independently of code changes.
# README.md is needed by the build (hatchling reads it via pyproject).
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

# Application code (installed as the project itself)
COPY markitdown_mcp/ ./markitdown_mcp/
RUN uv sync --frozen --no-dev

ENV MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    PATH="/app/.venv/bin:$PATH"

EXPOSE 8000

# The auth-exempt health endpoint backs this check.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

CMD ["python", "-m", "markitdown_mcp"]
