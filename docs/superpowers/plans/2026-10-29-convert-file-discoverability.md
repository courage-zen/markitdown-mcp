# convert_file Discoverability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make agents that need to read a Multica attachment reach for `convert_file` instead of hand-writing parsers: purpose-first tool descriptions, `s3_key` values that accept a pasted storage URL, and validation errors that teach the key format.

**Architecture:** All changes live in markitdown-mcp. URL normalization happens inside `validate_s3_key` (security.py) BEFORE all existing checks, so traversal/extension/prefix guards run on the normalized key and the security surface is unchanged. Spec: `docs/superpowers/specs/2026-10-29-convert-file-discoverability-design.md`.

**Tech Stack:** Python 3.10+, mcp SDK, pytest + moto, ruff/mypy gates.

---

### Task 1: URL normalization in `validate_s3_key`

**Files:**
- Modify: `markitdown_mcp/security.py:471-514`
- Test: `tests/security/test_s3_key_validation.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/security/test_s3_key_validation.py` (after `TestValidateS3KeyPrefixAllowlist`):

```python
class TestValidateS3KeyURLNormalization:
    """A full storage URL pasted as the s3_key value normalizes to its key.

    Agents copy the `url` field straight from issue/comment JSON; the server
    strips scheme/host/query so the existing checks run on the bare key.
    """

    @pytest.mark.security
    def test_path_style_url_with_bucket_segment(self):
        key = validate_s3_key(
            "http://minio.internal:9000/multica-uploads/workspaces/ws-1/report.xlsx",
            allowed_prefixes=None,
            bucket="multica-uploads",
        )
        assert key == "workspaces/ws-1/report.xlsx"

    @pytest.mark.security
    def test_virtual_hosted_url_takes_whole_path(self):
        key = validate_s3_key(
            "https://multica-uploads.s3.us-east-1.amazonaws.com/workspaces/ws-1/report.xlsx",
            allowed_prefixes=None,
            bucket="multica-uploads",
        )
        assert key == "workspaces/ws-1/report.xlsx"

    @pytest.mark.security
    def test_query_string_and_fragment_are_stripped(self):
        key = validate_s3_key(
            "http://minio.internal:9000/multica-uploads/workspaces/ws-1/report.xlsx"
            "?X-Amz-Signature=abc&X-Amz-Expires=60#frag",
            allowed_prefixes=None,
            bucket="multica-uploads",
        )
        assert key == "workspaces/ws-1/report.xlsx"

    @pytest.mark.security
    def test_no_bucket_argument_keeps_path_minus_host(self):
        # Without a known bucket name, the first path segment may still be
        # the bucket; a leading non-matching segment is preserved.
        key = validate_s3_key(
            "https://cdn.example.com/workspaces/ws-1/report.xlsx",
            allowed_prefixes=None,
            bucket="multica-uploads",
        )
        assert key == "workspaces/ws-1/report.xlsx"

    @pytest.mark.security
    def test_plain_key_with_slashes_is_not_treated_as_url(self):
        key = validate_s3_key("workspaces/ws-1/report.xlsx", allowed_prefixes=None)
        assert key == "workspaces/ws-1/report.xlsx"

    @pytest.mark.security
    def test_url_traversal_is_rejected_after_normalization(self):
        with pytest.raises(Exception, match="(?i)security violation"):
            validate_s3_key(
                "http://minio.internal:9000/multica-uploads/workspaces/../../etc/passwd",
                allowed_prefixes=None,
                bucket="multica-uploads",
            )

    @pytest.mark.security
    def test_url_prefix_allowlist_runs_on_normalized_key(self):
        # The URL carries a bucket segment then a key outside the allowlist;
        # normalization must land on the key so the prefix check rejects it.
        with pytest.raises(Exception, match="(?i)key outside allowed prefixes"):
            validate_s3_key(
                "http://minio.internal:9000/multica-uploads/users/42/report.xlsx",
                allowed_prefixes=["workspaces/allowed"],
                bucket="multica-uploads",
            )

    @pytest.mark.security
    def test_url_dangerous_extension_rejected_after_normalization(self):
        with pytest.raises(Exception, match="(?i)security violation"):
            validate_s3_key(
                "http://minio.internal:9000/multica-uploads/workspaces/ws-1/payload.exe",
                allowed_prefixes=None,
                bucket="multica-uploads",
            )

    @pytest.mark.security
    def test_unparseable_url_like_value_fails_sanitized(self):
        # "http:// with no host is not parseable; validation must still
        # reject it as a security violation, never crash with a traceback.
        with pytest.raises(Exception, match="(?i)security violation"):
            validate_s3_key("http://", allowed_prefixes=None)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/security/test_s3_key_validation.py -q`
Expected: FAIL — `validate_s3_key() got an unexpected keyword argument 'bucket'` (9 failures).

- [ ] **Step 3: Implement normalization**

In `markitdown_mcp/security.py`, add `urllib.parse` import to the import block (stdlib group, after `re`):

```python
import contextlib
import csv
import functools
import json
import re
import tempfile
import unicodedata
import urllib.parse
```

Replace the whole `validate_s3_key` function (security.py:471-514) with:

```python
def _normalize_s3_key_value(value: str, bucket: str | None) -> str:
    """Normalize a caller-supplied s3_key value to a bare object key.

    Multica's attachment JSON carries full storage URLs; agents paste them
    as-is. Strip scheme, host, port, query, and fragment; for path-style
    URLs also strip the leading bucket segment when it matches. Mirrors the
    multica backend's S3Storage.KeyFromURL host/bucket stripping.

    A value with no scheme is a plain key and passes through unchanged.
    Unparseable URL-shaped values raise SecurityError so a garbage input
    never reaches the S3 client.
    """
    if "://" not in value:
        return value

    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError as e:
        raise SecurityError("Security violation: malformed URL in S3 key") from e

    path = parsed.path or ""
    if not path.lstrip("/"):
        raise SecurityError("Security violation: URL has no object path")

    segments = [segment for segment in path.lstrip("/").split("/") if segment]
    if bucket and segments and segments[0] == bucket:
        segments = segments[1:]
    if not segments:
        raise SecurityError("Security violation: URL has no object path")

    return "/".join(segments)


def validate_s3_key(
    key: str,
    allowed_prefixes: list[str] | None = None,
    *,
    bucket: str | None = None,
) -> str:
    """Validate an S3 object key requested by a caller.

    Args:
        key: The object key to fetch (e.g. "workspaces/<ws>/<uuid>.pdf"),
            or a full storage URL, which is normalized to its key first.
        allowed_prefixes: Optional key-prefix allowlist. Empty or None means
            no restriction — only appropriate when every caller is trusted.
        bucket: Optional configured bucket name, used to strip the bucket
            segment from path-style URLs.

    Returns:
        The normalized, stripped key.

    Raises:
        SecurityError: If the key is empty, carries ``..`` segments, has a
            dangerous extension, or falls outside the prefix allowlist.
    """
    raw = key.strip() if isinstance(key, str) else ""
    if not raw:
        raise SecurityError("Security violation: empty S3 key")

    stripped = _normalize_s3_key_value(raw, bucket)

    # S3 keys are slash-separated on every platform; reject traversal segments
    # so a key can never be reinterpreted as a filesystem escape downstream.
    # Backslashes are normalized to slashes first: a Windows-styled key with
    # a ".." segment is the same escape attempt.
    normalized = stripped.replace("\\", "/")
    segments = normalized.split("/")
    if any(segment == ".." for segment in segments):
        raise SecurityError("Security violation: path traversal detected")

    # Same dangerous-extension blocklist the local path check applies, judged
    # on the key's basename (its final segment).
    from pathlib import PurePosixPath

    suffix = PurePosixPath(stripped).suffix.lower()
    if suffix in DANGEROUS_EXTENSIONS:
        raise SecurityError("Security violation: file type not allowed")

    if allowed_prefixes and not any(
        stripped == prefix or stripped.startswith(prefix + "/") for prefix in allowed_prefixes
    ):
        # Segment-aware matching: "workspaces/abc" admits exactly itself and
        # its descendants ("workspaces/abc/x.pdf"), never "workspaces/abc123".
        raise SecurityError("Security violation: key outside allowed prefixes")

    return stripped
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/security/test_s3_key_validation.py -q`
Expected: PASS (all old + 9 new).

- [ ] **Step 5: Run the full gates**

Run: `uv run ruff format --check . && uv run ruff check . && uv run mypy markitdown_mcp/ && uv run pytest -q`
Expected: all pass (existing `validate_s3_key` callers pass no `bucket` — keyword-only, so no call sites break).

- [ ] **Step 6: Commit**

```bash
git add markitdown_mcp/security.py tests/security/test_s3_key_validation.py
git commit -m "feat: s3_key accepts a full storage URL, normalized before validation"
```

---

### Task 2: Teaching error message on prefix rejection

**Files:**
- Modify: `markitdown_mcp/security.py` (the prefix-rejection branch from Task 1)
- Modify: `markitdown_mcp/conversion.py:116` (pass `bucket` into `validate_s3_key`)
- Test: `tests/unit/test_convert_file_tool.py`

- [ ] **Step 1: Write the failing tests**

Add to `TestConvertFileSecurityAspects` in `tests/unit/test_convert_file_tool.py` (after `test_prefix_allowlist_enforced`):

```python
    @pytest.mark.unit
    @pytest.mark.security
    async def test_prefix_rejection_teaches_key_format(self, monkeypatch):
        """A wrong-prefix failure tells the agent how to build the key.

        This is the one message an agent that guessed wrong will read; the
        template turns one failed call into a self-correction.
        """
        _env(monkeypatch, S3_KEY_PREFIXES="workspaces/allowed")
        with pytest.raises(ToolError) as exc_info:
            await convert_file_impl(s3_key="users/42/report.txt")

        message = str(exc_info.value)
        assert "workspaces/<workspace-id>/<attachment-id>" in message
        assert "url" in message.lower()

    @pytest.mark.unit
    @pytest.mark.security
    async def test_prefix_rejection_teaches_key_format_for_url_too(self, monkeypatch):
        """The teaching message fires for URL-shaped inputs as well."""
        _env(monkeypatch, S3_KEY_PREFIXES="workspaces/allowed")
        with pytest.raises(ToolError) as exc_info:
            await convert_file_impl(
                s3_key="http://minio.internal:9000/multica-uploads/users/42/report.txt"
            )

        message = str(exc_info.value)
        assert "workspaces/<workspace-id>/<attachment-id>" in message
        assert "url" in message.lower()
        # No deployment details leak.
        assert "minio.internal" not in message
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_convert_file_tool.py -q -k "teaches"`
Expected: FAIL — current message is bare "Security violation: key outside allowed prefixes" (2 failures).

- [ ] **Step 3: Implement the message and thread `bucket`**

In `markitdown_mcp/security.py`, replace the prefix-rejection raise inside `validate_s3_key`:

```python
    if allowed_prefixes and not any(
        stripped == prefix or stripped.startswith(prefix + "/") for prefix in allowed_prefixes
    ):
        # Segment-aware matching: "workspaces/abc" admits exactly itself and
        # its descendants ("workspaces/abc/x.pdf"), never "workspaces/abc123".
        raise SecurityError(
            'Security violation: key outside allowed prefixes. Expected '
            '"workspaces/<workspace-id>/<attachment-id><ext>" — use the '
            "attachment's url or build it from its id and filename."
        )
```

In `markitdown_mcp/conversion.py`, change the `validate_s3_key` call (conversion.py:116) to pass the configured bucket:

```python
        try:
            key = validate_s3_key(s3_key, config.allowed_key_prefixes(), bucket=config.bucket)
        except SecurityError as e:
            logger.warning("Security violation blocked: %s", e)
            raise ToolError(str(e)) from e
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_convert_file_tool.py tests/security/test_s3_key_validation.py -q`
Expected: PASS (both suites — the security-suite prefix tests use `pytest.raises(..., match="(?i)key outside allowed prefixes")` patterns that still match the extended message).

- [ ] **Step 5: Commit**

```bash
git add markitdown_mcp/security.py markitdown_mcp/conversion.py tests/unit/test_convert_file_tool.py
git commit -m "feat: prefix-rejection error teaches the attachment key format"
```

---

### Task 3: End-to-end URL input through the tool

**Files:**
- Test: `tests/unit/test_convert_file_tool.py`

- [ ] **Step 1: Write the failing test**

Add to `TestConvertFileBasicFunctionality` in `tests/unit/test_convert_file_tool.py`:

```python
    @pytest.mark.unit
    async def test_convert_via_pasted_storage_url(self, monkeypatch):
        """An agent pasting the attachment JSON's url field converts fine.

        Path-style URL with bucket segment, query string and fragment — the
        server must land on the same object as the bare key.
        """
        _env(monkeypatch, AWS_ENDPOINT_URL="http://minio.internal:9000")
        with aws_backend():
            client = _make_bucket()
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws-1/sample.txt",
                Body=b"URL input works.",
            )

            result = await convert_file_impl(
                s3_key=(
                    "http://minio.internal:9000/multica-uploads/workspaces/ws-1/sample.txt"
                    "?X-Amz-Signature=abc#frag"
                )
            )

        assert "Successfully converted" in result
        assert "URL input works." in result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_convert_file_tool.py::TestConvertFileBasicFunctionality::test_convert_via_pasted_storage_url -q`
Expected: FAIL — "Security violation: key outside allowed prefixes" (no `S3_KEY_PREFIXES` set, so actually expected FAIL is: prefix check passes but the normalized key... verify: with no prefixes the normalization already works from Task 1, so this may already PASS. If it passes, keep the test as a regression guard and skip to Step 4.)

- [ ] **Step 3: (Conditional) Fix if failing**

If Step 2 failed, the gap is that `convert_file_impl` (conversion.py) does not pass `bucket` — re-check Task 2's conversion.py edit landed, and that `S3SourceConfig.from_env()` resolved `bucket="multica-uploads"`.

- [ ] **Step 4: Run the suite**

Run: `uv run pytest tests/unit/test_convert_file_tool.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_convert_file_tool.py
git commit -m "test: convert_file converts a pasted storage URL end-to-end"
```

---

### Task 4: Tool descriptions (purpose-first, compressed)

**Files:**
- Modify: `markitdown_mcp/server.py:91-114`
- Test: `tests/unit/test_mcp_protocol.py:68-84`

- [ ] **Step 1: Rewrite the failing description assertions**

Replace `test_convert_file_description_guides_s3_usage` (test_mcp_protocol.py:68-84) with:

```python
    @pytest.mark.unit
    async def test_convert_file_description_is_purpose_first(self):
        """The description leads with the use case (read a Multica
        attachment), documents the key template, and states the output
        limitations — the four gaps the field report identified."""
        from mcp.client import Client

        async with Client(mcp) as client:
            result = await client.list_tools()

        convert_tool = next(t for t in result.tools if t.name == "convert_file")
        desc = convert_tool.description or ""
        # Purpose-first: what it is for, before how it works.
        assert "Multica attachment" in desc
        assert "do not download-and-parse" in desc
        # Office formats named; the full catalog stays on list_supported_formats.
        for ext in ["pdf", "docx", "pptx", "xlsx", "xls"]:
            assert ext in desc
        # Key derivation rule and the paste-a-url shortcut.
        assert "workspaces/<workspace-id>/<attachment-id>" in desc
        assert "url" in desc.lower()
        # Limitations: when to fall back to raw XML.
        assert "formulas" in desc
        assert "merged-cell" in desc
        # The removed inputs must not be advertised anymore.
        assert "file_path" not in desc
        assert "file_content" not in desc
        assert "base64" not in desc.lower()
```

And extend the `list_supported_formats` coverage by adding after `test_list_supported_formats_has_empty_schema`:

```python
    @pytest.mark.unit
    async def test_list_supported_formats_description_routes_agents(self):
        """The formats tool tells an unsure agent to call it first."""
        from mcp.client import Client

        async with Client(mcp) as client:
            result = await client.list_tools()

        formats_tool = next(t for t in result.tools if t.name == "list_supported_formats")
        desc = formats_tool.description or ""
        assert "before convert_file" in desc
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_mcp_protocol.py -q`
Expected: FAIL — current descriptions lack "Multica attachment" / routing line (2 failures).

- [ ] **Step 3: Rewrite the docstrings**

In `markitdown_mcp/server.py`, replace the `convert_file_tool` docstring (server.py:93-107) and the `list_supported_formats_tool` docstring (server.py:113):

```python
@mcp.tool(name="convert_file")
async def convert_file_tool(s3_key: str, filename: str = "") -> str:
    """Convert pdf, docx, pptx, xlsx and xls files to Markdown. To read a
    Multica attachment, call this tool — the server fetches the file
    itself; do not download-and-parse by hand.

    s3_key: "workspaces/<workspace-id>/<attachment-id><ext>", built from
    the attachment entry in the issue/comment JSON (workspace_id, id,
    filename extension) — or paste the attachment's url field as-is.

    Output keeps values, not formulas or merged-cell structure; inspect
    raw XML only to explain how a total is computed.

    filename: optional display name.
    """
    return await convert_file_impl(s3_key=s3_key, filename=filename)


@mcp.tool(name="list_supported_formats")
async def list_supported_formats_tool() -> str:
    """List the file extensions this server converts to Markdown. Call
    this before convert_file when unsure an attachment's format is
    supported.
    """
    return await list_supported_formats_impl()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_mcp_protocol.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add markitdown_mcp/server.py tests/unit/test_mcp_protocol.py
git commit -m "feat: purpose-first convert_file description with key template and limits"
```

---

### Task 5: README agent guidance + CHANGELOG

**Files:**
- Modify: `README.md` (Tools table + S3 section)
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update README**

In `README.md`, replace the Tools table row for `convert_file` (README.md:14) with:

```markdown
| `convert_file` | Read a Multica attachment (pdf/docx/pptx/xlsx/xls and more) as Markdown: pass the object key — or paste the attachment's `url` field — and the server fetches it from its S3/MinIO store (`s3_key`, required; `filename` optional) |
```

And in the "Converting objects from S3 / MinIO" section, after the existing `{"s3_key": ...}` example (README.md:95), add:

```markdown
Multica agents can paste the attachment's storage `url` (from the
issue/comment JSON `attachments` array) as `s3_key` — the server strips
scheme, host, query and bucket to recover the key. Or build it from the
attachment entry: `workspaces/<workspace_id>/<id><ext-from-filename>`.

Output is values, not structure: formulas and merged-cell grouping are
not preserved. Verify numbers with `convert_file`; inspect the raw XML
(via attachment download) only to explain how a total is computed.
```

- [ ] **Step 2: Update CHANGELOG**

Prepend a `## [3.1.0] - 2026-10-29` section to `CHANGELOG.md` (above `## [3.0.0]`):

```markdown
## [3.1.0] - 2026-10-29

### Added
- **`s3_key` accepts a full storage URL.** Agents can paste the
  attachment's `url` field from issue/comment JSON as-is; the server
  normalizes it (strips scheme/host/query/fragment, and the bucket
  segment on path-style URLs) before validation, so traversal,
  extension, and prefix checks run on the recovered key. Mirrors the
  multica backend's `KeyFromURL` semantics.
- **Wrong-prefix errors now teach the key format.** The rejection
  message includes the `workspaces/<workspace-id>/<attachment-id><ext>`
  template and both recovery paths (paste the url / build from id and
  filename), turning a failed call into a self-correction.

### Changed
- **`convert_file` description is purpose-first.** It now leads with
  "to read a Multica attachment, call this tool" and names the office
  formats, documents the key derivation from the issue JSON, and states
  the output limitation (values, not formulas/merged-cell structure).
  Field feedback: an agent skipped this tool and hand-wrote an xlsx
  parser because the description led with S3 mechanics. Schema and tool
  names unchanged.
- **`list_supported_formats` description routes unsure agents** to call
  it before `convert_file`.
```

- [ ] **Step 3: Run docs-adjacent gates (all gates, cheap)**

Run: `uv run ruff format --check . && uv run ruff check . && uv run mypy markitdown_mcp/ && uv run pytest -q`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: agent guidance for reading multica attachments (3.1.0)"
```

---

### Task 6: Version bump and PR

**Files:**
- Modify: `pyproject.toml:3`, `markitdown_mcp/server.py:26`, `markitdown_mcp/__init__.py:16`
- Modify: `tests/unit/test_mcp_protocol.py:97` (version assertion)

- [ ] **Step 1: Bump versions to 3.1.0**

- `pyproject.toml:3`: `version = "3.1.0"`
- `markitdown_mcp/server.py:26`: `mcp = MCPServer("markitdown-mcp", version="3.1.0")`
- `markitdown_mcp/__init__.py:16`: `__version__ = "3.1.0"`
- `tests/unit/test_mcp_protocol.py` `test_initialize_negotiates_protocol`: `assert client.server_info.version == "3.1.0"`

- [ ] **Step 2: Run full gates**

Run: `uv run ruff format --check . && uv run ruff check . && uv run mypy markitdown_mcp/ && uv run pytest -q`
Expected: all pass.

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml markitdown_mcp/server.py markitdown_mcp/__init__.py tests/unit/test_mcp_protocol.py
git commit -m "chore: bump version to 3.1.0"
```

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin feat/convert-file-discoverability
```

PR title: `feat: convert_file discoverability — purpose-first description, URL leniency, teaching errors (3.1.0)`

PR body (end with the attribution line):

```markdown
## Why

Field report from a multica issue run: given an xlsx attachment, the
agent never called `convert_file` — it hand-wrote a Node parser. Four
gaps: implementation-first description, undocumented key format, no
"prefer this over hand parsing" signal, unstated output limitations.

## What

- `convert_file` description rewritten purpose-first (use case, key
  template, paste-the-url shortcut, output limits). Names the office
  formats; the full catalog stays on `list_supported_formats`.
- `s3_key` values that are full storage URLs (the attachment JSON's
  `url` field) are normalized to bare keys before validation — scheme,
  host, query, fragment, and the path-style bucket segment are
  stripped. Mirrors the multica backend's `KeyFromURL`. Security checks
  (traversal / extension / prefix) run on the recovered key; no new
  code path reads anything but S3.
- Wrong-prefix rejections now carry the key template and both recovery
  paths, so a failed call self-corrects on the next turn.
- `list_supported_formats` gains a routing line for unsure agents.

Tool names and schemas unchanged (`s3_key` + optional `filename`).

## Validation

ruff format/check, mypy, pytest (160+ new tests) — full chain green.

Spec: `docs/superpowers/specs/2026-10-29-convert-file-discoverability-design.md`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

- [ ] **Step 5: Merge after CI green, tag, verify release**

1. Merge PR into `main` (squash or merge commit per repo history).
2. `git checkout main && git pull && git tag v3.1.0 && git push origin v3.1.0` — the release workflow builds amd64/arm64 images and attaches them to the GitHub Release.
3. Confirm the workflow completes and the Release carries
   `markitdown-mcp-image-linux-arm64.tar.gz` (needed for the 82 deploy).

---

### Task 7: Deploy to 82

**Files:** none in-repo (host-side config)

- [ ] **Step 1: Pull and load the arm64 image on the registry host**

Following the established procedure (this is the step previously skipped):
download `markitdown-mcp-image-linux-arm64.tar.gz` from the GitHub
Release, `docker load` it, tag
`reg.telecomjs.com/eda-bigdata/markitdown-mcp:v3.1.0-arm64`, and push to
the registry.

- [ ] **Step 2: Bump the deployment on 82**

```bash
ssh 82 'sed -i "s|markitdown-mcp:v3.0.0-arm64|markitdown-mcp:v3.1.0-arm64|" /home/zhengyong/config/markitdown-mcp/deployment.yaml'
ssh 82 'kubectl apply -f /home/zhengyong/config/markitdown-mcp/ && kubectl rollout status deployment/markitdown-mcp -n eda-bigdata --timeout=180s'
```

- [ ] **Step 3: Verify rollout**

```bash
ssh 82 'kubectl get deploy markitdown-mcp -n eda-bigdata -o wide; kubectl get pods -n eda-bigdata -l app=markitdown-mcp'
```

Expected: 2/2 Running on `v3.1.0-arm64`, new pods with no restarts.
