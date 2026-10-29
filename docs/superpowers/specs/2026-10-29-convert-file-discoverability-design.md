# convert_file discoverability design

Date: 2026-10-29
Status: approved (user picked 方案二 with compressed copy)

## Problem

A multica issue agent, given an `.xlsx` attachment, did not use the
markitdown MCP tool. Post-run analysis identified four gaps:

1. The tool description led with implementation details ("The ONLY input
   is an S3 object key"), not the use case ("read a Multica attachment").
2. The `s3_key` format was undocumented at the time (the run was on
   v2.2.1); v3.0.0 added the template but no worked example and no
   mention that the attachment's `url` can be pasted as-is.
3. Nothing steered the agent away from hand-writing a parser after
   downloading the attachment.
4. The output's limitations (no formulas, no merged-cell structure) were
   undocumented, so the agent had no signal for when to fall back to raw
   XML.

Constraints: multica source is out of scope (user decision); tool names
and schemas are frozen client-facing API (AGENTS.md), so the fix cannot
add parameters.

## Design

Three changes, all inside markitdown-mcp.

### 1. `convert_file` description rewrite (purpose-first, compressed)

```
Convert pdf, docx, pptx, xlsx and xls files to Markdown. To read a Multica
attachment, call this tool — the server fetches the file itself; do not
download-and-parse by hand.

s3_key: "workspaces/<workspace-id>/<attachment-id><ext>", built from the
attachment entry in the issue/comment JSON (workspace_id, id, filename
extension) — or paste the attachment's url field as-is.

Output keeps values, not formulas or merged-cell structure; inspect raw
XML only to explain how a total is computed.

filename: optional display name.
```

- Only office formats are named; the full catalog stays on
  `list_supported_formats`.
- The schema (one required `s3_key` string, optional `filename`) is
  unchanged; only prose changes.

### 2. `s3_key` value leniency: accept a full storage URL

When the `s3_key` value looks like a URL (has a scheme), normalize it to
a bare key before validation:

- Strip scheme, host, port; strip any query string / fragment.
- Path-style (`http://host:9000/bucket/key...`): drop the first path
  segment when it equals the configured bucket name.
- Virtual-hosted (`http://bucket.host/key...`): the host starts with
  `<bucket>.` — take the whole path as the key.
- All existing validation (`..` segments, dangerous extensions, prefix
  allowlist) runs AFTER normalization, so the security surface is
  unchanged: a URL cannot smuggle a key that validation would reject.

Precedent: multica's own `S3Storage.KeyFromURL` does the same
host/endpoint/bucket stripping server-side.

### 3. Validation errors teach the format

When prefix validation fails, append guidance to the existing message:

```
Security violation: key outside allowed prefixes. Expected
"workspaces/<workspace-id>/<attachment-id><ext>" — use the attachment's
url or build it from its id and filename.
```

No bucket/endpoint/deployment details are exposed (sanitize rules hold).
The message is the one place an agent that guessed wrong will actually
read; it turns one failed call into a self-correction.

`list_supported_formats` description also gains a routing line ("call
this before convert_file when unsure a format is supported").

## Testing

- Extend `tests/unit/test_mcp_protocol.py::test_convert_file_description_guides_s3_usage`:
  assert purpose-first keywords ("Multica attachment", office formats,
  "url"), the key template, the limitations line; keep the assertions
  that `file_path` / `file_content` / `base64` do not appear.
- New unit tests for URL normalization: path-style, virtual-host, query
  strings, bucket stripping, normalization feeding prefix rejection.
- Error-message test: wrong-prefix key (plain and URL form) returns the
  extended guidance.

## Release

Version 3.1.0 (value-semantics extension, no schema change). Standard
PR → review → tag flow; deployment follows the existing 82 procedure.
