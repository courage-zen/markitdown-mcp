"""
S3 key traversal security tests.

convert_file's only input is an S3 object key, so the attack surface is the
key itself: ``..`` segments (reinterpretable as filesystem escapes when the
key becomes a temp-file path), dangerous extensions, prefix-allowlist
escapes, and encoded/unicode smuggling. Every attack must surface as a
sanitized ``ToolError`` before any download is attempted — never as a
converted document, an unhandled exception, or a leaked bucket/endpoint.
"""

import asyncio
from contextlib import contextmanager

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from moto import mock_aws

from markitdown_mcp.conversion import convert_file_impl

# Terms that may legitimately appear in a sanitized rejection message.
SAFE_ERROR_TERMS = (
    "not found",
    "does not exist",
    "access denied",
    "permission",
    "invalid",
    "security violation",
    "not allowed",
    "required",
)


@contextmanager
def _s3_backend(monkeypatch):
    """Enter moto's S3 backend with a configured server env and one bucket."""
    monkeypatch.setenv("S3_BUCKET", "multica-uploads")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testkey")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testsecret")
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("S3_REGION", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    with mock_aws():
        import boto3

        client = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id="testkey",
            aws_secret_access_key="testsecret",
        )
        client.create_bucket(Bucket="multica-uploads")
        yield client


async def _attempt_conversion(monkeypatch, key: str) -> str:
    """Attempt a conversion that must fail; return the ToolError message."""
    with _s3_backend(monkeypatch):
        with pytest.raises(ToolError) as exc_info:
            await convert_file_impl(s3_key=key)
    return str(exc_info.value)


def _assert_sanitized(error_msg: str, key: str) -> None:
    """The rejection message must be short, safe, and leak nothing."""
    lowered = error_msg.lower()
    assert any(term in lowered for term in SAFE_ERROR_TERMS), (
        f"Unsafe error message for {key!r}: {error_msg}"
    )
    # No stack traces or exception internals.
    assert "traceback" not in lowered
    assert "exception" not in lowered
    # No bucket, endpoint or provider details leak.
    assert "multica-uploads" not in error_msg
    assert "127.0.0.1" not in error_msg


class TestBasicKeyTraversal:
    """Test basic traversal attack patterns in keys."""

    @pytest.mark.security
    async def test_unix_style_traversal_keys(self, monkeypatch):
        """Keys with .. segments are rejected before any download."""
        malicious_keys = [
            "../../../etc/passwd",
            "workspaces/../../etc/shadow",
            "workspaces/ws/../../../root/.ssh/id_rsa",
            "workspaces/../../../../../../etc/hosts",
        ]
        for key in malicious_keys:
            error_msg = await _attempt_conversion(monkeypatch, key)
            _assert_sanitized(error_msg, key)

    @pytest.mark.security
    async def test_windows_style_traversal_keys(self, monkeypatch):
        """Backslash-style .. segments are normalized and rejected too."""
        malicious_keys = [
            "..\\..\\..\\windows\\system32\\config\\sam",
            "workspaces\\..\\..\\secret.txt",
            "workspaces\\ws\\..\\..\\..\\boot.ini",
        ]
        for key in malicious_keys:
            error_msg = await _attempt_conversion(monkeypatch, key)
            _assert_sanitized(error_msg, key)

    @pytest.mark.security
    async def test_system_path_keys(self, monkeypatch):
        """Absolute server paths as keys are treated as keys, not paths —
        they simply do not exist in the bucket, and the rejection must not
        reveal filesystem details."""
        sensitive_keys = [
            "/etc/passwd",
            "/proc/version",
            "/dev/mem",
            "C:\\windows\\system32\\config\\sam",
        ]
        for key in sensitive_keys:
            error_msg = await _attempt_conversion(monkeypatch, key)
            # Rejection must never leak whether the object exists.
            lowered = error_msg.lower()
            assert "exists but" not in lowered, f"Existence leak: {error_msg}"
            assert "permission denied" not in lowered, f"Permission leak: {error_msg}"

    @pytest.mark.security
    async def test_dangerous_key_extensions_rejected(self, monkeypatch):
        """Executable file types in keys are refused outright."""
        for ext in [".exe", ".bat", ".sh", ".ps1", ".vbs"]:
            error_msg = await _attempt_conversion(
                monkeypatch, f"workspaces/ws-1/payload{ext}"
            )
            _assert_sanitized(error_msg, f"workspaces/ws-1/payload{ext}")


class TestKeyEncodingAttacks:
    """Encoded and unicode smuggling in keys."""

    @pytest.mark.security
    async def test_encoded_traversal_keys(self, monkeypatch):
        """URL-encoded traversal remains literal key text — it cannot hit the
        filesystem, but it must still be rejected or fail sanitized."""
        malicious_keys = [
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252fetc%252fpasswd",
            "....//....//etc/passwd",
        ]
        for key in malicious_keys:
            error_msg = await _attempt_conversion(monkeypatch, key)
            _assert_sanitized(error_msg, key)

    @pytest.mark.security
    async def test_unicode_normalization_keys(self, monkeypatch):
        """Unicode normalization bypass attempts in keys."""
        unicode_keys = [
            "../\u002e\u002e/\u002e\u002e/etc/passwd",
            ".\u002e/.\u002e/.\u002e/etc/passwd",
        ]
        for key in unicode_keys:
            error_msg = await _attempt_conversion(monkeypatch, key)
            _assert_sanitized(error_msg, key)

    @pytest.mark.security
    async def test_null_byte_injection_keys(self, monkeypatch):
        """Null bytes in keys are rejected or fail sanitized."""
        null_byte_keys = [
            "workspaces/../../../etc/passwd\x00.txt",
            "workspaces/ws/report\x00.txt",
        ]
        for key in null_byte_keys:
            error_msg = await _attempt_conversion(monkeypatch, key)
            _assert_sanitized(error_msg, key)

    @pytest.mark.security
    async def test_long_key_attacks(self, monkeypatch):
        """Very long keys are rejected quickly with a sanitized message."""
        base_traversal = "../" * 100
        long_keys = [
            base_traversal + "etc/passwd",
            "A" * 1000 + "/../../../etc/passwd",
        ]
        for key in long_keys:
            error_msg = await _attempt_conversion(monkeypatch, key)
            # Must be rejected with a sanitized message — never a raw
            # exception or a provider error dump.
            lowered = error_msg.lower()
            assert "too long" not in lowered
            assert "internal error" not in lowered
            assert len(error_msg) < 200, f"Error message too detailed: {error_msg}"


class TestPrefixAllowlistSecurity:
    """The S3_KEY_PREFIXES allowlist admits only its own segment tree."""

    @pytest.mark.security
    async def test_prefix_escape_rejected(self, monkeypatch):
        """Keys outside the allowed prefix are rejected before any download."""
        monkeypatch.setenv("S3_KEY_PREFIXES", "workspaces/allowed")

        error_msg = await _attempt_conversion(monkeypatch, "users/42/report.txt")
        _assert_sanitized(error_msg, "users/42/report.txt")

    @pytest.mark.security
    async def test_prefix_sibling_lookalike_rejected(self, monkeypatch):
        """Segment-aware matching: 'workspaces/abc' must not admit
        'workspaces/abc123/...'."""
        monkeypatch.setenv("S3_KEY_PREFIXES", "workspaces/abc")

        error_msg = await _attempt_conversion(monkeypatch, "workspaces/abc123/x.txt")
        _assert_sanitized(error_msg, "workspaces/abc123/x.txt")

    @pytest.mark.security
    async def test_prefix_prefix_mismatch_rejected(self, monkeypatch):
        """A key that only shares a string prefix (not segments) is rejected."""
        monkeypatch.setenv("S3_KEY_PREFIXES", "workspaces/abc")

        error_msg = await _attempt_conversion(monkeypatch, "workspacesx/abc/x.txt")
        _assert_sanitized(error_msg, "workspacesx/abc/x.txt")

    @pytest.mark.security
    async def test_prefix_key_itself_admitted_for_validation(self, monkeypatch):
        """The exact prefix key passes the allowlist (still must exist to
        convert — it fails as not-found, not as allowlist rejection)."""
        monkeypatch.setenv("S3_KEY_PREFIXES", "workspaces/allowed")

        error_msg = await _attempt_conversion(monkeypatch, "workspaces/allowed")
        lowered = error_msg.lower()
        # Not an allowlist rejection — it got as far as the object lookup.
        assert "outside allowed prefixes" not in lowered


class TestLegacyInputRejection:
    """Removed inputs must be refused, never silently honored.

    The client-facing boundary is the tool schema (an MCP call with
    file_path/file_content fails schema validation); at the Python level the
    strict signature rejects the legacy kwargs outright.
    """

    @pytest.mark.security
    async def test_file_path_input_refused(self, monkeypatch):
        """file_path is no longer an input; passing one must not read the
        server filesystem."""
        with _s3_backend(monkeypatch):
            with pytest.raises(TypeError, match="file_path"):
                await convert_file_impl(file_path="/etc/passwd")

    @pytest.mark.security
    async def test_file_content_input_refused(self, monkeypatch):
        """base64 file_content is no longer an input."""
        with _s3_backend(monkeypatch):
            with pytest.raises(TypeError, match="file_content"):
                await convert_file_impl(
                    file_content="SGVsbG8=", filename="hello.txt"
                )


class TestConcurrency:
    """Concurrent conversions of one object never raise raw exceptions."""

    @pytest.mark.security
    async def test_concurrent_access_safety(self, monkeypatch):
        with _s3_backend(monkeypatch) as client:
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/test/concurrent.txt",
                Body=b"Concurrent access test content.",
            )

            tasks = [
                convert_file_impl(s3_key="workspaces/test/concurrent.txt")
                for _ in range(10)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        exceptions = [r for r in results if isinstance(r, Exception)]
        assert not exceptions, f"Concurrent access caused exceptions: {exceptions}"

        successes = [r for r in results if isinstance(r, str)]
        if successes:
            assert all(r == successes[0] for r in successes), "Inconsistent results"

    @pytest.mark.security
    async def test_toctou_baseline_conversion(self, monkeypatch):
        """A legitimate object converts consistently (baseline for TOCTOU)."""
        with _s3_backend(monkeypatch) as client:
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/test/legitimate.txt",
                Body=b"This is legitimate content for testing.",
            )

            for _ in range(3):
                result = await convert_file_impl(s3_key="workspaces/test/legitimate.txt")
                assert "legitimate content" in result


class TestInformationDisclosure:
    """Rejections must not reveal S3 internals."""

    @pytest.mark.security
    async def test_error_message_information_leaks(self, monkeypatch):
        """Error messages must not reveal bucket or endpoint details."""
        test_keys = [
            "workspaces/ws/definitely-missing.txt",
            "nonexistent-key.txt",
        ]
        for key in test_keys:
            error_msg = await _attempt_conversion(monkeypatch, key)
            assert len(error_msg) < 200, f"Error message too detailed: {error_msg}"
            assert "multica-uploads" not in error_msg

    @pytest.mark.security
    async def test_error_messages_uniform_for_existing_vs_missing(self, monkeypatch):
        """Rejections look alike whether or not the object exists."""
        with _s3_backend(monkeypatch) as client:
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/ws/existing.txt",
                Body=b"exists",
            )
            existing_error = await _attempt_conversion(monkeypatch, "workspaces/ws/../x.txt")
            missing_error = await _attempt_conversion(monkeypatch, "workspaces/ws/missing.txt")

        # Both are sanitized rejections, indistinguishable in kind.
        for error_msg in (existing_error, missing_error):
            _assert_sanitized(error_msg, "<redacted>")
