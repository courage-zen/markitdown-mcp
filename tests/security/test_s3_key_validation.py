"""
Security tests for S3 object key validation.
"""

import pytest

from markitdown_mcp.security import validate_s3_key


class TestValidateS3KeyBasics:
    """Basic shape validation of S3 keys."""

    @pytest.mark.security
    def test_rejects_empty_key(self):
        with pytest.raises(Exception, match="(?i)security violation"):
            validate_s3_key("", allowed_prefixes=None)

    @pytest.mark.security
    def test_rejects_whitespace_only_key(self):
        with pytest.raises(Exception, match="(?i)security violation"):
            validate_s3_key("   ", allowed_prefixes=None)

    @pytest.mark.security
    def test_accepts_simple_key(self):
        validate_s3_key("workspaces/abc/report.pdf", allowed_prefixes=None)

    @pytest.mark.security
    def test_accepts_root_level_key(self):
        validate_s3_key("report.pdf", allowed_prefixes=None)


class TestValidateS3KeyTraversal:
    """Keys must not carry path-traversal segments."""

    @pytest.mark.security
    @pytest.mark.parametrize(
        "key",
        [
            "../etc/passwd",
            "workspaces/../../../etc/passwd",
            "workspaces/..",
            "a/../b/report.pdf",
            "workspaces/abc/..\\windows\\file",
        ],
    )
    def test_rejects_dot_dot_segments(self, key):
        with pytest.raises(Exception, match="(?i)security violation"):
            validate_s3_key(key, allowed_prefixes=None)


class TestValidateS3KeyExtensions:
    """Keys must pass the dangerous-extension blocklist applied to local paths."""

    @pytest.mark.security
    @pytest.mark.parametrize("ext", [".exe", ".bat", ".sh", ".ps1"])
    def test_rejects_dangerous_extensions(self, ext):
        with pytest.raises(Exception, match="(?i)security violation"):
            validate_s3_key(f"workspaces/abc/payload{ext}", allowed_prefixes=None)

    @pytest.mark.security
    def test_accepts_supported_document_extension(self):
        validate_s3_key("workspaces/abc/report.pdf", allowed_prefixes=None)

    @pytest.mark.security
    def test_rejects_extension_check_on_basename_not_whole_key(self):
        # ".sh" appears as a directory segment, not as the file suffix.
        validate_s3_key("workspaces/abc.shell/report.pdf", allowed_prefixes=None)


class TestValidateS3KeyPrefixAllowlist:
    """Segment-aware prefix allowlist matching."""

    @pytest.mark.security
    def test_prefix_matches_descendant_segment(self):
        validate_s3_key(
            "workspaces/abc/report.pdf", allowed_prefixes=["workspaces/abc"]
        )

    @pytest.mark.security
    def test_prefix_matches_exact_key(self):
        validate_s3_key("workspaces/abc", allowed_prefixes=["workspaces/abc"])

    @pytest.mark.security
    def test_prefix_must_not_match_partial_segment(self):
        # "workspaces/abc" must not admit "workspaces/abc123/...".
        with pytest.raises(Exception, match="(?i)security violation"):
            validate_s3_key(
                "workspaces/abc123/report.pdf", allowed_prefixes=["workspaces/abc"]
            )

    @pytest.mark.security
    def test_empty_prefix_list_means_no_restriction(self):
        validate_s3_key("anything/report.pdf", allowed_prefixes=[])

    @pytest.mark.security
    def test_first_matching_prefix_admits_key(self):
        validate_s3_key(
            "users/42/report.pdf", allowed_prefixes=["workspaces/abc", "users/42"]
        )

    @pytest.mark.security
    def test_outside_prefix_is_rejected(self):
        with pytest.raises(Exception, match="(?i)security violation"):
            validate_s3_key(
                "users/42/report.pdf", allowed_prefixes=["workspaces/abc"]
            )


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
        # "http://" with no host/path is URL-shaped but carries no object;
        # validation must still reject it, never crash with a traceback.
        with pytest.raises(Exception, match="(?i)security violation"):
            validate_s3_key("http://", allowed_prefixes=None)
