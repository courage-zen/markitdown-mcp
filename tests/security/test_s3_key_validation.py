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
