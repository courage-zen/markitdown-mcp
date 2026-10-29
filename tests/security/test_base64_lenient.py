"""Tests for lenient-but-guarded base64 decoding in validate_base64.

Agents legitimately produce base64 with a trailing newline (shell `base64`
output), MIME line folding, or URL-safe alphabet characters. All of these
must decode; garbage and oversize payloads must still be rejected.
"""

import base64

import pytest

from markitdown_mcp.security import SecurityError, validate_base64

CONTENT = b"# title\n\nhello markdown test content padding\n" * 4
ENCODED = base64.b64encode(CONTENT).decode()


class TestLenientBase64Variants:
    def test_standard_base64_still_works(self) -> None:
        assert validate_base64(ENCODED) == CONTENT

    def test_trailing_newline_accepted(self) -> None:
        # shell `base64` output ends with a newline
        assert validate_base64(ENCODED + "\n") == CONTENT

    def test_crlf_trailing_accepted(self) -> None:
        assert validate_base64(ENCODED + "\r\n") == CONTENT

    def test_mime_folded_lines_accepted(self) -> None:
        # `base64 -w 76` / Python encodebytes style
        folded = "\n".join(ENCODED[i : i + 76] for i in range(0, len(ENCODED), 76))
        assert validate_base64(folded) == CONTENT

    def test_leading_whitespace_accepted(self) -> None:
        assert validate_base64("  " + ENCODED) == CONTENT

    def test_urlsafe_alphabet_accepted(self) -> None:
        # Content that forces +/ in standard alphabet (thus -_ in urlsafe)
        binary = b"\xfb\xef\xbe\xca\xfe" * 10
        urlsafe = base64.urlsafe_b64encode(binary).decode()
        assert "+" not in urlsafe and "-" in urlsafe
        assert validate_base64(urlsafe) == binary

    def test_internal_spaces_ignored(self) -> None:
        # Some toolchains emit space-separated chunks
        spaced = " ".join(ENCODED[i : i + 4] for i in range(0, len(ENCODED), 4))
        assert validate_base64(spaced) == CONTENT


class TestBase64StillRejectsGarbage:
    def test_garbage_rejected(self) -> None:
        with pytest.raises(SecurityError):
            validate_base64("not!valid@base64$$$")

    def test_empty_rejected(self) -> None:
        with pytest.raises(SecurityError):
            validate_base64("   \n  ")

    def test_oversize_rejected(self) -> None:
        big = base64.b64encode(b"x" * (10 * 1024 * 1024 + 100)).decode()
        with pytest.raises(SecurityError):
            validate_base64(big)

    def test_type_error_rejected(self) -> None:
        with pytest.raises(SecurityError):
            validate_base64(b"\x00rawbytes")  # type: ignore[arg-type]
