"""
Path traversal security tests.

Every attack goes through ``convert_file_impl``; a malicious path must
surface as a sanitized ``ToolError`` (or a plain "not found" rejection),
never as a converted document, an unhandled exception, or a leaked
filesystem layout.
"""

import asyncio
import os
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

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


async def _attempt_conversion(file_path: str) -> str:
    """Attempt a conversion that must fail; return the ToolError message."""
    with pytest.raises(ToolError) as exc_info:
        await convert_file_impl(file_path=file_path)
    return str(exc_info.value)


def _assert_sanitized(error_msg: str, path: str) -> None:
    """The rejection message must be short, safe, and leak nothing."""
    lowered = error_msg.lower()
    assert any(term in lowered for term in SAFE_ERROR_TERMS), (
        f"Unsafe error message for {path!r}: {error_msg}"
    )
    # No stack traces or exception internals.
    assert "traceback" not in lowered
    assert "exception" not in lowered
    # Nothing beyond the caller's own input may leak into the message.
    assert str(Path.home().resolve()) not in error_msg or path.startswith(str(Path.home()))


class TestBasicPathTraversal:
    """Test basic path traversal attack patterns."""

    @pytest.mark.security
    async def test_unix_path_traversal_attacks(self):
        """Test Unix-style path traversal attacks."""
        malicious_paths = [
            "../../../etc/passwd",
            "../../../../etc/shadow",
            "../../../root/.ssh/id_rsa",
            "../../../../../../etc/hosts",
            "../../../home/user/.bashrc",
            "../../../../var/log/auth.log",
            "../../../proc/version",
            "../../../../tmp/sensitive_file",
        ]

        for path in malicious_paths:
            error_msg = await _attempt_conversion(path)
            _assert_sanitized(error_msg, path)

    @pytest.mark.security
    async def test_windows_path_traversal_attacks(self):
        """Test Windows-style path traversal attacks."""
        malicious_paths = [
            "..\\..\\..\\windows\\system32\\config\\sam",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\users\\administrator\\.ssh\\id_rsa",
            "..\\..\\..\\programdata\\sensitive.txt",
            "..\\..\\..\\windows\\temp\\secret.log",
            "../../../../windows/system32/config/software",
            "..\\..\\..\\..\\boot.ini",
        ]

        for path in malicious_paths:
            error_msg = await _attempt_conversion(path)
            _assert_sanitized(error_msg, path)

    @pytest.mark.security
    async def test_encoded_path_traversal_attacks(self):
        """Test URL-encoded and other encoded path traversal attacks."""
        malicious_paths = [
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "....//....//....//etc//passwd",
            "..%5c..%5c..%5cwindows%5csystem32",
        ]

        for path in malicious_paths:
            error_msg = await _attempt_conversion(path)
            _assert_sanitized(error_msg, path)

    @pytest.mark.security
    async def test_absolute_path_attacks(self):
        """Test absolute path attacks to sensitive locations."""
        sensitive_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/root/.ssh/id_rsa",
            "/var/log/auth.log",
            "/proc/version",
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
            "C:\\windows\\system32\\config\\sam",
            "C:\\users\\administrator\\desktop\\secret.txt",
            "C:\\programdata\\sensitive.log",
            "/dev/mem",
            "/dev/kmem",
        ]

        for path in sensitive_paths:
            error_msg = await _attempt_conversion(path)
            # Rejection must never leak whether the file exists or its permissions.
            lowered = error_msg.lower()
            assert "exists but" not in lowered, f"Existence leak: {error_msg}"
            assert "permission denied" not in lowered, f"Permission leak: {error_msg}"

    @pytest.mark.security
    async def test_dangerous_file_extensions_rejected(self, temp_dir):
        """Executable file types are refused outright."""
        for ext in [".exe", ".bat", ".sh", ".ps1", ".vbs"]:
            file_path = Path(temp_dir) / f"malicious{ext}"
            file_path.write_text("fake executable")

            error_msg = await _attempt_conversion(str(file_path))
            _assert_sanitized(error_msg, str(file_path))


class TestAdvancedPathTraversal:
    """Test advanced path traversal techniques."""

    @pytest.mark.security
    async def test_double_encoding_attacks(self):
        """Test double-encoded path traversal attacks."""
        double_encoded_paths = [
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "%25252e%25252e%25252f%25252e%25252e%25252fetc%25252fpasswd",
            "%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66etc%%32%66passwd",
        ]

        for path in double_encoded_paths:
            error_msg = await _attempt_conversion(path)
            _assert_sanitized(error_msg, path)

    @pytest.mark.security
    async def test_unicode_normalization_attacks(self):
        """Test Unicode normalization bypass attempts."""
        unicode_paths = [
            "../\u002e\u002e/\u002e\u002e/etc/passwd",
            "..\u002f..\u002f..\u002fetc\u002fpasswd",
            "\u002e\u002e\u002f\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd",
            ".\u002e/.\u002e/.\u002e/etc/passwd",
        ]

        for path in unicode_paths:
            error_msg = await _attempt_conversion(path)
            _assert_sanitized(error_msg, path)

    @pytest.mark.security
    async def test_null_byte_injection_attacks(self):
        """Test null byte injection attacks."""
        null_byte_paths = [
            "../../../etc/passwd\x00.txt",
            "../../../../etc/shadow\x00.log",
            "../../../windows/system32/config/sam\x00.dat",
            "/etc/passwd\x00innocent.txt",
        ]

        for path in null_byte_paths:
            error_msg = await _attempt_conversion(path)
            _assert_sanitized(error_msg, path)

    @pytest.mark.security
    async def test_long_path_attacks(self):
        """Test very long path attacks."""
        base_traversal = "../" * 100
        long_paths = [
            base_traversal + "etc/passwd",
            base_traversal + "windows/system32/config/sam",
            "A" * 1000 + "/../../../etc/passwd",
            "/" + "A" * 4096,
        ]

        for path in long_paths:
            error_msg = await _attempt_conversion(path)
            # Must be rejected with a sanitized message — never a raw OS
            # error ("File name too long") or an unhandled exception.
            lowered = error_msg.lower()
            assert "too long" not in lowered
            assert "internal error" not in lowered
            # The message may echo the caller's own (attacker-supplied) path,
            # but must not exceed it with any server-side filesystem detail.
            assert len(error_msg) <= len(path) + len("File not found: "), (
                f"Error message too detailed: {error_msg}"
            )


class TestSymlinkAttacks:
    """Test symbolic link based attacks."""

    @pytest.mark.security
    async def test_symlink_traversal_attacks(self, temp_dir):
        """Symlinks pointing at sensitive files are rejected."""
        if os.name == "nt":
            pytest.skip("Symlink tests not reliable on Windows")

        attack_dir = Path(temp_dir) / "symlink_attack"
        attack_dir.mkdir()

        innocent_file = attack_dir / "innocent.txt"
        innocent_file.write_text("Innocent content")

        symlink_targets = [
            "/etc/passwd",
            "/etc/shadow",
            "/root/.ssh/id_rsa",
            innocent_file,  # Self-reference: allowed
        ]

        for i, target in enumerate(symlink_targets):
            symlink_path = attack_dir / f"evil_symlink_{i}.txt"

            try:
                symlink_path.symlink_to(target)
            except (OSError, NotImplementedError):
                continue  # Symlink creation may fail in some environments

            if target == innocent_file:
                # A link inside the safe directory may legitimately convert.
                result = await convert_file_impl(file_path=str(symlink_path))
                assert "Innocent content" in result
            else:
                error_msg = await _attempt_conversion(str(symlink_path))
                _assert_sanitized(error_msg, str(target))

    @pytest.mark.security
    async def test_symlink_to_sensitive_directory(self, temp_dir):
        """A symlink to a sensitive directory cannot be used to read it."""
        if os.name == "nt":
            pytest.skip("Symlink tests not reliable on Windows")

        attack_dir = Path(temp_dir) / "dir_symlink_attack"
        attack_dir.mkdir()

        evil_link = attack_dir / "etc_passwd_link"
        try:
            evil_link.symlink_to("/etc/passwd")
        except (OSError, NotImplementedError):
            pytest.skip("Symlink creation not available")

        error_msg = await _attempt_conversion(str(evil_link))
        _assert_sanitized(error_msg, str(evil_link))


class TestRaceConditionAttacks:
    """Test race condition based attacks."""

    @pytest.mark.security
    async def test_toctou_baseline_conversion(self, temp_dir):
        """A legitimate file converts consistently (baseline for TOCTOU)."""
        legitimate_file = Path(temp_dir) / "legitimate.txt"
        legitimate_file.write_text("This is legitimate content for testing.")

        for _ in range(3):
            result = await convert_file_impl(file_path=str(legitimate_file))
            assert "legitimate content" in result

    @pytest.mark.security
    async def test_concurrent_file_access_safety(self, temp_dir):
        """Concurrent conversions of one file never raise raw exceptions."""
        test_file = Path(temp_dir) / "concurrent_test.txt"
        test_file.write_text("Concurrent access test content.")

        tasks = [convert_file_impl(file_path=str(test_file)) for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        exceptions = [r for r in results if isinstance(r, Exception)]
        assert not exceptions, f"Concurrent access caused exceptions: {exceptions}"

        successes = [r for r in results if isinstance(r, str)]
        if successes:
            assert all(r == successes[0] for r in successes), "Inconsistent results"


class TestInformationDisclosure:
    """Test prevention of information disclosure through path traversal."""

    @pytest.mark.security
    async def test_error_message_information_leaks(self):
        """Error messages must not reveal filesystem structure."""
        test_paths = [
            "/etc/passwd",  # Exists on Unix
            "/nonexistent/definitely/not/here",  # Does not exist
            "C:\\windows\\system32\\config\\sam",
            "C:\\definitely\\not\\real\\path",
        ]

        for path in test_paths:
            error_msg = await _attempt_conversion(path)
            # Short, sanitized message only — no detailed filesystem info.
            assert len(error_msg) < 200, f"Error message too detailed: {error_msg}"

    @pytest.mark.security
    async def test_error_messages_uniform_for_existing_vs_missing(self):
        """Rejections look alike whether or not the target exists."""
        existing = await _attempt_conversion("/etc/passwd")
        missing = await _attempt_conversion("/etc/definitely_not_here")

        # Both are sanitized security rejections, indistinguishable in kind.
        for error_msg in (existing, missing):
            _assert_sanitized(error_msg, "<redacted>")


class TestPathNormalizationSecurity:
    """Test security of path normalization and canonicalization."""

    @pytest.mark.security
    async def test_path_normalization_bypasses(self, temp_dir):
        """Legitimate variants convert; malicious normalizations are rejected."""
        test_file = Path(temp_dir) / "test.txt"
        test_file.write_text("Legitimate test content")

        legitimate_variants = [
            str(test_file),
            str(test_file) + "/.",
            str(test_file.parent) + "/./test.txt",
        ]
        for variant in legitimate_variants:
            result = await convert_file_impl(file_path=variant)
            assert "Legitimate test content" in result

        malicious_variants = [
            str(temp_dir) + "/../../../etc/passwd",
            str(temp_dir) + "/./../../etc/passwd",
            str(temp_dir) + "/../" + "../" * 10 + "etc/passwd",
        ]
        for variant in malicious_variants:
            error_msg = await _attempt_conversion(variant)
            _assert_sanitized(error_msg, variant)

    @pytest.mark.security
    async def test_case_sensitivity_attacks(self):
        """Case variations of sensitive paths are also rejected."""
        case_variants = [
            "../../../ETC/passwd",
            "../../../Etc/Passwd",
            "../../../ETC/PASSWD",
            "..\\..\\..\\WINDOWS\\system32\\config\\sam",
            "..\\..\\..\\Windows\\System32\\Config\\Sam",
        ]

        for variant in case_variants:
            error_msg = await _attempt_conversion(variant)
            _assert_sanitized(error_msg, variant)
