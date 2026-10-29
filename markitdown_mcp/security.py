#!/usr/bin/env python3
"""Security helpers for the MarkItDown MCP server.

S3-key validation, content sanitization, and resource-limit guards used by
the conversion tools. All helpers raise :class:`SecurityError` on violation.
"""

import contextlib
import csv
import functools
import json
import re
import tempfile
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any, ParamSpec, TypeVar, cast

P = ParamSpec("P")
R = TypeVar("R")

XML_MIME_TYPES = {"application/xml", "text/xml"}
JSON_MIME_TYPES = {"application/json", "text/json"}
CSV_MIME_TYPES = {"application/csv", "text/csv"}


class SecurityError(Exception):
    """Raised when a security violation is detected."""


class TimeoutError(Exception):
    """Raised when an operation times out."""


# 100MB cap applied to any file whose format has no tighter content-specific
# limit (and to S3 downloads before they hit disk).
MAX_FILE_BYTES = 100 * 1024 * 1024

# Extensions refused for local paths and S3 keys alike: nothing the converter
# should ever be asked to open, and a cheap block on smuggling executables.
DANGEROUS_EXTENSIONS = [
    ".exe",
    ".bat",
    ".cmd",
    ".sh",
    ".ps1",
    ".scr",
    ".vbs",
    ".jar",
    ".app",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
]


def with_timeout(timeout_seconds: int = 30) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to add timeout protection to functions using threading."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            import threading

            result: list[Any] = [None]
            exception: list[Exception | None] = [None]

            def target() -> None:
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e

            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout_seconds)

            if thread.is_alive():
                # Thread is still running, timeout occurred
                raise TimeoutError("Operation timed out")

            if exception[0]:
                raise exception[0]

            return cast("R", result[0])

        return wrapper

    return decorator


def sanitize_unicode_text(text: str) -> str:
    """Sanitize Unicode text by normalizing and removing dangerous characters.

    Args:
        text: Input text

    Returns:
        Sanitized text
    """
    if not isinstance(text, str):
        return str(text)

    # Unicode normalization
    text = unicodedata.normalize("NFKC", text)

    # Remove Bidi override characters and other potentially dangerous Unicode
    dangerous_chars = [
        "‮",  # RIGHT-TO-LEFT OVERRIDE
        "‭",  # LEFT-TO-RIGHT OVERRIDE
        "⁦",  # LEFT-TO-RIGHT ISOLATE
        "⁧",  # RIGHT-TO-LEFT ISOLATE
        "⁨",  # FIRST STRONG ISOLATE
        "⁩",  # POP DIRECTIONAL ISOLATE
        "\u0000",  # NULL byte
        "﻿",  # BYTE ORDER MARK
        "​",  # ZERO WIDTH SPACE
        "‌",  # ZERO WIDTH NON-JOINER
        "‍",  # ZERO WIDTH JOINER
        "�",  # REPLACEMENT CHARACTER
    ]

    for char in dangerous_chars:
        text = text.replace(char, "")

    return text


def validate_xml_security(file_path: str) -> str:
    """Validate and sanitize XML files to prevent entity expansion attacks.

    Args:
        file_path: Path to XML file

    Returns:
        Path to sanitized temporary file

    Raises:
        SecurityError: If XML contains dangerous constructs
    """
    try:
        with Path(file_path).open(encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Check for dangerous XML patterns
        dangerous_patterns = [
            r'<!ENTITY\s+\w+\s+"[^"]*&[^"]*"[^>]*>',  # Entity references within entities
            r"<!ENTITY[^>]*&[^>]*>",  # Entities with references
            r'SYSTEM\s+["\']',  # External entity references
            r'PUBLIC\s+["\']',  # Public entity references
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                raise SecurityError("Security violation: dangerous XML entities detected")

        # Count entity definitions (limit to prevent expansion bombs)
        entity_count = len(re.findall(r"<!ENTITY", content, re.IGNORECASE))
        if entity_count > 10:
            raise SecurityError("Security violation: too many XML entities")

        # Remove or disable DOCTYPE declarations with entities
        # Simple approach: remove entire DOCTYPE section
        content = re.sub(r"<!DOCTYPE[^>]*\[[^\]]*\]>", "", content, flags=re.DOTALL | re.IGNORECASE)
        content = re.sub(r"<!DOCTYPE[^>]*>", "", content, flags=re.IGNORECASE)

        # Create sanitized temporary file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            return tmp.name

    except Exception as e:
        if isinstance(e, SecurityError):
            raise
        raise SecurityError("Security violation: XML validation failed") from e


def validate_json_security(file_path: str) -> str:
    """Validate and sanitize JSON files to prevent recursion bombs.

    Args:
        file_path: Path to JSON file

    Returns:
        Path to validated file (or original if safe)

    Raises:
        SecurityError: If JSON is too deeply nested or complex
    """
    try:
        with Path(file_path).open(encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Check file size first
        if len(content) > 10 * 1024 * 1024:  # 10MB limit
            raise SecurityError("Security violation: JSON file too large")

        # Parse and analyze structure
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # If it's not valid JSON, let MarkItDown handle it normally
            return file_path
        except RecursionError as e:
            raise SecurityError("Security violation: JSON recursion depth limit exceeded") from e

        # Check nesting depth
        def check_depth(obj: Any, current_depth: int = 0, max_depth: int = 30) -> None:
            if current_depth > max_depth:
                raise SecurityError("Security violation: JSON recursion depth limit exceeded")

            if isinstance(obj, dict):
                for value in obj.values():
                    check_depth(value, current_depth + 1, max_depth)
            elif isinstance(obj, list):
                for item in obj:
                    check_depth(item, current_depth + 1, max_depth)

        check_depth(data)
        return file_path  # Return original file if safe

    except Exception as e:
        if isinstance(e, SecurityError):
            raise
        if isinstance(e, RecursionError):
            raise SecurityError("Security violation: JSON recursion depth limit exceeded") from e
        # If validation fails, let MarkItDown handle it
        return file_path


def validate_csv_security(file_path: str) -> str:
    """Validate CSV files to prevent bombs and excessive resource usage.

    Args:
        file_path: Path to CSV file

    Returns:
        Path to original file if safe

    Raises:
        SecurityError: If CSV is too large or complex
    """
    try:
        # Check file size first
        file_size = Path(file_path).stat().st_size
        if file_size > 50 * 1024 * 1024:  # 50MB limit
            raise SecurityError("Security violation: CSV file too large")

        # Analyze CSV structure
        with Path(file_path).open(encoding="utf-8", errors="ignore") as f:
            # Read first few lines to check structure
            sample = f.read(1024 * 1024)  # 1MB sample

        # Count columns and rows in sample
        try:
            dialect = csv.Sniffer().sniff(sample[:1024])
            reader = csv.reader(sample.splitlines(), dialect=dialect)

            max_cols = 0

            for row_count, row in enumerate(reader, 1):
                max_cols = max(max_cols, len(row))

                # Limits to prevent CSV bombs
                if row_count > 100000:  # 100k rows limit for initial check
                    raise SecurityError("Security violation: CSV too many rows")
                if max_cols > 1000:  # 1000 columns limit
                    raise SecurityError("Security violation: CSV too many columns")
                if any(len(cell) > 10000 for cell in row):  # 10k chars per cell
                    raise SecurityError("Security violation: CSV cell too large")

        except csv.Error:
            # If CSV parsing fails, let MarkItDown handle it
            pass

        return file_path

    except Exception as e:
        if isinstance(e, SecurityError):
            raise
        return file_path


def validate_file_content_security(file_path: str) -> str:
    """Perform comprehensive security validation on file content before processing.

    Args:
        file_path: Path to file to validate

    Returns:
        Path to validated file (may be temporary sanitized version)

    Raises:
        SecurityError: If file contains dangerous content
    """
    import mimetypes

    try:
        # Get file type
        mime_type, _ = mimetypes.guess_type(file_path)
        file_ext = Path(file_path).suffix.lower()

        # Apply format-specific validation
        if mime_type in XML_MIME_TYPES or file_ext in [".xml", ".xhtml"]:
            return validate_xml_security(file_path)
        if mime_type in JSON_MIME_TYPES or file_ext == ".json":
            return validate_json_security(file_path)
        if mime_type in CSV_MIME_TYPES or file_ext == ".csv":
            return validate_csv_security(file_path)

        # General file size check
        file_size = Path(file_path).stat().st_size
        if file_size > MAX_FILE_BYTES:
            raise SecurityError("Security violation: file too large")

        return file_path

    except Exception as e:
        if isinstance(e, SecurityError):
            raise
        # If validation fails, let MarkItDown handle it
        return file_path


def extract_text_from_binary(data: bytes, filename: str = "") -> str | None:  # noqa: ARG001
    """Extract readable text from potentially binary data.

    Args:
        data: Binary data
        filename: Optional filename for context

    Returns:
        Extracted text or None if no readable content found
    """
    try:
        # Try UTF-8 first
        try:
            text = data.decode("utf-8")
            # Check if it contains reasonable amount of printable characters
            printable_ratio = sum(1 for c in text if c.isprintable() or c.isspace()) / len(text)
            if printable_ratio > 0.7:  # At least 70% printable
                return text
        except UnicodeDecodeError:
            pass

        # Try other common encodings
        encodings = ["latin1", "cp1252", "iso-8859-1"]
        for encoding in encodings:
            try:
                text = data.decode(encoding, errors="ignore")
                printable_ratio = sum(1 for c in text if c.isprintable() or c.isspace()) / len(text)
                if printable_ratio > 0.7:
                    return text
            except (UnicodeDecodeError, AttributeError, ValueError):
                # Skip this encoding and try the next one
                pass

        # Extract printable ASCII characters as fallback
        printable_chars = "".join(chr(b) for b in data if 32 <= b <= 126 or b in [9, 10, 13])
        if len(printable_chars) > 20:  # At least some readable content
            return printable_chars

        return None

    except Exception:
        return None


@with_timeout(30)
def safe_convert_with_limits(markitdown_instance: Any, file_path: str) -> Any:
    """Safely convert a file with timeout and recursion protection.

    Args:
        markitdown_instance: MarkItDown instance
        file_path: Path to file to convert

    Returns:
        Conversion result

    Raises:
        TimeoutError: If conversion times out
        RecursionError: If recursion depth is exceeded
        SecurityError: For security violations
    """
    sanitized_file_path = None

    try:
        # Perform comprehensive security validation first
        validated_file_path = validate_file_content_security(file_path)

        # Track if we created a temporary sanitized file
        if validated_file_path != file_path:
            sanitized_file_path = validated_file_path

        # Check if file might contain binary data in text format
        file_path_obj = Path(validated_file_path)
        if file_path_obj.exists():
            with Path(validated_file_path).open("rb") as f:
                data = f.read(1024)  # Read first 1KB to check

            # If it's a text file but contains significant binary content
            mime_type = None
            try:
                import mimetypes

                mime_type = mimetypes.guess_type(validated_file_path)[0]
            except (ImportError, OSError):
                pass  # Ignore mime type detection errors

            if mime_type and mime_type.startswith("text/"):
                # For text files, extract readable content if binary data present
                try:
                    # Test if it's valid text
                    data.decode("utf-8")
                except UnicodeDecodeError:
                    # Contains binary data, extract text portions
                    extracted_text = extract_text_from_binary(data, str(file_path_obj))
                    if extracted_text:
                        # Create temporary file with extracted text
                        with tempfile.NamedTemporaryFile(
                            mode="w", suffix=".txt", delete=False
                        ) as tmp:
                            tmp.write(extracted_text)
                            temp_path = tmp.name
                        try:
                            result = markitdown_instance.convert(temp_path)
                            if hasattr(result, "text_content") and result.text_content:
                                result.text_content = sanitize_unicode_text(result.text_content)
                            return result
                        finally:
                            Path(temp_path).unlink(missing_ok=True)

        # Normal conversion with validated file
        result = markitdown_instance.convert(validated_file_path)

        # Sanitize the result text
        if hasattr(result, "text_content") and result.text_content:
            result.text_content = sanitize_unicode_text(result.text_content)

            # Limit output size to prevent resource exhaustion
            max_output_size = 10 * 1024 * 1024  # 10MB
            if len(result.text_content) > max_output_size:
                result.text_content = (
                    result.text_content[:max_output_size]
                    + "\n\n[Output truncated due to size limits]"
                )

        return result

    except RecursionError as e:
        raise SecurityError(
            "Security violation: recursion depth limit exceeded during processing"
        ) from e
    except Exception as e:
        if "recursion" in str(e).lower():
            raise SecurityError(
                "Security violation: recursion depth limit exceeded during processing"
            ) from e
        raise
    finally:
        # Clean up temporary sanitized file if created
        if sanitized_file_path and sanitized_file_path != file_path:
            with contextlib.suppress(OSError, PermissionError):
                Path(sanitized_file_path).unlink(missing_ok=True)


def validate_s3_key(key: str, allowed_prefixes: list[str] | None = None) -> str:
    """Validate an S3 object key requested by a caller.

    Args:
        key: The object key to fetch (e.g. "workspaces/<ws>/<uuid>.pdf")
        allowed_prefixes: Optional key-prefix allowlist. Empty or None means
            no restriction — only appropriate when every caller is trusted.

    Returns:
        The stripped key, unchanged.

    Raises:
        SecurityError: If the key is empty, carries ``..`` segments, has a
            dangerous extension, or falls outside the prefix allowlist.
    """
    stripped = key.strip() if isinstance(key, str) else ""
    if not stripped:
        raise SecurityError("Security violation: empty S3 key")

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
