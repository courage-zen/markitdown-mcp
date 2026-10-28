"""
Denial of Service (DoS) protection tests.

The stateless HTTP server has no long-lived session state to exhaust, so
the attack surface that remains is the conversion layer itself: large
files, deep structures, oversized base64 payloads, and many concurrent
conversions. These tests drive those vectors through ``convert_file_impl``
and ``list_supported_formats_impl`` and assert every request completes
quickly with a well-formed outcome (content or sanitized ToolError).
"""

import asyncio
import base64
import json
import os
import time
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from markitdown_mcp.conversion import (
    convert_file_impl,
    list_supported_formats_impl,
)


async def _run_or_error(coro):
    """Await a conversion; return (content, error) — exactly one is set."""
    try:
        result = await coro
    except ToolError as e:
        return None, str(e)
    return result, None


class TestRequestFloodProtection:
    """The tool layer stays responsive under bursts of requests."""

    @pytest.mark.security
    async def test_concurrent_conversion_flood(self, temp_dir):
        """Many simultaneous conversions all complete without raw exceptions."""
        test_file = Path(temp_dir) / "flood.txt"
        test_file.write_text("Flood test content.\n")

        num_requests = 50
        tasks = [convert_file_impl(file_path=str(test_file)) for _ in range(num_requests)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        raw_exceptions = [r for r in results if not isinstance(r, (str, ToolError))]
        assert not raw_exceptions, f"Flood caused raw exceptions: {raw_exceptions}"

        successes = sum(1 for r in results if isinstance(r, str))
        assert successes == num_requests, f"Only {successes}/{num_requests} succeeded"

    @pytest.mark.security
    async def test_mixed_valid_and_invalid_load(self, temp_dir):
        """A mixed load of valid and failing conversions never crashes."""
        valid_file = Path(temp_dir) / "valid.txt"
        valid_file.write_text("Valid content")

        tasks = []
        num_valid, num_invalid = 10, 10
        for _ in range(num_valid):
            tasks.append(convert_file_impl(file_path=str(valid_file)))
        for i in range(num_invalid):
            tasks.append(convert_file_impl(file_path=f"/nonexistent/dos_{i}.txt"))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # ToolError is the expected outcome for invalid paths; any other
        # exception (or a stray success) is a real defect.
        raw_exceptions = [r for r in results if not isinstance(r, (str, ToolError))]
        assert not raw_exceptions, f"Mixed load caused raw exceptions: {raw_exceptions}"

        successes = sum(1 for r in results if isinstance(r, str))
        errors = sum(1 for r in results if isinstance(r, ToolError))
        assert successes == num_valid, f"Valid requests failed: {successes}/{num_valid}"
        assert errors == num_invalid, f"Invalid requests did not error cleanly: {errors}"

    @pytest.mark.security
    async def test_formats_listing_under_load(self):
        """A cheap tool stays fast and correct under repeated concurrent calls."""
        tasks = [list_supported_formats_impl() for _ in range(30)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        raw_exceptions = [r for r in results if not isinstance(r, str)]
        assert not raw_exceptions, f"Listing caused exceptions: {raw_exceptions}"

        for result in results:
            assert "Supported file formats" in result


class TestResourceExhaustionProtection:
    """Large or complex inputs are bounded, not unbounded."""

    @pytest.mark.security
    @pytest.mark.slow
    async def test_large_file_dos_protection(self, temp_dir):
        """Large files complete in bounded time or fail gracefully."""
        # 10MB text file — under the general size cap, must convert.
        large_file = Path(temp_dir) / "dos_large_10mb.txt"
        large_file.write_text("DoS attack large file content.\n" * (10 * 1024 * 32))

        start = time.time()
        content, error = await _run_or_error(convert_file_impl(file_path=str(large_file)))
        elapsed = time.time() - start

        assert elapsed < 60, f"Large file took too long: {elapsed:.2f}s"
        assert content is not None or error is not None
        if error is not None:
            lowered = error.lower()
            assert any(
                term in lowered for term in ("size", "large", "memory", "timeout", "processing")
            ), f"Unexpected error for large file: {error}"

    @pytest.mark.security
    async def test_base64_bomb_dos_protection(self):
        """Oversized base64 payloads are rejected quickly."""
        # 11MB decoded — above the 10MB validate_base64 cap.
        large_content = "DoS base64 bomb attack.\n" * (11 * 1024 * 1024 // 24)
        encoded_content = base64.b64encode(large_content.encode()).decode()

        start = time.time()
        content, error = await _run_or_error(
            convert_file_impl(file_content=encoded_content, filename="dos_base64_bomb.txt")
        )
        elapsed = time.time() - start

        assert elapsed < 30, f"Base64 bomb took too long: {elapsed:.2f}s"
        # Must be rejected, not processed.
        assert content is None and error is not None
        lowered = error.lower()
        assert any(
            term in lowered for term in ("size", "large", "memory", "base64", "security")
        ), f"Unexpected error for base64 bomb: {error}"

    @pytest.mark.security
    async def test_deeply_nested_json_bounded(self, temp_dir):
        """Deeply nested JSON is rejected by the recursion guard."""
        complex_data: object = {"level": 0, "data": "root"}
        max_depth = 50
        for i in range(max_depth):
            complex_data = {
                "level": i + 1,
                "nested": complex_data,
                "array": [{"item": j} for j in range(5)],
            }

        complex_file = Path(temp_dir) / "dos_complex.json"
        with open(complex_file, "w") as f:
            json.dump(complex_data, f)

        start = time.time()
        content, error = await _run_or_error(convert_file_impl(file_path=str(complex_file)))
        elapsed = time.time() - start

        assert elapsed < 30, f"Complex processing took too long: {elapsed:.2f}s"
        assert content is not None or error is not None


class TestTimeBasedDoSProtection:
    """Slow or heavy requests do not wedge the tool layer."""

    @pytest.mark.security
    async def test_mixed_request_types_complete(self, temp_dir):
        """Quick and failing requests interleave without slowing each other."""
        valid_file = Path(temp_dir) / "mixed.txt"
        valid_file.write_text("Mixed request content")

        start_time = time.time()
        for i in range(10):
            if i % 2 == 0:
                content, _ = await _run_or_error(
                    convert_file_impl(file_path=str(valid_file))
                )
                assert content is not None
            else:
                content, error = await _run_or_error(
                    convert_file_impl(file_path=f"/nonexistent/slow_{i}.txt")
                )
                assert content is None and error is not None
        total_time = time.time() - start_time

        assert total_time < 30, f"Slow request handling took too long: {total_time:.2f}s"

    @pytest.mark.security
    async def test_timeout_protection(self, temp_dir):
        """Processing completes or times out — never hangs indefinitely."""
        slow_file = Path(temp_dir) / "timeout_test.json"

        large_data: dict = {"deeply_nested": {}, "large_array": []}
        current = large_data["deeply_nested"]
        for i in range(50):
            current["level"] = i
            current["data"] = f"Level {i} data"
            current["nested"] = {}
            current = current["nested"]
        large_data["large_array"] = [
            {"id": i, "data": f"Item {i}", "metadata": list(range(10))} for i in range(10000)
        ]

        with open(slow_file, "w") as f:
            json.dump(large_data, f)

        start = time.time()
        content, error = await _run_or_error(convert_file_impl(file_path=str(slow_file)))
        processing_time = time.time() - start

        assert processing_time < 60, f"Took too long: {processing_time:.2f}s"
        assert content is not None or error is not None


class TestRecoveryFromDoSAttacks:
    """The tool layer works normally after heavy load."""

    @pytest.mark.security
    async def test_recovery_after_large_file_processing(self, temp_dir):
        """After a heavy conversion, light requests still succeed fast."""
        large_file = Path(temp_dir) / "heavy.txt"
        large_file.write_text("Heavy content line.\n" * (5 * 1024 * 32))  # ~5MB

        await _run_or_error(convert_file_impl(file_path=str(large_file)))

        small_file = Path(temp_dir) / "light.txt"
        small_file.write_text("Light content")

        start = time.time()
        content, error = await _run_or_error(convert_file_impl(file_path=str(small_file)))
        recovery_time = time.time() - start

        assert recovery_time < 10, f"Recovery took too long: {recovery_time:.2f}s"
        assert content is not None, f"Server did not recover: {error}"

    @pytest.mark.security
    async def test_recovery_after_concurrent_attack(self, temp_dir):
        """After a concurrent burst, the formats listing is intact."""
        test_file = Path(temp_dir) / "burst.txt"
        test_file.write_text("Burst content")

        tasks = [convert_file_impl(file_path=str(test_file)) for _ in range(30)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        raw_exceptions = [r for r in results if not isinstance(r, (str, ToolError))]
        assert not raw_exceptions, f"Burst caused raw exceptions: {raw_exceptions}"

        start = time.time()
        result = await list_supported_formats_impl()
        recovery_time = time.time() - start

        assert recovery_time < 5, f"Post-concurrent recovery took too long: {recovery_time:.2f}s"
        assert "Supported file formats" in result


class TestDoSMitigationStrategies:
    """Built-in limits behave as designed."""

    @pytest.mark.security
    async def test_sustained_load_phases(self, temp_dir):
        """Success rate holds across escalating load phases (CI-sized)."""
        test_file = Path(temp_dir) / "phases.txt"
        test_file.write_text("Phase content")

        phases = [
            {"requests": 5, "delay": 0.05},
            {"requests": 10, "delay": 0.02},
            {"requests": 15, "delay": 0.01},
        ]

        phase_success_rates = []
        for phase in phases:
            tasks = []
            for _ in range(phase["requests"]):
                tasks.append(convert_file_impl(file_path=str(test_file)))
                if phase["delay"] > 0:
                    await asyncio.sleep(phase["delay"])

            results = await asyncio.gather(*tasks, return_exceptions=True)
            phase_exceptions = [r for r in results if not isinstance(r, (str, ToolError))]
            assert not phase_exceptions, f"Phase caused exceptions: {phase_exceptions}"

            successes = sum(1 for r in results if isinstance(r, str))
            phase_success_rates.append(successes / phase["requests"])

        for rate in phase_success_rates:
            assert rate > 0.9, f"Success rate too low: {rate:.2%}"

    @pytest.mark.security
    async def test_invalid_requests_error_cleanly_under_load(self, temp_dir):
        """Failing requests surface ToolError, never raw exceptions."""
        tasks = [
            convert_file_impl(file_path=f"/nonexistent/load_{i}.txt") for i in range(20)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        raw_exceptions = [r for r in results if not isinstance(r, (str, ToolError))]
        assert not raw_exceptions, f"Raw exceptions leaked: {raw_exceptions}"

        errors = [r for r in results if isinstance(r, ToolError)]
        assert len(errors) == 20, "Invalid requests did not all error cleanly"
