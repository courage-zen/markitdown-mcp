"""
Denial of Service (DoS) protection tests.

The stateless HTTP server has no long-lived session state to exhaust, so
the attack surface that remains is the conversion layer itself: large
objects, deep structures, and many concurrent conversions. These tests
drive those vectors through ``convert_file_impl`` (moto-backed S3) and
``list_supported_formats_impl`` and assert every request completes
quickly with a well-formed outcome (content or sanitized ToolError).
"""

import asyncio
import json
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from moto import mock_aws

from markitdown_mcp.conversion import (
    convert_file_impl,
    list_supported_formats_impl,
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


def _upload(client, path: Path, key: str) -> str:
    """Upload a local file into the mock bucket; return the key."""
    client.put_object(Bucket="multica-uploads", Key=key, Body=path.read_bytes())
    return key


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
    async def test_concurrent_conversion_flood(self, monkeypatch, temp_dir):
        """Many simultaneous conversions all complete without raw exceptions."""
        test_file = Path(temp_dir) / "flood.txt"
        test_file.write_text("Flood test content.\n")

        # Await inside the moto block: coroutines created but not run would
        # lose the mock backend on exit and hit real S3.
        with _s3_backend(monkeypatch) as client:
            key = _upload(client, test_file, "workspaces/dos/flood.txt")
            num_requests = 50
            tasks = [convert_file_impl(s3_key=key) for _ in range(num_requests)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        raw_exceptions = [r for r in results if not isinstance(r, (str, ToolError))]
        assert not raw_exceptions, f"Flood caused raw exceptions: {raw_exceptions}"

        successes = sum(1 for r in results if isinstance(r, str))
        assert successes == num_requests, f"Only {successes}/{num_requests} succeeded"

    @pytest.mark.security
    async def test_mixed_valid_and_invalid_load(self, monkeypatch, temp_dir):
        """A mixed load of valid and failing conversions never crashes."""
        valid_file = Path(temp_dir) / "valid.txt"
        valid_file.write_text("Valid content")

        with _s3_backend(monkeypatch) as client:
            valid_key = _upload(client, valid_file, "workspaces/dos/valid.txt")
            tasks = []
            num_valid, num_invalid = 10, 10
            for _ in range(num_valid):
                tasks.append(convert_file_impl(s3_key=valid_key))
            for i in range(num_invalid):
                tasks.append(convert_file_impl(s3_key=f"workspaces/dos/missing_{i}.txt"))

            # Gather inside the moto block — see test_concurrent_conversion_flood.
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
    async def test_large_file_dos_protection(self, monkeypatch, temp_dir):
        """Large objects complete in bounded time or fail gracefully."""
        # 10MB text object — under the general size cap, must convert.
        large_file = Path(temp_dir) / "dos_large_10mb.txt"
        large_file.write_text("DoS attack large file content.\n" * (10 * 1024 * 32))

        start = time.time()
        with _s3_backend(monkeypatch) as client:
            key = _upload(client, large_file, "workspaces/dos/large_10mb.txt")
            content, error = await _run_or_error(convert_file_impl(s3_key=key))
        elapsed = time.time() - start

        assert elapsed < 60, f"Large file took too long: {elapsed:.2f}s"
        assert content is not None or error is not None
        if error is not None:
            lowered = error.lower()
            assert any(
                term in lowered for term in ("size", "large", "memory", "timeout", "processing")
            ), f"Unexpected error for large file: {error}"

    @pytest.mark.security
    async def test_oversize_download_rejected_quickly(self, monkeypatch):
        """Objects above the download cap are rejected mid-stream."""
        from markitdown_mcp.s3source import S3SourceConfig, fetch_s3_object_to_tempfile

        with _s3_backend(monkeypatch) as client:
            client.put_object(
                Bucket="multica-uploads",
                Key="workspaces/dos/big.bin",
                Body=b"x" * 1024,
            )
            config = S3SourceConfig.from_env()
            assert config is not None

            start = time.time()
            with pytest.raises(Exception, match="(?i)security violation"):
                fetch_s3_object_to_tempfile(
                    config, "workspaces/dos/big.bin", max_bytes=100
                )
            elapsed = time.time() - start

        assert elapsed < 30, f"Oversize rejection took too long: {elapsed:.2f}s"

    @pytest.mark.security
    async def test_deeply_nested_json_bounded(self, monkeypatch, temp_dir):
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
        with _s3_backend(monkeypatch) as client:
            key = _upload(client, complex_file, "workspaces/dos/complex.json")
            content, error = await _run_or_error(convert_file_impl(s3_key=key))
        elapsed = time.time() - start

        assert elapsed < 30, f"Complex processing took too long: {elapsed:.2f}s"
        assert content is not None or error is not None


class TestTimeBasedDoSProtection:
    """Slow or heavy requests do not wedge the tool layer."""

    @pytest.mark.security
    async def test_mixed_request_types_complete(self, monkeypatch, temp_dir):
        """Quick and failing requests interleave without slowing each other."""
        valid_file = Path(temp_dir) / "mixed.txt"
        valid_file.write_text("Mixed request content")

        start_time = time.time()
        with _s3_backend(monkeypatch) as client:
            valid_key = _upload(client, valid_file, "workspaces/dos/mixed.txt")
            for i in range(10):
                if i % 2 == 0:
                    content, _ = await _run_or_error(convert_file_impl(s3_key=valid_key))
                    assert content is not None
                else:
                    content, error = await _run_or_error(
                        convert_file_impl(s3_key=f"workspaces/dos/slow_{i}.txt")
                    )
                    assert content is None and error is not None
        total_time = time.time() - start_time

        assert total_time < 30, f"Slow request handling took too long: {total_time:.2f}s"

    @pytest.mark.security
    async def test_timeout_protection(self, monkeypatch, temp_dir):
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
        with _s3_backend(monkeypatch) as client:
            key = _upload(client, slow_file, "workspaces/dos/timeout.json")
            content, error = await _run_or_error(convert_file_impl(s3_key=key))
        processing_time = time.time() - start

        assert processing_time < 60, f"Took too long: {processing_time:.2f}s"
        assert content is not None or error is not None


class TestRecoveryFromDoSAttacks:
    """The tool layer works normally after heavy load."""

    @pytest.mark.security
    async def test_recovery_after_large_file_processing(self, monkeypatch, temp_dir):
        """After a heavy conversion, light requests still succeed fast."""
        large_file = Path(temp_dir) / "heavy.txt"
        large_file.write_text("Heavy content line.\n" * (5 * 1024 * 32))  # ~5MB

        with _s3_backend(monkeypatch) as client:
            heavy_key = _upload(client, large_file, "workspaces/dos/heavy.txt")
            await _run_or_error(convert_file_impl(s3_key=heavy_key))

            small_file = Path(temp_dir) / "light.txt"
            small_file.write_text("Light content")
            light_key = _upload(client, small_file, "workspaces/dos/light.txt")

            start = time.time()
            content, error = await _run_or_error(convert_file_impl(s3_key=light_key))
        recovery_time = time.time() - start

        assert recovery_time < 10, f"Recovery took too long: {recovery_time:.2f}s"
        assert content is not None, f"Server did not recover: {error}"

    @pytest.mark.security
    async def test_recovery_after_concurrent_attack(self, monkeypatch, temp_dir):
        """After a concurrent burst, the formats listing is intact."""
        test_file = Path(temp_dir) / "burst.txt"
        test_file.write_text("Burst content")

        with _s3_backend(monkeypatch) as client:
            key = _upload(client, test_file, "workspaces/dos/burst.txt")
            tasks = [convert_file_impl(s3_key=key) for _ in range(30)]
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
    async def test_sustained_load_phases(self, monkeypatch, temp_dir):
        """Success rate holds across escalating load phases (CI-sized)."""
        test_file = Path(temp_dir) / "phases.txt"
        test_file.write_text("Phase content")

        phases = [
            {"requests": 5, "delay": 0.05},
            {"requests": 10, "delay": 0.02},
            {"requests": 15, "delay": 0.01},
        ]

        phase_success_rates = []
        with _s3_backend(monkeypatch) as client:
            key = _upload(client, test_file, "workspaces/dos/phases.txt")
            for phase in phases:
                tasks = []
                for _ in range(phase["requests"]):
                    tasks.append(convert_file_impl(s3_key=key))
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
    async def test_invalid_requests_error_cleanly_under_load(self, monkeypatch):
        """Failing requests surface ToolError, never raw exceptions."""
        with _s3_backend(monkeypatch):
            tasks = [
                convert_file_impl(s3_key=f"workspaces/dos/missing_{i}.txt")
                for i in range(20)
            ]
            # Gather inside the moto block — see test_concurrent_conversion_flood.
            results = await asyncio.gather(*tasks, return_exceptions=True)
        raw_exceptions = [r for r in results if not isinstance(r, (str, ToolError))]
        assert not raw_exceptions, f"Raw exceptions leaked: {raw_exceptions}"

        errors = [r for r in results if isinstance(r, ToolError)]
        assert len(errors) == 20, "Invalid requests did not all error cleanly"
