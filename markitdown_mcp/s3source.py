#!/usr/bin/env python3
"""S3 object source for the MarkItDown MCP server.

Fetches an object from S3-compatible storage (AWS S3 or a MinIO endpoint in
the same cluster) into a local temporary file so it can flow through the
normal conversion pipeline. Configuration mirrors the multica backend's
environment variables so both can share one secret.
"""

import logging
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from markitdown_mcp.security import MAX_FILE_BYTES, SecurityError

logger = logging.getLogger("markitdown-mcp")

# Wall-clock budget for one download, covering connect + full body transfer.
DOWNLOAD_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class S3SourceConfig:
    """Resolved S3 source configuration. Endpoint and path-style handling
    follow the multica backend's semantics: a custom endpoint (MinIO / R2)
    implies path-style addressing unless explicitly overridden."""

    bucket: str
    region: str
    access_key_id: str
    secret_access_key: str
    endpoint_url: str
    use_path_style: bool

    @classmethod
    def from_env(cls) -> "S3SourceConfig | None":
        """Build the config from the environment.

        Returns None when S3 input is not configured (missing bucket or
        credentials) so callers can distinguish "not set up" from "set up
        but failing".
        """
        bucket = os.getenv("S3_BUCKET", "").strip()
        access_key = os.getenv("AWS_ACCESS_KEY_ID", "").strip()
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()
        if not bucket or not access_key or not secret_key:
            return None

        endpoint_url = os.getenv("AWS_ENDPOINT_URL", "").strip()
        region = (
            os.getenv("S3_REGION", "").strip() or os.getenv("AWS_REGION", "").strip() or "us-east-1"
        )

        raw_path_style = os.getenv("S3_USE_PATH_STYLE", "").strip().lower()
        if raw_path_style in ("1", "true", "yes"):
            use_path_style = True
        elif raw_path_style in ("0", "false", "no"):
            use_path_style = False
        else:
            # Custom endpoints (MinIO and friends) cannot do virtual-host
            # style: the bucket would become a subdomain of an internal host.
            use_path_style = bool(endpoint_url)

        return cls(
            bucket=bucket,
            region=region,
            access_key_id=access_key,
            secret_access_key=secret_key,
            endpoint_url=endpoint_url,
            use_path_style=use_path_style,
        )

    def allowed_key_prefixes(self) -> list[str]:
        """Read the S3_KEY_PREFIXES allowlist (comma-separated). Empty means
        no restriction — appropriate only when every caller is trusted."""
        raw = os.getenv("S3_KEY_PREFIXES", "")
        return [prefix.strip() for prefix in raw.split(",") if prefix.strip()]


def _make_client(config: S3SourceConfig):  # type: ignore[no-untyped-def]
    """Create a boto3 S3 client from the resolved config. Imported lazily so
    deployments that never use the S3 input do not pay for boto3 startup."""
    import boto3
    from botocore.config import Config

    botocore_config = Config(
        connect_timeout=10,
        read_timeout=DOWNLOAD_TIMEOUT_SECONDS,
        signature_version="s3v4",
        s3={
            "addressing_style": "path" if config.use_path_style else "virtual",
        },
    )
    return boto3.client(
        "s3",
        region_name=config.region,
        aws_access_key_id=config.access_key_id,
        aws_secret_access_key=config.secret_access_key,
        endpoint_url=config.endpoint_url or None,
        config=botocore_config,
    )


def fetch_s3_object_to_tempfile(
    config: S3SourceConfig,
    key: str,
    *,
    max_bytes: int = MAX_FILE_BYTES,
    timeout_seconds: int = DOWNLOAD_TIMEOUT_SECONDS,
) -> str:
    """Download one S3 object into a local temporary file.

    Args:
        config: Resolved S3 source configuration.
        key: The object key to fetch.
        max_bytes: Download aborts and raises once this many bytes have been
            read, so a huge object cannot fill the disk.
        timeout_seconds: Wall-clock budget for the whole download.

    Returns:
        Path to the downloaded temporary file. The caller owns cleanup.

    Raises:
        SecurityError: On timeout, oversize object, or any S3 access failure
            (with a sanitized message — no bucket/endpoint/key details).
    """
    deadline = time.monotonic() + timeout_seconds

    client = _make_client(config)
    botocore_kwargs = {"Bucket": config.bucket, "Key": key}
    try:
        response = client.get_object(**botocore_kwargs)
    except Exception as e:
        logger.warning("S3 get_object failed for key %s: %s", key, e)
        raise SecurityError("Security violation: S3 object not found or not accessible") from e

    suffix = Path(key).suffix
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, prefix="s3-", delete=False) as temp_file:
            temp_path = temp_file.name
            body = response["Body"]
            written = 0
            while True:
                if time.monotonic() > deadline:
                    raise SecurityError("Security violation: S3 download timed out")
                chunk = body.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise SecurityError("Security violation: file too large")
                temp_file.write(chunk)
        return temp_path
    except SecurityError:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
        raise
    except Exception as e:
        logger.warning("S3 download failed for key %s: %s", key, e)
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
        raise SecurityError("Security violation: S3 download failed") from e
