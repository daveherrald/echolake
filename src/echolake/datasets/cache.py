"""Cache management for datasets."""

import hashlib
import logging
import shutil
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
import requests
from .utils import get_cache_dir
from .models import DatasetManifest

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

logger = logging.getLogger(__name__)


class DatasetCache:
    """Manages caching of downloaded datasets."""

    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize cache manager.

        Args:
            cache_dir: Optional custom cache directory
        """
        self.cache_dir = cache_dir or get_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_cache_path(self, cache_key: str, version: Optional[str] = None) -> Path:
        """
        Get cache path for a dataset.

        Args:
            cache_key: Unique key for the dataset (e.g., "github.com/org/repo/path")
            version: Optional version string

        Returns:
            Path to cached dataset directory
        """
        # Sanitize cache key for filesystem
        safe_key = cache_key.replace("://", "/").replace(":", "/")

        if version:
            return self.cache_dir / safe_key / version
        else:
            return self.cache_dir / safe_key

    def is_cached(self, cache_key: str, version: Optional[str] = None) -> bool:
        """
        Check if dataset is cached.

        Args:
            cache_key: Unique key for the dataset
            version: Optional version string

        Returns:
            True if cached, False otherwise
        """
        cache_path = self.get_cache_path(cache_key, version)
        manifest_path = cache_path / "dataset.yaml"
        return manifest_path.exists()

    def get_cached_manifest(self, cache_key: str, version: Optional[str] = None) -> Optional[DatasetManifest]:
        """
        Load manifest from cache.

        Args:
            cache_key: Unique key for the dataset
            version: Optional version string

        Returns:
            DatasetManifest if cached, None otherwise
        """
        if not self.is_cached(cache_key, version):
            return None

        cache_path = self.get_cache_path(cache_key, version)
        manifest_path = cache_path / "dataset.yaml"

        return DatasetManifest.from_file(manifest_path)

    def _download_s3(
        self,
        uri: str,
        dest_path: Path,
    ) -> None:
        """
        Download file from S3 with requester-pays support.

        Args:
            uri: S3 URI (s3://bucket/key)
            dest_path: Destination file path

        Raises:
            ImportError: If boto3 is not installed
            ClientError: If S3 download fails
        """
        if not BOTO3_AVAILABLE:
            raise ImportError(
                "boto3 is required for S3 downloads. Install with: pip install boto3"
            )

        parsed = urlparse(uri)
        bucket = parsed.netloc
        key = parsed.path.lstrip('/')

        s3 = boto3.client('s3')
        logger.info("Downloading s3://%s/%s", bucket, key)
        s3.download_file(
            bucket, key, str(dest_path),
            ExtraArgs={'RequestPayer': 'requester'},
        )

    def download_file(
        self,
        url: str,
        dest_path: Path,
        checksum: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        """
        Download file from URL or S3 URI.

        Args:
            url: URL or S3 URI to download from
            dest_path: Destination file path
            checksum: Optional checksum in format "algorithm:value"
            timeout: Request timeout in seconds

        Raises:
            ValueError: If checksum validation fails
            requests.RequestException: If HTTP download fails
        """
        # Create parent directory
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        if url.startswith('s3://'):
            self._download_s3(url, dest_path)
            # Verify checksum if provided
            if checksum:
                algorithm, expected_hash = checksum.split(":", 1)
                hasher = hashlib.new(algorithm)
                with open(dest_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        hasher.update(chunk)
                actual_hash = hasher.hexdigest()
                if actual_hash != expected_hash:
                    dest_path.unlink()
                    raise ValueError(
                        f"Checksum mismatch: expected {expected_hash}, got {actual_hash}"
                    )
            return

        # HTTP download
        response = requests.get(url, timeout=timeout, stream=True)
        response.raise_for_status()

        # Write to file and calculate checksum if needed
        if checksum:
            algorithm, expected_hash = checksum.split(":", 1)
            hasher = hashlib.new(algorithm)

            with open(dest_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        hasher.update(chunk)

            actual_hash = hasher.hexdigest()
            if actual_hash != expected_hash:
                dest_path.unlink()  # Delete invalid file
                raise ValueError(
                    f"Checksum mismatch: expected {expected_hash}, got {actual_hash}"
                )
        else:
            with open(dest_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

    def cache_dataset(
        self,
        cache_key: str,
        manifest_url: str,
        bundled_files_base_url: str,
        manifest: DatasetManifest,
        version: Optional[str] = None,
        timeout: int = 30,
    ) -> Path:
        """
        Download and cache a dataset.

        Args:
            cache_key: Unique key for the dataset
            manifest_url: URL to dataset.yaml
            bundled_files_base_url: Base URL for bundled files
            manifest: Parsed manifest
            version: Optional version string
            timeout: Request timeout in seconds

        Returns:
            Path to cached dataset directory

        Raises:
            requests.RequestException: If download fails
            ValueError: If checksum validation fails
        """
        cache_path = self.get_cache_path(cache_key, version)

        # Create cache directory
        cache_path.mkdir(parents=True, exist_ok=True)

        # Save manifest
        manifest_path = cache_path / "dataset.yaml"
        manifest.to_file(manifest_path)

        # Download bundled files
        for bundled_file in manifest.files.bundled:
            file_url = f"{bundled_files_base_url}/{bundled_file.path}"
            file_dest = cache_path / bundled_file.path

            self.download_file(file_url, file_dest, timeout=timeout)

        # Create cache metadata
        metadata_path = cache_path / ".cache_metadata"
        with open(metadata_path, 'w') as f:
            f.write(f"cached_at: {time.time()}\n")
            f.write(f"cache_key: {cache_key}\n")
            f.write(f"version: {version or 'latest'}\n")

        return cache_path

    def is_cache_expired(
        self,
        cache_key: str,
        version: Optional[str] = None,
        max_age_seconds: int = 86400,  # 24 hours
    ) -> bool:
        """
        Check if cache is expired.

        Args:
            cache_key: Unique key for the dataset
            version: Optional version string
            max_age_seconds: Maximum cache age in seconds

        Returns:
            True if expired, False otherwise
        """
        cache_path = self.get_cache_path(cache_key, version)
        metadata_path = cache_path / ".cache_metadata"

        if not metadata_path.exists():
            return True

        try:
            with open(metadata_path, 'r') as f:
                for line in f:
                    if line.startswith("cached_at:"):
                        cached_at = float(line.split(":", 1)[1].strip())
                        age = time.time() - cached_at
                        return age > max_age_seconds
        except (ValueError, IOError):
            return True

        return True

    def invalidate_cache(self, cache_key: str, version: Optional[str] = None) -> None:
        """
        Remove dataset from cache.

        Args:
            cache_key: Unique key for the dataset
            version: Optional version string
        """
        cache_path = self.get_cache_path(cache_key, version)
        if cache_path.exists():
            shutil.rmtree(cache_path)

    def clear_all(self) -> None:
        """Clear entire cache directory."""
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_cache_size(self) -> int:
        """
        Get total cache size in bytes.

        Returns:
            Cache size in bytes
        """
        total_size = 0
        for path in self.cache_dir.rglob('*'):
            if path.is_file():
                total_size += path.stat().st_size
        return total_size

    def get_file_reference_cache_path(self, uri: str) -> Path:
        """
        Get cache path for a file reference.

        Args:
            uri: URI of the file reference

        Returns:
            Path to cached file
        """
        # Create a safe filename from the URI
        uri_hash = hashlib.sha256(uri.encode()).hexdigest()[:16]

        # Extract filename from URI
        parsed = urlparse(uri)
        filename = Path(parsed.path).name or "data"

        # Store in file-refs subdirectory
        file_refs_dir = self.cache_dir / "file-refs"
        return file_refs_dir / f"{uri_hash}_{filename}"

    def is_file_reference_cached(
        self,
        uri: str,
        checksum: Optional[str] = None,
        max_age_seconds: int = 604800,  # 7 days default
    ) -> bool:
        """
        Check if file reference is cached and valid.

        Args:
            uri: URI of the file reference
            checksum: Optional checksum to verify
            max_age_seconds: Maximum cache age in seconds (default 7 days)

        Returns:
            True if cached and valid, False otherwise
        """
        cache_path = self.get_file_reference_cache_path(uri)

        if not cache_path.exists():
            return False

        # Check age
        age = time.time() - cache_path.stat().st_mtime
        if age > max_age_seconds:
            return False

        # Verify checksum if provided
        if checksum:
            algorithm, expected_hash = checksum.split(":", 1)
            hasher = hashlib.new(algorithm)

            with open(cache_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)

            actual_hash = hasher.hexdigest()
            if actual_hash != expected_hash:
                # Checksum mismatch - invalidate cache
                cache_path.unlink()
                return False

        return True

    def download_file_reference(
        self,
        uri: str,
        checksum: Optional[str] = None,
        timeout: int = 60,
        max_age_seconds: int = 604800,  # 7 days
    ) -> Path:
        """
        Download and cache a file reference.

        Args:
            uri: URI to download from
            checksum: Optional checksum in format "algorithm:value"
            timeout: Request timeout in seconds
            max_age_seconds: Maximum cache age in seconds

        Returns:
            Path to cached file

        Raises:
            ValueError: If checksum validation fails
            requests.RequestException: If download fails
        """
        # Check if already cached
        if self.is_file_reference_cached(uri, checksum, max_age_seconds):
            return self.get_file_reference_cache_path(uri)

        # Download to cache
        cache_path = self.get_file_reference_cache_path(uri)
        self.download_file(uri, cache_path, checksum, timeout)

        return cache_path

    def get_cached_file_reference(self, uri: str) -> Optional[Path]:
        """
        Get path to cached file reference if it exists.

        Args:
            uri: URI of the file reference

        Returns:
            Path to cached file if exists, None otherwise
        """
        cache_path = self.get_file_reference_cache_path(uri)
        if cache_path.exists():
            return cache_path
        return None
