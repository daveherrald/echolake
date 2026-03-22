"""Google Cloud Storage input source."""

from typing import Iterator, Optional
import fnmatch

try:
    from google.cloud import storage
    from google.cloud.exceptions import GoogleCloudError
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False

from ..base import InputSource


class GCSSource(InputSource):
    """Input source for Google Cloud Storage."""

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        pattern: str = "*",
        project: Optional[str] = None,
    ):
        """
        Initialize GCS source.

        Args:
            bucket: GCS bucket name
            prefix: Blob prefix (folder path)
            pattern: File pattern for matching
            project: GCP project ID (optional, uses ADC default if not provided)
        """
        if not GCS_AVAILABLE:
            raise ImportError(
                "google-cloud-storage is required for GCS source. "
                "Install with: pip install google-cloud-storage"
            )

        self.bucket_name = bucket
        self.prefix = prefix.rstrip('/')
        self.pattern = pattern

        # Initialize GCS client
        try:
            if project:
                self.client = storage.Client(project=project)
            else:
                self.client = storage.Client()

            self.bucket = self.client.bucket(bucket)

            # Verify bucket access
            if not self.bucket.exists():
                raise ValueError(f"Bucket does not exist: {bucket}")

        except GoogleCloudError as e:
            raise ConnectionError(f"Cannot access GCS bucket {bucket}: {e}")

    def list_files(self) -> Iterator[str]:
        """
        List blobs in GCS bucket matching pattern.

        Yields:
            Blob names (paths)
        """
        blobs = self.client.list_blobs(self.bucket_name, prefix=self.prefix)

        for blob in blobs:
            # Skip directories
            if blob.name.endswith('/'):
                continue

            # Check pattern match
            filename = blob.name.split('/')[-1]
            if fnmatch.fnmatch(filename, self.pattern):
                yield blob.name

    def read_file(self, file_id: str, chunk_size: int = 8 * 1024 * 1024) -> Iterator[bytes]:
        """
        Read blob from GCS in chunks (streaming).

        Args:
            file_id: Blob name
            chunk_size: Chunk size in bytes (default: 8MB)

        Yields:
            Chunks of blob content as bytes
        """
        try:
            blob = self.bucket.blob(file_id)
            # Download in chunks using byte range requests
            blob.reload()  # Get blob size
            total_size = blob.size

            offset = 0
            while offset < total_size:
                # Download chunk using range
                end = min(offset + chunk_size - 1, total_size - 1)
                chunk = blob.download_as_bytes(start=offset, end=end + 1)
                yield chunk
                offset += len(chunk)

        except GoogleCloudError:
            # Skip files that can't be read
            pass

    def close(self):
        """Clean up resources."""
        # GCS client doesn't need explicit cleanup
        pass
