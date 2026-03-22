"""Azure Blob Storage input source."""

from typing import Iterator, Optional
import fnmatch

try:
    from azure.storage.blob import BlobServiceClient
    from azure.core.exceptions import AzureError
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

from ..base import InputSource


class AzureBlobSource(InputSource):
    """Input source for Azure Blob Storage."""

    def __init__(
        self,
        container: str,
        prefix: str = "",
        pattern: str = "*",
        connection_string: Optional[str] = None,
        account_url: Optional[str] = None,
    ):
        """
        Initialize Azure Blob source.

        Args:
            container: Container name
            prefix: Blob prefix (folder path)
            pattern: File pattern for matching
            connection_string: Azure connection string (optional)
            account_url: Storage account URL (optional, for managed identity)
        """
        if not AZURE_AVAILABLE:
            raise ImportError(
                "azure-storage-blob is required for Azure source. "
                "Install with: pip install azure-storage-blob"
            )

        self.container_name = container
        self.prefix = prefix.rstrip('/')
        self.pattern = pattern

        # Initialize client
        try:
            if connection_string:
                self.blob_service_client = BlobServiceClient.from_connection_string(
                    connection_string
                )
            elif account_url:
                # Use DefaultAzureCredential for managed identity
                from azure.identity import DefaultAzureCredential
                credential = DefaultAzureCredential()
                self.blob_service_client = BlobServiceClient(
                    account_url=account_url, credential=credential
                )
            else:
                raise ValueError(
                    "Either connection_string or account_url must be provided"
                )

            self.container_client = self.blob_service_client.get_container_client(
                container
            )

            # Verify container access
            if not self.container_client.exists():
                raise ValueError(f"Container does not exist: {container}")

        except AzureError as e:
            raise ConnectionError(f"Cannot access Azure container {container}: {e}")

    def list_files(self) -> Iterator[str]:
        """
        List blobs in container matching pattern.

        Yields:
            Blob names (paths)
        """
        blobs = self.container_client.list_blobs(name_starts_with=self.prefix)

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
        Read blob from Azure in chunks (streaming).

        Args:
            file_id: Blob name
            chunk_size: Chunk size in bytes (default: 8MB)

        Yields:
            Chunks of blob content as bytes
        """
        try:
            blob_client = self.container_client.get_blob_client(file_id)
            # Azure's download_blob() supports streaming via chunks()
            downloader = blob_client.download_blob()
            for chunk in downloader.chunks():
                yield chunk
        except AzureError:
            # Skip files that can't be read
            pass

    def close(self):
        """Clean up resources."""
        if hasattr(self, 'blob_service_client'):
            self.blob_service_client.close()
