"""Azure Blob Storage output destination."""

import re
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

try:
    from azure.storage.blob import BlobServiceClient
    from azure.core.exceptions import AzureError
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

from ..base import OutputDestination


class AzureBlobDestination(OutputDestination):
    """Output destination for Azure Blob Storage."""

    def __init__(
        self,
        container: str,
        path_template: str = "output/{filename}",
        connection_string: Optional[str] = None,
        account_url: Optional[str] = None,
        compression: Optional[str] = None,
    ):
        """
        Initialize Azure Blob destination.

        Args:
            container: Container name
            path_template: Template for output blob name with variables
            connection_string: Azure connection string (optional)
            account_url: Storage account URL (optional)
            compression: Compression type (gzip, bzip2, or None)
        """
        if not AZURE_AVAILABLE:
            raise ImportError(
                "azure-storage-blob is required for Azure destination. "
                "Install with: pip install azure-storage-blob"
            )

        self.container_name = container
        self.path_template = path_template
        self.compression = compression

        # Initialize client
        try:
            if connection_string:
                self.blob_service_client = BlobServiceClient.from_connection_string(
                    connection_string
                )
            elif account_url:
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

        except AzureError as e:
            raise ConnectionError(f"Cannot access Azure container {container}: {e}")

    def write(self, source_file_id: str, events: List[str], batch_size: int = 1000, metadata: Optional[Dict[str, str]] = None):
        """
        Write events to Azure Blob Storage.

        Args:
            source_file_id: Source file identifier
            events: List of serialized events
            batch_size: Number of events per batch (unused, writes all at once)
            metadata: Optional metadata dict (e.g., sourcetype for routing)
        """
        # Generate output blob name
        blob_name = self._generate_blob_name(source_file_id, metadata=metadata)

        # Combine events
        content = '\n'.join(events)
        content_bytes = content.encode('utf-8')
        content_bytes = self._compress_bytes(content_bytes, self.compression)

        # Upload to Azure
        try:
            blob_client = self.container_client.get_blob_client(blob_name)
            blob_client.upload_blob(content_bytes, overwrite=True)
        except AzureError as e:
            raise IOError(f"Failed to write to Azure: {e}")

    def _generate_blob_name(self, source_file_id: str, metadata: Optional[Dict[str, str]] = None) -> str:
        """
        Generate output blob name from template.

        Args:
            source_file_id: Source file identifier
            metadata: Optional metadata dict with sourcetype etc.

        Returns:
            Blob name
        """
        now = datetime.utcnow()
        source_filename = Path(source_file_id).name

        # Template variables
        variables = {
            'filename': source_filename,
            'year': now.strftime('%Y'),
            'month': now.strftime('%m'),
            'day': now.strftime('%d'),
            'hour': now.strftime('%H'),
            'minute': now.strftime('%M'),
        }

        # Add sourcetype from metadata (normalize for path safety)
        if metadata and 'sourcetype' in metadata:
            variables['sourcetype'] = re.sub(r'[:/\\]', '-', metadata['sourcetype'])
        else:
            variables['sourcetype'] = 'unknown'

        # Format template
        name = self.path_template.format(**variables)

        # Append compression extension
        ext = self._compression_extension(self.compression)
        if ext and not name.endswith(ext):
            name += ext

        return name

    def close(self):
        """Clean up resources."""
        if hasattr(self, 'blob_service_client'):
            self.blob_service_client.close()
