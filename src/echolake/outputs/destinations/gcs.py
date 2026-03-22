"""Google Cloud Storage output destination."""

import re
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

try:
    from google.cloud import storage
    from google.cloud.exceptions import GoogleCloudError
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False

from ..base import OutputDestination


class GCSDestination(OutputDestination):
    """Output destination for Google Cloud Storage."""

    def __init__(
        self,
        bucket: str,
        path_template: str = "output/{filename}",
        project: Optional[str] = None,
        compression: Optional[str] = None,
    ):
        """
        Initialize GCS destination.

        Args:
            bucket: GCS bucket name
            path_template: Template for output blob name with variables
            project: GCP project ID (optional)
            compression: Compression type (gzip, bzip2, or None)
        """
        if not GCS_AVAILABLE:
            raise ImportError(
                "google-cloud-storage is required for GCS destination. "
                "Install with: pip install google-cloud-storage"
            )

        self.bucket_name = bucket
        self.path_template = path_template
        self.compression = compression

        # Initialize GCS client
        try:
            if project:
                self.client = storage.Client(project=project)
            else:
                self.client = storage.Client()

            self.bucket = self.client.bucket(bucket)

        except GoogleCloudError as e:
            raise ConnectionError(f"Cannot access GCS bucket {bucket}: {e}")

    def write(self, source_file_id: str, events: List[str], batch_size: int = 1000, metadata: Optional[Dict[str, str]] = None):
        """
        Write events to GCS.

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

        # Upload to GCS
        try:
            blob = self.bucket.blob(blob_name)
            content_type = 'application/gzip' if self.compression == 'gzip' else 'application/json'
            blob.upload_from_string(content_bytes, content_type=content_type)
        except GoogleCloudError as e:
            raise IOError(f"Failed to write to GCS: {e}")

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
        # GCS client doesn't need explicit cleanup
        pass
