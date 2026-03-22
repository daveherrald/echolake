"""Input source handlers."""

from .local_dir import LocalDirectorySource
from .s3 import S3Source
from .gcs import GCSSource
from .azure_blob import AzureBlobSource

__all__ = [
    'LocalDirectorySource',
    'S3Source',
    'GCSSource',
    'AzureBlobSource',
    'get_source',
]


def get_source(source_type: str, **kwargs):
    """
    Factory function to get input source.

    Args:
        source_type: Source type (local, s3, gcs, azure)
        **kwargs: Arguments for source initialization

    Returns:
        Source instance
    """
    sources = {
        'local': LocalDirectorySource,
        's3': S3Source,
        'gcs': GCSSource,
        'azure': AzureBlobSource,
    }

    source_class = sources.get(source_type.lower())
    if not source_class:
        raise ValueError(f"Unsupported source type: {source_type}")

    return source_class(**kwargs)
