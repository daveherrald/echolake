"""Output destination handlers."""

from .local import LocalDestination
from .s3 import S3Destination
from .gcs import GCSDestination
from .azure_blob import AzureBlobDestination
from .stdout import StdoutDestination
from .splunk_hec import SplunkHECDestination

__all__ = [
    'LocalDestination',
    'S3Destination',
    'GCSDestination',
    'AzureBlobDestination',
    'StdoutDestination',
    'SplunkHECDestination',
    'get_destination',
]


def get_destination(destination_type: str, **kwargs):
    """
    Factory function to get output destination.

    Args:
        destination_type: Destination type (local, s3, gcs, azure, stdout)
        **kwargs: Arguments for destination initialization

    Returns:
        Destination instance
    """
    destinations = {
        'local': LocalDestination,
        's3': S3Destination,
        'gcs': GCSDestination,
        'azure': AzureBlobDestination,
        'azure_blob': AzureBlobDestination,  # Alias
        'stdout': StdoutDestination,
        'splunk_hec': SplunkHECDestination,
        'hec': SplunkHECDestination,  # Alias
    }

    destination_class = destinations.get(destination_type.lower())
    if not destination_class:
        raise ValueError(f"Unsupported destination type: {destination_type}")

    return destination_class(**kwargs)
