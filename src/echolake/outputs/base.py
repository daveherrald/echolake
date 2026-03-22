"""Base classes for output handling."""

import gzip
import bz2
from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from ..models.event import Event


class OutputDestination(ABC):
    """Abstract base class for output destinations (where to write data)."""

    def _compress_bytes(self, data: bytes, compression: Optional[str]) -> bytes:
        """Compress bytes using the specified algorithm."""
        if compression == 'gzip':
            return gzip.compress(data)
        elif compression == 'bzip2':
            return bz2.compress(data)
        return data

    @staticmethod
    def _compression_extension(compression: Optional[str]) -> str:
        """Return file extension for compression type."""
        if compression == 'gzip':
            return '.gz'
        elif compression == 'bzip2':
            return '.bz2'
        return ''

    @abstractmethod
    def write(self, source_file_id: str, events: List[str], batch_size: int = 1000, metadata: Optional[Dict[str, str]] = None):
        """
        Write events to destination.

        Args:
            source_file_id: Identifier of source file (for naming output)
            events: List of serialized events
            batch_size: Number of events per batch
            metadata: Optional metadata dict (e.g., sourcetype for routing)
        """
        pass

    @abstractmethod
    def close(self):
        """Clean up resources."""
        pass


class OutputFormat(ABC):
    """Abstract base class for output formats (how to serialize data)."""

    @abstractmethod
    def format_event(self, event: Event) -> str:
        """
        Format event for output.

        Args:
            event: Event to format

        Returns:
            Formatted event as string
        """
        pass

    @abstractmethod
    def format_batch(self, events: List[Event]) -> str:
        """
        Format batch of events.

        Args:
            events: List of events to format

        Returns:
            Formatted batch as string
        """
        pass
