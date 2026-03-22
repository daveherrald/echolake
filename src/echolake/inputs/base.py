"""Base classes for input handling."""

from abc import ABC, abstractmethod
from typing import Iterator, Optional
from ..models.event import Event


class InputSource(ABC):
    """Abstract base class for input sources (where data comes from)."""

    @abstractmethod
    def list_files(self) -> Iterator[str]:
        """
        List available files from source.

        Yields:
            File identifiers (paths, URIs, etc.)
        """
        pass

    @abstractmethod
    def read_file(self, file_id: str) -> Iterator[bytes]:
        """
        Read file content in chunks.

        Args:
            file_id: File identifier from list_files

        Yields:
            Chunks of file content as bytes
        """
        pass

    @abstractmethod
    def close(self):
        """Clean up resources."""
        pass


class InputFormat(ABC):
    """Abstract base class for input formats (how to parse data)."""

    @abstractmethod
    def parse(self, content_stream: Iterator[bytes]) -> Iterator[dict]:
        """
        Parse streaming content into raw event dictionaries.

        Args:
            content_stream: Iterator yielding chunks of bytes

        Yields:
            Parsed events as dictionaries
        """
        pass


class InputSchema(ABC):
    """Abstract base class for input schemas (what the data represents)."""

    @abstractmethod
    def extract_event(self, raw_data: dict, format_type: str, sourcetype: str = None) -> Event:
        """
        Extract Event from raw data according to schema.

        Args:
            raw_data: Parsed data dictionary
            format_type: Format type (json, jsonl, text, etc.)
            sourcetype: Optional sourcetype for timestamp registry lookup

        Returns:
            Event instance with extracted timestamps and metadata
        """
        pass

    @abstractmethod
    def get_timestamp_patterns(self) -> list:
        """
        Get timestamp extraction patterns for this schema.

        Returns:
            List of timestamp pattern configurations
        """
        pass
