"""Local directory input source."""

from pathlib import Path
from typing import Iterator, Optional, List
import fnmatch
import gzip
from ..base import InputSource


class LocalDirectorySource(InputSource):
    """Input source for local filesystem directories."""

    def __init__(self, path: str, pattern: str = "*", recursive: bool = True, include_files: Optional[List[str]] = None):
        """
        Initialize local directory source.

        Args:
            path: Directory path
            pattern: File pattern for matching (glob-style)
            recursive: Recursively search subdirectories
            include_files: Optional list of specific file paths to include (filters the results)
        """
        self.path = Path(path)
        self.pattern = pattern
        self.recursive = recursive
        self.include_files = set(include_files) if include_files else None

        if not self.path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        if not self.path.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {path}")

    def list_files(self) -> Iterator[str]:
        """
        List files matching pattern.

        Yields:
            File paths as strings
        """
        if self.recursive:
            # Recursive search
            for file_path in self.path.rglob(self.pattern):
                if file_path.is_file():
                    file_str = str(file_path)
                    # Filter by include_files if specified
                    if self.include_files is None or file_str in self.include_files:
                        yield file_str
        else:
            # Non-recursive search
            for file_path in self.path.glob(self.pattern):
                if file_path.is_file():
                    file_str = str(file_path)
                    # Filter by include_files if specified
                    if self.include_files is None or file_str in self.include_files:
                        yield file_str

    def read_file(self, file_id: str, chunk_size: int = 8 * 1024 * 1024) -> Iterator[bytes]:
        """
        Read file content in chunks (streaming).

        Args:
            file_id: File path
            chunk_size: Chunk size in bytes (default: 8MB)

        Yields:
            Chunks of file content (decompressed if gzipped)
        """
        file_path = Path(file_id)
        if not file_path.exists() or not file_path.is_file():
            return

        # Check if file is gzipped
        is_gzipped = file_path.suffix == '.gz'

        if is_gzipped:
            # Stream decompress gzipped files in chunks
            with gzip.open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
        else:
            # Read non-gzipped files in chunks
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

    def close(self):
        """Clean up resources (none needed for local files)."""
        pass
