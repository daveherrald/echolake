"""Memory safety utilities for EchoLake."""

import os
import psutil
from pathlib import Path
from typing import List, Optional, Tuple
import gzip


class MemoryGuard:
    """Memory safety checks and estimates."""

    # Conservative estimate: decompressed size is typically 5-10x compressed size for logs
    # We use 10x to be safe
    COMPRESSION_RATIO = 10

    # Events in memory expansion factor (parsed objects + overhead)
    # Each event becomes a dict with timestamps, metadata, etc.
    MEMORY_EXPANSION_FACTOR = 3

    # Safety margin - don't use more than this percentage of available memory
    SAFETY_MARGIN = 0.7  # 70%

    def __init__(self, max_memory_mb: Optional[int] = None):
        """
        Initialize memory guard.

        Args:
            max_memory_mb: Maximum memory to use in MB. If None, uses 70% of available memory.
        """
        self.max_memory_bytes = (
            max_memory_mb * 1024 * 1024 if max_memory_mb else self._get_safe_memory_limit()
        )

    @staticmethod
    def _get_safe_memory_limit() -> int:
        """Get safe memory limit (70% of available memory)."""
        mem = psutil.virtual_memory()
        return int(mem.available * MemoryGuard.SAFETY_MARGIN)

    @staticmethod
    def _estimate_decompressed_size(file_path: Path) -> int:
        """
        Estimate decompressed size of a file.

        Args:
            file_path: Path to file

        Returns:
            Estimated decompressed size in bytes
        """
        compressed_size = file_path.stat().st_size

        # Check if file is gzipped
        if file_path.suffix == '.gz' or file_path.name.endswith('.gz'):
            # For gzipped files, try to get actual decompressed size from gzip header
            try:
                with gzip.open(file_path, 'rb') as f:
                    # Seek to end to get uncompressed size
                    # Note: This is fast as it just reads the gzip trailer
                    f.seek(-4, 2)  # Last 4 bytes contain uncompressed size
                    uncompressed_size = int.from_bytes(f.read(4), 'little')
                    if uncompressed_size > 0:
                        return uncompressed_size
            except (OSError, IOError):
                pass

            # Fallback to compression ratio estimate
            return compressed_size * MemoryGuard.COMPRESSION_RATIO
        else:
            # Not compressed
            return compressed_size

    def estimate_memory_usage(self, file_paths: List[Path], streaming: bool = True) -> Tuple[int, int]:
        """
        Estimate memory usage for processing files.

        Args:
            file_paths: List of file paths to process
            streaming: If True, only checks largest single file (streaming mode).
                      If False, checks all files together (legacy batch mode).

        Returns:
            Tuple of (estimated_bytes, max_allowed_bytes)
        """
        if streaming:
            # Streaming mode: only need to fit the largest file in memory
            max_decompressed = 0
            for file_path in file_paths:
                size = self._estimate_decompressed_size(file_path)
                if size > max_decompressed:
                    max_decompressed = size
            estimated_usage = int(max_decompressed * self.MEMORY_EXPANSION_FACTOR)
        else:
            # Legacy batch mode: need to fit all files in memory at once
            total_decompressed = 0
            for file_path in file_paths:
                total_decompressed += self._estimate_decompressed_size(file_path)
            estimated_usage = int(total_decompressed * self.MEMORY_EXPANSION_FACTOR)

        return estimated_usage, self.max_memory_bytes

    def check_files(self, file_paths: List[Path], streaming: bool = True) -> Tuple[bool, str, int, int]:
        """
        Check if files are safe to process.

        Args:
            file_paths: List of file paths to check
            streaming: If True, uses streaming mode (checks largest file only)

        Returns:
            Tuple of (is_safe, message, estimated_mb, limit_mb)
        """
        if not file_paths:
            return True, "No files to process", 0, 0

        estimated_bytes, limit_bytes = self.estimate_memory_usage(file_paths, streaming=streaming)
        estimated_mb = estimated_bytes // (1024 * 1024)
        limit_mb = limit_bytes // (1024 * 1024)

        if estimated_bytes > limit_bytes:
            files_by_size = sorted(
                [(f, self._estimate_decompressed_size(f)) for f in file_paths],
                key=lambda x: x[1],
                reverse=True
            )

            largest_file, largest_size = files_by_size[0]
            largest_mb = largest_size // (1024 * 1024)

            if streaming:
                message = (
                    f"Memory safety check FAILED:\n"
                    f"  Largest file needs: {estimated_mb} MB (streaming mode)\n"
                    f"  Safe memory limit: {limit_mb} MB\n"
                    f"  Largest file: {largest_file.name} (~{largest_mb} MB decompressed)\n"
                    f"\n"
                    f"Recommendations:\n"
                    f"  1. Skip this file: --max-file-size {largest_mb - 1}\n"
                    f"  2. Process on a machine with more memory\n"
                    f"  3. Increase limit: --max-memory {estimated_mb + 1024}"
                )
            else:
                message = (
                    f"Memory safety check FAILED:\n"
                    f"  Estimated memory needed: {estimated_mb} MB\n"
                    f"  Safe memory limit: {limit_mb} MB\n"
                    f"  Largest file: {largest_file.name} (~{largest_mb} MB decompressed)\n"
                    f"\n"
                    f"Recommendations:\n"
                    f"  1. Process files individually (use --max-file-size)\n"
                    f"  2. Process on a machine with more memory\n"
                    f"  3. Use --max-memory to override limit (risky)"
                )
            return False, message, estimated_mb, limit_mb

        # Warn if using more than 50% but less than 70%
        if estimated_bytes > limit_bytes * 0.7:
            message = (
                f"Memory usage warning:\n"
                f"  Estimated memory needed: {estimated_mb} MB\n"
                f"  Safe memory limit: {limit_mb} MB\n"
                f"  This will use significant memory. Consider processing files individually."
            )
            return True, message, estimated_mb, limit_mb

        message = f"Memory check passed: {estimated_mb} MB / {limit_mb} MB"
        return True, message, estimated_mb, limit_mb

    def check_single_file(self, file_path: Path) -> Tuple[bool, str, int]:
        """
        Check if a single file is safe to process.

        Args:
            file_path: File path to check

        Returns:
            Tuple of (is_safe, message, estimated_mb)
        """
        is_safe, message, estimated_mb, limit_mb = self.check_files([file_path])
        return is_safe, message, estimated_mb

    @staticmethod
    def get_current_memory_usage() -> Tuple[int, int]:
        """
        Get current process memory usage.

        Returns:
            Tuple of (current_mb, available_mb)
        """
        process = psutil.Process(os.getpid())
        current_bytes = process.memory_info().rss
        mem = psutil.virtual_memory()

        current_mb = current_bytes // (1024 * 1024)
        available_mb = mem.available // (1024 * 1024)

        return current_mb, available_mb

    @staticmethod
    def format_bytes(bytes_value: int) -> str:
        """Format bytes into human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
