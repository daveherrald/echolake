"""Local filesystem output destination."""

import gzip
import bz2
import re
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import tempfile
import shutil
from ..base import OutputDestination


class LocalDestination(OutputDestination):
    """Output destination for local filesystem."""

    def __init__(self, path: str, path_template: str = "{filename}", compression: Optional[str] = None):
        """
        Initialize local destination.

        Args:
            path: Base directory path
            path_template: Template for output path with variables
            compression: Compression type (gzip, bzip2, or None)
        """
        self.base_path = Path(path)
        self.path_template = path_template
        self.compression = compression

        # Create directory if it doesn't exist
        self.base_path.mkdir(parents=True, exist_ok=True)

    def write(self, source_file_id: str, events: List[str], batch_size: int = 1000, metadata: Optional[Dict[str, str]] = None):
        """
        Write events to local file (appends to existing file).

        Args:
            source_file_id: Source file identifier
            events: List of serialized events
            batch_size: Number of events per batch (unused, writes all at once)
            metadata: Optional metadata dict (e.g., sourcetype for routing)
        """
        # Generate output path
        output_path = self._generate_path(source_file_id, metadata=metadata)

        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Append to file (create if doesn't exist)
        if self.compression == 'gzip':
            with gzip.open(output_path, 'at') as output_file:
                for event in events:
                    output_file.write(event)
                    output_file.write('\n')
        elif self.compression == 'bzip2':
            with bz2.open(output_path, 'at') as output_file:
                for event in events:
                    output_file.write(event)
                    output_file.write('\n')
        else:
            with open(output_path, 'a') as output_file:
                for event in events:
                    output_file.write(event)
                    output_file.write('\n')

    def _generate_path(self, source_file_id: str, metadata: Optional[Dict[str, str]] = None) -> Path:
        """
        Generate output path from template.

        Args:
            source_file_id: Source file identifier
            metadata: Optional metadata dict with sourcetype etc.

        Returns:
            Output path
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

        # Add sourcetype from metadata (normalize for filesystem safety)
        if metadata and 'sourcetype' in metadata:
            sourcetype = re.sub(r'[:/\\]', '-', metadata['sourcetype'])
            variables['sourcetype'] = sourcetype
        else:
            variables['sourcetype'] = 'unknown'

        # Format template
        relative_path = self.path_template.format(**variables)

        # Append compression extension
        ext = self._compression_extension(self.compression)
        if ext and not relative_path.endswith(ext):
            relative_path += ext

        return self.base_path / relative_path

    def close(self):
        """Clean up resources (none needed for local files)."""
        pass
