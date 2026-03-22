"""Standard output (stdout) destination."""

import sys
from typing import Dict, List, Optional
from ..base import OutputDestination


class StdoutDestination(OutputDestination):
    """Output destination for standard output (stdout)."""

    def __init__(self):
        """Initialize stdout destination."""
        pass

    def write(self, source_file_id: str, events: List[str], batch_size: int = 1000, metadata: Optional[Dict[str, str]] = None):
        """
        Write events to stdout.

        Args:
            source_file_id: Source file identifier (unused)
            events: List of serialized events
            batch_size: Number of events per batch (unused, writes all at once)
        """
        for event in events:
            sys.stdout.write(event)
            sys.stdout.write('\n')

        # Flush to ensure output appears immediately
        sys.stdout.flush()

    def close(self):
        """Clean up resources (none needed for stdout)."""
        pass
