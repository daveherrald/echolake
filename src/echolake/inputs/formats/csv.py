"""CSV format handler."""

import csv
import io
import logging
from typing import Iterator
from ..base import InputFormat

logger = logging.getLogger(__name__)

# Increase field size limit to handle large fields (e.g. lsof output).
# Use 2GB rather than sys.maxsize which can overflow on 64-bit platforms.
csv.field_size_limit(2**31 - 1)


class CSVFormat(InputFormat):
    """Handler for CSV format (Comma-Separated Values)."""

    def parse(self, content_stream: Iterator[bytes]) -> Iterator[dict]:
        """
        Parse CSV content stream into dictionaries (streaming, line-buffered).

        Args:
            content_stream: Iterator yielding chunks of bytes

        Yields:
            Parsed dictionaries (one per row, using header as keys)
        """
        # Create a line-buffered text stream from byte chunks
        # This handles line boundaries across chunk boundaries
        text_stream = self._decode_stream(content_stream)

        # Use csv.DictReader on the text stream
        # DictReader yields rows one at a time (never loads entire file)
        csv_reader = csv.DictReader(text_stream)

        while True:
            try:
                row = next(csv_reader)
            except StopIteration:
                break
            except csv.Error as e:
                logger.debug("Skipping bad CSV row at line %d: %s", csv_reader.line_num, e)
                continue
            if row:  # Skip empty rows
                yield dict(row)

    @staticmethod
    def _decode_stream(byte_stream: Iterator[bytes]) -> Iterator[str]:
        """
        Decode byte stream to text lines (handles partial line boundaries).

        Args:
            byte_stream: Iterator yielding byte chunks

        Yields:
            Complete text lines
        """
        buffer = b''

        for chunk in byte_stream:
            buffer += chunk

            # Split on newlines, keep incomplete last line in buffer
            lines = buffer.split(b'\n')
            buffer = lines[-1]  # Keep incomplete line

            # Yield complete lines
            for line in lines[:-1]:
                # Strip trailing \r from \r\n pairs to prevent \r leaking into field values
                if line.endswith(b'\r'):
                    line = line[:-1]
                # Use errors='replace' to preserve lines with binary content
                # (replaces non-UTF-8 bytes with U+FFFD instead of dropping the line)
                text = line.decode('utf-8', errors='replace')
                # Normalize standalone \r (Mac line endings) to \n for consistent output
                text = text.replace('\r', '\n')
                yield text + '\n'

        # Yield final line if exists
        if buffer:
            if buffer.endswith(b'\r'):
                buffer = buffer[:-1]
            text = buffer.decode('utf-8', errors='replace')
            text = text.replace('\r', '\n')
            yield text
